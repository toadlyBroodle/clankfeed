"""Nostr relay: WebSocket handler, subscription manager, filter matching, event storage/query."""

import json
import logging
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import WebSocket
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import (
    settings,
    payments_enabled,
    tempo_enabled,
    MAX_SUBSCRIPTIONS_PER_CONN,
    MAX_FILTERS_PER_REQ,
    MAX_MESSAGE_BYTES,
    MAX_CONTENT_LENGTH,
    MAX_EVENT_TAGS,
    MAX_TAG_VALUE_LENGTH,
    PENDING_EVENT_TTL,
    ALLOWED_EVENT_KINDS,
    NWC_EVENT_KINDS,
)
from app.models import NostrEvent, PendingEvent
from app.nostr import validate_event, verify_event_id, verify_signature

logger = logging.getLogger("clankfeed.relay")


class Connection:
    """Per-WebSocket connection state."""

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.subscriptions: dict[str, list[dict]] = {}  # sub_id -> [filter, ...]
        self.challenge: str = secrets.token_hex(16)  # NIP-42 auth challenge
        self.authed_pubkeys: set[str] = set()  # pubkeys authenticated via NIP-42

    async def send(self, msg: list):
        await self.ws.send_text(json.dumps(msg))


# Global connection registry
connections: set[Connection] = set()


async def broadcast_event(event_dict: dict):
    """Send an event to all connections with matching subscriptions."""
    dead = set()
    for conn in connections:
        for sub_id, filters in conn.subscriptions.items():
            if any(_matches_filter(event_dict, f) for f in filters):
                try:
                    await conn.send(["EVENT", sub_id, event_dict])
                except Exception:
                    dead.add(conn)
                break  # one match per connection is enough
    connections.difference_update(dead)


def _matches_filter(event: dict, filt: dict) -> bool:
    """Check if an event matches a NIP-01 filter."""
    if "ids" in filt:
        if not any(event["id"].startswith(prefix) for prefix in filt["ids"]):
            return False
    if "authors" in filt:
        if not any(event["pubkey"].startswith(prefix) for prefix in filt["authors"]):
            return False
    if "kinds" in filt:
        if event["kind"] not in filt["kinds"]:
            return False
    if "since" in filt:
        if event["created_at"] < filt["since"]:
            return False
    if "until" in filt:
        if event["created_at"] > filt["until"]:
            return False
    # Tag filters: #e, #p, etc.
    for key, values in filt.items():
        if key.startswith("#") and len(key) == 2:
            tag_name = key[1]
            event_tag_values = [t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == tag_name]
            if not any(v in event_tag_values for v in values):
                return False
    return True


async def query_events(
    db: AsyncSession,
    filters: list[dict],
    sort: str = "newest",
    min_value: int | None = None,
    max_value: int | None = None,
) -> list[dict]:
    """Query stored events matching any of the given filters.

    sort: "newest" (created_at DESC) or "value" (value_sats DESC)
    min_value/max_value: filter by value_sats range
    """
    results = []
    seen_ids = set()

    for filt in filters:
        conditions = []

        if "ids" in filt:
            id_conds = [NostrEvent.id.startswith(prefix) for prefix in filt["ids"]]
            conditions.append(or_(*id_conds))
        if "authors" in filt:
            auth_conds = [NostrEvent.pubkey.startswith(prefix) for prefix in filt["authors"]]
            conditions.append(or_(*auth_conds))
        if "kinds" in filt:
            conditions.append(NostrEvent.kind.in_(filt["kinds"]))
        if "since" in filt:
            conditions.append(NostrEvent.created_at >= filt["since"])
        if "until" in filt:
            conditions.append(NostrEvent.created_at <= filt["until"])

        # Value filters
        if min_value is not None:
            conditions.append(NostrEvent.value_sats >= min_value)
        if max_value is not None:
            conditions.append(NostrEvent.value_sats <= max_value)

        # Reply filter
        if "reply_to" in filt:
            # Match events that have an "e" tag with the parent event ID
            # json.dumps uses ", " separator, so search for '"e", "parent_id"'
            conditions.append(NostrEvent.tags.contains(f'"e", "{filt["reply_to"]}"'))

        # Sort order
        if sort == "value":
            stmt = select(NostrEvent).order_by(NostrEvent.value_sats.desc(), NostrEvent.created_at.desc())
        else:
            stmt = select(NostrEvent).order_by(NostrEvent.created_at.desc())

        if conditions:
            stmt = stmt.where(and_(*conditions))

        limit = min(filt.get("limit", 500), 500)
        stmt = stmt.limit(limit)

        rows = (await db.execute(stmt)).scalars().all()
        for row in rows:
            if row.id not in seen_ids:
                seen_ids.add(row.id)
                results.append(row_to_event(row))

    return results


def row_to_event(row: NostrEvent) -> dict:
    """Convert a DB row to a Nostr event dict."""
    d = {
        "id": row.id,
        "pubkey": row.pubkey,
        "created_at": row.created_at,
        "kind": row.kind,
        "tags": json.loads(row.tags),
        "content": row.content,
        "sig": row.sig,
    }
    if row.value_sats:
        d["value_sats"] = row.value_sats
    if row.value_usd and row.value_usd != "0":
        d["value_usd"] = row.value_usd
    return d


async def store_event(db: AsyncSession, event: dict, value_sats: int = 0, value_usd: str = "0"):
    """Store a validated, paid event in the database.

    Kind 0 (metadata) is replaceable: only the latest per pubkey is kept.
    If a newer kind:0 already exists for this pubkey, the incoming event is skipped.
    """
    existing = await db.get(NostrEvent, event["id"])
    if existing:
        return  # duplicate, skip

    # Replaceable events (kind 0, 3, 10000-19999): keep only latest per pubkey+kind
    if event["kind"] == 0 or event["kind"] == 3 or 10000 <= event["kind"] < 20000:
        stmt = select(NostrEvent).where(
            and_(NostrEvent.pubkey == event["pubkey"], NostrEvent.kind == event["kind"])
        )
        old = (await db.execute(stmt)).scalar_one_or_none()
        if old:
            if old.created_at > event["created_at"]:
                return  # existing is newer, skip
            if old.created_at == event["created_at"] and old.id < event["id"]:
                return  # same timestamp, existing has lower id (per NIP-01 tie-break)
            await db.delete(old)

    row = NostrEvent(
        id=event["id"],
        pubkey=event["pubkey"],
        created_at=event["created_at"],
        kind=event["kind"],
        tags=json.dumps(event["tags"]),
        content=event["content"],
        sig=event["sig"],
        value_sats=value_sats,
        value_usd=value_usd,
    )
    db.add(row)
    await db.commit()


async def store_pending_event(
    db: AsyncSession, event: dict, amount_sats: int = 0, amount_usd: str = "0"
) -> str:
    """Store an event awaiting payment. Returns the token."""
    token = secrets.token_hex(32)
    expires = datetime.utcnow() + timedelta(seconds=PENDING_EVENT_TTL)
    row = PendingEvent(
        token=token,
        event_json=json.dumps(event),
        amount_sats=amount_sats,
        amount_usd=amount_usd,
        created_at=datetime.utcnow(),
        expires_at=expires,
    )
    db.add(row)
    await db.commit()
    return token


async def handle_message(conn: Connection, raw: str, db: AsyncSession):
    """Dispatch an incoming WebSocket message per NIP-01."""
    if len(raw) > MAX_MESSAGE_BYTES:
        await conn.send(["NOTICE", "error: message too large"])
        return

    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        await conn.send(["NOTICE", "error: invalid JSON"])
        return

    if not isinstance(msg, list) or len(msg) < 2:
        await conn.send(["NOTICE", "error: message must be a JSON array"])
        return

    msg_type = msg[0]

    if msg_type == "EVENT":
        await _handle_event(conn, msg, db)
    elif msg_type == "REQ":
        await _handle_req(conn, msg, db)
    elif msg_type == "CLOSE":
        await _handle_close(conn, msg)
    elif msg_type == "AUTH":
        await _handle_auth(conn, msg)
    else:
        await conn.send(["NOTICE", f"error: unknown message type: {msg_type}"])


async def _handle_event(conn: Connection, msg: list, db: AsyncSession):
    """Handle an EVENT message. Validate, then require payment."""
    if len(msg) < 2:
        await conn.send(["NOTICE", "error: EVENT requires an event object"])
        return

    event = msg[1]
    if not isinstance(event, dict):
        await conn.send(["NOTICE", "error: EVENT payload must be an object"])
        return

    valid, err = validate_event(event)
    if not valid:
        event_id = event.get("id", "")
        await conn.send(["OK", event_id, False, err])
        return

    event_id = event["id"]

    # Enforce allowed event kinds (paid notes + metadata + NWC)
    if event["kind"] not in ALLOWED_EVENT_KINDS and event["kind"] not in NWC_EVENT_KINDS:
        await conn.send(["OK", event_id, False, f"blocked: kind {event['kind']} not accepted"])
        return

    # NWC events (NIP-47): store and broadcast without payment
    if event["kind"] in NWC_EVENT_KINDS:
        await store_event(db, event)
        await conn.send(["OK", event_id, True, ""])
        await broadcast_event(event)
        return

    # Enforce content length
    if len(event["content"]) > MAX_CONTENT_LENGTH:
        await conn.send(["OK", event_id, False, f"invalid: content exceeds {MAX_CONTENT_LENGTH} chars"])
        return

    # Enforce tag count and tag value lengths
    if len(event["tags"]) > MAX_EVENT_TAGS:
        await conn.send(["OK", event_id, False, f"invalid: too many tags (max {MAX_EVENT_TAGS})"])
        return
    for tag in event["tags"]:
        if isinstance(tag, list):
            for val in tag:
                if isinstance(val, str) and len(val) > MAX_TAG_VALUE_LENGTH:
                    await conn.send(["OK", event_id, False, f"invalid: tag value exceeds {MAX_TAG_VALUE_LENGTH} chars"])
                    return

    if not payments_enabled() and not tempo_enabled():
        # No payment methods configured: store directly
        await store_event(db, event)
        await conn.send(["OK", event_id, True, ""])
        await broadcast_event(event)
        return

    # Payment required (Lightning and/or Tempo): store as pending, return payment URL
    token = await store_pending_event(db, event)
    base = settings.BASE_URL.replace("ws://", "http://").replace("wss://", "https://")
    pay_url = f"{base}/pay?token={token}"
    await conn.send(["OK", event_id, False, f"payment-required:{pay_url}"])


async def _handle_req(conn: Connection, msg: list, db: AsyncSession):
    """Handle a REQ message. Register subscription and send matching events."""
    if len(msg) < 3:
        await conn.send(["NOTICE", "error: REQ requires subscription_id and at least one filter"])
        return

    sub_id = msg[1]
    if not isinstance(sub_id, str):
        await conn.send(["NOTICE", "error: subscription_id must be a string"])
        return

    if len(conn.subscriptions) >= MAX_SUBSCRIPTIONS_PER_CONN and sub_id not in conn.subscriptions:
        await conn.send(["CLOSED", sub_id, "error: too many subscriptions"])
        return

    filters = msg[2:]
    if len(filters) > MAX_FILTERS_PER_REQ:
        await conn.send(["CLOSED", sub_id, "error: too many filters"])
        return

    # Validate filters are dicts
    for f in filters:
        if not isinstance(f, dict):
            await conn.send(["CLOSED", sub_id, "error: filter must be an object"])
            return

    conn.subscriptions[sub_id] = filters

    # Query and send stored events
    events = await query_events(db, filters)
    for event in events:
        await conn.send(["EVENT", sub_id, event])

    await conn.send(["EOSE", sub_id])


async def _handle_close(conn: Connection, msg: list):
    """Handle a CLOSE message. Remove subscription."""
    if len(msg) < 2:
        await conn.send(["NOTICE", "error: CLOSE requires subscription_id"])
        return

    sub_id = msg[1]
    conn.subscriptions.pop(sub_id, None)
    await conn.send(["CLOSED", sub_id, ""])


async def _handle_auth(conn: Connection, msg: list):
    """Handle an AUTH message per NIP-42.

    Client sends a signed kind:22242 event proving they control a pubkey.
    Verify: kind, created_at within 10 min, challenge tag matches, relay tag matches.
    """
    if len(msg) < 2 or not isinstance(msg[1], dict):
        await conn.send(["NOTICE", "error: AUTH requires a signed event"])
        return

    event = msg[1]
    event_id = event.get("id", "")

    # Basic validation
    if event.get("kind") != 22242:
        await conn.send(["OK", event_id, False, "invalid: AUTH event must be kind 22242"])
        return

    if not verify_event_id(event):
        await conn.send(["OK", event_id, False, "invalid: event id does not match"])
        return

    if not verify_signature(event):
        await conn.send(["OK", event_id, False, "invalid: bad signature"])
        return

    # Check created_at within 10 minutes
    import time
    now = int(time.time())
    if abs(now - event.get("created_at", 0)) > 600:
        await conn.send(["OK", event_id, False, "invalid: AUTH event timestamp too old"])
        return

    # Check challenge tag matches
    tags = event.get("tags", [])
    challenge_tag = None
    relay_tag = None
    for tag in tags:
        if len(tag) >= 2:
            if tag[0] == "challenge":
                challenge_tag = tag[1]
            elif tag[0] == "relay":
                relay_tag = tag[1]

    if challenge_tag != conn.challenge:
        await conn.send(["OK", event_id, False, "invalid: challenge mismatch"])
        return

    if not relay_tag:
        await conn.send(["OK", event_id, False, "invalid: missing relay tag"])
        return

    # Verify relay URL matches (just check domain)
    from urllib.parse import urlparse
    expected_domain = urlparse(settings.BASE_URL).netloc
    actual_domain = urlparse(relay_tag).netloc
    if expected_domain and actual_domain and expected_domain != actual_domain:
        await conn.send(["OK", event_id, False, "invalid: relay URL mismatch"])
        return

    # Authentication successful
    pubkey = event.get("pubkey", "")
    conn.authed_pubkeys.add(pubkey)
    logger.info(f"NIP-42 AUTH success: {pubkey[:16]}...")
    await conn.send(["OK", event_id, True, ""])
