"""Populate the external feed from public Nostr relays.

One lightweight WebSocket client per relay in EXTERNAL_RELAYS subscribes to
kind-9735 zap receipts. For each verified receipt, the zapped kind-1 note is
fetched (same connection, separate subscription) and stored with sats_ext
credited at face value — the same fair ranking clankfeed votes feed into.
Only zapped notes are stored, never the firehose, so storage stays small.

EXT-1a: when the author has no local kind:0 lud16, fetch+store their profile
from EXTERNAL_RELAYS before LNURL signer verification (else fail-closed).
"""

import asyncio
import json
import logging
import time

import websockets

from app.config import settings, MAX_CONTENT_LENGTH, MAX_EVENT_TAGS
from app.database import async_session
from app.models import NostrEvent
from app.nostr import validate_event
from app.relay import apply_zap_receipt, store_event
from app.zaps import (
    get_author_lud16,
    is_relay_fee_leg,
    verify_zap_receipt,
    verify_zap_receipt_signer,
)

logger = logging.getLogger("clankfeed.ingest")

BACKFILL_LIMIT = 200  # zap receipts requested on (re)connect
MAX_PENDING_TARGETS = 500  # receipts parked while their note is fetched
RECONNECT_MAX = 300  # seconds
KIND0_FETCH_TIMEOUT = 8  # seconds per relay attempt
KIND0_FETCH_OVERALL_TIMEOUT = 8  # wall-time budget across all EXTERNAL_RELAYS
KIND0_NEGATIVE_CACHE_TTL = 60  # seconds — miss fan-out cooldown per pubkey

# pubkey -> monotonic/unix time of last confirmed miss (no kind:0 found)
_kind0_miss_cache: dict[str, float] = {}


def clear_kind0_miss_cache() -> None:
    """Clear in-process kind:0 miss cache (tests)."""
    _kind0_miss_cache.clear()


def _acceptable_note(event: dict) -> bool:
    return (
        event.get("kind") == 1
        and len(event.get("content", "")) <= MAX_CONTENT_LENGTH
        and len(event.get("tags", [])) <= MAX_EVENT_TAGS
    )


async def _fetch_kind0_one_relay(url: str, pubkey: str) -> dict | None:
    """Query one relay for the author's latest kind:0. Returns event or None."""
    try:
        # Cap open_timeout by per-relay budget so hung DNS/TCP cannot overrun overall.
        open_timeout = min(10, KIND0_FETCH_TIMEOUT)
        async with websockets.connect(
            url, max_size=65536, open_timeout=open_timeout
        ) as ws:
            sub = f"k0-{pubkey[:16]}"
            await ws.send(json.dumps([
                "REQ", sub, {"kinds": [0], "authors": [pubkey], "limit": 1},
            ]))
            deadline = asyncio.get_running_loop().time() + KIND0_FETCH_TIMEOUT
            best: dict | None = None
            while asyncio.get_running_loop().time() < deadline:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(msg, list) or len(msg) < 2:
                    continue
                if msg[0] == "EOSE" and msg[1] == sub:
                    break
                if msg[0] != "EVENT" or len(msg) < 3 or msg[1] != sub:
                    continue
                event = msg[2]
                if not isinstance(event, dict):
                    continue
                valid, _ = validate_event(event)
                if (
                    valid
                    and event.get("kind") == 0
                    and event.get("pubkey") == pubkey
                ):
                    if best is None or event.get("created_at", 0) >= best.get(
                        "created_at", 0
                    ):
                        best = event
            try:
                await ws.send(json.dumps(["CLOSE", sub]))
            except Exception:
                pass
            return best
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.debug("kind:0 fetch from %s failed: %s", url, e)
        return None


async def fetch_author_kind0(pubkey: str) -> dict | None:
    """Fetch the author's latest kind:0 from EXTERNAL_RELAYS (EXT-1a).

    Parallel first-success across relays, capped by KIND0_FETCH_OVERALL_TIMEOUT.
    Confirmed misses are short-TTL negative-cached so random pubkeys cannot
    re-hold workers for N×per-relay waits.

    Returns a validated kind:0 event dict, or None if none found / all fail.
    """
    if not isinstance(pubkey, str) or len(pubkey) != 64:
        return None

    now = time.time()
    miss_at = _kind0_miss_cache.get(pubkey)
    if miss_at is not None and now - miss_at < KIND0_NEGATIVE_CACHE_TTL:
        return None

    urls = [u.strip() for u in settings.EXTERNAL_RELAYS.split(",") if u.strip()]
    if not urls:
        _kind0_miss_cache[pubkey] = now
        return None

    tasks = {
        asyncio.create_task(_fetch_kind0_one_relay(url, pubkey), name=f"k0:{url}")
        for url in urls
    }
    best: dict | None = None
    loop = asyncio.get_running_loop()
    overall_deadline = loop.time() + KIND0_FETCH_OVERALL_TIMEOUT
    try:
        while tasks and best is None:
            remaining = overall_deadline - loop.time()
            if remaining <= 0:
                break
            done, tasks = await asyncio.wait(
                tasks, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                break  # overall timeout
            for task in done:
                try:
                    event = task.result()
                except asyncio.CancelledError:
                    continue
                except Exception as e:
                    logger.debug("kind:0 relay task failed: %s", e)
                    continue
                if event is None:
                    continue
                if best is None or event.get("created_at", 0) >= best.get(
                    "created_at", 0
                ):
                    best = event
            # On first success, cancel siblings; do not wait for slower relays.
            if best is not None:
                break
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    if best is not None:
        _kind0_miss_cache.pop(pubkey, None)
        return best

    _kind0_miss_cache[pubkey] = time.time()
    return None


async def _ensure_author_lud16(db, author_pubkey: str) -> str | None:
    """Return lud16 from local kind:0, fetching+storing from EXTERNAL_RELAYS if missing."""
    lud16 = await get_author_lud16(db, author_pubkey)
    if lud16:
        return lud16
    profile = await fetch_author_kind0(author_pubkey)
    if not profile:
        return None
    await store_event(db, profile, sats_clank=0, origin="external")
    return await get_author_lud16(db, author_pubkey)


async def _signer_ok(db, event: dict, info: dict, target: NostrEvent) -> bool:
    """True if zap-request p is author or relay fee-leg and LNURL nostrPubkey matches."""
    recipient = info.get("recipient_pubkey", "")
    fee_leg = is_relay_fee_leg(recipient)
    author_leg = recipient == target.pubkey
    if not fee_leg and not author_leg:
        return False
    # EXT-1a: author-leg needs kind:0 lud16 — fetch if missing locally
    if author_leg and not fee_leg:
        if not await _ensure_author_lud16(db, target.pubkey):
            return False
    err = await verify_zap_receipt_signer(event, recipient, db)
    return not err


async def _apply_receipts(target_id: str, receipts: list[tuple[dict, dict]]):
    """Credit parked (event, info) receipts now that their target is stored."""
    async with async_session() as db:
        target = await db.get(NostrEvent, target_id)
        if not target:
            return
        for event, info in receipts:
            if await db.get(NostrEvent, event["id"]):
                continue  # receipt already credited
            if not await _signer_ok(db, event, info, target):
                logger.info("Dropped forged/unverified zap receipt %s", event.get("id", "")[:12])
                continue
            await apply_zap_receipt(db, event, info, target)


async def _handle_receipt(ws, event: dict, pending: dict):
    valid, _ = validate_event(event)
    if not valid or event.get("kind") != 9735:
        return
    err, info = verify_zap_receipt(event)
    if err:
        return
    target_id = info["target_event_id"]

    async with async_session() as db:
        if await db.get(NostrEvent, event["id"]):
            return  # duplicate receipt
        target = await db.get(NostrEvent, target_id)
        if target:
            if not await _signer_ok(db, event, info, target):
                logger.info("Dropped forged/unverified zap receipt %s", event.get("id", "")[:12])
                return
            await apply_zap_receipt(db, event, info, target)
            return

    # Target unknown: park the receipt and fetch the note on this connection
    if target_id not in pending and len(pending) >= MAX_PENDING_TARGETS:
        return
    first_request = target_id not in pending
    pending.setdefault(target_id, []).append((event, info))
    if first_request:
        await ws.send(json.dumps(["REQ", f"t-{target_id}", {"ids": [target_id], "limit": 1}]))


async def _handle_target(ws, sub_id: str, event: dict, pending: dict):
    target_id = sub_id[2:]
    receipts = pending.pop(target_id, [])
    await ws.send(json.dumps(["CLOSE", sub_id]))
    if not receipts or event.get("id") != target_id:
        return
    valid, _ = validate_event(event)
    if not valid or not _acceptable_note(event):
        return
    async with async_session() as db:
        await store_event(db, event, sats_clank=0, origin="external")
    await _apply_receipts(target_id, receipts)
    logger.info("Ingested external note %s with %d zap(s)", target_id[:12], len(receipts))


async def _relay_loop(url: str):
    delay = 5
    while True:
        try:
            async with websockets.connect(url, max_size=131072, open_timeout=15) as ws:
                logger.info("Ingest connected: %s", url)
                delay = 5
                pending: dict[str, list] = {}
                await ws.send(json.dumps(["REQ", "zaps", {"kinds": [9735], "limit": BACKFILL_LIMIT}]))
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(msg, list) or len(msg) < 3 or msg[0] != "EVENT":
                        continue
                    sub_id, event = msg[1], msg[2]
                    if not isinstance(event, dict):
                        continue
                    if sub_id == "zaps":
                        await _handle_receipt(ws, event, pending)
                    elif isinstance(sub_id, str) and sub_id.startswith("t-"):
                        await _handle_target(ws, sub_id, event, pending)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Ingest %s: %s (reconnect in %ds)", url, e, delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, RECONNECT_MAX)


def start_ingest_tasks() -> list[asyncio.Task]:
    """Start one ingest task per configured external relay."""
    if not settings.EXTERNAL_INGEST:
        return []
    urls = [u.strip() for u in settings.EXTERNAL_RELAYS.split(",") if u.strip()]
    tasks = [asyncio.create_task(_relay_loop(url)) for url in urls]
    if tasks:
        logger.info("External ingest started for %d relay(s)", len(tasks))
    return tasks
