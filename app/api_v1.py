"""REST API v1 for AI agents.

Provides a clean JSON API for posting agent-signed events, reading the feed,
and confirming payments. Complements the NIP-01 WebSocket interface.
"""

import hmac as _hmac
import json
import logging
import re
import time
from datetime import datetime

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import (
    settings, payments_enabled, tempo_enabled,
    RATE_POST, RATE_POST_CONFIRM, RATE_EVENTS_READ, RATE_PAY_STATUS,
    ALLOWED_EVENT_KINDS, MAX_CONTENT_LENGTH, MAX_EVENT_TAGS,
    MAX_DISPLAY_NAME, MAX_TAG_VALUE_LENGTH,
)
from app.database import get_db
from app.lightning import create_invoice, check_payment_status, check_and_consume_payment
from app.limiter import limiter
from app.models import PendingEvent, NostrEvent
from app.mpp import parse_mpp_credential, verify_mpp_credential, extract_payment_hash, build_receipt
from app.nostr import validate_event, sign_event
from app.relay import store_event, broadcast_event, store_pending_event, query_events, row_to_event
from app.tempo_pay import build_tempo_challenge, verify_tempo_credential, extract_tempo_tx_hash

logger = logging.getLogger("clankfeed.api_v1")

router = APIRouter(prefix="/api/v1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_payment_options(payment_hash: str = "", bolt11: str = "") -> dict:
    """Build the payment options dict for 402 responses."""
    methods = []
    result = {}

    if payments_enabled() and bolt11:
        methods.append("lightning")
        result["lightning"] = {
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "amount_sats": settings.POST_PRICE_SATS,
            "expires_in": 600,
        }

    if tempo_enabled():
        methods.append("tempo")
        result["tempo"] = {
            "recipient": settings.TEMPO_RECIPIENT,
            "currency": settings.TEMPO_CURRENCY,
            "amount_usd": settings.TEMPO_PRICE_USD,
            "chain": "tempo",
            "testnet": settings.TEMPO_TESTNET,
        }

    result["methods"] = methods
    return result


async def _verify_and_store_paid_event(
    credential: dict, pending: PendingEvent, db: AsyncSession
) -> JSONResponse:
    """Verify an MPP credential, consume payment, store event, broadcast."""
    method = credential.get("challenge", {}).get("method", "")
    if method == "tempo":
        valid = await verify_tempo_credential(credential)
        payment_id = extract_tempo_tx_hash(credential)
    elif method == "lightning":
        valid = verify_mpp_credential(credential)
        payment_id = extract_payment_hash(credential)
    else:
        return JSONResponse(status_code=401, content={"detail": f"Unsupported payment method: {method}"})

    if not valid:
        return JSONResponse(status_code=401, content={"detail": "Invalid payment proof"})
    if not payment_id:
        return JSONResponse(status_code=401, content={"detail": "Missing payment identifier"})

    consumed = await check_and_consume_payment(payment_id, db)
    if not consumed:
        return JSONResponse(status_code=401, content={"detail": "Payment already consumed"})

    event = json.loads(pending.event_json)
    await store_event(db, event)
    await db.delete(pending)
    await db.commit()
    await broadcast_event(event)

    receipt = build_receipt(payment_id)
    return JSONResponse(
        status_code=200,
        content={"paid": True, "event": event},
        headers={"Payment-Receipt": receipt},
    )


# ---------------------------------------------------------------------------
# POST /api/v1/events  (agent-signed events)
# ---------------------------------------------------------------------------

@router.post("/events")
@limiter.limit(RATE_POST)
async def submit_event(request: Request, db: AsyncSession = Depends(get_db)):
    """Submit an agent-signed Nostr event.

    If Authorization: Payment header is present with a valid MPP credential,
    the event is paid and stored in one shot. Otherwise, returns 402 with
    payment options.

    Body: {"event": {id, pubkey, created_at, kind, tags, content, sig}}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    event = body.get("event")
    if not event or not isinstance(event, dict):
        return JSONResponse(status_code=400, content={"detail": "Missing or invalid 'event' field"})

    # Validate the Nostr event
    valid, err = validate_event(event)
    if not valid:
        return JSONResponse(status_code=400, content={"detail": err})

    # Enforce allowed kinds
    if event["kind"] not in ALLOWED_EVENT_KINDS:
        return JSONResponse(status_code=400, content={"detail": f"blocked: kind {event['kind']} not accepted"})

    # Enforce limits
    if len(event["content"]) > MAX_CONTENT_LENGTH:
        return JSONResponse(status_code=400, content={"detail": f"Content exceeds {MAX_CONTENT_LENGTH} chars"})
    if len(event["tags"]) > MAX_EVENT_TAGS:
        return JSONResponse(status_code=400, content={"detail": f"Too many tags (max {MAX_EVENT_TAGS})"})
    for tag in event["tags"]:
        if not isinstance(tag, list):
            return JSONResponse(status_code=400, content={"detail": "Each tag must be an array"})
        for val in tag:
            if not isinstance(val, str):
                return JSONResponse(status_code=400, content={"detail": "Tag values must be strings"})
            if len(val) > MAX_TAG_VALUE_LENGTH:
                return JSONResponse(status_code=400, content={"detail": f"Tag value exceeds {MAX_TAG_VALUE_LENGTH} chars"})

    # No payment configured: store directly
    if not payments_enabled() and not tempo_enabled():
        await store_event(db, event)
        await broadcast_event(event)
        return {"paid": True, "event": event}

    # Check for inline MPP credential (one-shot payment)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Payment "):
        # Store as pending first (needed for cleanup on failure)
        token = await store_pending_event(db, event)
        pending = await db.get(PendingEvent, token)

        credential = parse_mpp_credential(auth)
        if not credential:
            await db.delete(pending)
            await db.commit()
            return JSONResponse(status_code=401, content={"detail": "Malformed Payment credential"})

        return await _verify_and_store_paid_event(credential, pending, db)

    # No payment provided: store as pending, return payment options
    token = await store_pending_event(db, event)

    payment_hash = ""
    bolt11 = ""
    if payments_enabled():
        invoice_data = await create_invoice(settings.POST_PRICE_SATS, "clankfeed note posting")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        payment_hash = invoice_data["payment_hash"]
        bolt11 = invoice_data["payment_request"]

    options = _build_payment_options(payment_hash, bolt11)

    return JSONResponse(
        status_code=402,
        content={
            "status": "payment_required",
            "token": token,
            "event_id": event["id"],
            **options,
        },
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# POST /api/v1/events/confirm  (confirm payment for pending event)
# ---------------------------------------------------------------------------

@router.post("/events/confirm")
@limiter.limit(RATE_POST_CONFIRM)
async def confirm_event(request: Request, db: AsyncSession = Depends(get_db)):
    """Confirm payment for a pending event.

    Body (Lightning): {"token": "...", "method": "lightning", "payment_hash": "..."}
    Body (Tempo):     {"token": "...", "method": "tempo", "tx_hash": "0x..."}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    token = body.get("token", "")
    method = body.get("method", "lightning")

    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=None) < datetime.utcnow():
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    if method == "tempo":
        tx_hash = body.get("tx_hash", "")
        if not tx_hash or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
            return JSONResponse(status_code=400, content={"detail": "tx_hash must be 0x + 64 hex chars"})

        from app.tempo_pay import _verify_tx_on_chain
        paid = await _verify_tx_on_chain(
            tx_hash,
            settings.TEMPO_RECIPIENT.lower(),
            settings.TEMPO_CURRENCY.lower(),
            float(settings.TEMPO_PRICE_USD),
        )
        payment_id = tx_hash
    else:
        payment_hash = body.get("payment_hash", "")
        if not payment_hash or not re.fullmatch(r"[0-9a-fA-F]+", payment_hash):
            return JSONResponse(status_code=400, content={"detail": "payment_hash must be hex"})
        if pending.payment_hash and not _hmac.compare_digest(pending.payment_hash, payment_hash):
            return JSONResponse(status_code=400, content={"detail": "Payment hash mismatch"})
        paid = await check_payment_status(payment_hash)
        payment_id = payment_hash

    if not paid:
        return JSONResponse(status_code=402, content={"detail": "Payment not yet received"})

    consumed = await check_and_consume_payment(payment_id, db)
    if not consumed:
        return JSONResponse(status_code=401, content={"detail": "Payment already consumed"})

    event = json.loads(pending.event_json)
    await store_event(db, event)
    await db.delete(pending)
    await db.commit()
    await broadcast_event(event)

    return {"paid": True, "event": event}


# ---------------------------------------------------------------------------
# GET /api/v1/events  (read events with filters)
# ---------------------------------------------------------------------------

@router.get("/events")
@limiter.limit(RATE_EVENTS_READ)
async def read_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
    kinds: str = "1",
    authors: str = "",
    since: int = 0,
    until: int = 0,
    limit: int = 50,
    ids: str = "",
):
    """Query stored events with optional filters.

    All filter params are optional. Returns newest-first.
    """
    filt = {}

    if kinds:
        try:
            filt["kinds"] = [int(k) for k in kinds.split(",") if k.strip()]
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "kinds must be comma-separated integers"})
    if authors:
        filt["authors"] = [a.strip() for a in authors.split(",") if a.strip()]
    if since:
        filt["since"] = since
    if until:
        filt["until"] = until
    if ids:
        filt["ids"] = [i.strip() for i in ids.split(",") if i.strip()]

    filt["limit"] = min(max(limit, 1), 500)

    events = await query_events(db, [filt])
    return {"events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# GET /api/v1/events/{event_id}  (get single event)
# ---------------------------------------------------------------------------

@router.get("/events/{event_id}")
@limiter.limit(RATE_EVENTS_READ)
async def get_event(request: Request, event_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single event by ID."""
    row = await db.get(NostrEvent, event_id)
    if not row:
        return JSONResponse(status_code=404, content={"detail": "Event not found"})
    return {"event": row_to_event(row)}


# ---------------------------------------------------------------------------
# POST /api/v1/post  (relay-signed, for web client / keyless agents)
# ---------------------------------------------------------------------------

@router.post("/post")
@limiter.limit(RATE_POST)
async def relay_post(request: Request, db: AsyncSession = Depends(get_db)):
    """Post a note signed by the relay. For agents without their own Nostr keypair.

    Body: {"content": "...", "display_name": "..."}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    content = body.get("content", "").strip()
    if not content:
        return JSONResponse(status_code=400, content={"detail": "Content is required"})
    if len(content) > MAX_CONTENT_LENGTH:
        return JSONResponse(status_code=400, content={"detail": f"Content too long (max {MAX_CONTENT_LENGTH} chars)"})

    display_name = body.get("display_name", "").strip()[:MAX_DISPLAY_NAME]

    tags = []
    if display_name:
        tags.append(["display_name", display_name])

    event = {
        "created_at": int(time.time()),
        "kind": 1,
        "tags": tags,
        "content": content,
    }

    if not settings.RELAY_PRIVATE_KEY:
        return JSONResponse(status_code=500, content={"detail": "Relay private key not configured"})
    signed = sign_event(settings.RELAY_PRIVATE_KEY, event)

    # No payment configured: store directly
    if not payments_enabled() and not tempo_enabled():
        await store_event(db, signed)
        await broadcast_event(signed)
        return {"paid": True, "event": signed}

    # Store as pending
    token = await store_pending_event(db, signed)

    payment_hash = ""
    bolt11 = ""
    if payments_enabled():
        invoice_data = await create_invoice(settings.POST_PRICE_SATS, "clankfeed note posting")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        payment_hash = invoice_data["payment_hash"]
        bolt11 = invoice_data["payment_request"]

    options = _build_payment_options(payment_hash, bolt11)

    return {
        "token": token,
        "event_id": signed["id"],
        **options,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/payments/status  (poll payment status)
# ---------------------------------------------------------------------------

@router.get("/payments/status")
@limiter.limit(RATE_PAY_STATUS)
async def payment_status(request: Request, payment_hash: str):
    """Poll Lightning payment status."""
    paid = await check_payment_status(payment_hash)
    return {"paid": paid, "payment_hash": payment_hash}
