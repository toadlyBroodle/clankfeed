"""REST API v1 for AI agents.

Provides a clean JSON API for posting agent-signed events, reading the feed,
and confirming payments. Complements the NIP-01 WebSocket interface.
"""

import hmac as _hmac
import json
import logging
import re
import secrets
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
from app.accounts import create_account, get_account, deposit_credits, spend_credits
from app.rates import get_btc_usd_price, usd_to_sats
from app.models import PendingEvent, NostrEvent
from app.mpp import build_mpp_challenge, parse_mpp_credential, verify_mpp_credential, extract_payment_hash, build_receipt
from app.crypto import decrypt_field
from app.nostr import validate_event, sign_event
from app.relay import store_event, broadcast_event, store_pending_event, query_events, row_to_event
from app.tempo_pay import build_tempo_challenge, verify_tempo_credential, extract_tempo_tx_hash

logger = logging.getLogger("clankfeed.api_v1")

router = APIRouter(prefix="/api/v1")


async def _error_402_with_challenge(
    error_body: dict,
    amount_sats: int = 0,
    amount_usd: str = "",
    description: str = "Pay to post a note on clankfeed relay",
) -> "RawResponse":
    """Build a 402 error response with fresh WWW-Authenticate challenge headers (Core 1.7)."""
    from starlette.responses import Response as RawResponse

    sats = amount_sats or settings.POST_PRICE_SATS
    usd = amount_usd or settings.TEMPO_PRICE_USD
    response = RawResponse(
        content=json.dumps(error_body),
        status_code=402,
        media_type="application/json",
    )
    response.headers["Cache-Control"] = "no-store"

    if payments_enabled():
        try:
            invoice_data = await create_invoice(sats, description)
            challenge = build_mpp_challenge(
                sats, invoice_data["payment_hash"],
                invoice_data["payment_request"], description,
            )
            response.headers.append("WWW-Authenticate", challenge)
        except Exception as e:
            logger.warning("Could not generate Lightning challenge for error 402: %s", e)

    if tempo_enabled():
        tempo_challenge = build_tempo_challenge(usd, description)
        response.headers.append("WWW-Authenticate", tempo_challenge)

    return response


async def _try_spend_credits(request: Request, db: AsyncSession, amount_sats: int) -> tuple[bool, str]:
    """Check auth (NIP-98 or X-Account-Key) and try to spend credits.

    Returns (spent, api_key). If spent=True, credits were deducted.
    """
    from app.auth import get_auth
    acct, pubkey, _ = await get_auth(request, db)
    if not acct:
        return False, ""
    ok, _ = await spend_credits(db, acct.id, amount_sats)
    return ok, acct.id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_payment_options(
    payment_hash: str = "",
    bolt11: str = "",
    amount_sats: int = 0,
    amount_usd: str = "",
) -> dict:
    """Build the payment options dict for 402 responses."""
    methods = []
    result = {}
    sats = amount_sats or settings.POST_PRICE_SATS
    usd = amount_usd or settings.TEMPO_PRICE_USD

    if payments_enabled() and bolt11:
        methods.append("lightning")
        result["lightning"] = {
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "amount_sats": sats,
            "expires_in": 600,
        }

    if tempo_enabled():
        methods.append("tempo")
        result["tempo"] = {
            "recipient": settings.TEMPO_RECIPIENT,
            "currency": settings.TEMPO_CURRENCY,
            "amount_usd": usd,
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
    challenge_id = credential.get("challenge", {}).get("id", "")
    amt_sats = pending.amount_sats or settings.POST_PRICE_SATS
    amt_usd = pending.amount_usd or settings.TEMPO_PRICE_USD
    if method == "tempo":
        valid = await verify_tempo_credential(credential)
        payment_id = extract_tempo_tx_hash(credential)
    elif method == "lightning":
        valid = verify_mpp_credential(credential)
        payment_id = extract_payment_hash(credential)
    else:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/method-unsupported",
            "title": "Unsupported payment method",
            "detail": f"Method '{method}' is not supported",
        }, amount_sats=amt_sats, amount_usd=amt_usd)

    if not valid:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/verification-failed",
            "title": "Verification failed",
            "detail": "Invalid payment proof",
        }, amount_sats=amt_sats, amount_usd=amt_usd)
    if not payment_id:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/verification-failed",
            "title": "Verification failed",
            "detail": "Missing payment identifier",
        }, amount_sats=amt_sats, amount_usd=amt_usd)

    consumed = await check_and_consume_payment(payment_id, db)
    if not consumed:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/invalid-challenge",
            "title": "Invalid challenge",
            "detail": "Payment already consumed",
        }, amount_sats=amt_sats, amount_usd=amt_usd)

    event = json.loads(pending.event_json)
    await store_event(db, event)
    await db.delete(pending)
    await db.commit()
    await broadcast_event(event)

    receipt = build_receipt(payment_id, method=method, challenge_id=challenge_id)
    return JSONResponse(
        status_code=200,
        content={"paid": True, "event": event},
        headers={"Payment-Receipt": receipt, "Cache-Control": "private"},
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
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
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

    # Parse optional custom amount (>= minimum)
    req_sats = body.get("amount_sats", settings.POST_PRICE_SATS)
    req_usd = body.get("amount_usd", settings.TEMPO_PRICE_USD)
    if not isinstance(req_sats, int) or req_sats < settings.POST_PRICE_SATS:
        req_sats = settings.POST_PRICE_SATS
    if isinstance(req_usd, (int, float)):
        req_usd = str(req_usd)
    try:
        if float(req_usd) < float(settings.TEMPO_PRICE_USD):
            req_usd = settings.TEMPO_PRICE_USD
    except (ValueError, TypeError) as e:
        logger.warning("Invalid USD amount, using default: %s", e)
        req_usd = settings.TEMPO_PRICE_USD

    # No payment configured: store directly with minimum value
    if not payments_enabled() and not tempo_enabled():
        await store_event(db, event, value_sats=req_sats, value_usd=req_usd)
        await broadcast_event(event)
        return {"paid": True, "event": event, "value_sats": req_sats}

    # Try spending credits (X-Account-Key header)
    spent, _ = await _try_spend_credits(request, db, req_sats)
    if spent:
        await store_event(db, event, value_sats=req_sats, value_usd=req_usd)
        await broadcast_event(event)
        return {"paid": True, "event": event, "value_sats": req_sats, "credits_used": True}

    # Check for inline MPP credential (one-shot payment)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Payment "):
        token = await store_pending_event(db, event, amount_sats=req_sats, amount_usd=req_usd)
        pending = await db.get(PendingEvent, token)

        credential = parse_mpp_credential(auth)
        if not credential:
            await db.delete(pending)
            await db.commit()
            return await _error_402_with_challenge({
                "type": "https://paymentauth.org/problems/malformed-credential",
                "title": "Malformed credential",
                "detail": "Could not decode Payment credential",
            }, amount_sats=req_sats, amount_usd=req_usd)

        return await _verify_and_store_paid_event(credential, pending, db)

    # No payment provided: store as pending, return payment options
    token = await store_pending_event(db, event, amount_sats=req_sats, amount_usd=req_usd)

    payment_hash = ""
    bolt11 = ""
    if payments_enabled():
        invoice_data = await create_invoice(req_sats, "clankfeed note posting")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        payment_hash = invoice_data["payment_hash"]
        bolt11 = invoice_data["payment_request"]

    options = _build_payment_options(payment_hash, bolt11, amount_sats=req_sats, amount_usd=req_usd)

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
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
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
        return JSONResponse(status_code=402, content={
            "type": "https://paymentauth.org/problems/invalid-challenge",
            "title": "Invalid challenge",
            "detail": "Payment already consumed",
        })

    event = json.loads(pending.event_json)
    v_usd = pending.amount_usd or settings.TEMPO_PRICE_USD

    # Convert USD to sats at spot for Tempo payments
    if method == "tempo":
        btc_price = await get_btc_usd_price()
        v_sats = usd_to_sats(float(v_usd), btc_price) if btc_price > 0 else (pending.amount_sats or settings.POST_PRICE_SATS)
    else:
        v_sats = pending.amount_sats or settings.POST_PRICE_SATS

    await store_event(db, event, value_sats=v_sats, value_usd=v_usd)
    await db.delete(pending)
    await db.commit()
    await broadcast_event(event)
    logger.info("Event confirmed (paid): id=%s method=%s value=%d sats",
                event["id"][:12], method, v_sats)

    return {"paid": True, "event": event, "value_sats": v_sats}


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
    sort: str = "newest",
    min_value: int | None = None,
    max_value: int | None = None,
    reply_to: str = "",
):
    """Query stored events with optional filters.

    sort: "newest" (default) or "value" (highest value first)
    min_value/max_value: filter by value_sats range
    reply_to: filter replies to a specific event ID
    """
    filt = {}

    if kinds:
        try:
            filt["kinds"] = [int(k) for k in kinds.split(",") if k.strip()]
        except ValueError as e:
            logger.warning("Invalid kinds parameter: %s", e)
            return JSONResponse(status_code=400, content={"detail": "kinds must be comma-separated integers"})
    if authors:
        filt["authors"] = [a.strip() for a in authors.split(",") if a.strip()]
    if since:
        filt["since"] = since
    if until:
        filt["until"] = until
    if ids:
        filt["ids"] = [i.strip() for i in ids.split(",") if i.strip()]
    if reply_to:
        filt["reply_to"] = reply_to

    filt["limit"] = min(max(limit, 1), 500)

    if sort not in ("newest", "value"):
        sort = "newest"

    events = await query_events(db, [filt], sort=sort, min_value=min_value, max_value=max_value)
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

    Body: {"content": "...", "display_name": "...", "reply_to": "...", "amount_sats": 21}
    """
    try:
        body = await request.json()
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    content = body.get("content", "").strip()
    if not content:
        return JSONResponse(status_code=400, content={"detail": "Content is required"})
    if len(content) > MAX_CONTENT_LENGTH:
        return JSONResponse(status_code=400, content={"detail": f"Content too long (max {MAX_CONTENT_LENGTH} chars)"})

    display_name = body.get("display_name", "").strip()[:MAX_DISPLAY_NAME]
    reply_to = body.get("reply_to", "").strip()

    tags = []
    if display_name:
        tags.append(["display_name", display_name])
    if reply_to and len(reply_to) == 64:
        tags.append(["e", reply_to, "", "reply"])

    event = {
        "created_at": int(time.time()),
        "kind": 1,
        "tags": tags,
        "content": content,
    }

    # Sign with account's Nostr key if logged in, otherwise relay key
    from app.auth import get_auth
    acct, _, _ = await get_auth(request, db)
    signing_key = settings.RELAY_PRIVATE_KEY
    if acct and acct.nostr_privkey:
        signing_key = decrypt_field(acct.nostr_privkey)

    if not signing_key:
        return JSONResponse(status_code=500, content={"detail": "Relay private key not configured"})
    signed = sign_event(signing_key, event)

    # Parse custom amount
    req_sats = body.get("amount_sats", settings.POST_PRICE_SATS)
    req_usd = body.get("amount_usd", settings.TEMPO_PRICE_USD)
    if not isinstance(req_sats, int) or req_sats < settings.POST_PRICE_SATS:
        req_sats = settings.POST_PRICE_SATS
    if isinstance(req_usd, (int, float)):
        req_usd = str(req_usd)
    try:
        if float(req_usd) < float(settings.TEMPO_PRICE_USD):
            req_usd = settings.TEMPO_PRICE_USD
    except (ValueError, TypeError) as e:
        logger.warning("Invalid USD amount, using default: %s", e)
        req_usd = settings.TEMPO_PRICE_USD

    # No payment configured: store directly
    if not payments_enabled() and not tempo_enabled():
        await store_event(db, signed, value_sats=req_sats, value_usd=req_usd)
        await broadcast_event(signed)
        return {"paid": True, "event": signed, "value_sats": req_sats}

    # Try spending credits
    spent, _ = await _try_spend_credits(request, db, req_sats)
    if spent:
        await store_event(db, signed, value_sats=req_sats, value_usd=req_usd)
        await broadcast_event(signed)
        return {"paid": True, "event": signed, "value_sats": req_sats, "credits_used": True}

    # Store as pending
    token = await store_pending_event(db, signed, amount_sats=req_sats, amount_usd=req_usd)

    payment_hash = ""
    bolt11 = ""
    if payments_enabled():
        invoice_data = await create_invoice(req_sats, "clankfeed note posting")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        payment_hash = invoice_data["payment_hash"]
        bolt11 = invoice_data["payment_request"]

    options = _build_payment_options(payment_hash, bolt11, amount_sats=req_sats, amount_usd=req_usd)

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


# ---------------------------------------------------------------------------
# POST /api/v1/events/reply-counts  (batch reply counts)
# ---------------------------------------------------------------------------

@router.post("/events/reply-counts")
@limiter.limit(RATE_EVENTS_READ)
async def reply_counts(request: Request, db: AsyncSession = Depends(get_db)):
    """Return reply counts for a batch of event IDs."""
    body = await request.json()
    event_ids = body.get("event_ids", [])
    if not isinstance(event_ids, list) or len(event_ids) > 200:
        return JSONResponse(status_code=400, content={"detail": "event_ids must be a list (max 200)"})

    from sqlalchemy import select, func, and_
    counts = {}
    for eid in event_ids:
        stmt = select(func.count()).select_from(NostrEvent).where(
            and_(NostrEvent.kind == 1, NostrEvent.tags.contains(f'"e", "{eid}"'))
        )
        result = await db.execute(stmt)
        c = result.scalar()
        if c:
            counts[eid] = c
    return {"counts": counts}


# ---------------------------------------------------------------------------
# GET /api/v1/events/{event_id}/replies  (get replies to a note)
# ---------------------------------------------------------------------------

@router.get("/events/{event_id}/replies")
@limiter.limit(RATE_EVENTS_READ)
async def get_replies(
    request: Request,
    event_id: str,
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    sort: str = "newest",
):
    """Get replies to a specific note."""
    row = await db.get(NostrEvent, event_id)
    if not row:
        return JSONResponse(status_code=404, content={"detail": "Event not found"})

    filt = {"reply_to": event_id, "kinds": [1], "limit": min(max(limit, 1), 500)}
    replies = await query_events(db, [filt], sort=sort)
    return {"event_id": event_id, "replies": replies, "count": len(replies)}


# ---------------------------------------------------------------------------
# POST /api/v1/events/{event_id}/vote  (upvote/downvote with payment)
# ---------------------------------------------------------------------------

@router.post("/events/{event_id}/vote")
@limiter.limit(RATE_POST)
async def vote_event(request: Request, event_id: str, db: AsyncSession = Depends(get_db)):
    """Vote on a note. Requires payment.

    Body: {"direction": 1, "amount_sats": 21} or {"direction": -1, "amount_usd": "0.01"}
    direction: 1 (upvote) or -1 (downvote)
    amount: must be >= minimum (POST_PRICE_SATS / TEMPO_PRICE_USD)
    """
    row = await db.get(NostrEvent, event_id)
    if not row:
        return JSONResponse(status_code=404, content={"detail": "Event not found"})

    try:
        body = await request.json()
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    direction = body.get("direction", 1)
    if direction not in (1, -1):
        return JSONResponse(status_code=400, content={"detail": "direction must be 1 or -1"})

    req_sats = body.get("amount_sats", settings.POST_PRICE_SATS)
    req_usd = body.get("amount_usd", settings.TEMPO_PRICE_USD)
    if not isinstance(req_sats, int) or req_sats < settings.POST_PRICE_SATS:
        req_sats = settings.POST_PRICE_SATS
    if isinstance(req_usd, (int, float)):
        req_usd = str(req_usd)
    try:
        if float(req_usd) < float(settings.TEMPO_PRICE_USD):
            req_usd = settings.TEMPO_PRICE_USD
    except (ValueError, TypeError) as e:
        logger.warning("Invalid USD amount, using default: %s", e)
        req_usd = settings.TEMPO_PRICE_USD

    # Build a synthetic pending event for the vote (reuses payment flow)
    vote_data = {
        "vote_event_id": event_id,
        "direction": direction,
        "amount_sats": req_sats,
        "amount_usd": req_usd,
    }

    # No payment configured: apply vote directly
    if not payments_enabled() and not tempo_enabled():
        from app.models import Vote
        vote = Vote(
            id=secrets.token_hex(32),
            event_id=event_id,
            pubkey="relay",
            direction=direction,
            amount_sats=req_sats,
            amount_usd=req_usd,
            payment_id="free",
        )
        db.add(vote)
        row.value_sats = (row.value_sats or 0) + (direction * req_sats)
        await db.commit()
        logger.info("Vote recorded (free): event=%s dir=%+d amount=%d sats new_value=%d",
                    event_id[:12], direction, req_sats, row.value_sats)
        return {"voted": True, "direction": direction, "amount_sats": req_sats, "new_value_sats": row.value_sats}

    # Try spending credits
    spent, api_key = await _try_spend_credits(request, db, req_sats)
    if spent:
        from app.models import Vote
        vote = Vote(
            id=secrets.token_hex(32),
            event_id=event_id,
            pubkey=api_key[:16],
            direction=direction,
            amount_sats=req_sats,
            amount_usd=req_usd,
            payment_id=f"credits:{api_key[:16]}",
        )
        db.add(vote)
        row.value_sats = (row.value_sats or 0) + (direction * req_sats)
        await db.commit()
        logger.info("Vote recorded (credits): event=%s dir=%+d amount=%d sats new_value=%d account=%s",
                    event_id[:12], direction, req_sats, row.value_sats, api_key[:12])
        return {"voted": True, "direction": direction, "amount_sats": req_sats, "new_value_sats": row.value_sats, "credits_used": True}

    # Store vote intent as pending event (reuse PendingEvent table)
    token = await store_pending_event(
        db,
        vote_data,  # not a real Nostr event, but JSON-serializable
        amount_sats=req_sats,
        amount_usd=req_usd,
    )

    payment_hash = ""
    bolt11 = ""
    if payments_enabled():
        invoice_data = await create_invoice(req_sats, f"clankfeed vote on {event_id[:12]}")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        payment_hash = invoice_data["payment_hash"]
        bolt11 = invoice_data["payment_request"]

    options = _build_payment_options(payment_hash, bolt11, amount_sats=req_sats, amount_usd=req_usd)

    return JSONResponse(
        status_code=402,
        content={
            "status": "payment_required",
            "token": token,
            "event_id": event_id,
            "direction": direction,
            **options,
        },
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# POST /api/v1/events/{event_id}/vote/confirm  (confirm vote payment)
# ---------------------------------------------------------------------------

@router.post("/events/{event_id}/vote/confirm")
@limiter.limit(RATE_POST_CONFIRM)
async def confirm_vote(request: Request, event_id: str, db: AsyncSession = Depends(get_db)):
    """Confirm vote payment.

    Body: {"token": "...", "method": "tempo", "tx_hash": "0x..."} (same as event confirm)
    """
    try:
        body = await request.json()
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    token = body.get("token", "")
    method = body.get("method", "lightning")

    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=None) < datetime.utcnow():
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    # Verify payment (same logic as event confirm)
    if method == "tempo":
        tx_hash = body.get("tx_hash", "")
        if not tx_hash or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
            return JSONResponse(status_code=400, content={"detail": "tx_hash must be 0x + 64 hex chars"})
        from app.tempo_pay import _verify_tx_on_chain
        paid = await _verify_tx_on_chain(
            tx_hash, settings.TEMPO_RECIPIENT.lower(),
            settings.TEMPO_CURRENCY.lower(), float(pending.amount_usd or settings.TEMPO_PRICE_USD),
        )
        payment_id = tx_hash
    else:
        pay_hash = body.get("payment_hash", "")
        if not pay_hash or not re.fullmatch(r"[0-9a-fA-F]+", pay_hash):
            return JSONResponse(status_code=400, content={"detail": "payment_hash must be hex"})
        if pending.payment_hash and not _hmac.compare_digest(pending.payment_hash, pay_hash):
            return JSONResponse(status_code=400, content={"detail": "Payment hash mismatch"})
        paid = await check_payment_status(pay_hash)
        payment_id = pay_hash

    if not paid:
        return JSONResponse(status_code=402, content={"detail": "Payment not yet received"})

    consumed = await check_and_consume_payment(payment_id, db)
    if not consumed:
        return JSONResponse(status_code=402, content={
            "type": "https://paymentauth.org/problems/invalid-challenge",
            "title": "Invalid challenge",
            "detail": "Payment already consumed",
        })

    # Parse vote data from pending
    vote_data = json.loads(pending.event_json)
    direction = vote_data.get("direction", 1)

    # Convert USD to sats at spot for Tempo payments
    if method == "tempo":
        v_usd = pending.amount_usd or settings.TEMPO_PRICE_USD
        btc_price = await get_btc_usd_price()
        v_sats = usd_to_sats(float(v_usd), btc_price) if btc_price > 0 else (pending.amount_sats or settings.POST_PRICE_SATS)
    else:
        v_sats = pending.amount_sats or settings.POST_PRICE_SATS

    # Apply vote
    from app.models import Vote
    row = await db.get(NostrEvent, event_id)
    if not row:
        await db.delete(pending)
        await db.commit()
        return JSONResponse(status_code=404, content={"detail": "Event not found"})

    vote = Vote(
        id=secrets.token_hex(32),
        event_id=event_id,
        pubkey=vote_data.get("pubkey", "anonymous"),
        direction=direction,
        amount_sats=v_sats,
        amount_usd=pending.amount_usd or "0",
        payment_id=payment_id,
    )
    db.add(vote)
    row.value_sats = (row.value_sats or 0) + (direction * v_sats)
    await db.delete(pending)
    await db.commit()
    logger.info("Vote confirmed (paid): event=%s dir=%+d amount=%d sats method=%s new_value=%d",
                event_id[:12], direction, v_sats, method, row.value_sats)

    return {
        "voted": True,
        "direction": direction,
        "amount_sats": v_sats,
        "new_value_sats": row.value_sats,
    }


# ---------------------------------------------------------------------------
# Account endpoints
# ---------------------------------------------------------------------------

@router.post("/account/create")
@limiter.limit(RATE_POST)
async def account_create(request: Request, db: AsyncSession = Depends(get_db)):
    """Create a new account or import an existing Nostr key.

    Body: {} (generate new keypair)
          {"pubkey": "hex"} (link external pubkey)
          {"nostr_privkey": "hex"} (import existing Nostr private key)
    """
    try:
        body = await request.json()
    except Exception as e:
        logger.warning("Invalid JSON in account create (using empty body): %s", e)
        body = {}

    pubkey = body.get("pubkey", "")
    if pubkey and (not isinstance(pubkey, str) or len(pubkey) != 64):
        return JSONResponse(status_code=400, content={"detail": "pubkey must be 64-char hex"})

    nostr_privkey = body.get("nostr_privkey", "")
    if nostr_privkey and (not isinstance(nostr_privkey, str) or len(nostr_privkey) != 64):
        return JSONResponse(status_code=400, content={"detail": "nostr_privkey must be 64-char hex"})

    acct = await create_account(db, pubkey, nostr_privkey=nostr_privkey)
    return {
        "nostr_pubkey": acct.nostr_pubkey or "",
        "balance_sats": acct.balance_sats or 0,
    }


@router.get("/account/balance")
@limiter.limit(RATE_EVENTS_READ)
async def account_balance(request: Request, db: AsyncSession = Depends(get_db)):
    """Check account balance. Accepts NIP-98 or X-Account-Key auth."""
    from app.auth import get_auth
    acct, _, _ = await get_auth(request, db)
    if not acct:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    return {
        "balance_sats": acct.balance_sats or 0,
        "balance_usd": acct.balance_usd or "0",
        "nostr_pubkey": acct.nostr_pubkey or "",
    }


@router.post("/account/deposit")
@limiter.limit(RATE_POST)
async def account_deposit(request: Request, db: AsyncSession = Depends(get_db)):
    """Deposit credits. Returns 402 with payment options.

    Body: {"amount_sats": 1000} or {"amount_usd": "0.50"}
    Accepts NIP-98 or X-Account-Key auth.
    """
    from app.auth import get_auth
    acct, _, _ = await get_auth(request, db)
    if not acct:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    try:
        body = await request.json()
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    req_sats = body.get("amount_sats", settings.POST_PRICE_SATS)
    req_usd = body.get("amount_usd", settings.TEMPO_PRICE_USD)
    if not isinstance(req_sats, int) or req_sats < settings.POST_PRICE_SATS:
        req_sats = settings.POST_PRICE_SATS
    if isinstance(req_usd, (int, float)):
        req_usd = str(req_usd)

    # Store deposit intent as pending event (reuse table)
    deposit_data = {"deposit_account": acct.id, "amount_sats": req_sats, "amount_usd": req_usd}
    token = await store_pending_event(db, deposit_data, amount_sats=req_sats, amount_usd=str(req_usd))

    payment_hash = ""
    bolt11 = ""
    if payments_enabled():
        invoice_data = await create_invoice(req_sats, f"clankfeed credit deposit")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        payment_hash = invoice_data["payment_hash"]
        bolt11 = invoice_data["payment_request"]

    options = _build_payment_options(payment_hash, bolt11, amount_sats=req_sats, amount_usd=str(req_usd))

    return JSONResponse(
        status_code=402,
        content={
            "status": "payment_required",
            "token": token,
            "deposit_amount_sats": req_sats,
            **options,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/account/deposit/confirm")
@limiter.limit(RATE_POST_CONFIRM)
async def account_deposit_confirm(request: Request, db: AsyncSession = Depends(get_db)):
    """Confirm deposit payment. Credits added to account.

    Body: {"token": "...", "method": "tempo", "tx_hash": "0x..."}
    Accepts NIP-98 or X-Account-Key auth.
    """
    from app.auth import get_auth
    acct, _, _ = await get_auth(request, db)
    if not acct:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    api_key = acct.id

    try:
        body = await request.json()
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    token = body.get("token", "")
    method = body.get("method", "lightning")

    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=None) < datetime.utcnow():
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    # Verify payment (same logic as event confirm)
    if method == "tempo":
        tx_hash = body.get("tx_hash", "")
        if not tx_hash or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
            return JSONResponse(status_code=400, content={"detail": "tx_hash must be 0x + 64 hex chars"})
        from app.tempo_pay import _verify_tx_on_chain
        paid = await _verify_tx_on_chain(
            tx_hash, settings.TEMPO_RECIPIENT.lower(),
            settings.TEMPO_CURRENCY.lower(), float(pending.amount_usd or settings.TEMPO_PRICE_USD),
        )
        payment_id = tx_hash
    else:
        pay_hash = body.get("payment_hash", "")
        if not pay_hash or not re.fullmatch(r"[0-9a-fA-F]+", pay_hash):
            return JSONResponse(status_code=400, content={"detail": "payment_hash must be hex"})
        if pending.payment_hash and not _hmac.compare_digest(pending.payment_hash, pay_hash):
            return JSONResponse(status_code=400, content={"detail": "Payment hash mismatch"})
        paid = await check_payment_status(pay_hash)
        payment_id = pay_hash

    if not paid:
        return JSONResponse(status_code=402, content={"detail": "Payment not yet received"})

    consumed = await check_and_consume_payment(payment_id, db)
    if not consumed:
        return JSONResponse(status_code=402, content={
            "type": "https://paymentauth.org/problems/invalid-challenge",
            "title": "Invalid challenge",
            "detail": "Payment already consumed",
        })

    # Add credits (convert USD to sats at spot for Tempo)
    dep_usd = pending.amount_usd or "0"
    if method == "tempo":
        btc_price = await get_btc_usd_price()
        dep_sats = usd_to_sats(float(dep_usd), btc_price) if btc_price > 0 else (pending.amount_sats or settings.POST_PRICE_SATS)
    else:
        dep_sats = pending.amount_sats or settings.POST_PRICE_SATS
    acct = await deposit_credits(db, api_key, dep_sats, dep_usd)
    if not acct:
        return JSONResponse(status_code=404, content={"detail": "Account not found"})

    await db.delete(pending)
    await db.commit()
    logger.info("Deposit confirmed: account=%s amount=%d sats method=%s balance=%d sats",
                api_key[:12], dep_sats, method, acct.balance_sats or 0)

    return {
        "deposited": True,
        "amount_sats": dep_sats,
        "balance_sats": acct.balance_sats or 0,
    }


# ---------------------------------------------------------------------------
# POST /api/v1/account/key  (export Nostr private key)
# ---------------------------------------------------------------------------

@router.post("/account/key")
@limiter.limit(RATE_EVENTS_READ)
async def account_export_key(request: Request, db: AsyncSession = Depends(get_db)):
    """Export the account's Nostr private key. Accepts NIP-98 or X-Account-Key auth."""
    from app.auth import get_auth
    acct, _, _ = await get_auth(request, db)
    if not acct:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    return {
        "nostr_privkey": decrypt_field(acct.nostr_privkey) if acct.nostr_privkey else "",
        "nostr_pubkey": acct.nostr_pubkey or "",
    }


# ---------------------------------------------------------------------------
# POST /api/v1/account/profile  (update avatar and about via kind:0)
# ---------------------------------------------------------------------------

@router.post("/account/profile")
@limiter.limit(RATE_POST)
async def account_update_profile(request: Request, db: AsyncSession = Depends(get_db)):
    """Update account profile (name, about, picture) by posting a kind:0 metadata event.

    Accepts NIP-98 or X-Account-Key auth. Uses credits if available.
    Body: {"name": "...", "about": "...", "picture": "https://..."}
    """
    from app.auth import get_auth
    acct, _, _ = await get_auth(request, db)
    if not acct:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    if not acct.nostr_privkey:
        return JSONResponse(status_code=500, content={"detail": "Account has no Nostr key"})

    try:
        body = await request.json()
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    # Build kind:0 metadata content
    metadata = {}
    if "name" in body and isinstance(body["name"], str):
        metadata["name"] = body["name"][:MAX_DISPLAY_NAME]
    if "about" in body and isinstance(body["about"], str):
        metadata["about"] = body["about"][:MAX_CONTENT_LENGTH]
    if "picture" in body and isinstance(body["picture"], str):
        metadata["picture"] = body["picture"][:1024]

    if not metadata:
        return JSONResponse(status_code=400, content={"detail": "Provide at least one of: name, about, picture"})

    # Create and sign kind:0 event with account's key
    event = {
        "created_at": int(time.time()),
        "kind": 0,
        "tags": [],
        "content": json.dumps(metadata),
    }
    signed = sign_event(decrypt_field(acct.nostr_privkey), event)

    # Try spending credits
    req_sats = settings.POST_PRICE_SATS
    spent, _ = await _try_spend_credits(request, db, req_sats)
    if spent:
        await store_event(db, signed, value_sats=req_sats)
        await broadcast_event(signed)
        return {"updated": True, "event": signed, "metadata": metadata}

    # No payment configured: store directly
    if not payments_enabled() and not tempo_enabled():
        await store_event(db, signed, value_sats=req_sats)
        await broadcast_event(signed)
        return {"updated": True, "event": signed, "metadata": metadata}

    # Requires payment
    token = await store_pending_event(db, signed, amount_sats=req_sats)

    payment_hash = ""
    bolt11 = ""
    if payments_enabled():
        invoice_data = await create_invoice(req_sats, "clankfeed profile update")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        payment_hash = invoice_data["payment_hash"]
        bolt11 = invoice_data["payment_request"]

    options = _build_payment_options(payment_hash, bolt11, amount_sats=req_sats)

    return JSONResponse(
        status_code=402,
        content={
            "status": "payment_required",
            "token": token,
            **options,
        },
        headers={"Cache-Control": "no-store"},
    )
