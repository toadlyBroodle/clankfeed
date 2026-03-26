"""HTTP payment endpoints: MPP challenge/verify, payment status polling, web client posting."""

import hmac as _hmac
import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import (
    settings, payments_enabled, tempo_enabled, PENDING_EVENT_TTL,
    RATE_POST, RATE_PAY, RATE_PAY_STATUS, RATE_POST_CONFIRM,
    MAX_CONTENT_LENGTH, MAX_DISPLAY_NAME,
)
from app.database import get_db
from app.lightning import create_invoice, check_payment_status, check_and_consume_payment
from app.models import PendingEvent, NostrEvent
from app.mpp import build_mpp_challenge, parse_mpp_credential, verify_mpp_credential, extract_payment_hash, build_receipt
from app.nostr import sign_event
from app.relay import store_event, broadcast_event, store_pending_event
from app.tempo_pay import build_tempo_challenge, verify_tempo_credential, extract_tempo_tx_hash

from app.limiter import limiter

logger = logging.getLogger("clankfeed.payment")

router = APIRouter()


async def _error_402_with_challenge(
    error_body: dict,
    amount_sats: int = 0,
    description: str = "Pay to post a note on clankfeed relay",
) -> "RawResponse":
    """Build a 402 error response with fresh WWW-Authenticate challenge headers (Core 1.7)."""
    from starlette.responses import Response as RawResponse

    sats = amount_sats or settings.POST_PRICE_SATS
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
        except Exception:
            logger.debug("Could not generate Lightning challenge for error 402")

    if tempo_enabled():
        tempo_challenge = build_tempo_challenge(settings.TEMPO_PRICE_USD, description)
        response.headers.append("WWW-Authenticate", tempo_challenge)

    return response


@router.get("/pay")
@limiter.limit(RATE_PAY)
async def pay_get(request: Request, token: str, db: AsyncSession = Depends(get_db)):
    """Issue a 402 MPP challenge with a Lightning invoice for a pending event."""
    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=None) < datetime.utcnow():
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    price = settings.POST_PRICE_SATS
    invoice_data = await create_invoice(price, "clankfeed note posting")

    # Update pending event with the payment hash
    pending.payment_hash = invoice_data["payment_hash"]
    await db.commit()

    # Build Lightning challenge
    lightning_challenge = build_mpp_challenge(
        price,
        invoice_data["payment_hash"],
        invoice_data["payment_request"],
        "Pay to post a note on clankfeed relay",
    )

    body = {
        "bolt11": invoice_data["payment_request"],
        "payment_hash": invoice_data["payment_hash"],
        "amount_sats": price,
        "token": token,
        "methods": ["lightning"],
    }

    # Multiple WWW-Authenticate headers via raw Response
    from starlette.responses import Response as RawResponse
    response = RawResponse(
        content=json.dumps(body),
        status_code=402,
        media_type="application/json",
    )
    response.headers.append("WWW-Authenticate", lightning_challenge)
    response.headers["Cache-Control"] = "no-store"

    # Add Tempo challenge if configured
    if tempo_enabled():
        tempo_challenge = build_tempo_challenge(
            settings.TEMPO_PRICE_USD,
            "Pay to post a note on clankfeed relay",
        )
        response.headers.append("WWW-Authenticate", tempo_challenge)
        body["methods"].append("tempo")
        body["tempo"] = {
            "recipient": settings.TEMPO_RECIPIENT,
            "currency": settings.TEMPO_CURRENCY,
            "amount_usd": settings.TEMPO_PRICE_USD,
            "chain": "tempo",
            "testnet": settings.TEMPO_TESTNET,
        }
        # Re-serialize body with tempo info
        response.body = json.dumps(body).encode()

    return response


@router.post("/pay")
@limiter.limit(RATE_PAY)
async def pay_post(request: Request, token: str, db: AsyncSession = Depends(get_db)):
    """Verify MPP credential and store the paid event."""
    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=None) < datetime.utcnow():
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Payment "):
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/malformed-credential",
            "title": "Missing Payment authorization",
            "detail": "Authorization header must start with 'Payment '",
        })

    credential = parse_mpp_credential(auth)
    if not credential:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/malformed-credential",
            "title": "Malformed credential",
            "detail": "Could not decode Payment credential",
        })

    # Route verification by payment method
    method = credential.get("challenge", {}).get("method", "")
    challenge_id = credential.get("challenge", {}).get("id", "")
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
        })

    if not valid:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/verification-failed",
            "title": "Verification failed",
            "detail": "Invalid payment proof",
        })

    if not payment_id:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/verification-failed",
            "title": "Verification failed",
            "detail": "Missing payment identifier",
        })

    consumed = await check_and_consume_payment(payment_id, db)
    if not consumed:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/invalid-challenge",
            "title": "Invalid challenge",
            "detail": "Payment already consumed",
        })

    # Store the event
    event = json.loads(pending.event_json)
    await store_event(db, event)

    # Clean up pending
    await db.delete(pending)
    await db.commit()

    # Broadcast to WebSocket subscribers
    await broadcast_event(event)

    receipt = build_receipt(payment_id, method=method, challenge_id=challenge_id)
    return JSONResponse(
        status_code=200,
        content={"event": event},
        headers={"Payment-Receipt": receipt, "Cache-Control": "private"},
    )


@router.get("/pay/status")
@limiter.limit(RATE_PAY_STATUS)
async def pay_status(request: Request, payment_hash: str):
    """Poll LNBits for payment status (used by web client)."""
    paid = await check_payment_status(payment_hash)
    return {"paid": paid, "payment_hash": payment_hash}


@router.post("/api/post")
@limiter.limit(RATE_POST)
async def api_post(request: Request, db: AsyncSession = Depends(get_db)):
    """Web client note posting. Creates a relay-signed event and returns an invoice.

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

    # Build a Nostr event
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

    # Test mode without Tempo: skip payment entirely
    if not payments_enabled() and not tempo_enabled():
        await store_event(db, signed)
        await broadcast_event(signed)
        return {"event": signed, "paid": True}

    # Store as pending (requires payment via Lightning or Tempo)
    token = await store_pending_event(db, signed)

    result = {
        "token": token,
        "event_id": signed["id"],
        "methods": [],
    }

    # Add Lightning if payments enabled (has LNBits)
    if payments_enabled():
        price = settings.POST_PRICE_SATS
        invoice_data = await create_invoice(price, "clankfeed note posting")
        pending = await db.get(PendingEvent, token)
        pending.payment_hash = invoice_data["payment_hash"]
        await db.commit()
        result["bolt11"] = invoice_data["payment_request"]
        result["payment_hash"] = invoice_data["payment_hash"]
        result["amount_sats"] = price
        result["methods"].append("lightning")

    # Add Tempo if configured (works in both test and prod mode)
    if tempo_enabled():
        result["methods"].append("tempo")
        result["tempo"] = {
            "recipient": settings.TEMPO_RECIPIENT,
            "currency": settings.TEMPO_CURRENCY,
            "amount_usd": settings.TEMPO_PRICE_USD,
            "chain": "tempo",
            "testnet": settings.TEMPO_TESTNET,
        }

    return result


@router.post("/api/post/confirm")
@limiter.limit(RATE_POST_CONFIRM)
async def api_post_confirm(request: Request, db: AsyncSession = Depends(get_db)):
    """Confirm payment and store a web-client event.

    Body: {"token": "...", "payment_hash": "...", "method": "lightning"}
      or: {"token": "...", "tx_hash": "...", "method": "tempo"}
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
        if not _hmac.compare_digest(pending.payment_hash, payment_hash):
            return JSONResponse(status_code=400, content={"detail": "Payment hash mismatch"})
        paid = await check_payment_status(payment_hash)
        payment_id = payment_hash

    if not paid:
        return JSONResponse(status_code=402, content={"detail": "Payment not yet received"})

    # Consume payment (replay protection)
    consumed = await check_and_consume_payment(payment_id, db)
    if not consumed:
        return JSONResponse(status_code=402, content={
            "type": "https://paymentauth.org/problems/invalid-challenge",
            "title": "Invalid challenge",
            "detail": "Payment already consumed",
        })

    # Store the event
    event = json.loads(pending.event_json)
    await store_event(db, event)

    # Clean up
    await db.delete(pending)
    await db.commit()

    # Broadcast
    await broadcast_event(event)

    return {"event": event, "paid": True}
