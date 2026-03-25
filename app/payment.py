"""HTTP payment endpoints: MPP challenge/verify, payment status polling, web client posting."""

import json
import logging
import time
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import (
    settings, payments_enabled, PENDING_EVENT_TTL,
    RATE_POST, RATE_PAY, RATE_PAY_STATUS, RATE_POST_CONFIRM,
)
from app.database import get_db
from app.lightning import create_invoice, check_payment_status, check_and_consume_payment
from app.models import PendingEvent, NostrEvent
from app.mpp import build_mpp_challenge, parse_mpp_credential, verify_mpp_credential, extract_payment_hash, build_receipt
from app.nostr import sign_event
from app.relay import store_event, broadcast_event, store_pending_event

from app.limiter import limiter

logger = logging.getLogger("clankfeed.payment")

router = APIRouter()


@router.get("/pay")
@limiter.limit(RATE_PAY)
async def pay_get(request: Request, token: str, db: AsyncSession = Depends(get_db)):
    """Issue a 402 MPP challenge with a Lightning invoice for a pending event."""
    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at < datetime.now(timezone.utc):
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    price = settings.POST_PRICE_SATS
    invoice_data = await create_invoice(price, "clankfeed note posting")

    # Update pending event with the payment hash
    pending.payment_hash = invoice_data["payment_hash"]
    await db.commit()

    challenge = build_mpp_challenge(
        price,
        invoice_data["payment_hash"],
        invoice_data["payment_request"],
        "Pay to post a note on clankfeed relay",
    )

    return JSONResponse(
        status_code=402,
        content={
            "bolt11": invoice_data["payment_request"],
            "payment_hash": invoice_data["payment_hash"],
            "amount_sats": price,
            "token": token,
        },
        headers={
            "WWW-Authenticate": challenge,
            "Cache-Control": "no-store",
        },
    )


@router.post("/pay")
@limiter.limit(RATE_PAY)
async def pay_post(request: Request, token: str, db: AsyncSession = Depends(get_db)):
    """Verify MPP credential and store the paid event."""
    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at < datetime.now(timezone.utc):
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Payment "):
        return JSONResponse(status_code=401, content={"detail": "Missing Payment authorization"})

    credential = parse_mpp_credential(auth)
    if not credential:
        return JSONResponse(status_code=401, content={"detail": "Malformed Payment credential"})

    if not verify_mpp_credential(credential):
        return JSONResponse(status_code=401, content={"detail": "Invalid payment proof"})

    payment_hash = extract_payment_hash(credential)
    if not payment_hash:
        return JSONResponse(status_code=401, content={"detail": "Missing payment hash"})

    consumed = await check_and_consume_payment(payment_hash, db)
    if not consumed:
        return JSONResponse(status_code=401, content={"detail": "Payment already consumed"})

    # Store the event
    event = json.loads(pending.event_json)
    await store_event(db, event)

    # Clean up pending
    await db.delete(pending)
    await db.commit()

    # Broadcast to WebSocket subscribers
    await broadcast_event(event)

    receipt = build_receipt(payment_hash)
    return JSONResponse(
        status_code=200,
        content={"event": event},
        headers={"Payment-Receipt": receipt},
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
    if len(content) > 8196:
        return JSONResponse(status_code=400, content={"detail": "Content too long (max 8196 chars)"})

    display_name = body.get("display_name", "").strip()

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

    if not payments_enabled():
        # Test mode: sign, store, broadcast immediately
        if not settings.RELAY_PRIVATE_KEY:
            return JSONResponse(status_code=500, content={"detail": "Relay private key not configured"})
        signed = sign_event(settings.RELAY_PRIVATE_KEY, event)
        await store_event(db, signed)
        await broadcast_event(signed)
        return {"event": signed, "paid": True}

    # Sign the event (so it's ready to store after payment)
    if not settings.RELAY_PRIVATE_KEY:
        return JSONResponse(status_code=500, content={"detail": "Relay private key not configured"})
    signed = sign_event(settings.RELAY_PRIVATE_KEY, event)

    # Store as pending
    token = await store_pending_event(db, signed)

    # Create invoice
    price = settings.POST_PRICE_SATS
    invoice_data = await create_invoice(price, "clankfeed note posting")

    # Update pending with payment hash
    pending = await db.get(PendingEvent, token)
    pending.payment_hash = invoice_data["payment_hash"]
    await db.commit()

    return {
        "token": token,
        "bolt11": invoice_data["payment_request"],
        "payment_hash": invoice_data["payment_hash"],
        "amount_sats": price,
        "event_id": signed["id"],
    }


@router.post("/api/post/confirm")
@limiter.limit(RATE_POST_CONFIRM)
async def api_post_confirm(request: Request, db: AsyncSession = Depends(get_db)):
    """Confirm payment and store a web-client event after LNBits reports it paid.

    Body: {"token": "...", "payment_hash": "..."}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    token = body.get("token", "")
    payment_hash = body.get("payment_hash", "")

    if not token or not payment_hash:
        return JSONResponse(status_code=400, content={"detail": "token and payment_hash required"})

    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at < datetime.now(timezone.utc):
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    if pending.payment_hash != payment_hash:
        return JSONResponse(status_code=400, content={"detail": "Payment hash mismatch"})

    # Verify payment with LNBits
    paid = await check_payment_status(payment_hash)
    if not paid:
        return JSONResponse(status_code=402, content={"detail": "Payment not yet received"})

    # Consume payment (replay protection)
    consumed = await check_and_consume_payment(payment_hash, db)
    if not consumed:
        return JSONResponse(status_code=401, content={"detail": "Payment already consumed"})

    # Store the event
    event = json.loads(pending.event_json)
    await store_event(db, event)

    # Clean up
    await db.delete(pending)
    await db.commit()

    # Broadcast
    await broadcast_event(event)

    return {"event": event, "paid": True}
