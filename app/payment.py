"""HTTP payment endpoints + unified multi-protocol payment gate (Phase 14.4).

Unified router (satring payment.py pattern):
  - Authorization: L402|LSAT ... → L402 path (primary)
  - Authorization: Payment ...   → MPP Lightning or Tempo (co-challenge)
  - No auth                      → 402 with L402 + MPP (+ Tempo) challenges

Legacy HTTP routes: GET/POST /pay, GET /pay/status, POST /api/post, confirm.
"""

import hmac as _hmac
import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Request, Depends
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
from app.mpp import (
    build_mpp_challenge,
    parse_mpp_credential,
    verify_mpp_credential,
    extract_payment_hash,
    extract_amount_from_credential,
    build_receipt,
)
from app.nostr import sign_event
from app.zaps import append_zap_split_tags, pubkey_from_privkey
from app.relay import store_event, broadcast_event, store_pending_event
from app.tempo_pay import build_tempo_challenge, verify_tempo_credential, extract_tempo_tx_hash

from app.limiter import limiter

logger = logging.getLogger("clankfeed.payment")

router = APIRouter()


# ---------------------------------------------------------------------------
# Unified payment router (Phase 14.4 — satring require_payment pattern)
# ---------------------------------------------------------------------------


async def payment_required_challenge(
    error_body: dict,
    amount_sats: int = 0,
    amount_usd: str = "",
    description: str = "Pay to post a note on clankfeed relay",
) -> "RawResponse":
    """Flat 402 JSON with L402 (primary) + MPP (+ Tempo) WWW-Authenticate challenges.

    Prefer this for agent-facing endpoints that expect how_to_pay at the top level.
    """
    from starlette.responses import Response as RawResponse
    from app.l402 import build_how_to_pay, l402_www_authenticate

    sats = amount_sats or settings.POST_PRICE_SATS
    usd = amount_usd or settings.TEMPO_PRICE_USD
    include_l402 = False
    body = dict(error_body)
    www_headers: list[str] = []

    if payments_enabled():
        try:
            invoice_data = await create_invoice(sats, description)
            www_headers.append(
                l402_www_authenticate(
                    invoice_data["payment_hash"],
                    invoice_data["payment_request"],
                )
            )
            include_l402 = True
            www_headers.append(
                build_mpp_challenge(
                    sats, invoice_data["payment_hash"],
                    invoice_data["payment_request"], description,
                )
            )
        except Exception as e:
            logger.warning("Could not generate Lightning challenge for 402: %s", e)

    if tempo_enabled():
        www_headers.append(build_tempo_challenge(usd, description))

    body["how_to_pay"] = build_how_to_pay(include_l402=include_l402)
    response = RawResponse(
        content=json.dumps(body),
        status_code=402,
        media_type="application/json",
    )
    response.headers["Cache-Control"] = "no-store"
    for h in www_headers:
        response.headers.append("WWW-Authenticate", h)
    return response


async def _raise_unified_402(
    amount_sats: int,
    memo: str,
    amount_usd: str = "",
    detail: str = "Payment Required",
) -> None:
    """Raise HTTPException(402) with L402 primary + MPP co-challenge (satring style)."""
    from app.l402 import build_how_to_pay, l402_www_authenticate

    sats = amount_sats or settings.POST_PRICE_SATS
    usd = amount_usd or settings.TEMPO_PRICE_USD
    www_parts: list[str] = []
    include_l402 = False

    if payments_enabled():
        invoice_data = await create_invoice(sats, memo)
        www_parts.append(
            l402_www_authenticate(
                invoice_data["payment_hash"],
                invoice_data["payment_request"],
            )
        )
        include_l402 = True
        www_parts.append(
            build_mpp_challenge(
                sats,
                invoice_data["payment_hash"],
                invoice_data["payment_request"],
                memo,
            )
        )

    if tempo_enabled():
        www_parts.append(build_tempo_challenge(usd, memo))

    if not www_parts:
        raise HTTPException(status_code=402, detail=detail)

    how = build_how_to_pay(include_l402=include_l402)
    raise HTTPException(
        status_code=402,
        detail={
            "detail": detail,
            "price": {"sats": sats, "usd": usd},
            "how_to_pay": how,
        },
        headers={
            "WWW-Authenticate": ", ".join(www_parts),
            "Cache-Control": "no-store",
        },
    )


async def require_payment(
    request: Request,
    amount_sats: int,
    memo: str,
    db: AsyncSession | None = None,
    *,
    amount_usd: str | None = None,
    challenge_on_missing: bool = True,
) -> dict | None:
    """Unified payment gate: L402 (primary) + MPP Lightning + Tempo.

    Returns a settlement dict on success:
      {"_protocol": "l402"} |
      {"_protocol": "mpp", "payment_hash": "..."} |
      {"_protocol": "tempo", "tx_hash": "..."}

    Returns None when payments are disabled (test mode) or when there is no
    Authorization header and challenge_on_missing is False (caller handles
    pending-token / flat 402 flow).

    Raises HTTPException(402) with L402+MPP(+Tempo) challenges when unpaid
    (challenge_on_missing=True) or when credentials are invalid.
    """
    from app.l402 import require_l402

    if not payments_enabled() and not tempo_enabled():
        return None

    auth = request.headers.get("Authorization", "")
    has_l402 = auth.startswith("L402 ") or auth.startswith("LSAT ")
    has_mpp = auth.startswith("Payment ")
    usd = amount_usd if amount_usd is not None else settings.TEMPO_PRICE_USD

    # L402 / LSAT (primary Lightning path)
    if has_l402:
        if not payments_enabled():
            await _raise_unified_402(amount_sats, memo, usd, "Lightning/L402 not configured")
        await require_l402(request=request, db=db, amount_sats=amount_sats, memo=memo)
        return {"_protocol": "l402"}

    # MPP Payment auth (Lightning or Tempo)
    if has_mpp:
        credential = parse_mpp_credential(auth)
        if not credential:
            await _raise_unified_402(
                amount_sats, memo, usd, "Could not decode Payment credential",
            )

        method = credential.get("challenge", {}).get("method", "")
        if method == "tempo":
            if not tempo_enabled():
                await _raise_unified_402(amount_sats, memo, usd, "Tempo payments not configured")
            valid = await verify_tempo_credential(credential)
            if not valid:
                await _raise_unified_402(amount_sats, memo, usd, "Invalid Tempo payment proof")
            tx_hash = extract_tempo_tx_hash(credential)
            if not tx_hash:
                await _raise_unified_402(amount_sats, memo, usd, "Missing Tempo tx hash")
            if db is not None:
                consumed = await check_and_consume_payment(tx_hash, db)
                if not consumed:
                    await _raise_unified_402(
                        amount_sats, memo, usd, "Payment already consumed",
                    )
            return {"_protocol": "tempo", "tx_hash": tx_hash, "payment_hash": tx_hash}

        if method == "lightning" or method == "":
            if not payments_enabled():
                await _raise_unified_402(amount_sats, memo, usd, "Lightning/MPP not configured")
            if not verify_mpp_credential(credential):
                await _raise_unified_402(amount_sats, memo, usd, "Invalid payment proof")
            challenge_amount = extract_amount_from_credential(credential)
            if challenge_amount < amount_sats:
                await _raise_unified_402(
                    amount_sats,
                    memo,
                    usd,
                    f"This resource requires {amount_sats} sats; credential amount is {challenge_amount}.",
                )
            payment_hash = extract_payment_hash(credential) or ""
            if db is not None and payment_hash:
                consumed = await check_and_consume_payment(payment_hash, db)
                if not consumed:
                    await _raise_unified_402(
                        amount_sats, memo, usd, "Payment already consumed",
                    )
            return {"_protocol": "mpp", "payment_hash": payment_hash}

        await _raise_unified_402(
            amount_sats, memo, usd, f"Method '{method}' is not supported",
        )

    if not challenge_on_missing:
        return None

    await _raise_unified_402(amount_sats, memo, usd)
    return None  # pragma: no cover


async def _error_402_with_challenge(
    error_body: dict,
    amount_sats: int = 0,
    description: str = "Pay to post a note on clankfeed relay",
) -> "RawResponse":
    """Build a 402 error response with L402 + MPP WWW-Authenticate challenges."""
    return await payment_required_challenge(
        error_body, amount_sats=amount_sats, description=description,
    )


@router.get("/pay")
@limiter.limit(RATE_PAY)
async def pay_get(request: Request, token: str, db: AsyncSession = Depends(get_db)):
    """Issue a 402 MPP challenge with a Lightning invoice for a pending event."""
    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    price = settings.POST_PRICE_SATS
    invoice_data = await create_invoice(price, "clankfeed note posting")

    # Update pending event with the payment hash
    pending.payment_hash = invoice_data["payment_hash"]
    await db.commit()

    from app.l402 import build_how_to_pay, l402_www_authenticate

    # L402 primary + MPP co-challenge (same invoice) for WS payment-required URL
    l402_challenge = l402_www_authenticate(
        invoice_data["payment_hash"],
        invoice_data["payment_request"],
    )
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
        "how_to_pay": build_how_to_pay(include_l402=True),
    }

    # Multiple WWW-Authenticate headers via raw Response
    from starlette.responses import Response as RawResponse
    response = RawResponse(
        content=json.dumps(body),
        status_code=402,
        media_type="application/json",
    )
    response.headers.append("WWW-Authenticate", l402_challenge)
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
    """Verify L402 or MPP credential via require_payment and store the paid event."""
    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return JSONResponse(status_code=404, content={"detail": "Token expired or not found"})

    req_sats = pending.amount_sats or settings.POST_PRICE_SATS
    req_usd = pending.amount_usd or settings.TEMPO_PRICE_USD

    # Unified payment router (14.13): L402|LSAT|MPP|Tempo; underpay gated
    settlement = await require_payment(
        request,
        amount_sats=req_sats,
        memo="clankfeed note posting",
        db=db,
        amount_usd=req_usd,
        challenge_on_missing=True,
    )

    event = json.loads(pending.event_json)
    await store_event(db, event)
    await db.delete(pending)
    await db.commit()
    await broadcast_event(event)

    protocol = (settlement or {}).get("_protocol", "unknown")
    payment_id = (settlement or {}).get("payment_hash") or (settlement or {}).get("tx_hash") or ""
    logger.info(
        "Payment confirmed (%s): event=%s payment=%s",
        protocol, event["id"][:12], (payment_id or "")[:16],
    )

    headers = {"Cache-Control": "private"}
    if protocol in ("mpp", "tempo") and payment_id:
        method = "lightning" if protocol == "mpp" else "tempo"
        headers["Payment-Receipt"] = build_receipt(payment_id, method=method)

    return JSONResponse(
        status_code=200,
        content={"event": event},
        headers=headers,
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
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
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

    if not settings.RELAY_PRIVATE_KEY:
        return JSONResponse(status_code=500, content={"detail": "Relay private key not configured"})

    # Phase 13: inject NIP-57 zap fee tags before sign (author 9 + relay 1)
    author_pk = pubkey_from_privkey(settings.RELAY_PRIVATE_KEY)
    tags = append_zap_split_tags(tags, author_pk)

    event = {
        "created_at": int(time.time()),
        "kind": 1,
        "tags": tags,
        "content": content,
    }
    signed = sign_event(settings.RELAY_PRIVATE_KEY, event)

    # Test mode without Tempo: skip payment entirely
    if not payments_enabled() and not tempo_enabled():
        await store_event(db, signed)
        await broadcast_event(signed)
        return {"event": signed, "paid": True}

    # Unified payment router (14.13)
    from app.l402 import build_how_to_pay, l402_www_authenticate
    settlement = await require_payment(
        request,
        amount_sats=settings.POST_PRICE_SATS,
        memo="clankfeed note posting",
        db=db,
        challenge_on_missing=False,
    )
    if settlement:
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

    # Add Lightning if payments enabled (has LNBits) — return 402 with L402+MPP
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
        result["how_to_pay"] = build_how_to_pay(include_l402=True)

        if tempo_enabled():
            result["methods"].append("tempo")
            result["tempo"] = {
                "recipient": settings.TEMPO_RECIPIENT,
                "currency": settings.TEMPO_CURRENCY,
                "amount_usd": settings.TEMPO_PRICE_USD,
                "chain": "tempo",
                "testnet": settings.TEMPO_TESTNET,
            }

        from starlette.responses import Response as RawResponse
        response = RawResponse(
            content=json.dumps(result),
            status_code=402,
            media_type="application/json",
        )
        response.headers.append(
            "WWW-Authenticate",
            l402_www_authenticate(invoice_data["payment_hash"], invoice_data["payment_request"]),
        )
        response.headers.append(
            "WWW-Authenticate",
            build_mpp_challenge(
                price,
                invoice_data["payment_hash"],
                invoice_data["payment_request"],
                "clankfeed note posting",
            ),
        )
        response.headers["Cache-Control"] = "no-store"
        if tempo_enabled():
            response.headers.append(
                "WWW-Authenticate",
                build_tempo_challenge(settings.TEMPO_PRICE_USD, "clankfeed note posting"),
            )
        return response

    # Tempo-only (no Lightning)
    if tempo_enabled():
        result["methods"].append("tempo")
        result["tempo"] = {
            "recipient": settings.TEMPO_RECIPIENT,
            "currency": settings.TEMPO_CURRENCY,
            "amount_usd": settings.TEMPO_PRICE_USD,
            "chain": "tempo",
            "testnet": settings.TEMPO_TESTNET,
        }
        result["how_to_pay"] = build_how_to_pay(include_l402=False)

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
    except Exception as e:
        logger.warning("Invalid JSON body: %s", e)
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    token = body.get("token", "")
    method = body.get("method", "lightning")

    pending = await db.get(PendingEvent, token)
    if not pending or pending.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
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
        if not payment_hash or not re.fullmatch(r"[0-9a-fA-F]{64}", payment_hash):
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
    logger.info("Post confirmed (legacy): event=%s method=%s payment=%s",
                event["id"][:12], method, payment_id[:16])

    return {"event": event, "paid": True}
