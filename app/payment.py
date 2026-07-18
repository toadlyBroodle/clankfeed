"""HTTP payment endpoints + unified multi-protocol payment gate (Phase 14.4).

Unified router (satring payment.py pattern):
  - Authorization: L402|LSAT ... → L402 path (primary)
  - Authorization: Payment ...   → MPP Lightning, Tempo, or Stripe SPT (co-challenge)
  - No auth                      → 402 with L402 + MPP (+ Tempo/Stripe) challenges

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
    settings, payments_enabled, tempo_enabled, stripe_enabled, PENDING_EVENT_TTL,
    RATE_POST, RATE_PAY, RATE_PAY_STATUS, RATE_POST_CONFIRM,
    MAX_CONTENT_LENGTH, MAX_DISPLAY_NAME,
)
from app.database import get_db
from app.lightning import (
    create_invoice,
    check_payment_status,
    check_and_consume_payment,
    get_payment_status,
)
from app.models import PendingEvent, NostrEvent
from app.mpp import (
    build_mpp_challenge,
    parse_mpp_credential,
    verify_mpp_credential,
    extract_payment_hash,
    extract_amount_from_credential,
    build_receipt,
)
from app.attribution import with_clankfeed_attribution
from app.nostr import sign_event
from app.zaps import append_zap_split_tags, pubkey_from_privkey
from app.relay import store_event, broadcast_event, store_pending_event
from app.tempo_pay import build_tempo_challenge, verify_tempo_credential, extract_tempo_tx_hash
from app.stripe_pay import (
    build_stripe_challenge,
    verify_stripe_credential,
    extract_stripe_payment_id,
    stripe_challenge_echo,
)

from app.limiter import limiter

logger = logging.getLogger("clankfeed.payment")

router = APIRouter()


def _stripe_option_body(amount_usd: str | None = None, description: str = "clankfeed payment") -> dict:
    """JSON stripe block for 402 bodies (includes challenge echo for web client)."""
    usd = amount_usd or settings.STRIPE_PRICE_USD
    return {
        "network_id": settings.STRIPE_PROFILE_ID,
        "amount_usd": usd,
        "currency": "usd",
        "publishable_key": settings.STRIPE_PUBLISHABLE_KEY,
        "payment_method_types": ["card", "link"],
        "challenge": stripe_challenge_echo(usd, description),
    }


# ---------------------------------------------------------------------------
# Unified payment router (Phase 14.4 — satring require_payment pattern)
# ---------------------------------------------------------------------------


async def payment_required_challenge(
    error_body: dict,
    amount_sats: int = 0,
    amount_usd: str = "",
    description: str = "Pay to post a note on clankfeed relay",
) -> "RawResponse":
    """Flat 402 JSON with L402 (primary) + MPP (+ Tempo/Stripe) WWW-Authenticate challenges.

    Prefer this for agent-facing endpoints that expect how_to_pay at the top level.
    """
    from starlette.responses import Response as RawResponse
    from app.l402 import build_how_to_pay, l402_www_authenticate

    sats = amount_sats or settings.POST_PRICE_SATS
    usd = amount_usd or settings.TEMPO_PRICE_USD
    stripe_usd = amount_usd or settings.STRIPE_PRICE_USD
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
            from app.l402 import mint_macaroon

            body["l402"] = {
                "macaroon": mint_macaroon(invoice_data["payment_hash"]),
                "invoice": invoice_data["payment_request"],
            }
            from app.mpp import mpp_challenge_echo
            body["lightning"] = {
                "bolt11": invoice_data["payment_request"],
                "payment_hash": invoice_data["payment_hash"],
                "amount_sats": sats,
                "challenge": mpp_challenge_echo(
                    sats,
                    invoice_data["payment_hash"],
                    invoice_data["payment_request"],
                    description,
                ),
            }
            methods = list(body.get("methods") or [])
            if "lightning" not in methods:
                methods.append("lightning")
            body["methods"] = methods
        except Exception as e:
            logger.warning("Could not generate Lightning challenge for 402: %s", e)

    if tempo_enabled():
        www_headers.append(build_tempo_challenge(usd, description))
        from app.tempo_pay import tempo_challenge_echo
        body["tempo"] = {
            "recipient": settings.TEMPO_RECIPIENT,
            "currency": settings.TEMPO_CURRENCY,
            "amount_usd": usd,
            "chain": "tempo",
            "testnet": settings.TEMPO_TESTNET,
            "challenge": tempo_challenge_echo(usd, description),
        }
        methods = list(body.get("methods") or [])
        if "tempo" not in methods:
            methods.append("tempo")
        body["methods"] = methods

    if stripe_enabled():
        www_headers.append(build_stripe_challenge(stripe_usd, description))
        methods = list(body.get("methods") or [])
        if "stripe" not in methods:
            methods.append("stripe")
        body["methods"] = methods
        body["stripe"] = _stripe_option_body(stripe_usd, description or "clankfeed payment")

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
    stripe_usd = amount_usd or settings.STRIPE_PRICE_USD
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

    if stripe_enabled():
        www_parts.append(build_stripe_challenge(stripe_usd, memo))

    if not www_parts:
        raise HTTPException(status_code=402, detail=detail)

    how = build_how_to_pay(include_l402=include_l402)
    # Emit distinct WWW-Authenticate challenges (not comma-joined): L402 params
    # contain commas, so a single joined header breaks scheme-naïve parsers and
    # diverges from payment_required_challenge / GET /pay. The exception handler
    # appends each part as its own header (see app/main.py).
    exc = HTTPException(
        status_code=402,
        detail={
            "detail": detail,
            "price": {"sats": sats, "usd": usd},
            "how_to_pay": how,
        },
        headers={"Cache-Control": "no-store"},
    )
    exc.www_authenticate = list(www_parts)
    raise exc


async def require_payment(
    request: Request,
    amount_sats: int,
    memo: str,
    db: AsyncSession | None = None,
    *,
    amount_usd: str | None = None,
    challenge_on_missing: bool = True,
) -> dict | None:
    """Unified payment gate: L402 (primary) + MPP Lightning + Tempo + Stripe SPT.

    Returns a settlement dict on success:
      {"_protocol": "l402"} |
      {"_protocol": "mpp", "payment_hash": "..."} |
      {"_protocol": "tempo", "tx_hash": "..."} |
      {"_protocol": "stripe", "payment_hash": "pi_..."}

    Returns None when payments are disabled (test mode) or when there is no
    Authorization header and challenge_on_missing is False (caller handles
    pending-token / flat 402 flow).

    Raises HTTPException(402) with L402+MPP(+Tempo/Stripe) challenges when unpaid
    (challenge_on_missing=True) or when credentials are invalid.
    """
    from app.l402 import require_l402

    if not payments_enabled() and not tempo_enabled() and not stripe_enabled():
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

    # MPP Payment auth (Lightning, Tempo, or Stripe)
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

        if method == "stripe":
            if not stripe_enabled():
                await _raise_unified_402(amount_sats, memo, usd, "Stripe payments not configured")
            valid = await verify_stripe_credential(credential)
            if not valid:
                await _raise_unified_402(amount_sats, memo, usd, "Invalid Stripe payment proof")
            payment_id = extract_stripe_payment_id(credential)
            if not payment_id:
                await _raise_unified_402(amount_sats, memo, usd, "Missing Stripe payment id")
            if db is not None:
                consumed = await check_and_consume_payment(payment_id, db)
                if not consumed:
                    await _raise_unified_402(
                        amount_sats, memo, usd, "Payment already consumed",
                    )
            return {"_protocol": "stripe", "payment_hash": payment_id}

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

    # Add Tempo / Stripe co-challenges if configured
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

    if stripe_enabled():
        response.headers.append(
            "WWW-Authenticate",
            build_stripe_challenge(
                settings.STRIPE_PRICE_USD,
                "Pay to post a note on clankfeed relay",
            ),
        )
        body["methods"].append("stripe")
        body["stripe"] = _stripe_option_body(
            settings.STRIPE_PRICE_USD, "Pay to post a note on clankfeed relay",
        )

    if tempo_enabled() or stripe_enabled():
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
    if protocol in ("mpp", "tempo", "stripe") and payment_id:
        method = {"mpp": "lightning", "tempo": "tempo", "stripe": "stripe"}[protocol]
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
    status = await get_payment_status(payment_hash)
    body = {"paid": status["paid"], "payment_hash": payment_hash}
    if status.get("preimage"):
        body["preimage"] = status["preimage"]
    return body


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

    content = with_clankfeed_attribution(content)
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

    # Test mode without Tempo/Stripe: skip payment entirely
    if not payments_enabled() and not tempo_enabled() and not stripe_enabled():
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
        from app.mpp import mpp_challenge_echo
        result["lightning"] = {
            "bolt11": invoice_data["payment_request"],
            "payment_hash": invoice_data["payment_hash"],
            "amount_sats": price,
            "challenge": mpp_challenge_echo(
                price,
                invoice_data["payment_hash"],
                invoice_data["payment_request"],
                "clankfeed note posting",
            ),
        }
        result["how_to_pay"] = build_how_to_pay(include_l402=True)

        if tempo_enabled():
            result["methods"].append("tempo")
            from app.tempo_pay import tempo_challenge_echo
            result["tempo"] = {
                "recipient": settings.TEMPO_RECIPIENT,
                "currency": settings.TEMPO_CURRENCY,
                "amount_usd": settings.TEMPO_PRICE_USD,
                "chain": "tempo",
                "testnet": settings.TEMPO_TESTNET,
                "challenge": tempo_challenge_echo(
                    settings.TEMPO_PRICE_USD, "clankfeed note posting",
                ),
            }

        if stripe_enabled():
            result["methods"].append("stripe")
            result["stripe"] = _stripe_option_body(
                settings.STRIPE_PRICE_USD, "clankfeed note posting",
            )

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
        if stripe_enabled():
            response.headers.append(
                "WWW-Authenticate",
                build_stripe_challenge(settings.STRIPE_PRICE_USD, "clankfeed note posting"),
            )
        return response

    # Tempo / Stripe only (no Lightning) — return true 402 with Payment challenges
    from starlette.responses import Response as RawResponse
    if tempo_enabled():
        result["methods"].append("tempo")
        from app.tempo_pay import tempo_challenge_echo
        result["tempo"] = {
            "recipient": settings.TEMPO_RECIPIENT,
            "currency": settings.TEMPO_CURRENCY,
            "amount_usd": settings.TEMPO_PRICE_USD,
            "chain": "tempo",
            "testnet": settings.TEMPO_TESTNET,
            "challenge": tempo_challenge_echo(
                settings.TEMPO_PRICE_USD, "clankfeed note posting",
            ),
        }
        result["how_to_pay"] = build_how_to_pay(include_l402=False)

    if stripe_enabled():
        result["methods"].append("stripe")
        result["stripe"] = _stripe_option_body(
            settings.STRIPE_PRICE_USD, "clankfeed note posting",
        )
        result["how_to_pay"] = build_how_to_pay(include_l402=False)

    if not result["methods"]:
        return result

    response = RawResponse(
        content=json.dumps(result),
        status_code=402,
        media_type="application/json",
    )
    response.headers["Cache-Control"] = "no-store"
    if tempo_enabled():
        response.headers.append(
            "WWW-Authenticate",
            build_tempo_challenge(settings.TEMPO_PRICE_USD, "clankfeed note posting"),
        )
    if stripe_enabled():
        response.headers.append(
            "WWW-Authenticate",
            build_stripe_challenge(settings.STRIPE_PRICE_USD, "clankfeed note posting"),
        )
    return response


@router.post(
    "/api/post/confirm",
    status_code=410,
    deprecated=True,
    responses={
        410: {
            "description": (
                "Gone — retry the original POST with Authorization: L402 "
                "or Authorization: Payment"
            ),
        },
    },
)
@limiter.limit(RATE_POST_CONFIRM)
async def api_post_confirm(request: Request, db: AsyncSession = Depends(get_db)):
    """Phase 11c: legacy confirm removed — use Authorization: Payment (or L402)."""
    return JSONResponse(
        status_code=410,
        content={
            "detail": (
                "Gone: /api/post/confirm removed. "
                "Retry the original POST with Authorization: L402 <macaroon>:<preimage> "
                "or Authorization: Payment <base64url-credential>."
            ),
        },
    )

