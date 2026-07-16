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
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import (
    settings, payments_enabled, tempo_enabled, stripe_enabled,
    RATE_POST, RATE_POST_CONFIRM, RATE_EVENTS_READ, RATE_PAY_STATUS,
    RATE_ACCOUNT_CREATE, RATE_INVOICE,
    ALLOWED_EVENT_KINDS, MAX_CONTENT_LENGTH, MAX_EVENT_TAGS,
    MAX_DISPLAY_NAME, MAX_TAG_VALUE_LENGTH,
)
from app.database import get_db
from app.lightning import create_invoice, check_payment_status, check_and_consume_payment
from app.limiter import limiter
from app.rates import get_btc_usd_price, usd_to_sats
from app.models import PendingEvent, NostrEvent
from app.mpp import build_mpp_challenge, parse_mpp_credential, verify_mpp_credential, extract_payment_hash, build_receipt
from app.nostr import validate_event, sign_event
from app.zaps import append_zap_split_tags, pubkey_from_privkey, validate_kind1_zap_fee_tags
from app.relay import store_event, broadcast_event, store_pending_event, query_events, row_to_event
from app.tempo_pay import build_tempo_challenge, verify_tempo_credential, extract_tempo_tx_hash
from app.stripe_pay import build_stripe_challenge

logger = logging.getLogger("clankfeed.api_v1")

_EVENT_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def _invalid_event_id(event_id: str) -> JSONResponse | None:
    """SECURITY L3: path event_id must be exactly 64 lowercase hex chars."""
    if not _EVENT_ID_RE.fullmatch(event_id or ""):
        return JSONResponse(
            status_code=400,
            content={"detail": "event_id must be 64 lowercase hex characters"},
        )
    return None


def _apply_vote_delta(row: NostrEvent, direction: int, amount_sats: int) -> None:
    """Apply upvote/downvote to sats_clank and sats_ext, floored at 0 (SECURITY M1)."""
    row.sats_clank = max(0, (row.sats_clank or 0) + (direction * amount_sats))
    row.sats_ext = max(0, (row.sats_ext or 0) + (direction * amount_sats))


router = APIRouter(prefix="/api/v1")


async def _error_402_with_challenge(
    error_body: dict,
    amount_sats: int = 0,
    amount_usd: str = "",
    description: str = "Pay to post a note on clankfeed relay",
) -> "RawResponse":
    """Build a 402 error response with L402 + MPP (+ Tempo) WWW-Authenticate challenges."""
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
            logger.warning("Could not generate Lightning challenge for error 402: %s", e)

    if tempo_enabled():
        www_headers.append(build_tempo_challenge(usd, description))

    if stripe_enabled():
        www_headers.append(build_stripe_challenge(amount_usd or settings.STRIPE_PRICE_USD, description))

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


async def _try_spend_credits(request: Request, db: AsyncSession, amount_sats: int) -> tuple[bool, str]:
    """REMOVED (14.3): credit-spend bypass disabled. Always returns (False, "")."""
    return False, ""


def _payment_required_response(
    content: dict,
    *,
    payment_hash: str = "",
    bolt11: str = "",
    amount_sats: int = 0,
    amount_usd: str = "",
    description: str = "Pay to post a note on clankfeed relay",
) -> "RawResponse":
    """402 JSON body with L402 (+ MPP) WWW-Authenticate when a Lightning invoice exists."""
    from starlette.responses import Response as RawResponse
    from app.l402 import l402_www_authenticate, build_how_to_pay
    from app.mpp import build_mpp_challenge as _mpp

    sats = amount_sats or settings.POST_PRICE_SATS
    include_l402 = bool(payments_enabled() and bolt11 and payment_hash)
    body = dict(content)
    body.update(
        _build_payment_options(
            payment_hash, bolt11, amount_sats=sats, amount_usd=amount_usd,
            include_l402=include_l402,
        )
    )
    # Ensure how_to_pay reflects L402 when we attach the header
    if include_l402:
        body["how_to_pay"] = build_how_to_pay(include_l402=True)

    response = RawResponse(
        content=json.dumps(body),
        status_code=402,
        media_type="application/json",
    )
    response.headers["Cache-Control"] = "no-store"
    if include_l402:
        response.headers.append(
            "WWW-Authenticate",
            l402_www_authenticate(payment_hash, bolt11),
        )
        response.headers.append(
            "WWW-Authenticate",
            _mpp(sats, payment_hash, bolt11, description),
        )
    if tempo_enabled():
        response.headers.append(
            "WWW-Authenticate",
            build_tempo_challenge(amount_usd or settings.TEMPO_PRICE_USD, description),
        )
    if stripe_enabled():
        response.headers.append(
            "WWW-Authenticate",
            build_stripe_challenge(amount_usd or settings.STRIPE_PRICE_USD, description),
        )
    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_payment_options(
    payment_hash: str = "",
    bolt11: str = "",
    amount_sats: int = 0,
    amount_usd: str = "",
    *,
    include_l402: bool = False,
) -> dict:
    """Build the payment options dict for 402 responses."""
    from app.l402 import build_how_to_pay

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

    if stripe_enabled():
        stripe_usd = amount_usd or settings.STRIPE_PRICE_USD
        methods.append("stripe")
        from app.stripe_pay import stripe_challenge_echo
        result["stripe"] = {
            "network_id": settings.STRIPE_PROFILE_ID,
            "amount_usd": stripe_usd,
            "currency": "usd",
            "publishable_key": settings.STRIPE_PUBLISHABLE_KEY,
            "payment_method_types": ["card", "link"],
            "challenge": stripe_challenge_echo(stripe_usd, "clankfeed payment"),
        }

    result["methods"] = methods
    result["how_to_pay"] = build_how_to_pay(include_l402=include_l402)
    # 14.6: expose macaroon+invoice in JSON for web clients (header multi-value is flaky)
    if include_l402 and payments_enabled() and bolt11 and payment_hash:
        from app.l402 import mint_macaroon

        result["l402"] = {
            "macaroon": mint_macaroon(payment_hash),
            "invoice": bolt11,
        }
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
    # Early 402 for payment discovery: if payment is required and there's
    # no Authorization header at all, return 402 before body validation.
    # This lets mppscan probe the endpoint without needing a valid body.
    auth_header = request.headers.get("authorization", "")
    if (payments_enabled() or tempo_enabled() or stripe_enabled()) and not auth_header:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/payment-required",
            "title": "Payment required",
            "detail": "Submit with Authorization: L402 or Payment header",
        })

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

    # Phase 13: kind:1 must carry NIP-57 zap fee tags (cannot rewrite without breaking sig)
    zap_ok, zap_err = validate_kind1_zap_fee_tags(event)
    if not zap_ok:
        return JSONResponse(status_code=400, content={"detail": zap_err})

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
    if not payments_enabled() and not tempo_enabled() and not stripe_enabled():
        await store_event(db, event, sats_clank=req_sats, value_usd=req_usd)
        await broadcast_event(event)
        return {"paid": True, "event": event, "sats_clank": req_sats}

    # Unified payment router (14.13): L402|LSAT primary + MPP/Tempo; underpay gated
    from app.payment import require_payment
    settlement = await require_payment(
        request,
        amount_sats=req_sats,
        memo="clankfeed note posting",
        db=db,
        amount_usd=req_usd,
        challenge_on_missing=False,
    )
    if settlement:
        await store_event(db, event, sats_clank=req_sats, value_usd=req_usd)
        await broadcast_event(event)
        protocol = settlement.get("_protocol", "")
        payment_id = (
            settlement.get("payment_hash")
            or settlement.get("tx_hash")
            or ""
        )
        # 14.15 / 7a: MPP/Tempo/Stripe settle must emit Payment-Receipt (mirror pay_post)
        if protocol in ("mpp", "tempo", "stripe") and payment_id:
            method = {"mpp": "lightning", "tempo": "tempo", "stripe": "stripe"}[protocol]
            return JSONResponse(
                status_code=200,
                content={"paid": True, "event": event, "sats_clank": req_sats},
                headers={
                    "Payment-Receipt": build_receipt(payment_id, method=method),
                    "Cache-Control": "private",
                },
            )
        return {"paid": True, "event": event, "sats_clank": req_sats}

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

    return _payment_required_response(
        {
            "status": "payment_required",
            "token": token,
            "event_id": event["id"],
        },
        payment_hash=payment_hash,
        bolt11=bolt11,
        amount_sats=req_sats,
        amount_usd=req_usd,
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

    await store_event(db, event, sats_clank=v_sats, value_usd=v_usd)
    await db.delete(pending)
    await db.commit()
    await broadcast_event(event)
    logger.info("Event confirmed (paid): id=%s method=%s value=%d sats",
                event["id"][:12], method, v_sats)

    return {"paid": True, "event": event, "sats_clank": v_sats}


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
    origin: str = "all",
):
    """Query stored events with optional filters.

    sort: "newest" (default), "value"/"clank" (paid value first), or "zaps"/"ext" (sats_ext first)
    min_value/max_value: filter by sats_clank range
    reply_to: filter replies to a specific event ID
    origin: "clankfeed" (submitted here), "external" (ingested), or "all" (default)
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
        # SECURITY M3: exact 64-hex only — never pass wildcards into LIKE
        if not _EVENT_ID_RE.fullmatch(reply_to):
            return JSONResponse(
                status_code=400,
                content={"detail": "reply_to must be 64 lowercase hex characters"},
            )
        filt["reply_to"] = reply_to

    filt["limit"] = min(max(limit, 1), 500)

    if sort not in ("newest", "value", "clank", "zaps", "ext"):
        sort = "newest"

    if origin not in ("all", "clankfeed", "external"):
        return JSONResponse(
            status_code=400,
            content={"detail": "origin must be all, clankfeed, or external"},
        )
    if origin != "all":
        filt["origin"] = origin

    events = await query_events(
        db, [filt], sort=sort, min_value=min_value, max_value=max_value, origin=origin if origin != "all" else None
    )
    return {"events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# GET /api/v1/events/{event_id}  (get single event)
# ---------------------------------------------------------------------------

@router.get("/events/{event_id}")
@limiter.limit(RATE_EVENTS_READ)
async def get_event(request: Request, event_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single event by ID."""
    bad = _invalid_event_id(event_id)
    if bad:
        return bad
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
    auth_header = request.headers.get("authorization", "")

    # Early 402 for payment discovery only (empty body / no content, no auth).
    # Content-bearing unpaid posts fall through to pending + token/l402/lightning JSON
    # so the web client's Tempo/QR fallback can run (14.16).
    if (payments_enabled() or tempo_enabled() or stripe_enabled()) and not auth_header and not content:
        return await _error_402_with_challenge({
            "type": "https://paymentauth.org/problems/payment-required",
            "title": "Payment required",
            "detail": "Submit with Authorization: L402 or Payment header",
        })

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

    # Always relay-signed (14.5: no custodial account keys)
    signing_key = settings.RELAY_PRIVATE_KEY
    if not signing_key:
        return JSONResponse(status_code=500, content={"detail": "Relay private key not configured"})

    # Phase 13: inject NIP-57 zap fee tags before sign (author 9 + relay 1)
    author_pk = pubkey_from_privkey(signing_key)
    tags = append_zap_split_tags(tags, author_pk)

    event = {
        "created_at": int(time.time()),
        "kind": 1,
        "tags": tags,
        "content": content,
    }
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
    if not payments_enabled() and not tempo_enabled() and not stripe_enabled():
        await store_event(db, signed, sats_clank=req_sats, value_usd=req_usd)
        await broadcast_event(signed)
        return {"paid": True, "event": signed, "sats_clank": req_sats}

    # Unified payment router (14.13)
    from app.payment import require_payment
    settlement = await require_payment(
        request,
        amount_sats=req_sats,
        memo="clankfeed note posting",
        db=db,
        amount_usd=req_usd,
        challenge_on_missing=False,
    )
    if settlement:
        await store_event(db, signed, sats_clank=req_sats, value_usd=req_usd)
        await broadcast_event(signed)
        return {"paid": True, "event": signed, "sats_clank": req_sats}

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

    # Tempo-only (no Lightning): keep 200 token body for transitional Tempo clients
    if not payments_enabled() and (tempo_enabled() or stripe_enabled()):
        options = _build_payment_options(
            payment_hash, bolt11, amount_sats=req_sats, amount_usd=req_usd,
        )
        return {
            "token": token,
            "event_id": signed["id"],
            **options,
        }

    return _payment_required_response(
        {
            "status": "payment_required",
            "token": token,
            "event_id": signed["id"],
        },
        payment_hash=payment_hash,
        bolt11=bolt11,
        amount_sats=req_sats,
        amount_usd=req_usd,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/payments/stripe-spt  (MPP createToken proxy for web client)
# ---------------------------------------------------------------------------

@router.post("/payments/stripe-spt")
@limiter.limit(RATE_INVOICE)
async def create_stripe_spt(request: Request):
    """Mint a Shared Payment Token from a Stripe PaymentMethod (7a.5).

    Body: {"payment_method": "pm_…"}. Amount/currency/expiry are server-derived
    from STRIPE_PRICE_USD — client-supplied amount fields are ignored.
    """
    if not stripe_enabled():
        return JSONResponse(
            status_code=503,
            content={"detail": "Stripe is not configured"},
        )
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    payment_method = (body.get("payment_method") or "").strip()
    if not payment_method or not payment_method.startswith("pm_"):
        return JSONResponse(
            status_code=400,
            content={"detail": "payment_method (pm_…) is required"},
        )

    from app.stripe_pay import create_spt_from_payment_method, usd_to_cents

    # Server-derived amount only — ignore any client amount/max_amount/currency
    amount_cents = usd_to_cents(settings.STRIPE_PRICE_USD)
    try:
        spt = await create_spt_from_payment_method(
            payment_method,
            amount_cents=amount_cents,
        )
    except ValueError as e:
        return JSONResponse(status_code=400, content={"detail": str(e)})
    except Exception as e:
        logger.error("Stripe SPT mint failed: %s", e)
        return JSONResponse(
            status_code=502,
            content={"detail": "Failed to create Shared Payment Token"},
        )
    return {"spt": spt}


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

    # Dedupe while preserving order; empty batch → no SQL
    unique_ids = list(dict.fromkeys(eid for eid in event_ids if isinstance(eid, str) and eid))
    if not unique_ids:
        return {"counts": {}}

    # SECURITY M2a: exact 64-hex only — never pass LIKE wildcards into the query
    if any(not _EVENT_ID_RE.fullmatch(eid) for eid in unique_ids):
        return JSONResponse(
            status_code=400,
            content={"detail": "each event_id must be 64 lowercase hex characters"},
        )

    from sqlalchemy import select, func, and_, or_, case

    # One SELECT with CASE + GROUP BY (was N COUNT queries — SECURITY M2)
    parent_case = case(
        *[(NostrEvent.tags.contains(f'"e", "{eid}"'), eid) for eid in unique_ids],
    )
    stmt = (
        select(parent_case.label("parent_id"), func.count().label("cnt"))
        .where(
            and_(
                NostrEvent.kind == 1,
                or_(*[NostrEvent.tags.contains(f'"e", "{eid}"') for eid in unique_ids]),
            )
        )
        .group_by(parent_case)
    )
    result = await db.execute(stmt)
    counts = {row.parent_id: row.cnt for row in result if row.parent_id and row.cnt}
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
    bad = _invalid_event_id(event_id)
    if bad:
        return bad
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
@limiter.limit(RATE_INVOICE)
async def vote_event(request: Request, event_id: str, db: AsyncSession = Depends(get_db)):
    """Downvote a note (anti-signal). Requires payment.

    Body: {"direction": -1, "amount_sats": 21} or {"direction": -1, "amount_usd": "0.01"}
    direction: -1 only (upvote tips removed in 14.7 — use NIP-57 zap)
    amount: must be >= minimum (POST_PRICE_SATS / TEMPO_PRICE_USD)
    """
    bad = _invalid_event_id(event_id)
    if bad:
        return bad
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
    # 14.7: tips are NIP-57 zaps only — no custodial upvote invoice-to-relay
    if direction == 1:
        return JSONResponse(
            status_code=410,
            content={
                "detail": "Upvote tips removed; use NIP-57 zap (90/10 author+relay). "
                          "Downvote remains direction=-1.",
            },
        )

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
    if not payments_enabled() and not tempo_enabled() and not stripe_enabled():
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
        _apply_vote_delta(row, direction, req_sats)
        await db.commit()
        logger.info("Vote recorded (free): event=%s dir=%+d amount=%d sats new_value=%d",
                    event_id[:12], direction, req_sats, row.sats_clank)
        return {"voted": True, "direction": direction, "amount_sats": req_sats, "new_sats_clank": row.sats_clank, "new_sats_ext": row.sats_ext}

    # Unified payment router (14.13)
    from app.payment import require_payment
    settlement = await require_payment(
        request,
        amount_sats=req_sats,
        memo=f"clankfeed vote on {event_id[:12]}",
        db=db,
        amount_usd=req_usd,
        challenge_on_missing=False,
    )
    if settlement:
        from app.models import Vote
        protocol = settlement.get("_protocol", "l402")
        payment_id = settlement.get("payment_hash") or settlement.get("tx_hash") or protocol
        vote = Vote(
            id=secrets.token_hex(32),
            event_id=event_id,
            pubkey=protocol,
            direction=direction,
            amount_sats=req_sats,
            amount_usd=req_usd,
            payment_id=str(payment_id)[:64],
        )
        db.add(vote)
        _apply_vote_delta(row, direction, req_sats)
        await db.commit()
        logger.info("Vote recorded (%s): event=%s dir=%+d amount=%d sats new_value=%d",
                    protocol, event_id[:12], direction, req_sats, row.sats_clank)
        return {
            "voted": True,
            "direction": direction,
            "amount_sats": req_sats,
            "new_sats_clank": row.sats_clank,
            "new_sats_ext": row.sats_ext,
        }

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

    if not payments_enabled() and (tempo_enabled() or stripe_enabled()):
        options = _build_payment_options(
            payment_hash, bolt11, amount_sats=req_sats, amount_usd=req_usd,
        )
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

    return _payment_required_response(
        {
            "status": "payment_required",
            "token": token,
            "event_id": event_id,
            "direction": direction,
        },
        payment_hash=payment_hash,
        bolt11=bolt11,
        amount_sats=req_sats,
        amount_usd=req_usd,
        description=f"Pay to vote on {event_id[:12]}",
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
    bad = _invalid_event_id(event_id)
    if bad:
        return bad
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

    # 14.18: refuse legacy upvote PendingEvent before status/consume (don't burn payment)
    try:
        vote_data = json.loads(pending.event_json)
    except (json.JSONDecodeError, TypeError):
        return JSONResponse(status_code=400, content={"detail": "Invalid pending vote data"})
    direction = vote_data.get("direction", 1)
    if direction == 1:
        await db.delete(pending)
        await db.commit()
        return JSONResponse(
            status_code=410,
            content={
                "detail": "Upvote tips removed; use NIP-57 zap (90/10 author+relay).",
            },
        )

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
        if not pay_hash or not re.fullmatch(r"[0-9a-fA-F]{64}", pay_hash):
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
    _apply_vote_delta(row, direction, v_sats)
    await db.delete(pending)
    await db.commit()
    logger.info("Vote confirmed (paid): event=%s dir=%+d amount=%d sats method=%s new_value=%d",
                event_id[:12], direction, v_sats, method, row.sats_clank)

    return {
        "voted": True,
        "direction": direction,
        "amount_sats": v_sats,
        "new_sats_clank": row.sats_clank,
        "new_sats_ext": row.sats_ext,
    }


# ---------------------------------------------------------------------------
# Auth (NIP-98 identity only — Phase 14.5)
# ---------------------------------------------------------------------------

_ACCOUNTS_GONE = {
    "detail": "Accounts and credits removed; pay per action with L402 (Phase 14)",
}


@router.post("/auth/login")
@limiter.limit(RATE_EVENTS_READ)
async def auth_login(request: Request):
    """Session login removed (14.5). Use NIP-98 per request or client-side keys."""
    del request
    return JSONResponse(status_code=410, content=_ACCOUNTS_GONE)


@router.post("/auth/logout")
@limiter.limit(RATE_EVENTS_READ)
async def auth_logout(request: Request):
    """Clear any legacy httpOnly session cookie."""
    from app.session_auth import clear_session_cookie

    response = JSONResponse(content={"ok": True})
    clear_session_cookie(response, request)
    return response


@router.get("/auth/me")
@limiter.limit(RATE_EVENTS_READ)
async def auth_me(request: Request, db: AsyncSession = Depends(get_db)):
    """Return NIP-98 authenticated pubkey (no account / no session cookie)."""
    from app.auth import get_auth

    _, pubkey, method = await get_auth(request, db)
    if not pubkey:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    return {"pubkey": pubkey, "auth_method": method}


# ---------------------------------------------------------------------------
# Account endpoints — hard-disabled (Phase 14.5)
# ---------------------------------------------------------------------------

@router.post("/account/create")
@limiter.limit(RATE_ACCOUNT_CREATE)
async def account_create(request: Request):
    del request
    return JSONResponse(status_code=410, content=_ACCOUNTS_GONE)


@router.get("/account/balance")
@limiter.limit(RATE_EVENTS_READ)
async def account_balance(request: Request):
    del request
    return JSONResponse(status_code=410, content=_ACCOUNTS_GONE)


@router.post("/account/deposit")
@limiter.limit(RATE_INVOICE)
async def account_deposit(request: Request):
    del request
    return JSONResponse(status_code=410, content=_ACCOUNTS_GONE)


@router.post("/account/deposit/confirm")
@limiter.limit(RATE_POST_CONFIRM)
async def account_deposit_confirm(request: Request):
    del request
    return JSONResponse(status_code=410, content=_ACCOUNTS_GONE)


@router.post("/account/key")
@limiter.limit(RATE_EVENTS_READ)
async def account_export_key(request: Request):
    del request
    return JSONResponse(status_code=410, content=_ACCOUNTS_GONE)


@router.post("/account/profile")
@limiter.limit(RATE_POST)
async def account_update_profile(request: Request):
    del request
    return JSONResponse(status_code=410, content=_ACCOUNTS_GONE)


# ---------------------------------------------------------------------------
# POST /api/v1/zap/invoice  (LNURL invoice helper for web NIP-57 zaps — 14.6)
# ---------------------------------------------------------------------------

@router.post("/zap/invoice")
@limiter.limit(RATE_INVOICE)
async def zap_invoice(request: Request):
    """Fetch an LNURL-pay BOLT11 for a lud16 (CSP-safe proxy; no custody).

    Body: {"lud16": "user@domain", "amount_msat": 21000, "zap_request": {...optional kind:9734...}}
    """
    from app.zaps import fetch_lnurl_pay_invoice

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    lud16 = body.get("lud16", "")
    amount_msat = body.get("amount_msat")
    zap_request = body.get("zap_request")

    if not isinstance(lud16, str) or "@" not in lud16:
        return JSONResponse(status_code=400, content={"detail": "lud16 lightning address required"})
    if not isinstance(amount_msat, int):
        return JSONResponse(status_code=400, content={"detail": "amount_msat must be an integer"})
    if zap_request is not None and not isinstance(zap_request, dict):
        return JSONResponse(status_code=400, content={"detail": "zap_request must be an object"})

    bolt11, err = await fetch_lnurl_pay_invoice(lud16, amount_msat, zap_request)
    if err:
        # SSRF / blocked host → 403; other client errors → 400; upstream → 502
        status = 403 if "blocked" in err else (502 if "fetch failed" in err or "unavailable" in err else 400)
        return JSONResponse(status_code=status, content={"detail": err})
    return {"bolt11": bolt11, "lud16": lud16, "amount_msat": amount_msat}
