"""L402 (Lightning HTTP 402) macaroon mint/verify and require_l402 gate.

Ported from satring/app/l402.py. LNBits invoice helpers live in app/lightning.py;
this module owns macaroon crypto, amount-bound status checks, and the FastAPI
dependency that issues WWW-Authenticate: L402 challenges.
"""

import base64
import hashlib
import logging

import httpx
from fastapi import HTTPException, Request
from pymacaroons import Macaroon, Verifier

from app.config import settings, payments_enabled
from app.lightning import create_invoice, check_and_consume_payment

logger = logging.getLogger("clankfeed.l402")


async def check_payment_status(payment_hash: str) -> tuple[bool, int]:
    """Return (paid, amount_sats). (False, 0) on any error or unpaid invoice.

    Amount is the settled amount in sats, parsed from the LNBits response.
    Callers MUST verify amount >= their endpoint's price to prevent
    cross-endpoint payment reuse (paying a cheap invoice and replaying the
    hash at an expensive endpoint).
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.PAYMENT_URL}/api/v1/payments/{payment_hash}",
                headers={"X-Api-Key": settings.PAYMENT_KEY},
            )
            if resp.status_code != 200:
                return False, 0
            data = resp.json()
            if not data.get("paid", False):
                return False, 0
            # LNBits returns amount in msats under details.amount (primary),
            # with a top-level "amount" field on some deployments as fallback.
            msats = (data.get("details") or {}).get("amount")
            if msats is None:
                msats = data.get("amount", 0)
            sats = abs(int(msats)) // 1000
            return True, sats
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError, ValueError, TypeError):
        return False, 0


def mint_macaroon(payment_hash: str) -> str:
    payment_hash = payment_hash.lower()
    mac = Macaroon(
        location="clankfeed",
        identifier=payment_hash,
        key=settings.AUTH_ROOT_KEY,
    )
    mac.add_first_party_caveat(f"payment_hash = {payment_hash}")
    return base64.b64encode(mac.serialize().encode()).decode()


def verify_l402(macaroon_b64: str, preimage_hex: str) -> bool:
    try:
        raw = base64.b64decode(macaroon_b64).decode()
        mac = Macaroon.deserialize(raw)
    except Exception:
        return False

    # Verify preimage: SHA256(preimage) must equal the payment_hash in the caveat
    try:
        preimage_bytes = bytes.fromhex(preimage_hex)
    except ValueError:
        return False
    expected_hash = hashlib.sha256(preimage_bytes).hexdigest()

    payment_hash = None
    for caveat in mac.caveats:
        cid = caveat.caveat_id
        if hasattr(cid, "decode"):
            cid = cid.decode()
        if cid.startswith("payment_hash = "):
            payment_hash = cid.split("= ", 1)[1]
            break

    if not payment_hash or expected_hash != payment_hash.lower():
        return False

    # Verify macaroon signature (AUTH_ROOT_KEY is the macaroon root)
    v = Verifier()
    v.satisfy_exact(f"payment_hash = {payment_hash}")
    try:
        v.verify(mac, settings.AUTH_ROOT_KEY)
        return True
    except Exception:
        return False


def _extract_payment_hash(macaroon_b64: str) -> str | None:
    """Extract the payment_hash from a serialized macaroon's caveats."""
    try:
        raw = base64.b64decode(macaroon_b64).decode()
        mac = Macaroon.deserialize(raw)
        for caveat in mac.caveats:
            cid = caveat.caveat_id
            if hasattr(cid, "decode"):
                cid = cid.decode()
            if cid.startswith("payment_hash = "):
                return cid.split("= ", 1)[1]
    except Exception:
        pass
    return None


def http_base_url() -> str:
    """HTTP(S) base derived from BASE_URL (ws→http, wss→https)."""
    return settings.BASE_URL.replace("wss://", "https://").replace("ws://", "http://").rstrip("/")


def build_how_to_pay(*, include_l402: bool = False) -> dict:
    """Agent-facing how_to_pay block for 402 bodies.

    include_l402=True when the response also emits WWW-Authenticate: L402
    (require_l402 / gated paid endpoints). Omit L402 when only MPP/Tempo
    challenges are present.
    """
    base = http_base_url()
    out: dict = {
        "MPP": {
            "steps": [
                "1. Extract Payment challenge from WWW-Authenticate header",
                "2. Pay the BOLT11 invoice in the challenge request field",
                "3. Build credential with paymentHash and preimage",
                "4. Retry with header: Authorization: Payment <base64url-credential>",
            ],
            "docs": f"{base}/openapi.json",
        },
    }
    if include_l402:
        out = {
            "L402": {
                "steps": [
                    "1. Extract macaroon and invoice from WWW-Authenticate header",
                    "2. Pay the BOLT11 Lightning invoice",
                    "3. Retry with header: Authorization: L402 <macaroon>:<preimage>",
                ],
                "docs": f"{base}/.well-known/l402",
            },
            **out,
        }
    return out


def l402_402_detail(message: str, amount_sats: int | None = None) -> dict:
    """Structured 402 detail with how_to_pay.L402 (for require_l402 challenges)."""
    price = amount_sats if amount_sats is not None else settings.POST_PRICE_SATS
    return {
        "detail": message,
        "price": {"sats": price},
        "how_to_pay": build_how_to_pay(include_l402=True),
    }


def well_known_l402_document() -> dict:
    """Body for GET /.well-known/l402 discovery."""
    base = http_base_url()
    return {
        "protocol": "L402",
        "description": (
            "Lightning-native HTTP 402 payments. Pay invoice, get preimage, "
            "authenticate with macaroon."
        ),
        "auth_scheme": "L402",
        "auth_header_format": "Authorization: L402 <macaroon>:<preimage>",
        "endpoints": {
            "events": f"{base}/api/v1/events",
            "post": f"{base}/api/v1/post",
            "vote": f"{base}/api/v1/events/{{event_id}}/vote",
        },
        "pricing_sats": {
            "post": settings.POST_PRICE_SATS,
            "events": settings.POST_PRICE_SATS,
            "vote": settings.POST_PRICE_SATS,
        },
        "example": {
            "description": "Post a note with L402 payment (Python)",
            "code": (
                "import httpx\n"
                "# 1. Hit endpoint to get 402 challenge\n"
                f"r = httpx.post('{base}/api/v1/post', json={{'content': 'hello'}})\n"
                "www_auth = r.headers['WWW-Authenticate']\n"
                "macaroon = www_auth.split('macaroon=\"')[1].split('\"')[0]\n"
                "invoice = www_auth.split('invoice=\"')[1].split('\"')[0]\n"
                "# 2. Pay invoice via your Lightning wallet, get preimage\n"
                "preimage = pay_invoice(invoice)  # your wallet SDK\n"
                "# 3. Retry with L402 auth\n"
                f"r = httpx.post('{base}/api/v1/post',\n"
                "    json={'content': 'hello'},\n"
                "    headers={'Authorization': f'L402 {macaroon}:{preimage}'}\n"
                ")\n"
            ),
        },
        "docs": f"{base}/.well-known/l402",
    }


async def try_l402(
    request: Request,
    db=None,
    amount_sats: int | None = None,
    memo: str | None = None,
) -> bool:
    """If Authorization is L402|LSAT, verify via require_l402 and return True.

    Returns False when no L402/LSAT header is present so callers can fall through
    to MPP/Tempo/token flows. Raises HTTPException on invalid/unpaid L402.
    Skips (returns False) when payments are disabled (test mode).
    """
    if not payments_enabled():
        return False
    auth = request.headers.get("Authorization", "")
    if not (auth.startswith("L402 ") or auth.startswith("LSAT ")):
        return False
    await require_l402(request=request, db=db, amount_sats=amount_sats, memo=memo)
    return True


def l402_www_authenticate(payment_hash: str, payment_request: str) -> str:
    """Build WWW-Authenticate: L402 macaroon=…, invoice=… for a minted invoice."""
    macaroon_b64 = mint_macaroon(payment_hash)
    return f'L402 macaroon="{macaroon_b64}", invoice="{payment_request}"'


async def require_l402(
    request: Request = None,
    db=None,
    amount_sats: int | None = None,
    memo: str | None = None,
):
    # Dev/test mode: skip L402 entirely
    if not payments_enabled():
        return

    if request is None:
        raise HTTPException(status_code=500, detail="L402 requires request context")

    auth = request.headers.get("Authorization", "")
    if auth.startswith("L402 ") or auth.startswith("LSAT "):
        token = auth.split(" ", 1)[1]
        if ":" not in token:
            raise HTTPException(status_code=401, detail="Invalid L402 token format")
        macaroon_b64, preimage_hex = token.split(":", 1)
        if verify_l402(macaroon_b64, preimage_hex):
            # SECURITY: Verify the invoice amount matches this endpoint's price.
            # Without this, a client could pay a cheap invoice at one endpoint
            # and replay its hash at an expensive endpoint. Macaroon caveats
            # don't bind amount, so we query LNBits for the settled amount.
            price = amount_sats if amount_sats is not None else settings.POST_PRICE_SATS
            inv_memo = memo or "clankfeed L402"
            payment_hash = _extract_payment_hash(macaroon_b64)
            if payment_hash:
                paid, paid_sats = await check_payment_status(payment_hash)
                if not paid or paid_sats < price:
                    logger.warning(
                        "L402 amount mismatch: expected=%s paid=%s hash=%s",
                        price, paid_sats, payment_hash,
                    )
                    invoice_data = await create_invoice(price, inv_memo)
                    fresh_mac = mint_macaroon(invoice_data["payment_hash"])
                    raise HTTPException(
                        status_code=402,
                        detail=l402_402_detail(
                            f"L402 amount mismatch. This resource requires {price} sats.",
                            amount_sats=price,
                        ),
                        headers={
                            "WWW-Authenticate": (
                                f'L402 macaroon="{fresh_mac}", '
                                f'invoice="{invoice_data["payment_request"]}"'
                            )
                        },
                    )
            # SECURITY: Replay protection — record the payment_hash so the same
            # L402 token cannot be reused for multiple paid actions.
            if db is not None and payment_hash:
                consumed = await check_and_consume_payment(payment_hash, db)
                if not consumed:
                    logger.warning("L402 replay blocked: payment_hash=%s", payment_hash)
                    invoice_data = await create_invoice(price, inv_memo)
                    fresh_mac = mint_macaroon(invoice_data["payment_hash"])
                    raise HTTPException(
                        status_code=402,
                        detail=l402_402_detail(
                            "L402 payment already consumed. Please pay a new invoice.",
                            amount_sats=price,
                        ),
                        headers={
                            "WWW-Authenticate": (
                                f'L402 macaroon="{fresh_mac}", '
                                f'invoice="{invoice_data["payment_request"]}"'
                            )
                        },
                    )
            return
        # Return 402 with a fresh challenge instead of a dead-end 401, so the client
        # can retry without an extra round-trip.
        price = amount_sats if amount_sats is not None else settings.POST_PRICE_SATS
        inv_memo = memo or "clankfeed L402"
        invoice_data = await create_invoice(price, inv_memo)
        fresh_mac = mint_macaroon(invoice_data["payment_hash"])
        raise HTTPException(
            status_code=402,
            detail=l402_402_detail(
                "Invalid L402 credentials. Ensure the macaroon and preimage are from the same invoice.",
                amount_sats=price,
            ),
            headers={
                "WWW-Authenticate": (
                    f'L402 macaroon="{fresh_mac}", '
                    f'invoice="{invoice_data["payment_request"]}"'
                )
            },
        )

    # No auth header — issue a 402 challenge
    price = amount_sats if amount_sats is not None else settings.POST_PRICE_SATS
    inv_memo = memo or "clankfeed L402"
    invoice_data = await create_invoice(price, inv_memo)
    macaroon_b64 = mint_macaroon(invoice_data["payment_hash"])

    raise HTTPException(
        status_code=402,
        detail=l402_402_detail("Payment Required", amount_sats=price),
        headers={
            "WWW-Authenticate": (
                f'L402 macaroon="{macaroon_b64}", '
                f'invoice="{invoice_data["payment_request"]}"'
            )
        },
    )
