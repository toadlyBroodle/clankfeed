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
                        detail=f"L402 amount mismatch. This resource requires {price} sats.",
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
                        detail="L402 payment already consumed. Please pay a new invoice.",
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
            detail="Invalid L402 credentials. Ensure the macaroon and preimage are from the same invoice.",
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
        detail="Payment Required",
        headers={
            "WWW-Authenticate": (
                f'L402 macaroon="{macaroon_b64}", '
                f'invoice="{invoice_data["payment_request"]}"'
            )
        },
    )
