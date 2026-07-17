"""LNBits wallet integration: invoice creation, payment status, replay protection.

Adapted from satring/app/l402.py (lines 17-56). Stripped of all L402/macaroon logic.
"""

import logging
import re

import httpx
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import ConsumedPayment

logger = logging.getLogger("clankfeed.lightning")

_PREIMAGE_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _normalize_preimage(raw) -> str | None:
    """Return lowercase 64-hex preimage, or None if missing/placeholder."""
    if raw is None:
        return None
    pre = str(raw).replace("0x", "").replace("0X", "").strip()
    if not _PREIMAGE_RE.fullmatch(pre):
        return None
    if pre.lower() == "0" * 64:
        return None
    return pre.lower()


async def get_payment_status(payment_hash: str) -> dict:
    """Poll LNBits for paid flag + preimage (when exposed).

    Returns {"paid": bool, "preimage": str | None}.
    LNBits GET /api/v1/payments/{hash} includes top-level ``preimage`` once settled.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.PAYMENT_URL}/api/v1/payments/{payment_hash}",
                headers={"X-Api-Key": settings.PAYMENT_KEY},
            )
            if resp.status_code != 200:
                return {"paid": False, "preimage": None}
            data = resp.json()
            paid = bool(data.get("paid", False))
            preimage = _normalize_preimage(data.get("preimage")) if paid else None
            return {"paid": paid, "preimage": preimage}
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as e:
        logger.warning("LNBits payment status check failed: %s", e)
        return {"paid": False, "preimage": None}


async def check_payment_status(payment_hash: str) -> bool:
    """Poll LNBits for whether an invoice has been paid."""
    status = await get_payment_status(payment_hash)
    return status["paid"]


async def check_and_consume_payment(payment_hash: str, db: AsyncSession) -> bool:
    """Record a payment_hash as consumed. Returns False if already used (replay)."""
    try:
        db.add(ConsumedPayment(payment_hash=payment_hash))
        await db.flush()
        logger.info("Payment consumed: hash=%s", payment_hash[:16])
        return True
    except IntegrityError as e:
        logger.warning("Payment replay detected (hash already consumed): %s", e)
        await db.rollback()
        return False


async def create_invoice(amount_sats: int, memo: str = "clankfeed note posting") -> dict:
    """Create a Lightning invoice via LNBits.

    Returns {"payment_hash": "...", "payment_request": "..."}.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{settings.PAYMENT_URL}/api/v1/payments",
                headers={"X-Api-Key": settings.PAYMENT_KEY},
                json={"out": False, "amount": amount_sats, "memo": memo},
            )
            resp.raise_for_status()
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as e:
        logger.error("LNBits invoice creation failed: %s", e)
        raise HTTPException(status_code=502, detail="Payment service unavailable")
    data = resp.json()
    logger.info("Invoice created: %d sats hash=%s", amount_sats, data["payment_hash"][:16])
    return {
        "payment_hash": data["payment_hash"],
        "payment_request": data["payment_request"],
    }
