"""LNBits wallet integration: invoice creation, payment status, replay protection.

Adapted from satring/app/l402.py (lines 17-56). Stripped of all L402/macaroon logic.
"""

import logging

import httpx
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import ConsumedPayment

logger = logging.getLogger("clankfeed.lightning")


async def check_payment_status(payment_hash: str) -> bool:
    """Poll LNBits for whether an invoice has been paid."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.PAYMENT_URL}/api/v1/payments/{payment_hash}",
                headers={"X-Api-Key": settings.PAYMENT_KEY},
            )
            if resp.status_code != 200:
                return False
            return resp.json().get("paid", False)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as e:
        logger.warning("LNBits payment status check failed: %s", e)
        return False


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
