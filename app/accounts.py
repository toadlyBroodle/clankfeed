"""User account management: create, balance, deposit, spend credits."""

import secrets
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Account

logger = logging.getLogger("clankfeed.accounts")


async def create_account(db: AsyncSession, pubkey: str = "") -> Account:
    """Create a new account with a random API key."""
    api_key = secrets.token_hex(32)

    # If pubkey provided, check for existing account
    if pubkey:
        existing = await get_account_by_pubkey(db, pubkey)
        if existing:
            return existing

    acct = Account(id=api_key, pubkey=pubkey or None, balance_sats=0, balance_usd="0")
    db.add(acct)
    await db.commit()
    return acct


async def get_account(db: AsyncSession, api_key: str) -> Account | None:
    """Look up account by API key."""
    return await db.get(Account, api_key)


async def get_account_by_pubkey(db: AsyncSession, pubkey: str) -> Account | None:
    """Look up account by Nostr pubkey."""
    stmt = select(Account).where(Account.pubkey == pubkey)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def deposit_credits(db: AsyncSession, api_key: str, amount_sats: int, amount_usd: str = "0") -> Account | None:
    """Add credits to an account. Returns updated account or None if not found."""
    acct = await get_account(db, api_key)
    if not acct:
        return None
    acct.balance_sats = (acct.balance_sats or 0) + amount_sats
    try:
        acct.balance_usd = str(float(acct.balance_usd or "0") + float(amount_usd))
    except (ValueError, TypeError):
        pass
    await db.commit()
    return acct


async def spend_credits(db: AsyncSession, api_key: str, amount_sats: int) -> tuple[bool, int]:
    """Deduct credits from an account.

    Returns (success, remaining_balance). Fails if insufficient funds.
    """
    acct = await get_account(db, api_key)
    if not acct:
        return False, 0
    if (acct.balance_sats or 0) < amount_sats:
        return False, acct.balance_sats or 0
    acct.balance_sats = (acct.balance_sats or 0) - amount_sats
    await db.commit()
    return True, acct.balance_sats
