"""User account management: create, balance, deposit, spend credits."""

import secrets
import logging

from coincurve import PrivateKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto import encrypt_field
from app.models import Account

logger = logging.getLogger("clankfeed.accounts")


def _generate_nostr_keypair() -> tuple[str, str]:
    """Generate a secp256k1 keypair for Nostr. Returns (privkey_hex, pubkey_hex)."""
    privkey_bytes = secrets.token_bytes(32)
    sk = PrivateKey(privkey_bytes)
    pk_compressed = sk.public_key.format(compressed=True)
    pubkey_hex = pk_compressed[1:].hex()  # x-only: strip prefix byte
    return privkey_bytes.hex(), pubkey_hex


def _derive_pubkey_from_privkey(privkey_hex: str) -> str:
    """Derive x-only pubkey from a hex private key."""
    sk = PrivateKey(bytes.fromhex(privkey_hex))
    pk_compressed = sk.public_key.format(compressed=True)
    return pk_compressed[1:].hex()


async def create_account(db: AsyncSession, pubkey: str = "", nostr_privkey: str = "") -> Account:
    """Create a new account with a random API key and Nostr keypair.

    If nostr_privkey is provided, imports that key instead of generating one.
    If pubkey is provided, links to that external Nostr identity.
    """
    api_key = secrets.token_hex(32)

    # If external pubkey provided, check for existing account
    if pubkey:
        existing = await get_account_by_pubkey(db, pubkey)
        if existing:
            return existing

    # Use provided private key or generate one
    if nostr_privkey:
        try:
            derived_pubkey = _derive_pubkey_from_privkey(nostr_privkey)
            # Check if this pubkey already has an account
            existing = await get_account_by_nostr_pubkey(db, derived_pubkey)
            if existing:
                return existing
        except Exception as e:
            # Invalid key, generate fresh
            logger.warning("Invalid Nostr private key provided, generating fresh: %s", e)
            nostr_privkey, derived_pubkey = _generate_nostr_keypair()
    else:
        nostr_privkey, derived_pubkey = _generate_nostr_keypair()

    acct = Account(
        id=api_key,
        pubkey=pubkey or None,
        nostr_privkey=encrypt_field(nostr_privkey),
        nostr_pubkey=derived_pubkey,
        balance_sats=0,
        balance_usd="0",
    )
    db.add(acct)
    await db.commit()
    return acct


async def get_account(db: AsyncSession, api_key: str) -> Account | None:
    """Look up account by API key."""
    return await db.get(Account, api_key)


async def get_account_by_pubkey(db: AsyncSession, pubkey: str) -> Account | None:
    """Look up account by linked external Nostr pubkey."""
    stmt = select(Account).where(Account.pubkey == pubkey)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_account_by_nostr_pubkey(db: AsyncSession, nostr_pubkey: str) -> Account | None:
    """Look up account by auto-generated Nostr pubkey."""
    stmt = select(Account).where(Account.nostr_pubkey == nostr_pubkey)
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
    except (ValueError, TypeError) as e:
        logger.warning("Failed to update USD balance: %s", e)
    await db.commit()
    logger.info("Credits deposited: account=%s amount=%d sats balance=%d sats",
                api_key[:12], amount_sats, acct.balance_sats or 0)
    return acct


async def spend_credits(db: AsyncSession, api_key: str, amount_sats: int) -> tuple[bool, int]:
    """Deduct credits from an account.

    Returns (success, remaining_balance). Fails if insufficient funds.
    """
    acct = await get_account(db, api_key)
    if not acct:
        return False, 0
    if (acct.balance_sats or 0) < amount_sats:
        logger.info("Insufficient credits: account=%s balance=%d required=%d",
                    api_key[:12], acct.balance_sats or 0, amount_sats)
        return False, acct.balance_sats or 0
    acct.balance_sats = (acct.balance_sats or 0) - amount_sats
    await db.commit()
    logger.info("Credits spent: account=%s amount=%d sats remaining=%d sats",
                api_key[:12], amount_sats, acct.balance_sats)
    return True, acct.balance_sats
