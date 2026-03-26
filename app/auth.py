"""Unified authentication: NIP-98 (preferred) with X-Account-Key fallback.

During the transition period, both auth methods are accepted.
NIP-98 is tried first; if absent, falls back to the legacy API key header.
"""

import logging

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.accounts import get_account, get_or_create_by_pubkey
from app.nip98 import verify_nip98

logger = logging.getLogger("clankfeed.auth")


async def get_auth(request: Request, db: AsyncSession) -> tuple:
    """Authenticate a request via NIP-98 or X-Account-Key.

    Returns (account, pubkey, auth_method):
      - account: Account object or None
      - pubkey: authenticated pubkey hex or ""
      - auth_method: "nip98", "api_key", or ""
    """
    # Try NIP-98 first
    pubkey = await verify_nip98(request)
    if pubkey:
        acct = await get_or_create_by_pubkey(db, pubkey)
        return acct, pubkey, "nip98"

    # Fall back to legacy X-Account-Key
    api_key = request.headers.get("X-Account-Key", "")
    if api_key:
        acct = await get_account(db, api_key)
        if acct:
            return acct, acct.nostr_pubkey or "", "api_key"

    return None, "", ""
