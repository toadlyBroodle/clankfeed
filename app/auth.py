"""NIP-98 authentication for HTTP endpoints.

Verifies Authorization: Nostr header, looks up or auto-creates account by pubkey.
"""

import logging

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.accounts import get_or_create_by_pubkey
from app.nip98 import verify_nip98

logger = logging.getLogger("clankfeed.auth")


async def get_auth(request: Request, db: AsyncSession) -> tuple:
    """Authenticate a request via NIP-98.

    Returns (account, pubkey, auth_method):
      - account: Account object or None
      - pubkey: authenticated pubkey hex or ""
      - auth_method: "nip98" or ""
    """
    pubkey = await verify_nip98(request)
    if pubkey:
        acct = await get_or_create_by_pubkey(db, pubkey)
        return acct, pubkey, "nip98"

    return None, "", ""
