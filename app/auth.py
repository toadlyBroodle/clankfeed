"""NIP-98 + httpOnly session authentication for HTTP endpoints.

Verifies Authorization: Nostr header or cf_session cookie, then looks up or
auto-creates account by pubkey.
"""

import logging

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.accounts import get_or_create_by_pubkey
from app.nip98 import verify_nip98
from app.session_auth import read_session_pubkey

logger = logging.getLogger("clankfeed.auth")


async def get_auth(request: Request, db: AsyncSession) -> tuple:
    """Authenticate via NIP-98, then fall back to httpOnly session cookie.

    Returns (account, pubkey, auth_method):
      - account: Account object or None
      - pubkey: authenticated pubkey hex or ""
      - auth_method: "nip98" | "session" | ""
    """
    pubkey = await verify_nip98(request)
    if pubkey:
        acct = await get_or_create_by_pubkey(db, pubkey)
        return acct, pubkey, "nip98"

    session_pk = read_session_pubkey(request)
    if session_pk:
        acct = await get_or_create_by_pubkey(db, session_pk)
        return acct, session_pk, "session"

    return None, "", ""
