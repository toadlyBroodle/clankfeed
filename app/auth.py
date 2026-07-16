"""NIP-98 authentication for HTTP endpoints.

Phase 14.5: no account auto-create, no session-cookie auth, no prepaid balance.
NIP-98 identifies a pubkey only (optional for signing/identity).
"""

import logging

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.nip98 import verify_nip98

logger = logging.getLogger("clankfeed.auth")


async def get_auth(request: Request, db: AsyncSession) -> tuple:
    """Authenticate via NIP-98 Authorization header only.

    Returns (account, pubkey, auth_method):
      - account: always None (custodial accounts removed)
      - pubkey: authenticated pubkey hex or ""
      - auth_method: "nip98" | ""
    """
    del db  # unused; kept for call-site compatibility
    pubkey = await verify_nip98(request)
    if pubkey:
        return None, pubkey, "nip98"
    return None, "", ""
