"""Stateless httpOnly session cookies for browser auth (SECURITY H2).

After a NIP-98 login, the server mints an HMAC-bound token so subsequent
same-origin requests can authenticate without re-signing and without
persisting private keys in localStorage.
"""

import hmac
import hashlib
import logging
import time
from urllib.parse import urlparse

from fastapi import Request, Response

from app.config import settings

logger = logging.getLogger("clankfeed.session")

SESSION_COOKIE = "cf_session"
SESSION_MAX_AGE = 7 * 24 * 3600  # 7 days
SESSION_COOKIE_PATH = "/"


def _session_secret() -> str:
    return f"session:{settings.AUTH_ROOT_KEY or 'dev'}"


def mint_session_token(pubkey: str, max_age: int = SESSION_MAX_AGE) -> str:
    """Return pubkey.exp.mac for a browser session cookie."""
    if not pubkey or len(pubkey) != 64:
        raise ValueError("pubkey must be 64-char hex")
    exp = int(time.time()) + max_age
    msg = f"{pubkey.lower()}:{exp}".encode()
    mac = hmac.new(_session_secret().encode(), msg, hashlib.sha256).hexdigest()
    return f"{pubkey.lower()}.{exp}.{mac}"


def verify_session_token(token: str) -> str | None:
    """Return pubkey if token is valid and unexpired, else None."""
    if not token or token.count(".") != 2:
        return None
    pubkey, exp_s, mac = token.split(".", 2)
    if len(pubkey) != 64 or not all(c in "0123456789abcdef" for c in pubkey):
        return None
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    if exp < int(time.time()):
        return None
    msg = f"{pubkey}:{exp}".encode()
    expected = hmac.new(_session_secret().encode(), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return None
    return pubkey


def _request_is_https(request: Request) -> bool:
    """True when the client connection is HTTPS (nginx X-Forwarded-Proto or scheme).

    Do not key off BASE_URL alone: prod may set BASE_URL=ws://localhost while
    TLS terminates at the reverse proxy.
    """
    fwd = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if fwd:
        return fwd == "https"
    return (request.url.scheme or "").lower() == "https"


def set_session_cookie(response: Response, pubkey: str, request: Request) -> None:
    token = mint_session_token(pubkey)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=_request_is_https(request),
        samesite="lax",
        max_age=SESSION_MAX_AGE,
        path=SESSION_COOKIE_PATH,
    )


def clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE,
        path=SESSION_COOKIE_PATH,
        secure=_request_is_https(request),
        httponly=True,
        samesite="lax",
    )


def read_session_pubkey(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE, "")
    return verify_session_token(token) if token else None


def cors_allow_origins() -> list[str]:
    """Explicit CORS origins — never '*'. Includes production + localhost + BASE_URL http origin."""
    origins = {
        "https://clankfeed.com",
        "http://localhost:8089",
        "http://127.0.0.1:8089",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    }
    base = settings.BASE_URL.replace("ws://", "http://").replace("wss://", "https://")
    parsed = urlparse(base)
    if parsed.scheme and parsed.netloc:
        origins.add(f"{parsed.scheme}://{parsed.netloc}")
    return sorted(origins)
