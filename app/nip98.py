"""NIP-98 HTTP Auth: verify kind:27235 signed events in Authorization header.

Clients send: Authorization: Nostr <base64-encoded-kind-27235-event>
Server verifies signature, URL, method, and timestamp, then returns the pubkey.
"""

import base64
import json
import logging
import time
from urllib.parse import urlparse

from fastapi import Request

from app.config import NIP98_TIME_WINDOW
from app.nostr import verify_event_id, verify_signature

logger = logging.getLogger("clankfeed.nip98")

NIP98_KIND = 27235


def _get_tag(event: dict, tag_name: str) -> str | None:
    """Extract the first value of a tag by name."""
    for tag in event.get("tags", []):
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == tag_name:
            return tag[1]
    return None


def _normalize_url(url: str) -> str:
    """Normalize URL for comparison: lowercase scheme+host, keep path+query."""
    parsed = urlparse(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}" + (
        f"?{parsed.query}" if parsed.query else ""
    )


async def verify_nip98(request: Request) -> str | None:
    """Extract and verify NIP-98 auth from Authorization header.

    Returns the authenticated pubkey hex on success, or None if not present/invalid.
    Logs warnings for invalid auth attempts.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Nostr "):
        return None

    token = auth_header[6:].strip()
    if not token:
        logger.warning("NIP-98: empty token after 'Nostr ' prefix")
        return None

    # Decode base64
    try:
        event_json = base64.b64decode(token)
        event = json.loads(event_json)
    except Exception as e:
        logger.warning("NIP-98: failed to decode/parse token: %s", e)
        return None

    # Validate event structure
    if not isinstance(event, dict):
        logger.warning("NIP-98: decoded token is not a JSON object")
        return None

    for field in ("id", "pubkey", "created_at", "kind", "tags", "content", "sig"):
        if field not in event:
            logger.warning("NIP-98: missing field: %s", field)
            return None

    # Must be kind 27235
    if event["kind"] != NIP98_KIND:
        logger.warning("NIP-98: wrong kind %d (expected %d)", event["kind"], NIP98_KIND)
        return None

    # Timestamp check
    now = int(time.time())
    if abs(now - event["created_at"]) > NIP98_TIME_WINDOW:
        logger.warning("NIP-98: timestamp too far off (event=%d, now=%d, window=%d)",
                        event["created_at"], now, NIP98_TIME_WINDOW)
        return None

    # Verify u tag matches request URL
    event_url = _get_tag(event, "u")
    if not event_url:
        logger.warning("NIP-98: missing 'u' tag")
        return None

    request_url = str(request.url)
    if _normalize_url(event_url) != _normalize_url(request_url):
        logger.warning("NIP-98: URL mismatch (event=%s, request=%s)", event_url, request_url)
        return None

    # Verify method tag matches HTTP method
    event_method = _get_tag(event, "method")
    if not event_method:
        logger.warning("NIP-98: missing 'method' tag")
        return None

    if event_method.upper() != request.method.upper():
        logger.warning("NIP-98: method mismatch (event=%s, request=%s)",
                        event_method, request.method)
        return None

    # Verify event id
    if not verify_event_id(event):
        logger.warning("NIP-98: event id does not match computed id")
        return None

    # Verify signature
    if not verify_signature(event):
        logger.warning("NIP-98: bad signature")
        return None

    logger.info("NIP-98 auth success: pubkey=%s", event["pubkey"][:16])
    return event["pubkey"]
