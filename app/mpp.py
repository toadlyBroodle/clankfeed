"""MPP (Machine Payments Protocol) Lightning payment handler.

Adapted from satring/app/mpp.py. Changed realm, logger, removed require_mpp dependency.
Kept all helpers + build/verify/parse/receipt functions.

Challenge flow:
  1. Server returns 402 with WWW-Authenticate: Payment header containing a
     BOLT11 invoice in the `request` auth-param.
  2. Client pays the Lightning invoice, obtains the preimage.
  3. Client retries with Authorization: Payment <base64url-json> containing
     the preimage in payload.preimage.
  4. Server verifies the HMAC-bound challenge ID, then checks
     SHA256(preimage) == paymentHash.
"""

import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone, timedelta

from app.config import settings

logger = logging.getLogger("clankfeed.mpp")

# ---------------------------------------------------------------------------
# Helpers: base64url (no padding, URL-safe)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# HMAC challenge binding (stateless verification)
# ---------------------------------------------------------------------------

_MPP_REALM = "clankfeed"
_MPP_METHOD = "lightning"
_MPP_INTENT = "charge"
_CHALLENGE_TTL = 600  # 10 minutes


def _get_mpp_secret() -> str:
    """Derive MPP HMAC secret from AUTH_ROOT_KEY."""
    return f"mpp:{settings.AUTH_ROOT_KEY}"


def _format_expires(ttl_seconds: int = _CHALLENGE_TTL) -> str:
    """Return RFC 3339 expiry timestamp (UTC)."""
    dt = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_expires(expires: str) -> float:
    """Parse an RFC 3339 expires string to Unix timestamp."""
    dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    return dt.timestamp()


def _compute_challenge_id(
    realm: str,
    method: str,
    intent: str,
    request_b64: str,
    expires: str,
) -> str:
    """HMAC-SHA256 over pipe-delimited challenge fields (7 slots per spec)."""
    message = f"{realm}|{method}|{intent}|{request_b64}|{expires}||"
    mac = hmac.new(
        _get_mpp_secret().encode(),
        message.encode(),
        hashlib.sha256,
    )
    return _b64url_encode(mac.digest())


def _verify_challenge_id(
    challenge_id: str,
    realm: str,
    method: str,
    intent: str,
    request_b64: str,
    expires: str,
) -> bool:
    """Verify the HMAC and check expiry."""
    expected = _compute_challenge_id(realm, method, intent, request_b64, expires)
    if not hmac.compare_digest(challenge_id, expected):
        return False
    try:
        if _parse_expires(expires) < time.time():
            return False
    except (ValueError, TypeError) as e:
        logger.warning("Invalid challenge expiry format: %s", e)
        return False
    return True


# ---------------------------------------------------------------------------
# Build MPP challenge (402 response)
# ---------------------------------------------------------------------------


def build_mpp_challenge(
    amount_sats: int,
    payment_hash: str,
    invoice: str,
    description: str = "",
) -> str:
    """Build the WWW-Authenticate: Payment header value."""
    expires = _format_expires()

    request_obj = {
        "amount": str(amount_sats),
        "currency": "sat",
        "recipient": _MPP_REALM,
        "methodDetails": {
            "invoice": invoice,
            "paymentHash": payment_hash,
            "network": "mainnet",
        },
    }
    request_b64 = _b64url_encode(json.dumps(request_obj, separators=(",", ":")).encode())

    challenge_id = _compute_challenge_id(
        _MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires,
    )

    parts = [
        f'id="{challenge_id}"',
        f'realm="{_MPP_REALM}"',
        f'method="{_MPP_METHOD}"',
        f'intent="{_MPP_INTENT}"',
        f'request="{request_b64}"',
        f'expires="{expires}"',
    ]
    if description:
        safe_desc = description.replace('"', '\\"')
        parts.append(f'description="{safe_desc}"')

    return "Payment " + ", ".join(parts)


# ---------------------------------------------------------------------------
# Parse MPP credential (Authorization header)
# ---------------------------------------------------------------------------


def parse_mpp_credential(auth_value: str) -> dict | None:
    """Parse Authorization: Payment <base64url-json> into a dict."""
    try:
        token = auth_value.split(" ", 1)[1]
        decoded = _b64url_decode(token)
        return json.loads(decoded)
    except Exception as e:
        logger.warning("Failed to parse MPP credential: %s", e)
        return None


# ---------------------------------------------------------------------------
# Verify MPP Lightning credential
# ---------------------------------------------------------------------------


def verify_mpp_credential(credential: dict) -> bool:
    """Verify an MPP Lightning credential.

    1. Check HMAC challenge binding (proves we issued this challenge).
    2. Check challenge has not expired.
    3. Verify SHA256(preimage) == paymentHash from the echoed request.
    """
    try:
        challenge = credential.get("challenge", {})
        payload = credential.get("payload", {})

        challenge_id = challenge.get("id", "")
        realm = challenge.get("realm", "")
        method = challenge.get("method", "")
        intent = challenge.get("intent", "")
        request_b64 = challenge.get("request", "")
        expires = challenge.get("expires", "")
        preimage_hex = payload.get("preimage", "")

        if not _verify_challenge_id(challenge_id, realm, method, intent, request_b64, expires):
            return False

        if method != "lightning":
            return False

        request_json = json.loads(_b64url_decode(request_b64))
        payment_hash = request_json.get("methodDetails", {}).get("paymentHash", "")
        if not payment_hash:
            return False

        if len(preimage_hex) != 64 or preimage_hex != preimage_hex.lower():
            return False

        preimage_bytes = bytes.fromhex(preimage_hex)
        computed_hash = hashlib.sha256(preimage_bytes).hexdigest()
        return hmac.compare_digest(computed_hash, payment_hash.lower())

    except Exception as e:
        logger.warning("MPP credential verification error: %s", e)
        return False


def extract_payment_hash(credential: dict) -> str | None:
    """Extract the paymentHash from an MPP credential's echoed challenge."""
    try:
        request_b64 = credential.get("challenge", {}).get("request", "")
        request_json = json.loads(_b64url_decode(request_b64))
        return request_json.get("methodDetails", {}).get("paymentHash", "")
    except Exception as e:
        logger.warning("Failed to extract payment hash: %s", e)
        return None


# ---------------------------------------------------------------------------
# Build Payment-Receipt header
# ---------------------------------------------------------------------------


def build_receipt(payment_hash: str, method: str = _MPP_METHOD, challenge_id: str = "") -> str:
    """Build base64url-encoded Payment-Receipt JSON."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    receipt = {
        "status": "success",
        "method": method,
        "challengeId": challenge_id,
        "timestamp": ts,
        "reference": payment_hash,
    }
    return _b64url_encode(json.dumps(receipt, separators=(",", ":")).encode())
