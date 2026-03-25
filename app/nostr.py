"""NIP-01 Nostr event validation: serialization, id computation, BIP-340 Schnorr verification."""

import hashlib
import json
import logging
import time

from coincurve import PublicKeyXOnly

logger = logging.getLogger("clankfeed.nostr")


def serialize_event(event: dict) -> bytes:
    """Canonical JSON serialization per NIP-01.

    Returns the UTF-8 bytes of: [0, pubkey, created_at, kind, tags, content]
    """
    canonical = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    return json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode()


def compute_event_id(event: dict) -> str:
    """SHA256 hex digest of the canonical serialization."""
    return hashlib.sha256(serialize_event(event)).hexdigest()


def verify_event_id(event: dict) -> bool:
    """Check that event['id'] matches the computed id."""
    return event.get("id", "") == compute_event_id(event)


def verify_signature(event: dict) -> bool:
    """BIP-340 Schnorr signature verification.

    The signature is over the 32-byte event id (as raw bytes, not hex).
    The pubkey is x-only (32 bytes).
    """
    try:
        pubkey_bytes = bytes.fromhex(event["pubkey"])
        sig_bytes = bytes.fromhex(event["sig"])
        msg_bytes = bytes.fromhex(event["id"])

        if len(pubkey_bytes) != 32 or len(sig_bytes) != 64 or len(msg_bytes) != 32:
            return False

        pk = PublicKeyXOnly(pubkey_bytes)
        return pk.verify(sig_bytes, msg_bytes)
    except Exception:
        return False


def validate_event(event: dict) -> tuple[bool, str]:
    """Full NIP-01 event validation.

    Returns (valid, error_message). On success error_message is empty.
    """
    # Required fields
    required = ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")
    for field in required:
        if field not in event:
            return False, f"missing field: {field}"

    # Type checks
    if not isinstance(event["id"], str) or len(event["id"]) != 64:
        return False, "invalid id: must be 64-char hex"
    if not isinstance(event["pubkey"], str) or len(event["pubkey"]) != 64:
        return False, "invalid pubkey: must be 64-char hex"
    if not isinstance(event["created_at"], int):
        return False, "invalid created_at: must be integer"
    if not isinstance(event["kind"], int) or event["kind"] < 0:
        return False, "invalid kind: must be non-negative integer"
    if not isinstance(event["tags"], list):
        return False, "invalid tags: must be array"
    if not isinstance(event["content"], str):
        return False, "invalid content: must be string"
    if not isinstance(event["sig"], str) or len(event["sig"]) != 128:
        return False, "invalid sig: must be 128-char hex"

    # Reject events too far in the future (5 min tolerance)
    if event["created_at"] > int(time.time()) + 300:
        return False, "invalid: event too far in the future"

    # Verify id
    if not verify_event_id(event):
        return False, "invalid: event id does not match"

    # Verify signature
    if not verify_signature(event):
        return False, "invalid: bad signature"

    return True, ""


def sign_event(private_key_hex: str, event: dict) -> dict:
    """Sign a Nostr event with the given private key.

    Computes the id and sig fields. Used for server-signed events (web client flow).
    Returns the event dict with id, pubkey, and sig populated.
    """
    from coincurve import PrivateKey

    sk = PrivateKey(bytes.fromhex(private_key_hex))
    pk_compressed = sk.public_key.format(compressed=True)
    pubkey_hex = pk_compressed[1:].hex()  # x-only: strip prefix byte

    event["pubkey"] = pubkey_hex
    event["id"] = compute_event_id(event)

    msg_bytes = bytes.fromhex(event["id"])
    sig = sk.sign_schnorr(msg_bytes)
    event["sig"] = sig.hex()

    return event
