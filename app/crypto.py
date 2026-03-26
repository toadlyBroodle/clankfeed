"""Encrypt/decrypt sensitive fields (e.g., Nostr private keys) at rest.

Uses Fernet symmetric encryption with a key derived from FIELD_ENCRYPTION_KEY env var.
If no key is configured, falls back to plaintext (logs a warning on startup).
"""

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("clankfeed.crypto")

_RAW_KEY = os.getenv("FIELD_ENCRYPTION_KEY", "")


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a 32-byte Fernet key from an arbitrary-length secret."""
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


if _RAW_KEY:
    _fernet = Fernet(_derive_fernet_key(_RAW_KEY))
    logger.info("Field encryption enabled")
else:
    _fernet = None
    logger.warning("FIELD_ENCRYPTION_KEY not set; private keys stored in plaintext")


def encrypt_field(value: str) -> str:
    """Encrypt a string value. Returns prefixed ciphertext or plaintext if no key."""
    if not value:
        return value
    if _fernet is None:
        return value
    return "enc:" + _fernet.encrypt(value.encode()).decode()


def decrypt_field(value: str) -> str:
    """Decrypt a string value. Handles both encrypted and legacy plaintext values."""
    if not value:
        return value
    if not value.startswith("enc:"):
        return value  # legacy plaintext
    if _fernet is None:
        logger.error("Cannot decrypt: FIELD_ENCRYPTION_KEY not set but encrypted data found")
        return ""
    try:
        return _fernet.decrypt(value[4:].encode()).decode()
    except InvalidToken:
        logger.error("Failed to decrypt field: invalid token or wrong key")
        return ""
