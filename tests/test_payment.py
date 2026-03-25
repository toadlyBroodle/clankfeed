"""Tests for MPP payment protocol functions."""

import time
import pytest
from app.mpp import (
    build_mpp_challenge,
    parse_mpp_credential,
    verify_mpp_credential,
    extract_payment_hash,
    build_receipt,
    _b64url_encode,
    _b64url_decode,
    _compute_challenge_id,
    _verify_challenge_id,
    _MPP_REALM,
    _MPP_METHOD,
    _MPP_INTENT,
)


class TestBase64Url:
    def test_roundtrip(self):
        data = b"hello world"
        encoded = _b64url_encode(data)
        assert "=" not in encoded  # no padding
        assert _b64url_decode(encoded) == data

    def test_url_safe_chars(self):
        # Bytes that produce + and / in standard base64
        data = b"\xff\xfe\xfd"
        encoded = _b64url_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded


class TestChallengeBinding:
    def test_compute_and_verify(self):
        request_b64 = _b64url_encode(b'{"test": true}')
        expires = str(int(time.time()) + 600)
        cid = _compute_challenge_id(_MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires)
        assert len(cid) == 64  # hex SHA256
        assert _verify_challenge_id(cid, _MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires)

    def test_tampered_challenge_fails(self):
        request_b64 = _b64url_encode(b'{"test": true}')
        expires = str(int(time.time()) + 600)
        cid = _compute_challenge_id(_MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires)
        # Tamper the id
        assert not _verify_challenge_id("00" * 32, _MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires)

    def test_expired_challenge_fails(self):
        request_b64 = _b64url_encode(b'{"test": true}')
        expires = str(int(time.time()) - 1)  # already expired
        cid = _compute_challenge_id(_MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires)
        assert not _verify_challenge_id(cid, _MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires)


class TestBuildChallenge:
    def test_build_returns_payment_header(self):
        header = build_mpp_challenge(21, "abc123", "lnbc210n1...")
        assert header.startswith("Payment ")
        assert 'realm="clankfeed"' in header
        assert 'method="lightning"' in header
        assert 'intent="charge"' in header

    def test_build_with_description(self):
        header = build_mpp_challenge(21, "abc123", "lnbc210n1...", "test desc")
        assert 'description="test desc"' in header


class TestReceipt:
    def test_build_receipt(self):
        receipt = build_receipt("abc123")
        decoded = _b64url_decode(receipt)
        import json
        data = json.loads(decoded)
        assert data["status"] == "settled"
        assert data["method"] == "lightning"
        assert data["reference"] == "abc123"
