"""Tests for NIP-01 event validation and Schnorr signature verification."""

import time
import pytest
from app.nostr import (
    serialize_event,
    compute_event_id,
    verify_event_id,
    verify_signature,
    validate_event,
    sign_event,
)


TEST_SK = "a" * 64


def _make_signed_event(content="test", kind=1, tags=None):
    """Helper: create a valid signed event."""
    event = {
        "created_at": int(time.time()),
        "kind": kind,
        "tags": tags or [],
        "content": content,
    }
    return sign_event(TEST_SK, event)


class TestSerialization:
    def test_serialize_produces_canonical_json(self):
        event = {
            "pubkey": "ab" * 32,
            "created_at": 1234567890,
            "kind": 1,
            "tags": [["e", "ff" * 32]],
            "content": "hello",
        }
        raw = serialize_event(event)
        assert raw.startswith(b"[0,")
        assert b'"hello"' in raw
        # No extra whitespace
        assert b" " not in raw.replace(b'" "', b'""')  # ignore space in content placeholder

    def test_compute_event_id_is_hex_sha256(self):
        event = _make_signed_event()
        eid = compute_event_id(event)
        assert len(eid) == 64
        assert all(c in "0123456789abcdef" for c in eid)


class TestSignAndVerify:
    def test_sign_event_roundtrip(self):
        event = _make_signed_event("roundtrip test")
        assert verify_event_id(event)
        assert verify_signature(event)

    def test_validate_event_accepts_valid(self):
        event = _make_signed_event("valid note")
        valid, err = validate_event(event)
        assert valid
        assert err == ""

    def test_validate_rejects_bad_id(self):
        event = _make_signed_event()
        event["id"] = "00" * 32  # tamper
        valid, err = validate_event(event)
        assert not valid
        assert "id does not match" in err

    def test_validate_rejects_bad_signature(self):
        event = _make_signed_event()
        event["sig"] = "00" * 64  # tamper
        valid, err = validate_event(event)
        assert not valid
        assert "bad signature" in err

    def test_validate_rejects_missing_fields(self):
        valid, err = validate_event({"id": "x"})
        assert not valid
        assert "missing field" in err

    def test_validate_rejects_future_event(self):
        event = _make_signed_event()
        event["created_at"] = int(time.time()) + 600  # 10 min in future
        # Re-sign with corrected timestamp
        event_data = {
            "created_at": event["created_at"],
            "kind": event["kind"],
            "tags": event["tags"],
            "content": event["content"],
        }
        signed = sign_event(TEST_SK, event_data)
        valid, err = validate_event(signed)
        assert not valid
        assert "future" in err

    def test_different_keys_produce_different_pubkeys(self):
        e1 = sign_event("a" * 64, {"created_at": 1, "kind": 1, "tags": [], "content": ""})
        e2 = sign_event("b" * 64, {"created_at": 1, "kind": 1, "tags": [], "content": ""})
        assert e1["pubkey"] != e2["pubkey"]

    def test_different_content_produces_different_ids(self):
        e1 = _make_signed_event("hello")
        e2 = _make_signed_event("world")
        assert e1["id"] != e2["id"]
