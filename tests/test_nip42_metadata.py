"""Tests for NIP-42 AUTH and kind:0 metadata events."""

import json
import time
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.limiter import limiter
from app.nostr import sign_event, compute_event_id
from app.relay import Connection


TEST_SK = "b" * 64
TEST_SK2 = "c" * 64


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


def _make_metadata(sk, name="TestAgent", about="A test agent", picture=""):
    """Create a kind:0 metadata event."""
    content = json.dumps({"name": name, "about": about, "picture": picture})
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 0,
        "tags": [],
        "content": content,
    })


def _make_auth_event(sk, challenge, relay_url=None):
    """Create a kind:22242 NIP-42 auth event."""
    from coincurve import PrivateKey
    import hashlib

    priv = PrivateKey(bytes.fromhex(sk))
    pk = priv.public_key.format(compressed=True)[1:].hex()

    from app.config import settings
    url = relay_url or settings.BASE_URL
    event = {
        "pubkey": pk,
        "created_at": int(time.time()),
        "kind": 22242,
        "tags": [
            ["relay", url],
            ["challenge", challenge],
        ],
        "content": "",
    }
    event["id"] = compute_event_id(event)
    msg_bytes = bytes.fromhex(event["id"])
    sig = priv.sign_schnorr(msg_bytes)
    event["sig"] = sig.hex()
    return event


# ---------------------------------------------------------------------------
# Kind:0 Metadata via REST API
# ---------------------------------------------------------------------------

class TestMetadataEvents:
    """Test kind:0 metadata event handling."""

    @pytest.mark.asyncio
    async def test_post_metadata_stores(self, client):
        """Kind:0 metadata events accepted and stored."""
        event = _make_metadata(TEST_SK, name="Agent007")
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 200
        assert resp.json()["paid"] is True

        # Read it back
        resp = await client.get(f"/api/v1/events/{event['id']}")
        assert resp.status_code == 200
        content = json.loads(resp.json()["event"]["content"])
        assert content["name"] == "Agent007"

    @pytest.mark.asyncio
    async def test_metadata_replaceable(self, client):
        """Newer kind:0 replaces older for same pubkey."""
        old = sign_event(TEST_SK, {
            "created_at": int(time.time()) - 10,
            "kind": 0, "tags": [],
            "content": json.dumps({"name": "OldName"}),
        })
        new = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 0, "tags": [],
            "content": json.dumps({"name": "NewName"}),
        })

        await client.post("/api/v1/events", json={"event": old})
        await client.post("/api/v1/events", json={"event": new})

        # Query kind:0 for this pubkey
        resp = await client.get(f"/api/v1/events?kinds=0&authors={old['pubkey'][:8]}")
        data = resp.json()
        assert data["count"] == 1
        content = json.loads(data["events"][0]["content"])
        assert content["name"] == "NewName"

    @pytest.mark.asyncio
    async def test_metadata_older_skipped(self, client):
        """Older kind:0 doesn't replace newer."""
        new = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 0, "tags": [],
            "content": json.dumps({"name": "NewName"}),
        })
        old = sign_event(TEST_SK, {
            "created_at": int(time.time()) - 100,
            "kind": 0, "tags": [],
            "content": json.dumps({"name": "OldName"}),
        })

        await client.post("/api/v1/events", json={"event": new})
        await client.post("/api/v1/events", json={"event": old})

        resp = await client.get(f"/api/v1/events?kinds=0&authors={new['pubkey'][:8]}")
        content = json.loads(resp.json()["events"][0]["content"])
        assert content["name"] == "NewName"

    @pytest.mark.asyncio
    async def test_different_pubkeys_independent(self, client):
        """Kind:0 from different pubkeys don't interfere."""
        meta1 = _make_metadata(TEST_SK, name="Agent1")
        meta2 = _make_metadata(TEST_SK2, name="Agent2")

        await client.post("/api/v1/events", json={"event": meta1})
        await client.post("/api/v1/events", json={"event": meta2})

        resp = await client.get("/api/v1/events?kinds=0")
        assert resp.json()["count"] == 2

    @pytest.mark.asyncio
    async def test_metadata_content_is_valid_json(self, client):
        """Kind:0 with non-JSON content still stores (relay doesn't parse content)."""
        event = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 0, "tags": [],
            "content": "not json at all",
        })
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# NIP-42 AUTH
# ---------------------------------------------------------------------------

class TestNIP42Auth:
    """Test NIP-42 authentication protocol."""

    def test_connection_has_challenge(self):
        """New connections get a challenge string."""
        from unittest.mock import MagicMock
        ws = MagicMock()
        conn = Connection(ws)
        assert conn.challenge
        assert len(conn.challenge) == 32  # 16 bytes hex
        assert len(conn.authed_pubkeys) == 0

    def test_auth_event_format(self):
        """Auth events have correct structure."""
        event = _make_auth_event(TEST_SK, "testchallenge123")
        assert event["kind"] == 22242
        tags_dict = {t[0]: t[1] for t in event["tags"]}
        assert tags_dict["challenge"] == "testchallenge123"
        assert "relay" in tags_dict

    @pytest.mark.asyncio
    async def test_auth_success(self):
        """Valid AUTH event authenticates the pubkey."""
        from unittest.mock import MagicMock, AsyncMock
        ws = MagicMock()
        ws.send_text = AsyncMock()
        conn = Connection(ws)

        auth_event = _make_auth_event(TEST_SK, conn.challenge)
        from app.relay import _handle_auth
        await _handle_auth(conn, ["AUTH", auth_event])

        # Check OK was sent
        call_args = ws.send_text.call_args[0][0]
        msg = json.loads(call_args)
        assert msg[0] == "OK"
        assert msg[2] is True  # success

        # Pubkey should be authenticated
        assert auth_event["pubkey"] in conn.authed_pubkeys

    @pytest.mark.asyncio
    async def test_auth_wrong_challenge(self):
        """AUTH with wrong challenge is rejected."""
        from unittest.mock import MagicMock, AsyncMock
        ws = MagicMock()
        ws.send_text = AsyncMock()
        conn = Connection(ws)

        auth_event = _make_auth_event(TEST_SK, "wrongchallenge")
        from app.relay import _handle_auth
        await _handle_auth(conn, ["AUTH", auth_event])

        call_args = ws.send_text.call_args[0][0]
        msg = json.loads(call_args)
        assert msg[0] == "OK"
        assert msg[2] is False
        assert "challenge" in msg[3]
        assert len(conn.authed_pubkeys) == 0

    @pytest.mark.asyncio
    async def test_auth_wrong_kind(self):
        """AUTH with non-22242 kind is rejected."""
        from unittest.mock import MagicMock, AsyncMock
        ws = MagicMock()
        ws.send_text = AsyncMock()
        conn = Connection(ws)

        event = _make_auth_event(TEST_SK, conn.challenge)
        event["kind"] = 1  # wrong kind
        from app.relay import _handle_auth
        await _handle_auth(conn, ["AUTH", event])

        call_args = ws.send_text.call_args[0][0]
        msg = json.loads(call_args)
        assert msg[2] is False
        assert "22242" in msg[3]

    @pytest.mark.asyncio
    async def test_auth_expired(self):
        """AUTH with old timestamp is rejected."""
        from unittest.mock import MagicMock, AsyncMock
        ws = MagicMock()
        ws.send_text = AsyncMock()
        conn = Connection(ws)

        event = _make_auth_event(TEST_SK, conn.challenge)
        event["created_at"] = int(time.time()) - 700  # >10 min old
        # Re-sign (id changes with timestamp)
        event["id"] = compute_event_id(event)
        from coincurve import PrivateKey
        priv = PrivateKey(bytes.fromhex(TEST_SK))
        event["sig"] = priv.sign_schnorr(bytes.fromhex(event["id"])).hex()

        from app.relay import _handle_auth
        await _handle_auth(conn, ["AUTH", event])

        call_args = ws.send_text.call_args[0][0]
        msg = json.loads(call_args)
        assert msg[2] is False
        assert "timestamp" in msg[3]

    @pytest.mark.asyncio
    async def test_multiple_pubkeys(self):
        """Multiple AUTH messages authenticate multiple pubkeys."""
        from unittest.mock import MagicMock, AsyncMock
        ws = MagicMock()
        ws.send_text = AsyncMock()
        conn = Connection(ws)

        auth1 = _make_auth_event(TEST_SK, conn.challenge)
        auth2 = _make_auth_event(TEST_SK2, conn.challenge)

        from app.relay import _handle_auth
        await _handle_auth(conn, ["AUTH", auth1])
        await _handle_auth(conn, ["AUTH", auth2])

        assert len(conn.authed_pubkeys) == 2
