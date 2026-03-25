"""Tests for the v1 REST API for agents."""

import json
import time
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.limiter import limiter
from app.nostr import sign_event


TEST_SK = "b" * 64


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


def _make_signed_event(content="agent test", kind=1, tags=None):
    return sign_event(TEST_SK, {
        "created_at": int(time.time()),
        "kind": kind,
        "tags": tags or [],
        "content": content,
    })


def _mock_create_invoice(hash_suffix=""):
    h = f"v1hash{hash_suffix or int(time.time())}"
    return patch("app.api_v1.create_invoice", new_callable=AsyncMock, return_value={
        "payment_hash": h,
        "payment_request": f"lnbc210n1fake{h}",
    })


def _mock_check_payment(paid=True):
    return patch("app.api_v1.check_payment_status", new_callable=AsyncMock, return_value=paid)


def _mock_tempo_verify(paid=True):
    return patch("app.tempo_pay._verify_tx_on_chain", new_callable=AsyncMock, return_value=paid)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def agent_client(monkeypatch):
    """Client with Tempo enabled, no Lightning (test-mode)."""
    from app import config
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "0xTestRecipient")
    monkeypatch.setattr(config.settings, "TEMPO_CURRENCY", "0xTestToken")
    monkeypatch.setattr(config.settings, "TEMPO_PRICE_USD", "0.01")
    monkeypatch.setattr(config.settings, "TEMPO_TESTNET", True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from app.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def full_agent_client(monkeypatch):
    """Client with both Lightning and Tempo enabled."""
    from app import config
    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "real-key")
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "0xTestRecipient")
    monkeypatch.setattr(config.settings, "TEMPO_CURRENCY", "0xTestToken")
    monkeypatch.setattr(config.settings, "TEMPO_PRICE_USD", "0.01")
    monkeypatch.setattr(config.settings, "TEMPO_TESTNET", True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from app.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# POST /api/v1/events
# ---------------------------------------------------------------------------

class TestSubmitEvent:
    @pytest.mark.asyncio
    async def test_submit_returns_402_with_tempo(self, agent_client):
        """Agent-signed event returns 402 with Tempo payment options."""
        event = _make_signed_event("agent says hi")
        resp = await agent_client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 402
        data = resp.json()
        assert data["status"] == "payment_required"
        assert "tempo" in data["methods"]
        assert data["tempo"]["recipient"] == "0xTestRecipient"
        assert data["token"]
        assert data["event_id"] == event["id"]

    @pytest.mark.asyncio
    async def test_submit_returns_402_with_both_methods(self, full_agent_client):
        """With both enabled, returns Lightning + Tempo options."""
        event = _make_signed_event("both methods")
        with _mock_create_invoice("both"):
            resp = await full_agent_client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 402
        data = resp.json()
        assert "lightning" in data["methods"]
        assert "tempo" in data["methods"]
        assert "bolt11" in data.get("lightning", {})

    @pytest.mark.asyncio
    async def test_submit_rejects_bad_signature(self, agent_client):
        event = _make_signed_event()
        event["sig"] = "00" * 64
        resp = await agent_client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 400
        assert "bad signature" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_submit_rejects_blocked_kind(self, agent_client):
        event = _make_signed_event(kind=0)
        resp = await agent_client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 400
        assert "kind 0" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_submit_missing_event_field(self, agent_client):
        resp = await agent_client.post("/api/v1/events", json={"content": "no event"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_no_payment_stores_directly(self, client):
        """No payment methods configured: event stored immediately."""
        event = _make_signed_event("free post")
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 200
        assert resp.json()["paid"] is True
        assert resp.json()["event"]["id"] == event["id"]


# ---------------------------------------------------------------------------
# POST /api/v1/events/confirm
# ---------------------------------------------------------------------------

class TestConfirmEvent:
    @pytest.mark.asyncio
    async def test_tempo_confirm(self, agent_client):
        event = _make_signed_event("confirm me")
        resp = await agent_client.post("/api/v1/events", json={"event": event})
        token = resp.json()["token"]

        with _mock_tempo_verify(paid=True):
            resp = await agent_client.post("/api/v1/events/confirm", json={
                "token": token, "method": "tempo", "tx_hash": "0xconfirmed",
            })
        assert resp.status_code == 200
        assert resp.json()["paid"] is True
        assert resp.json()["event"]["content"] == "confirm me"

    @pytest.mark.asyncio
    async def test_lightning_confirm(self, full_agent_client):
        event = _make_signed_event("ln confirm")
        with _mock_create_invoice("lnconf"):
            resp = await full_agent_client.post("/api/v1/events", json={"event": event})
        data = resp.json()

        with _mock_check_payment(paid=True):
            resp = await full_agent_client.post("/api/v1/events/confirm", json={
                "token": data["token"], "method": "lightning",
                "payment_hash": data["lightning"]["payment_hash"],
            })
        assert resp.status_code == 200
        assert resp.json()["paid"] is True

    @pytest.mark.asyncio
    async def test_confirm_replay_rejected(self, agent_client):
        """Same tx_hash rejected on second use."""
        e1 = _make_signed_event("first")
        resp = await agent_client.post("/api/v1/events", json={"event": e1})
        t1 = resp.json()["token"]
        with _mock_tempo_verify(paid=True):
            resp = await agent_client.post("/api/v1/events/confirm", json={
                "token": t1, "method": "tempo", "tx_hash": "0xreplay_v1",
            })
        assert resp.status_code == 200

        e2 = _make_signed_event("second")
        resp = await agent_client.post("/api/v1/events", json={"event": e2})
        t2 = resp.json()["token"]
        with _mock_tempo_verify(paid=True):
            resp = await agent_client.post("/api/v1/events/confirm", json={
                "token": t2, "method": "tempo", "tx_hash": "0xreplay_v1",
            })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/v1/events  (read)
# ---------------------------------------------------------------------------

class TestReadEvents:
    @pytest.mark.asyncio
    async def test_read_empty(self, client):
        resp = await client.get("/api/v1/events")
        assert resp.status_code == 200
        assert resp.json()["events"] == []
        assert resp.json()["count"] == 0

    @pytest.mark.asyncio
    async def test_read_after_post(self, client):
        """Post a note then read it back via REST."""
        await client.post("/api/v1/post", json={"content": "readable"})
        resp = await client.get("/api/v1/events?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert any(e["content"] == "readable" for e in data["events"])

    @pytest.mark.asyncio
    async def test_read_filter_by_author(self, client):
        """Filter by author prefix."""
        # Post two notes (both relay-signed, same pubkey)
        await client.post("/api/v1/post", json={"content": "a1"})
        resp = await client.get("/api/v1/events?limit=5")
        pubkey = resp.json()["events"][0]["pubkey"]

        # Filter by first 8 chars of pubkey
        resp = await client.get(f"/api/v1/events?authors={pubkey[:8]}")
        assert resp.json()["count"] >= 1

        # Filter by nonexistent pubkey
        resp = await client.get("/api/v1/events?authors=0000000000")
        assert resp.json()["count"] == 0

    @pytest.mark.asyncio
    async def test_read_with_limit(self, client):
        for i in range(5):
            await client.post("/api/v1/post", json={"content": f"note {i}"})
        resp = await client.get("/api/v1/events?limit=3")
        assert resp.json()["count"] == 3


# ---------------------------------------------------------------------------
# GET /api/v1/events/{event_id}
# ---------------------------------------------------------------------------

class TestGetEvent:
    @pytest.mark.asyncio
    async def test_get_existing(self, client):
        resp = await client.post("/api/v1/post", json={"content": "findme"})
        event_id = resp.json()["event"]["id"]
        resp = await client.get(f"/api/v1/events/{event_id}")
        assert resp.status_code == 200
        assert resp.json()["event"]["content"] == "findme"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, client):
        resp = await client.get("/api/v1/events/0000000000000000000000000000000000000000000000000000000000000000")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/post  (relay-signed)
# ---------------------------------------------------------------------------

class TestRelayPost:
    @pytest.mark.asyncio
    async def test_relay_post_no_payment(self, client):
        """No payment configured: stores immediately."""
        resp = await client.post("/api/v1/post", json={"content": "v1 post"})
        assert resp.status_code == 200
        assert resp.json()["paid"] is True

    @pytest.mark.asyncio
    async def test_relay_post_with_tempo(self, agent_client):
        """Tempo enabled: returns payment options."""
        resp = await agent_client.post("/api/v1/post", json={"content": "needs payment"})
        assert resp.status_code == 200
        data = resp.json()
        assert "tempo" in data["methods"]
        assert data["token"]

    @pytest.mark.asyncio
    async def test_relay_post_empty_content(self, client):
        resp = await client.post("/api/v1/post", json={"content": ""})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# NIP-11 payments field
# ---------------------------------------------------------------------------

class TestNip11Payments:
    @pytest.mark.asyncio
    async def test_nip11_includes_payments(self, agent_client):
        resp = await agent_client.get("/", headers={"Accept": "application/nostr+json"})
        data = resp.json()
        assert "payments" in data
        assert "tempo" in data["payments"]["methods"]
        assert data["payments"]["tempo"]["recipient"] == "0xTestRecipient"
