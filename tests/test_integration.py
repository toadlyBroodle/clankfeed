"""Integration tests for payment flows, multi-method 402, and credential routing.

Uses monkeypatching to simulate Lightning (LNBits) and Tempo (RPC) backends
without real network calls.
"""

import json
import os
import time
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.limiter import limiter


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Reset slowapi rate limiter state between tests."""
    limiter.reset()
    yield
    limiter.reset()


# ---------------------------------------------------------------------------
# Fixtures: two app configs (tempo-only, lightning+tempo)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def tempo_client(monkeypatch):
    """Client with Tempo enabled, Lightning disabled (test-mode + TEMPO_RECIPIENT set)."""
    monkeypatch.setenv("AUTH_ROOT_KEY", "test-mode")
    monkeypatch.setenv("TEMPO_RECIPIENT", "0xRecipientAddress")
    monkeypatch.setenv("TEMPO_RPC_URL", "https://rpc.test.tempo.xyz")
    monkeypatch.setenv("TEMPO_CURRENCY", "0xTokenAddress")
    monkeypatch.setenv("TEMPO_PRICE_USD", "0.01")
    monkeypatch.setenv("TEMPO_TESTNET", "true")

    # Reload config to pick up env changes
    from app import config
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "0xRecipientAddress")
    monkeypatch.setattr(config.settings, "TEMPO_RPC_URL", "https://rpc.test.tempo.xyz")
    monkeypatch.setattr(config.settings, "TEMPO_CURRENCY", "0xTokenAddress")
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
async def full_client(monkeypatch):
    """Client with both Lightning and Tempo enabled."""
    monkeypatch.setenv("AUTH_ROOT_KEY", "real-secret-key-for-testing")
    monkeypatch.setenv("TEMPO_RECIPIENT", "0xRecipientAddress")
    monkeypatch.setenv("TEMPO_CURRENCY", "0xTokenAddress")
    monkeypatch.setenv("TEMPO_PRICE_USD", "0.01")
    monkeypatch.setenv("TEMPO_TESTNET", "true")

    from app import config
    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "real-secret-key-for-testing")
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "0xRecipientAddress")
    monkeypatch.setattr(config.settings, "TEMPO_RPC_URL", "https://rpc.test.tempo.xyz")
    monkeypatch.setattr(config.settings, "TEMPO_CURRENCY", "0xTokenAddress")
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
# Helper: mock LNBits create_invoice
# ---------------------------------------------------------------------------

_invoice_counter = 0

def _mock_create_invoice():
    """Patch create_invoice to return fake Lightning data with unique hashes."""
    global _invoice_counter
    _invoice_counter += 1
    h = f"fakehash{_invoice_counter:04d}"
    return patch("app.payment.create_invoice", new_callable=AsyncMock, return_value={
        "payment_hash": h,
        "payment_request": f"lnbc210n1fake{_invoice_counter}",
    })


def _mock_check_payment(paid=True):
    """Patch check_payment_status to return a fixed result."""
    return patch("app.payment.check_payment_status", new_callable=AsyncMock, return_value=paid)


def _mock_tempo_verify(paid=True):
    """Patch _verify_tx_on_chain to return a fixed result."""
    return patch("app.tempo_pay._verify_tx_on_chain", new_callable=AsyncMock, return_value=paid)


# ---------------------------------------------------------------------------
# Tests: /api/post response format
# ---------------------------------------------------------------------------

class TestApiPostMethods:
    """Test that /api/post returns correct methods based on config."""

    @pytest.mark.asyncio
    async def test_tempo_only_returns_tempo_method(self, tempo_client):
        """When only Tempo is enabled, response has methods=['tempo'] and no bolt11."""
        resp = await tempo_client.post("/api/post", json={"content": "tempo only"})
        assert resp.status_code == 200
        data = resp.json()
        assert "tempo" in data["methods"]
        assert "lightning" not in data["methods"]
        assert "bolt11" not in data
        assert data["tempo"]["recipient"] == "0xRecipientAddress"
        assert data["tempo"]["amount_usd"] == "0.01"
        assert data["token"]  # pending event created

    @pytest.mark.asyncio
    async def test_full_returns_both_methods(self, full_client):
        """When both are enabled, response has methods=['lightning', 'tempo']."""
        with _mock_create_invoice():
            resp = await full_client.post("/api/post", json={"content": "both methods"})
        assert resp.status_code == 200
        data = resp.json()
        assert "lightning" in data["methods"]
        assert "tempo" in data["methods"]
        assert "bolt11" in data
        assert data["tempo"]["recipient"] == "0xRecipientAddress"

    @pytest.mark.asyncio
    async def test_no_payment_returns_paid_directly(self, client):
        """When neither Lightning nor Tempo is enabled, note posts immediately."""
        resp = await client.post("/api/post", json={"content": "free post"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["paid"] is True
        assert data["event"]["content"] == "free post"


# ---------------------------------------------------------------------------
# Tests: /api/post/confirm with Tempo
# ---------------------------------------------------------------------------

class TestTempoConfirm:
    """Test the Tempo confirmation flow via /api/post/confirm."""

    @pytest.mark.asyncio
    async def test_tempo_confirm_success(self, tempo_client):
        """Confirm with valid Tempo tx hash stores the note."""
        # Create pending note
        resp = await tempo_client.post("/api/post", json={"content": "tempo confirm test"})
        token = resp.json()["token"]

        # Confirm with mocked on-chain verification
        with _mock_tempo_verify(paid=True):
            resp = await tempo_client.post("/api/post/confirm", json={
                "token": token,
                "method": "tempo",
                "tx_hash": "0xvalidtxhash123",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["paid"] is True
        assert data["event"]["content"] == "tempo confirm test"

    @pytest.mark.asyncio
    async def test_tempo_confirm_unpaid_returns_402(self, tempo_client):
        """Confirm with unverified tx returns 402."""
        resp = await tempo_client.post("/api/post", json={"content": "unpaid"})
        token = resp.json()["token"]

        with _mock_tempo_verify(paid=False):
            resp = await tempo_client.post("/api/post/confirm", json={
                "token": token,
                "method": "tempo",
                "tx_hash": "0xunpaidtx",
            })
        assert resp.status_code == 402
        assert "not yet received" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_tempo_confirm_missing_tx_hash(self, tempo_client):
        """Confirm without tx_hash returns 400."""
        resp = await tempo_client.post("/api/post", json={"content": "no hash"})
        token = resp.json()["token"]

        resp = await tempo_client.post("/api/post/confirm", json={
            "token": token,
            "method": "tempo",
        })
        assert resp.status_code == 400
        assert "tx_hash required" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_tempo_confirm_expired_token(self, tempo_client):
        """Confirm with expired token returns 404."""
        resp = await tempo_client.post("/api/post", json={"content": "will expire"})
        token = resp.json()["token"]

        # Expire the pending event by manipulating the DB
        from app.database import async_session
        from app.models import PendingEvent
        from datetime import datetime, timedelta
        async with async_session() as db:
            pending = await db.get(PendingEvent, token)
            pending.expires_at = datetime.utcnow() - timedelta(minutes=1)
            await db.commit()

        with _mock_tempo_verify(paid=True):
            resp = await tempo_client.post("/api/post/confirm", json={
                "token": token,
                "method": "tempo",
                "tx_hash": "0xvalidbutexpired",
            })
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: /api/post/confirm with Lightning
# ---------------------------------------------------------------------------

class TestLightningConfirm:
    """Test the Lightning confirmation flow via /api/post/confirm."""

    @pytest.mark.asyncio
    async def test_lightning_confirm_success(self, full_client):
        """Confirm with valid Lightning payment stores the note."""
        with _mock_create_invoice():
            resp = await full_client.post("/api/post", json={"content": "lightning confirm"})
        data = resp.json()
        token = data["token"]
        payment_hash = data["payment_hash"]

        with _mock_check_payment(paid=True):
            resp = await full_client.post("/api/post/confirm", json={
                "token": token,
                "method": "lightning",
                "payment_hash": payment_hash,
            })
        assert resp.status_code == 200
        assert resp.json()["paid"] is True

    @pytest.mark.asyncio
    async def test_lightning_confirm_wrong_hash(self, full_client):
        """Confirm with mismatched payment_hash returns 400."""
        with _mock_create_invoice():
            resp = await full_client.post("/api/post", json={"content": "wrong hash"})
        token = resp.json()["token"]

        with _mock_check_payment(paid=True):
            resp = await full_client.post("/api/post/confirm", json={
                "token": token,
                "method": "lightning",
                "payment_hash": "wronghash",
            })
        assert resp.status_code == 400
        assert "mismatch" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_lightning_confirm_unpaid(self, full_client):
        """Confirm with unpaid invoice returns 402."""
        with _mock_create_invoice():
            resp = await full_client.post("/api/post", json={"content": "not paid"})
        data = resp.json()

        with _mock_check_payment(paid=False):
            resp = await full_client.post("/api/post/confirm", json={
                "token": data["token"],
                "method": "lightning",
                "payment_hash": data["payment_hash"],
            })
        assert resp.status_code == 402


# ---------------------------------------------------------------------------
# Tests: Replay protection across methods
# ---------------------------------------------------------------------------

class TestReplayProtection:
    """Test that the same payment ID can't be used twice, across methods."""

    @pytest.mark.asyncio
    async def test_tempo_replay_rejected(self, tempo_client):
        """Same tx_hash used for two notes: second is rejected."""
        # First note
        resp = await tempo_client.post("/api/post", json={"content": "first"})
        token1 = resp.json()["token"]
        with _mock_tempo_verify(paid=True):
            resp = await tempo_client.post("/api/post/confirm", json={
                "token": token1, "method": "tempo", "tx_hash": "0xreplaytx",
            })
        assert resp.status_code == 200

        # Second note with same tx_hash
        resp = await tempo_client.post("/api/post", json={"content": "second"})
        token2 = resp.json()["token"]
        with _mock_tempo_verify(paid=True):
            resp = await tempo_client.post("/api/post/confirm", json={
                "token": token2, "method": "tempo", "tx_hash": "0xreplaytx",
            })
        assert resp.status_code == 401
        assert "already consumed" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_lightning_replay_rejected(self, full_client):
        """Same payment_hash used for two notes: second is rejected."""
        fixed_hash = "replay_test_hash_001"
        mock_invoice = patch("app.payment.create_invoice", new_callable=AsyncMock, return_value={
            "payment_hash": fixed_hash,
            "payment_request": "lnbc210n1replay",
        })

        # First note
        with mock_invoice:
            resp = await full_client.post("/api/post", json={"content": "first ln"})
        data1 = resp.json()
        with _mock_check_payment(paid=True):
            resp = await full_client.post("/api/post/confirm", json={
                "token": data1["token"], "method": "lightning",
                "payment_hash": fixed_hash,
            })
        assert resp.status_code == 200

        # Second note with same hash
        mock_invoice2 = patch("app.payment.create_invoice", new_callable=AsyncMock, return_value={
            "payment_hash": fixed_hash,
            "payment_request": "lnbc210n1replay2",
        })
        with mock_invoice2:
            resp = await full_client.post("/api/post", json={"content": "second ln"})
        data2 = resp.json()
        with _mock_check_payment(paid=True):
            resp = await full_client.post("/api/post/confirm", json={
                "token": data2["token"], "method": "lightning",
                "payment_hash": fixed_hash,
            })
        assert resp.status_code == 401
        assert "already consumed" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Tests: /api/post/confirm bad inputs
# ---------------------------------------------------------------------------

class TestConfirmValidation:
    """Test input validation on /api/post/confirm."""

    @pytest.mark.asyncio
    async def test_missing_token(self, tempo_client):
        resp = await tempo_client.post("/api/post/confirm", json={
            "method": "tempo", "tx_hash": "0xabc",
        })
        assert resp.status_code == 404  # empty token not found

    @pytest.mark.asyncio
    async def test_invalid_json(self, tempo_client):
        resp = await tempo_client.post(
            "/api/post/confirm",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_nonexistent_token(self, tempo_client):
        resp = await tempo_client.post("/api/post/confirm", json={
            "token": "nonexistent", "method": "tempo", "tx_hash": "0xabc",
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_lightning_missing_payment_hash(self, full_client):
        with _mock_create_invoice():
            resp = await full_client.post("/api/post", json={"content": "test"})
        token = resp.json()["token"]

        resp = await full_client.post("/api/post/confirm", json={
            "token": token, "method": "lightning",
        })
        assert resp.status_code == 400
        assert "payment_hash required" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Tests: Security headers present on payment endpoints
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    """Verify security middleware applies to payment endpoints."""

    @pytest.mark.asyncio
    async def test_health_has_security_headers(self, client):
        resp = await client.get("/health")
        assert "content-security-policy" in resp.headers
        assert "strict-transport-security" in resp.headers
        assert "x-frame-options" in resp.headers
        assert resp.headers["x-content-type-options"] == "nosniff"

    @pytest.mark.asyncio
    async def test_api_post_has_security_headers(self, client):
        resp = await client.post("/api/post", json={"content": "sec test"})
        assert "content-security-policy" in resp.headers
        assert "strict-transport-security" in resp.headers
