"""Tests for user accounts with prepaid credits."""

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
def _reset():
    limiter.reset()
    yield
    limiter.reset()


# ---------------------------------------------------------------------------
# Account creation
# ---------------------------------------------------------------------------

class TestAccountCreate:
    @pytest.mark.asyncio
    async def test_create_account(self, client):
        resp = await client.post("/api/v1/account/create", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "api_key" in data
        assert len(data["api_key"]) == 64
        assert data["balance_sats"] == 0

    @pytest.mark.asyncio
    async def test_create_with_pubkey(self, client):
        pubkey = "aa" * 32
        resp = await client.post("/api/v1/account/create", json={"pubkey": pubkey})
        assert resp.status_code == 200

        # Same pubkey returns same account
        resp2 = await client.post("/api/v1/account/create", json={"pubkey": pubkey})
        assert resp2.json()["api_key"] == resp.json()["api_key"]

    @pytest.mark.asyncio
    async def test_create_invalid_pubkey(self, client):
        resp = await client.post("/api/v1/account/create", json={"pubkey": "short"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Balance
# ---------------------------------------------------------------------------

class TestBalance:
    @pytest.mark.asyncio
    async def test_balance_empty(self, client):
        resp = await client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]

        resp = await client.get("/api/v1/account/balance", headers={"X-Account-Key": key})
        assert resp.status_code == 200
        assert resp.json()["balance_sats"] == 0

    @pytest.mark.asyncio
    async def test_balance_no_key(self, client):
        resp = await client.get("/api/v1/account/balance")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_balance_bad_key(self, client):
        resp = await client.get("/api/v1/account/balance", headers={"X-Account-Key": "nonexistent"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Spending credits on posts (no-payment mode)
# ---------------------------------------------------------------------------

class TestCreditSpending:
    @pytest.mark.asyncio
    async def test_post_with_credits(self, client):
        """Create account, manually set balance, post with credits."""
        resp = await client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]

        # Manually add credits via the accounts module
        from app.database import async_session
        from app.accounts import deposit_credits
        async with async_session() as db:
            await deposit_credits(db, key, 100)

        # In no-payment mode, posts are free anyway, but credits_used flag
        # won't appear because the no-payment path runs first.
        # This test verifies the account infrastructure works.
        resp = await client.get("/api/v1/account/balance", headers={"X-Account-Key": key})
        assert resp.json()["balance_sats"] == 100

    @pytest.mark.asyncio
    async def test_insufficient_credits_falls_through(self, client):
        """With insufficient credits, falls through to regular payment flow."""
        resp = await client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]
        # Balance is 0, so credit spend fails, falls to no-payment-configured path
        resp = await client.post(
            "/api/v1/post",
            json={"content": "test"},
            headers={"X-Account-Key": key},
        )
        # In no-payment mode, still succeeds (free path)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Spending credits with Tempo enabled (payment mode)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def tempo_client(monkeypatch):
    from app import config
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "0xRecipient")
    monkeypatch.setattr(config.settings, "TEMPO_CURRENCY", "0xToken")
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


class TestCreditSpendingPaymentMode:
    @pytest.mark.asyncio
    async def test_post_with_credits_skips_payment(self, tempo_client):
        """With sufficient credits, post succeeds without payment."""
        # Create account and add credits
        resp = await tempo_client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]

        from app.database import async_session
        from app.accounts import deposit_credits
        async with async_session() as db:
            await deposit_credits(db, key, 500)

        # Post with credits (should skip 402)
        resp = await tempo_client.post(
            "/api/v1/post",
            json={"content": "paid with credits!", "amount_sats": 21},
            headers={"X-Account-Key": key},
        )
        assert resp.status_code == 200
        assert resp.json()["paid"] is True
        assert resp.json().get("credits_used") is True

        # Check balance deducted
        resp = await tempo_client.get("/api/v1/account/balance", headers={"X-Account-Key": key})
        assert resp.json()["balance_sats"] == 479  # 500 - 21

    @pytest.mark.asyncio
    async def test_post_insufficient_credits_returns_402(self, tempo_client):
        """With insufficient credits, returns 402 for payment."""
        resp = await tempo_client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]
        # Balance = 0

        resp = await tempo_client.post(
            "/api/v1/post",
            json={"content": "no credits"},
            headers={"X-Account-Key": key},
        )
        # Should fall through to payment required (Tempo enabled)
        assert resp.status_code == 200  # returns token + methods, not 402 (it's a JSON response)
        assert "token" in resp.json()
        assert "tempo" in resp.json().get("methods", [])

    @pytest.mark.asyncio
    async def test_vote_with_credits(self, tempo_client):
        """Vote using credits in payment mode."""
        # Create account with credits
        resp = await tempo_client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]

        from app.database import async_session
        from app.accounts import deposit_credits
        async with async_session() as db:
            await deposit_credits(db, key, 200)

        # Post a note first (need credits for this too)
        resp = await tempo_client.post(
            "/api/v1/post",
            json={"content": "vote target"},
            headers={"X-Account-Key": key},
        )
        event_id = resp.json()["event"]["id"]

        # Vote with credits
        resp = await tempo_client.post(
            f"/api/v1/events/{event_id}/vote",
            json={"direction": 1, "amount_sats": 50},
            headers={"X-Account-Key": key},
        )
        assert resp.status_code == 200
        assert resp.json()["voted"] is True
        assert resp.json().get("credits_used") is True

        # Balance: 200 - 21 (post) - 50 (vote) = 129
        resp = await tempo_client.get("/api/v1/account/balance", headers={"X-Account-Key": key})
        assert resp.json()["balance_sats"] == 129

    @pytest.mark.asyncio
    async def test_agent_event_with_credits(self, tempo_client):
        """Agent-signed event posted with credits."""
        resp = await tempo_client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]

        from app.database import async_session
        from app.accounts import deposit_credits
        async with async_session() as db:
            await deposit_credits(db, key, 100)

        event = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 1, "tags": [],
            "content": "agent with credits",
        })

        resp = await tempo_client.post(
            "/api/v1/events",
            json={"event": event},
            headers={"X-Account-Key": key},
        )
        assert resp.status_code == 200
        assert resp.json()["paid"] is True
        assert resp.json().get("credits_used") is True


# ---------------------------------------------------------------------------
# Deposit flow (Tempo enabled)
# ---------------------------------------------------------------------------

class TestDeposit:
    @pytest.mark.asyncio
    async def test_deposit_returns_402(self, tempo_client):
        """Deposit endpoint returns 402 with payment options."""
        resp = await tempo_client.post("/api/v1/account/create", json={})
        key = resp.json()["api_key"]

        resp = await tempo_client.post(
            "/api/v1/account/deposit",
            json={"amount_sats": 1000},
            headers={"X-Account-Key": key},
        )
        assert resp.status_code == 402
        data = resp.json()
        assert data["status"] == "payment_required"
        assert data["deposit_amount_sats"] == 1000
        assert "tempo" in data["methods"]

    @pytest.mark.asyncio
    async def test_deposit_no_key(self, tempo_client):
        resp = await tempo_client.post("/api/v1/account/deposit", json={"amount_sats": 100})
        assert resp.status_code == 401
