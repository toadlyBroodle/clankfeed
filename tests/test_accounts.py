"""Tests for user accounts with prepaid credits (NIP-98 auth)."""

import base64
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
TEST_SK2 = "c" * 64  # second key for separate accounts


@pytest.fixture(autouse=True)
def _reset():
    limiter.reset()
    yield
    limiter.reset()


def _nip98(url: str, method: str, privkey: str = TEST_SK) -> dict:
    """Build NIP-98 Authorization header dict."""
    event = {
        "kind": 27235,
        "created_at": int(time.time()),
        "tags": [["u", url], ["method", method.upper()]],
        "content": "",
    }
    signed = sign_event(privkey, event)
    token = base64.b64encode(json.dumps(signed).encode()).decode()
    return {"Authorization": f"Nostr {token}"}


def _nip98_json(url: str, method: str, privkey: str = TEST_SK) -> dict:
    """NIP-98 headers with Content-Type: application/json."""
    h = _nip98(url, method, privkey)
    h["Content-Type"] = "application/json"
    return h


# ---------------------------------------------------------------------------
# Account creation
# ---------------------------------------------------------------------------

class TestAccountCreate:
    @pytest.mark.asyncio
    async def test_create_account(self, client):
        resp = await client.post("/api/v1/account/create", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "nostr_pubkey" in data
        assert len(data["nostr_pubkey"]) == 64
        assert data["balance_sats"] == 0

    @pytest.mark.asyncio
    async def test_create_with_pubkey(self, client):
        pubkey = "aa" * 32
        resp = await client.post("/api/v1/account/create", json={"pubkey": pubkey})
        assert resp.status_code == 200

        # Same pubkey returns same account
        resp2 = await client.post("/api/v1/account/create", json={"pubkey": pubkey})
        assert resp2.json()["nostr_pubkey"] == resp.json()["nostr_pubkey"]

    @pytest.mark.asyncio
    async def test_create_invalid_pubkey(self, client):
        resp = await client.post("/api/v1/account/create", json={"pubkey": "short"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Balance (NIP-98 auth)
# ---------------------------------------------------------------------------

class TestBalance:
    @pytest.mark.asyncio
    async def test_balance_via_nip98(self, client):
        url = "http://test/api/v1/account/balance"
        resp = await client.get("/api/v1/account/balance", headers=_nip98(url, "GET"))
        assert resp.status_code == 200
        assert resp.json()["balance_sats"] == 0

    @pytest.mark.asyncio
    async def test_balance_no_auth(self, client):
        resp = await client.get("/api/v1/account/balance")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_balance_bad_auth(self, client):
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": "Nostr invalid"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Spending credits on posts (no-payment mode)
# ---------------------------------------------------------------------------

class TestCreditSpending:
    @pytest.mark.asyncio
    async def test_post_with_credits(self, client):
        """Create account via NIP-98, manually set balance, check balance."""
        url = "http://test/api/v1/account/balance"
        resp = await client.get("/api/v1/account/balance", headers=_nip98(url, "GET"))
        assert resp.json()["balance_sats"] == 0

        # Manually add credits via pubkey
        from app.database import async_session
        from app.accounts import deposit_credits_by_pubkey, get_account_by_nostr_pubkey
        pubkey = resp.json()["nostr_pubkey"]
        async with async_session() as db:
            await deposit_credits_by_pubkey(db, pubkey, 100)

        resp = await client.get("/api/v1/account/balance", headers=_nip98(url, "GET"))
        assert resp.json()["balance_sats"] == 100

    @pytest.mark.asyncio
    async def test_insufficient_credits_falls_through(self, client):
        """With insufficient credits, falls through to regular payment flow."""
        url = "http://test/api/v1/post"
        resp = await client.post(
            "/api/v1/post",
            json={"content": "test"},
            headers=_nip98_json(url, "POST"),
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


async def _create_and_fund(client, privkey=TEST_SK, amount=500):
    """Create account via NIP-98 and fund it. Returns pubkey."""
    url = "http://test/api/v1/account/balance"
    resp = await client.get("/api/v1/account/balance", headers=_nip98(url, "GET", privkey))
    pubkey = resp.json()["nostr_pubkey"]
    from app.database import async_session
    from app.accounts import deposit_credits_by_pubkey
    async with async_session() as db:
        await deposit_credits_by_pubkey(db, pubkey, amount)
    return pubkey


class TestCreditSpendingPaymentMode:
    @pytest.mark.asyncio
    async def test_post_with_credits_skips_payment(self, tempo_client):
        """With sufficient credits, post succeeds without payment."""
        await _create_and_fund(tempo_client, TEST_SK, 500)

        url = "http://test/api/v1/post"
        resp = await tempo_client.post(
            "/api/v1/post",
            json={"content": "paid with credits!", "amount_sats": 21},
            headers=_nip98_json(url, "POST"),
        )
        assert resp.status_code == 200
        assert resp.json()["paid"] is True
        assert resp.json().get("credits_used") is True

        # Check balance deducted
        bal_url = "http://test/api/v1/account/balance"
        resp = await tempo_client.get("/api/v1/account/balance", headers=_nip98(bal_url, "GET"))
        assert resp.json()["balance_sats"] == 479  # 500 - 21

    @pytest.mark.asyncio
    async def test_post_insufficient_credits_returns_402(self, tempo_client):
        """With insufficient credits, returns 402 for payment."""
        # Trigger auto-account creation via NIP-98 (0 balance)
        url = "http://test/api/v1/post"
        resp = await tempo_client.post(
            "/api/v1/post",
            json={"content": "no credits"},
            headers=_nip98_json(url, "POST", TEST_SK2),
        )
        # Authenticated but insufficient credits: returns payment options
        assert resp.status_code == 200
        assert "token" in resp.json()
        assert "tempo" in resp.json().get("methods", [])

    @pytest.mark.asyncio
    async def test_vote_with_credits(self, tempo_client):
        """Vote using credits in payment mode."""
        await _create_and_fund(tempo_client, TEST_SK, 200)

        # Post a note first
        post_url = "http://test/api/v1/post"
        resp = await tempo_client.post(
            "/api/v1/post",
            json={"content": "vote target"},
            headers=_nip98_json(post_url, "POST"),
        )
        event_id = resp.json()["event"]["id"]

        # Vote with credits
        vote_url = f"http://test/api/v1/events/{event_id}/vote"
        resp = await tempo_client.post(
            f"/api/v1/events/{event_id}/vote",
            json={"direction": 1, "amount_sats": 50},
            headers=_nip98_json(vote_url, "POST"),
        )
        assert resp.status_code == 200
        assert resp.json()["voted"] is True
        assert resp.json().get("credits_used") is True

        # Balance: 200 - 21 (post) - 50 (vote) = 129
        bal_url = "http://test/api/v1/account/balance"
        resp = await tempo_client.get("/api/v1/account/balance", headers=_nip98(bal_url, "GET"))
        assert resp.json()["balance_sats"] == 129

    @pytest.mark.asyncio
    async def test_agent_event_with_credits(self, tempo_client):
        """Agent-signed event posted with credits."""
        await _create_and_fund(tempo_client, TEST_SK, 100)

        event = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 1, "tags": [],
            "content": "agent with credits",
        })

        url = "http://test/api/v1/events"
        resp = await tempo_client.post(
            "/api/v1/events",
            json={"event": event},
            headers=_nip98_json(url, "POST"),
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
        url = "http://test/api/v1/account/deposit"
        resp = await tempo_client.post(
            "/api/v1/account/deposit",
            json={"amount_sats": 1000},
            headers=_nip98_json(url, "POST"),
        )
        assert resp.status_code == 402
        data = resp.json()
        assert data["status"] == "payment_required"
        assert data["deposit_amount_sats"] == 1000
        assert "tempo" in data["methods"]

    @pytest.mark.asyncio
    async def test_deposit_no_auth(self, tempo_client):
        resp = await tempo_client.post("/api/v1/account/deposit", json={"amount_sats": 100})
        assert resp.status_code == 401
