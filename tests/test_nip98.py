"""Tests for NIP-98 HTTP Auth (kind:27235 signed events)."""

import base64
import json
import time

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.limiter import limiter
from app.nostr import sign_event


TEST_SK = "b" * 64  # test private key


@pytest.fixture(autouse=True)
def _reset():
    limiter.reset()
    yield
    limiter.reset()


def _make_nip98_header(url: str, method: str, privkey: str = TEST_SK, created_at: int | None = None) -> str:
    """Build a valid NIP-98 Authorization header."""
    event = {
        "kind": 27235,
        "created_at": created_at or int(time.time()),
        "tags": [["u", url], ["method", method.upper()]],
        "content": "",
    }
    signed = sign_event(privkey, event)
    token = base64.b64encode(json.dumps(signed).encode()).decode()
    return f"Nostr {token}"


@pytest_asyncio.fixture
async def client():
    from app.main import app
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    transport = ASGITransport(app=app, root_path="")
    async with AsyncClient(transport=transport, base_url="http://localhost:8089") as c:
        yield c
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


class TestNip98Auth:
    """NIP-98 authentication on account/balance endpoint."""

    @pytest.mark.asyncio
    async def test_valid_nip98_creates_account(self, client):
        """Valid NIP-98 auth should auto-create an account."""
        url = "http://localhost:8089/api/v1/account/balance"
        auth = _make_nip98_header(url, "GET")
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": auth})
        assert resp.status_code == 200
        data = resp.json()
        assert data["balance_sats"] == 0
        assert "nostr_pubkey" in data

    @pytest.mark.asyncio
    async def test_valid_nip98_returns_same_account(self, client):
        """Repeated NIP-98 auth with same key returns the same account."""
        url = "http://localhost:8089/api/v1/account/balance"
        auth1 = _make_nip98_header(url, "GET")
        resp1 = await client.get("/api/v1/account/balance", headers={"Authorization": auth1})
        pk1 = resp1.json()["nostr_pubkey"]

        auth2 = _make_nip98_header(url, "GET")
        resp2 = await client.get("/api/v1/account/balance", headers={"Authorization": auth2})
        pk2 = resp2.json()["nostr_pubkey"]
        assert pk1 == pk2

    @pytest.mark.asyncio
    async def test_wrong_url(self, client):
        """NIP-98 with wrong URL in 'u' tag should fail."""
        auth = _make_nip98_header("http://localhost:8089/api/v1/wrong", "GET")
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": auth})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_method(self, client):
        """NIP-98 with wrong method tag should fail."""
        url = "http://localhost:8089/api/v1/account/balance"
        auth = _make_nip98_header(url, "POST")  # endpoint is GET
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": auth})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_timestamp(self, client):
        """NIP-98 with timestamp too far in the past should fail."""
        url = "http://localhost:8089/api/v1/account/balance"
        auth = _make_nip98_header(url, "GET", created_at=int(time.time()) - 120)
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": auth})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_bad_signature(self, client):
        """NIP-98 with tampered event should fail."""
        event = {
            "kind": 27235,
            "created_at": int(time.time()),
            "tags": [["u", "http://localhost:8089/api/v1/account/balance"], ["method", "GET"]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        signed["sig"] = "a" * 128  # tamper
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_u_tag(self, client):
        """NIP-98 without 'u' tag should fail."""
        event = {
            "kind": 27235,
            "created_at": int(time.time()),
            "tags": [["method", "GET"]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_method_tag(self, client):
        """NIP-98 without 'method' tag should fail."""
        event = {
            "kind": 27235,
            "created_at": int(time.time()),
            "tags": [["u", "http://localhost:8089/api/v1/account/balance"]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_kind(self, client):
        """NIP-98 with wrong kind should fail."""
        event = {
            "kind": 1,  # wrong kind
            "created_at": int(time.time()),
            "tags": [["u", "http://localhost:8089/api/v1/account/balance"], ["method", "GET"]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get("/api/v1/account/balance", headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_legacy_api_key_still_works(self, client):
        """Legacy X-Account-Key auth should still work during transition."""
        # Create account first
        resp = await client.post("/api/v1/account/create",
                                 json={}, headers={"Content-Type": "application/json"})
        assert resp.status_code == 200
        api_key = resp.json()["api_key"]

        # Use legacy auth
        resp = await client.get("/api/v1/account/balance",
                                headers={"X-Account-Key": api_key})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_no_auth_returns_401(self, client):
        """No auth at all should return 401."""
        resp = await client.get("/api/v1/account/balance")
        assert resp.status_code == 401
