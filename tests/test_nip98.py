"""Tests for NIP-98 HTTP Auth (kind:27235 signed events).

Phase 14.5: probe via GET /api/v1/auth/me (no account auto-create).
"""

import base64
import json
import time

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from app.database import engine, Base, async_session
from app.limiter import limiter
from app.models import Account
from app.nostr import sign_event
from app.zaps import pubkey_from_privkey


TEST_SK = "b" * 64  # test private key
ME_PATH = "/api/v1/auth/me"
ME_URL = f"http://test{ME_PATH}"


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
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as c:
        yield c
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


class TestNip98Auth:
    """NIP-98 authentication on /auth/me (identity only)."""

    @pytest.mark.asyncio
    async def test_valid_nip98_returns_pubkey_without_account(self, client):
        auth = _make_nip98_header(ME_URL, "GET")
        resp = await client.get(ME_PATH, headers={"Authorization": auth})
        assert resp.status_code == 200
        data = resp.json()
        assert data["pubkey"] == pubkey_from_privkey(TEST_SK)
        assert data["auth_method"] == "nip98"
        async with async_session() as db:
            rows = (await db.execute(select(Account))).scalars().all()
        assert rows == []

    @pytest.mark.asyncio
    async def test_valid_nip98_stable_pubkey(self, client):
        auth1 = _make_nip98_header(ME_URL, "GET")
        resp1 = await client.get(ME_PATH, headers={"Authorization": auth1})
        auth2 = _make_nip98_header(ME_URL, "GET")
        resp2 = await client.get(ME_PATH, headers={"Authorization": auth2})
        assert resp1.json()["pubkey"] == resp2.json()["pubkey"]

    @pytest.mark.asyncio
    async def test_wrong_url(self, client):
        auth = _make_nip98_header("http://test/api/v1/wrong", "GET")
        resp = await client.get(ME_PATH, headers={"Authorization": auth})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_method(self, client):
        auth = _make_nip98_header(ME_URL, "POST")
        resp = await client.get(ME_PATH, headers={"Authorization": auth})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_timestamp(self, client):
        auth = _make_nip98_header(ME_URL, "GET", created_at=int(time.time()) - 120)
        resp = await client.get(ME_PATH, headers={"Authorization": auth})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_bad_signature(self, client):
        event = {
            "kind": 27235,
            "created_at": int(time.time()),
            "tags": [["u", ME_URL], ["method", "GET"]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        signed["sig"] = "a" * 128
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get(ME_PATH, headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_u_tag(self, client):
        event = {
            "kind": 27235,
            "created_at": int(time.time()),
            "tags": [["method", "GET"]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get(ME_PATH, headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_method_tag(self, client):
        event = {
            "kind": 27235,
            "created_at": int(time.time()),
            "tags": [["u", ME_URL]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get(ME_PATH, headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_kind(self, client):
        event = {
            "kind": 1,
            "created_at": int(time.time()),
            "tags": [["u", ME_URL], ["method", "GET"]],
            "content": "",
        }
        signed = sign_event(TEST_SK, event)
        token = base64.b64encode(json.dumps(signed).encode()).decode()
        resp = await client.get(ME_PATH, headers={"Authorization": f"Nostr {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_legacy_api_key_rejected(self, client):
        resp = await client.get(ME_PATH, headers={"X-Account-Key": "a" * 64})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_no_auth_returns_401(self, client):
        resp = await client.get(ME_PATH)
        assert resp.status_code == 401
