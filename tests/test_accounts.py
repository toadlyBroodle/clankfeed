"""Phase 14.5: custodial account/credit APIs are gone (410)."""

import pytest

from app.limiter import limiter


ACCOUNT_ENDPOINTS = [
    ("POST", "/api/v1/account/create", {}),
    ("GET", "/api/v1/account/balance", None),
    ("POST", "/api/v1/account/deposit", {"amount_sats": 1000}),
    ("POST", "/api/v1/account/deposit/confirm", {"token": "x"}),
    ("POST", "/api/v1/account/key", {}),
    ("POST", "/api/v1/account/profile", {"name": "x"}),
]


@pytest.fixture(autouse=True)
def _reset():
    limiter.reset()
    yield
    limiter.reset()


class TestAccountsRemoved:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path,body", ACCOUNT_ENDPOINTS)
    async def test_account_api_gone(self, client, method, path, body):
        kwargs = {}
        if body is not None:
            kwargs["json"] = body
        resp = await client.request(method, path, **kwargs)
        assert resp.status_code == 410
        assert "removed" in resp.json()["detail"].lower() or "account" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_session_login_gone(self, client):
        resp = await client.post("/api/v1/auth/login")
        assert resp.status_code == 410
