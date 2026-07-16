"""Phase 14.5: custodial accounts/credits/session login removed."""

import base64
import json
import time
from pathlib import Path

import pytest
from sqlalchemy import select

from app.database import async_session
from app.limiter import limiter
from app.models import Account
from app.nostr import sign_event
from app.zaps import pubkey_from_privkey


TEST_SK = "b" * 64
STATIC = Path(__file__).resolve().parents[1] / "app" / "static"

ACCOUNT_PATHS = [
    ("POST", "/api/v1/account/create"),
    ("GET", "/api/v1/account/balance"),
    ("POST", "/api/v1/account/deposit"),
    ("POST", "/api/v1/account/deposit/confirm"),
    ("POST", "/api/v1/account/key"),
    ("POST", "/api/v1/account/profile"),
]


@pytest.fixture(autouse=True)
def _reset():
    limiter.reset()
    yield
    limiter.reset()


def _nip98(url: str, method: str, privkey: str = TEST_SK) -> dict:
    event = {
        "kind": 27235,
        "created_at": int(time.time()),
        "tags": [["u", url], ["method", method.upper()]],
        "content": "",
    }
    signed = sign_event(privkey, event)
    token = base64.b64encode(json.dumps(signed).encode()).decode()
    return {"Authorization": f"Nostr {token}"}


class TestAccountEndpointsGone:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path", ACCOUNT_PATHS)
    async def test_account_endpoints_return_410(self, client, method, path):
        kwargs = {}
        if method == "POST":
            kwargs["json"] = {}
            kwargs["headers"] = {
                **_nip98(f"http://test{path}", "POST"),
                "Content-Type": "application/json",
            }
        else:
            kwargs["headers"] = _nip98(f"http://test{path}", "GET")
        resp = await client.request(method, path, **kwargs)
        assert resp.status_code == 410, f"{method} {path}: {resp.status_code} {resp.text}"
        detail = (resp.json().get("detail") or "").lower()
        assert "account" in detail or "credit" in detail or "removed" in detail

    @pytest.mark.asyncio
    async def test_session_login_returns_410(self, client):
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        resp = await client.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code == 410
        set_cookie = resp.headers.get("set-cookie") or ""
        assert "cf_session=" not in set_cookie


class TestNoAccountAutoCreate:
    @pytest.mark.asyncio
    async def test_nip98_auth_me_does_not_create_account(self, client):
        url = "http://test/api/v1/auth/me"
        resp = await client.get("/api/v1/auth/me", headers=_nip98(url, "GET"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["pubkey"] == pubkey_from_privkey(TEST_SK)
        assert data["auth_method"] == "nip98"

        async with async_session() as db:
            rows = (await db.execute(select(Account))).scalars().all()
        assert rows == [], f"NIP-98 must not auto-create Account rows; got {len(rows)}"

    @pytest.mark.asyncio
    async def test_nip98_on_post_does_not_create_account(self, client):
        """Identity via NIP-98 on paid path must not mint custodial Account."""
        url = "http://test/api/v1/post"
        resp = await client.post(
            "/api/v1/post",
            json={"content": "no custody"},
            headers={
                **_nip98(url, "POST"),
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code in (200, 402)
        async with async_session() as db:
            rows = (await db.execute(select(Account))).scalars().all()
        assert rows == []


class TestProfileUiNoCustody:
    def test_profile_html_has_no_balance_or_deposit(self):
        html = (STATIC / "profile.html").read_text()
        assert "acct-balance" not in html
        assert "section-deposit" not in html
        assert "btn-deposit" not in html
        assert "Deposit Credits" not in html

    def test_profile_js_does_not_call_account_apis(self):
        js = (STATIC / "profile.js").read_text()
        assert "/api/v1/account/" not in js
        assert "startDeposit" not in js

    def test_index_header_not_login_for_accounts(self):
        html = (STATIC / "index.html").read_text()
        assert 'id="header-account-link"' in html
        assert ">Login<" not in html


class TestAuthMeNip98Only:
    @pytest.mark.asyncio
    async def test_auth_me_no_auth_401(self, client):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_me_rejects_session_cookie_alone(self, client):
        """Session cookie must not authenticate after 14.5."""
        from app.session_auth import mint_session_token

        token = mint_session_token(pubkey_from_privkey(TEST_SK))
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Cookie": f"cf_session={token}"},
        )
        assert resp.status_code == 401
