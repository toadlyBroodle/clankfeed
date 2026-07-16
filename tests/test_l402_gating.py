"""Phase 14.3: Gate paid actions with L402; no credit-spend bypass."""

import hashlib
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine
from app.l402 import mint_macaroon
from app.limiter import limiter
from app.main import app
from app.nostr import sign_event
from tests.conftest import kind1_tags

ROOT_KEY = "l402-gating-root-key"
TEST_SK = "d" * 64


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def _clear_openapi_cache():
    app.openapi_schema = None
    yield
    app.openapi_schema = None


@pytest_asyncio.fixture
async def paid_client(monkeypatch):
    """Payments enabled (AUTH_ROOT_KEY not test-mode)."""
    monkeypatch.setenv("AUTH_ROOT_KEY", ROOT_KEY)
    from app import config

    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", ROOT_KEY)
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")
    monkeypatch.setattr(config.settings, "POST_PRICE_SATS", 21)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as c:
        yield c

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def _l402_header(preimage: bytes) -> tuple[str, str]:
    """Return (Authorization value, payment_hash)."""
    payment_hash = hashlib.sha256(preimage).hexdigest()
    mac = mint_macaroon(payment_hash)
    return f"L402 {mac}:{preimage.hex()}", payment_hash


def _lsat_header(preimage: bytes) -> str:
    payment_hash = hashlib.sha256(preimage).hexdigest()
    mac = mint_macaroon(payment_hash)
    return f"LSAT {mac}:{preimage.hex()}"


def _signed_kind1(content: str = "l402 gated note") -> dict:
    return sign_event(TEST_SK, {
        "created_at": 1_700_000_000,
        "kind": 1,
        "tags": kind1_tags(TEST_SK),
        "content": content,
    })


MOCK_INVOICE = {
    "payment_hash": "ab" * 32,
    "payment_request": "lnbc210n1l402gate",
}


def _www_auth_values(resp) -> list[str]:
    if hasattr(resp.headers, "get_list"):
        return resp.headers.get_list("www-authenticate")
    return [v for k, v in resp.headers.multi_items() if k.lower() == "www-authenticate"]


# ---------------------------------------------------------------------------
# 402 challenges emit L402
# ---------------------------------------------------------------------------


class TestL402ChallengeOnPaidRoutes:
    @pytest.mark.asyncio
    async def test_post_probe_emits_l402_www_authenticate(self, paid_client):
        with patch(
            "app.api_v1.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ), patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ):
            resp = await paid_client.post("/api/v1/post", json={"content": "probe"})
        assert resp.status_code == 402
        body = resp.json()
        assert "how_to_pay" in body
        assert "L402" in body["how_to_pay"]
        www = _www_auth_values(resp)
        assert any(h.strip().startswith("L402 ") for h in www), f"expected L402 challenge; got {www}"
        assert any("macaroon=" in h and "invoice=" in h for h in www)

    @pytest.mark.asyncio
    async def test_events_probe_emits_l402(self, paid_client):
        with patch(
            "app.api_v1.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ), patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ):
            resp = await paid_client.post("/api/v1/events")
        assert resp.status_code == 402
        assert "L402" in resp.json().get("how_to_pay", {})
        www = _www_auth_values(resp)
        assert any(h.strip().startswith("L402 ") for h in www)

    @pytest.mark.asyncio
    async def test_legacy_api_post_accepts_l402_or_challenges(self, paid_client):
        """Legacy /api/post must participate in L402 (accept credential or emit challenge)."""
        with patch(
            "app.payment.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ), patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ):
            resp = await paid_client.post("/api/post", json={"content": "legacy"})
        # Either immediate L402 402, or body that includes L402 how_to_pay / challenge headers
        www = _www_auth_values(resp)
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        has_l402_header = any(h.strip().startswith("L402 ") for h in www)
        has_l402_body = isinstance(body, dict) and "L402" in body.get("how_to_pay", {})
        assert resp.status_code in (200, 402)
        assert has_l402_header or has_l402_body, (
            f"legacy /api/post must expose L402; status={resp.status_code} www={www} body_keys={list(body)}"
        )


# ---------------------------------------------------------------------------
# Valid L402 pays and stores
# ---------------------------------------------------------------------------


class TestL402PaysActions:
    @pytest.mark.asyncio
    async def test_post_with_valid_l402_stores_note(self, paid_client):
        auth, payment_hash = _l402_header(b"post-l402-preimage-ok!!")
        with patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.l402.check_and_consume_payment", new_callable=AsyncMock) as mock_consume, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume2:
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True
            mock_consume2.return_value = True
            resp = await paid_client.post(
                "/api/v1/post",
                json={"content": "paid via l402"},
                headers={"Authorization": auth},
            )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("paid") is True
        assert "event" in data
        assert data["event"]["content"] == "paid via l402"
        assert data.get("credits_used") is not True

    @pytest.mark.asyncio
    async def test_events_with_valid_l402_stores_event(self, paid_client):
        event = _signed_kind1("agent signed l402")
        auth, _ = _l402_header(b"events-l402-preimage!!!!")
        with patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True
            resp = await paid_client.post(
                "/api/v1/events",
                json={"event": event},
                headers={"Authorization": auth, "Content-Type": "application/json"},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json().get("paid") is True
        assert resp.json()["event"]["id"] == event["id"]

    @pytest.mark.asyncio
    async def test_lsat_prefix_accepted_on_post(self, paid_client):
        auth = _lsat_header(b"lsat-compat-preimage!!!!!")
        with patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True
            resp = await paid_client.post(
                "/api/v1/post",
                json={"content": "lsat ok"},
                headers={"Authorization": auth},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json().get("paid") is True

    @pytest.mark.asyncio
    async def test_downvote_with_valid_l402(self, paid_client):
        # Seed a note in test-mode path first via direct store is hard; post under L402 then downvote
        auth_post, _ = _l402_header(b"seed-note-for-downvote!!!")
        with patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True
            post = await paid_client.post(
                "/api/v1/post",
                json={"content": "vote target"},
                headers={"Authorization": auth_post},
            )
        assert post.status_code == 200, post.text
        event_id = post.json()["event"]["id"]

        auth_vote, _ = _l402_header(b"downvote-l402-preimage!!")
        with patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True
            resp = await paid_client.post(
                f"/api/v1/events/{event_id}/vote",
                json={"direction": -1, "amount_sats": 21},
                headers={"Authorization": auth_vote},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json().get("voted") is True
        assert resp.json().get("direction") == -1
        assert resp.json().get("credits_used") is not True


# ---------------------------------------------------------------------------
# No credit bypass
# ---------------------------------------------------------------------------


class TestNoCreditBypass:
    @pytest.mark.asyncio
    async def test_funded_account_cannot_skip_l402(self, paid_client, monkeypatch):
        """Even a pre-existing funded Account row must not short-circuit L402."""
        import base64
        import json
        import time
        from app.database import async_session
        from app.accounts import create_account, deposit_credits_by_pubkey
        from app.zaps import pubkey_from_privkey

        sk = "e" * 64
        pubkey = pubkey_from_privkey(sk)
        async with async_session() as db:
            await create_account(db, pubkey)
            await deposit_credits_by_pubkey(db, pubkey, 500)

        post_url = "http://test/api/v1/post"
        ev2 = {
            "kind": 27235,
            "created_at": int(time.time()),
            "tags": [["u", post_url], ["method", "POST"]],
            "content": "",
        }
        signed2 = sign_event(sk, ev2)
        token2 = base64.b64encode(json.dumps(signed2).encode()).decode()

        with patch(
            "app.api_v1.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ), patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ):
            resp = await paid_client.post(
                "/api/v1/post",
                json={"content": "should not use credits"},
                headers={
                    "Authorization": f"Nostr {token2}",
                    "Content-Type": "application/json",
                },
            )
        assert resp.status_code == 402, (
            f"credits must not bypass L402; got {resp.status_code}: {resp.text}"
        )
        assert resp.json().get("credits_used") is not True
        www = _www_auth_values(resp)
        assert any(h.strip().startswith("L402 ") for h in www), f"expected L402 on 402; got {www}"


# ---------------------------------------------------------------------------
# 14.12: POST /pay must accept L402|LSAT (GET /pay already advertises them)
# ---------------------------------------------------------------------------


class TestPayPostAcceptsL402:
    """WS payment-required agents follow GET /pay → L402; POST /pay must complete."""

    async def _pending_token(self, client) -> str:
        with patch(
            "app.payment.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ), patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ):
            resp = await client.post("/api/post", json={"content": "pending for l402 pay"})
        assert resp.status_code == 402, resp.text
        token = resp.json().get("token")
        assert token, f"expected pending token in 402 body; got {resp.text}"
        return token

    @pytest.mark.asyncio
    async def test_pay_post_with_valid_l402_stores_pending_event(self, paid_client):
        token = await self._pending_token(paid_client)
        auth, _ = _l402_header(b"pay-post-l402-preimage!!")
        with patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True
            resp = await paid_client.post(
                f"/pay?token={token}",
                headers={"Authorization": auth},
            )
        assert resp.status_code == 200, (
            f"POST /pay must accept L402 (not reject non-Payment prefix); "
            f"got {resp.status_code}: {resp.text}"
        )
        data = resp.json()
        assert "event" in data
        assert data["event"]["content"] == "pending for l402 pay"

    @pytest.mark.asyncio
    async def test_pay_post_accepts_lsat_prefix(self, paid_client):
        token = await self._pending_token(paid_client)
        auth = _lsat_header(b"pay-post-lsat-preimage!!!")
        with patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True
            resp = await paid_client.post(
                f"/pay?token={token}",
                headers={"Authorization": auth},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["event"]["content"] == "pending for l402 pay"

    @pytest.mark.asyncio
    async def test_pay_post_invalid_l402_gets_fresh_challenge(self, paid_client):
        token = await self._pending_token(paid_client)
        with patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ), patch(
            "app.payment.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ):
            resp = await paid_client.post(
                f"/pay?token={token}",
                headers={"Authorization": "L402 not-a-mac:deadbeef"},
            )
        assert resp.status_code == 402, resp.text
        www = _www_auth_values(resp)
        assert any(h.strip().startswith("L402 ") for h in www), (
            f"invalid L402 on POST /pay must mint fresh L402 challenge; got {www}"
        )
        # Must not be the old "Authorization header must start with Payment" dead-end
        assert "must start with 'Payment '" not in resp.text


# ---------------------------------------------------------------------------
# Adversarial / OpenAPI
# ---------------------------------------------------------------------------


class TestL402GatingAdversarial:
    @pytest.mark.asyncio
    async def test_invalid_l402_gets_fresh_challenge(self, paid_client):
        with patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value=MOCK_INVOICE,
        ):
            resp = await paid_client.post(
                "/api/v1/post",
                json={"content": "bad token"},
                headers={"Authorization": "L402 not-a-mac:deadbeef"},
            )
        assert resp.status_code == 402
        www = _www_auth_values(resp)
        assert any(h.strip().startswith("L402 ") for h in www)

    @pytest.mark.asyncio
    async def test_openapi_paid_routes_require_l402(self, paid_client):
        resp = await paid_client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        events_post = schema["paths"]["/api/v1/events"]["post"]
        security = events_post.get("security", [])
        assert any("L402" in entry for entry in security), (
            f"POST /api/v1/events must declare L402 security after 14.3; got {security}"
        )
        protocols = events_post.get("x-payment-info", {}).get("protocols", [])
        assert "l402" in protocols
        assert "mpp" in protocols
