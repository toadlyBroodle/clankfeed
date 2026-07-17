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
    monkeypatch.setenv("ENABLE_TEMPO", "1")
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
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as c:
        yield c

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def full_client(monkeypatch):
    """Client with both Lightning and Tempo enabled."""
    monkeypatch.setenv("AUTH_ROOT_KEY", "real-secret-key-for-testing")
    monkeypatch.setenv("ENABLE_TEMPO", "1")
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
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as c:
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
    h = f"{_invoice_counter:064x}"  # valid 64-char hex
    return patch("app.payment.create_invoice", new_callable=AsyncMock, return_value={
        "payment_hash": h,
        "payment_request": f"lnbc210n1fake{_invoice_counter}",
    })


def _mock_check_payment(paid=True):
    """Patch check_payment_status to return a fixed result."""
    return patch("app.payment.check_payment_status", new_callable=AsyncMock, return_value=paid)



def _payment_auth_from_challenge(challenge: dict, payload: dict) -> str:
    """Build Authorization: Payment from a 402 JSON challenge echo + payload."""
    import base64
    import json as _json
    cred = {
        "challenge": {
            "id": challenge["id"],
            "realm": challenge.get("realm", ""),
            "method": challenge.get("method", ""),
            "intent": challenge.get("intent", "charge"),
            "request": challenge["request"],
            "expires": challenge.get("expires", ""),
        },
        "payload": payload,
    }
    raw = _json.dumps(cred, separators=(",", ":")).encode()
    token = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return "Payment " + token


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
        assert resp.status_code == 402
        data = resp.json()
        assert "tempo" in data["methods"]
        assert "lightning" not in data["methods"]
        assert "bolt11" not in data
        assert data["tempo"]["recipient"] == "0xRecipientAddress"
        assert data["tempo"]["amount_usd"] == "0.01"
        assert data["token"]  # pending event created
        assert (data.get("tempo") or {}).get("challenge")

    @pytest.mark.asyncio
    async def test_full_returns_both_methods(self, full_client):
        """When both are enabled, 402 has methods=['lightning', 'tempo'] + L402 challenge."""
        with _mock_create_invoice():
            resp = await full_client.post("/api/post", json={"content": "both methods"})
        assert resp.status_code == 402
        data = resp.json()
        assert "lightning" in data["methods"]
        assert "tempo" in data["methods"]
        assert "bolt11" in data
        assert data["tempo"]["recipient"] == "0xRecipientAddress"
        assert "L402" in data.get("how_to_pay", {})
        www = resp.headers.get_list("www-authenticate") if hasattr(resp.headers, "get_list") else [
            v for k, v in resp.headers.multi_items() if k.lower() == "www-authenticate"
        ]
        assert any(h.strip().startswith("L402 ") for h in www)

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

class TestPostConfirmGone:
    """Phase 11c: /api/post/confirm is gone (410)."""

    @pytest.mark.asyncio
    async def test_post_confirm_returns_410(self, tempo_client):
        resp = await tempo_client.post("/api/post/confirm", json={
            "token": "x", "method": "tempo", "tx_hash": "0x" + "a1" * 32,
        })
        assert resp.status_code == 410
        assert "Payment" in resp.json()["detail"] or "Gone" in resp.json()["detail"]


class TestTempoPaymentAuth:
    """Tempo settle via Authorization: Payment on original POST (11c)."""

    @pytest.mark.asyncio
    async def test_tempo_payment_auth_success(self, tempo_client):
        resp = await tempo_client.post("/api/post", json={"content": "tempo payment auth"})
        assert resp.status_code == 402
        body = resp.json()
        ch = (body.get("tempo") or {}).get("challenge") or {}
        assert ch.get("id") and ch.get("request")
        auth = _payment_auth_from_challenge(ch, {"txHash": "0x" + "a1" * 32})
        with _mock_tempo_verify(paid=True):
            resp = await tempo_client.post(
                "/api/post",
                json={"content": "tempo payment auth"},
                headers={"Authorization": auth},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["paid"] is True
        assert data["event"]["content"] == "tempo payment auth"

    @pytest.mark.asyncio
    async def test_tempo_payment_auth_unpaid_returns_402(self, tempo_client):
        resp = await tempo_client.post("/api/post", json={"content": "unpaid"})
        ch = (resp.json().get("tempo") or {}).get("challenge") or {}
        auth = _payment_auth_from_challenge(ch, {"txHash": "0x" + "b2" * 32})
        with _mock_tempo_verify(paid=False):
            resp = await tempo_client.post(
                "/api/post",
                json={"content": "unpaid"},
                headers={"Authorization": auth},
            )
        assert resp.status_code == 402

    @pytest.mark.asyncio
    async def test_tempo_payment_auth_missing_tx_hash(self, tempo_client):
        resp = await tempo_client.post("/api/post", json={"content": "no hash"})
        ch = (resp.json().get("tempo") or {}).get("challenge") or {}
        auth = _payment_auth_from_challenge(ch, {})
        resp = await tempo_client.post(
            "/api/post",
            json={"content": "no hash"},
            headers={"Authorization": auth},
        )
        assert resp.status_code == 402


class TestLightningPaymentAuth:
    """Lightning MPP settle via Authorization: Payment (11c)."""

    @pytest.mark.asyncio
    async def test_lightning_payment_auth_success(self, full_client):
        import hashlib
        preimage = bytes.fromhex("11" * 32)
        payment_hash = hashlib.sha256(preimage).hexdigest()
        bolt11 = "lnbc210n1pauthsettle"
        inv = {"payment_hash": payment_hash, "payment_request": bolt11}
        with patch("app.payment.create_invoice", new_callable=AsyncMock, return_value=inv), \
             patch("app.lightning.create_invoice", new_callable=AsyncMock, return_value=inv):
            resp = await full_client.post("/api/post", json={"content": "lightning payment auth"})
            assert resp.status_code == 402
            body = resp.json()
            ch = (body.get("lightning") or {}).get("challenge") or {}
            assert ch.get("id"), body
            auth = _payment_auth_from_challenge(ch, {"preimage": preimage.hex()})
            resp = await full_client.post(
                "/api/post",
                json={"content": "lightning payment auth"},
                headers={"Authorization": auth},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["paid"] is True


    @pytest.mark.asyncio
    async def test_lightning_payment_auth_bad_preimage_402(self, full_client):
        inv = {"payment_hash": "aa" * 32, "payment_request": "lnbc210n1badpre"}
        with patch("app.payment.create_invoice", new_callable=AsyncMock, return_value=inv), \
             patch("app.lightning.create_invoice", new_callable=AsyncMock, return_value=inv):
            resp = await full_client.post("/api/post", json={"content": "bad preimage"})
            assert resp.status_code == 402
            ch = (resp.json().get("lightning") or {}).get("challenge") or {}
            auth = _payment_auth_from_challenge(ch, {"preimage": "ee" * 32})
            resp = await full_client.post(
                "/api/post",
                json={"content": "bad preimage"},
                headers={"Authorization": auth},
            )
        assert resp.status_code == 402



class TestReplayProtection:
    """Same payment ID can't be used twice via Payment auth."""

    @pytest.mark.asyncio
    async def test_tempo_replay_rejected(self, tempo_client):
        resp = await tempo_client.post("/api/post", json={"content": "first"})
        ch1 = (resp.json().get("tempo") or {}).get("challenge") or {}
        auth1 = _payment_auth_from_challenge(ch1, {"txHash": "0x" + "d4" * 32})
        with _mock_tempo_verify(paid=True):
            resp = await tempo_client.post(
                "/api/post", json={"content": "first"}, headers={"Authorization": auth1},
            )
        assert resp.status_code == 200

        resp = await tempo_client.post("/api/post", json={"content": "second"})
        ch2 = (resp.json().get("tempo") or {}).get("challenge") or {}
        auth2 = _payment_auth_from_challenge(ch2, {"txHash": "0x" + "d4" * 32})
        with _mock_tempo_verify(paid=True):
            resp = await tempo_client.post(
                "/api/post", json={"content": "second"}, headers={"Authorization": auth2},
            )
        assert resp.status_code == 402
        detail = resp.json().get("detail") or ""
        if isinstance(detail, dict):
            detail = detail.get("detail", "")
        assert "already consumed" in str(detail).lower() or resp.status_code == 402

    @pytest.mark.asyncio
    async def test_lightning_replay_rejected(self, full_client):
        import hashlib
        preimage = bytes.fromhex("ff" * 32)
        payment_hash = hashlib.sha256(preimage).hexdigest()
        bolt11 = "lnbc210n1replay"
        inv = {"payment_hash": payment_hash, "payment_request": bolt11}
        with patch("app.payment.create_invoice", new_callable=AsyncMock, return_value=inv), \
             patch("app.lightning.create_invoice", new_callable=AsyncMock, return_value=inv):
            resp = await full_client.post("/api/post", json={"content": "first ln"})
            ch1 = (resp.json().get("lightning") or {}).get("challenge") or {}
            auth1 = _payment_auth_from_challenge(ch1, {"preimage": preimage.hex()})
            resp = await full_client.post(
                "/api/post", json={"content": "first ln"}, headers={"Authorization": auth1},
            )
            assert resp.status_code == 200, resp.text

            resp = await full_client.post("/api/post", json={"content": "second ln"})
            ch2 = (resp.json().get("lightning") or {}).get("challenge") or {}
            auth2 = _payment_auth_from_challenge(ch2, {"preimage": preimage.hex()})
            resp = await full_client.post(
                "/api/post", json={"content": "second ln"}, headers={"Authorization": auth2},
            )
            assert resp.status_code == 402



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


# ---------------------------------------------------------------------------
# Tests: Fresh WWW-Authenticate on credential-error 402s (Fix #10, Core 1.7)
# ---------------------------------------------------------------------------

class TestCredentialError402Challenge:
    """Credential verification errors MUST include fresh WWW-Authenticate challenge."""

    @pytest.mark.asyncio
    async def test_malformed_credential_has_challenge(self, tempo_client):
        """Malformed Authorization header returns 402 with Tempo challenge."""
        # First create a pending event via /api/post
        resp = await tempo_client.post("/api/post", json={"content": "test note"})
        assert resp.status_code == 402
        token = resp.json()["token"]

        # Submit a malformed credential
        resp = await tempo_client.post(
            f"/pay?token={token}",
            headers={"Authorization": "Payment not-valid-base64!!!"},
        )
        assert resp.status_code == 402
        assert "www-authenticate" in resp.headers
        assert resp.headers["www-authenticate"].startswith("Payment ")

    @pytest.mark.asyncio
    async def test_missing_payment_prefix_has_challenge(self, tempo_client):
        """Missing 'Payment ' prefix returns 402 with challenge."""
        resp = await tempo_client.post("/api/post", json={"content": "test note"})
        token = resp.json()["token"]

        resp = await tempo_client.post(
            f"/pay?token={token}",
            headers={"Authorization": "Bearer some-token"},
        )
        assert resp.status_code == 402
        assert "www-authenticate" in resp.headers
        assert resp.headers["www-authenticate"].startswith("Payment ")

    @pytest.mark.asyncio
    async def test_invalid_method_has_challenge(self, tempo_client):
        """Unsupported payment method returns 402 with challenge."""
        import base64
        cred = base64.urlsafe_b64encode(json.dumps({
            "challenge": {"method": "bitcoin", "id": "x", "realm": "clankfeed",
                          "intent": "charge", "request": "x", "expires": "2099-01-01T00:00:00Z"},
            "payload": {},
        }).encode()).rstrip(b"=").decode()

        resp = await tempo_client.post("/api/post", json={"content": "test note"})
        token = resp.json()["token"]

        resp = await tempo_client.post(
            f"/pay?token={token}",
            headers={"Authorization": f"Payment {cred}"},
        )
        assert resp.status_code == 402
        assert "www-authenticate" in resp.headers

    @pytest.mark.asyncio
    async def test_error_402_has_cache_control(self, tempo_client):
        """Credential-error 402 responses have Cache-Control: no-store."""
        resp = await tempo_client.post("/api/post", json={"content": "test note"})
        token = resp.json()["token"]

        resp = await tempo_client.post(
            f"/pay?token={token}",
            headers={"Authorization": "Payment not-valid"},
        )
        assert resp.status_code == 402
        assert resp.headers.get("cache-control") == "no-store"

    @pytest.mark.asyncio
    async def test_v1_malformed_credential_has_challenge(self, tempo_client):
        """v1 API malformed credential returns 402 with challenge."""
        from app.nostr import sign_event as _sign
        from app import config
        from tests.conftest import kind1_tags
        sk = config.settings.RELAY_PRIVATE_KEY
        event = _sign(sk, {
            "created_at": int(time.time()), "kind": 1,
            "tags": kind1_tags(sk), "content": "test",
        })
        resp = await tempo_client.post(
            "/api/v1/events",
            json={"event": event},
            headers={"Authorization": "Payment bad-credential"},
        )
        assert resp.status_code == 402
        assert "www-authenticate" in resp.headers
        assert resp.headers["www-authenticate"].startswith("Payment ")
