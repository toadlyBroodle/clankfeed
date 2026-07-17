"""Phase 11c: Full MPP web client Payment settle (Authorization: Payment).

Web client settles Lightning/Tempo via MPP Payment credentials on the original
POST — not legacy /api/post/confirm. L402 remains primary; MPP is the true
credential fallthrough. Tempo tab stays as manual tx-hash fallback.
"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine
from app.main import app

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


def _index_src() -> str:
    return (STATIC / "index.js").read_text()


def _auth_src() -> str:
    return (STATIC / "nostr-auth.js").read_text()


def _widget_src() -> str:
    return (STATIC / "payment-widget.js").read_text()


def _profile_src() -> str:
    return (STATIC / "profile.js").read_text()


@pytest_asyncio.fixture
async def paid_client(monkeypatch):
    """Lightning on, Tempo/Stripe off — for Payment WWW-Authenticate asserts."""
    from app import config

    monkeypatch.setenv("AUTH_ROOT_KEY", "phase11c-root-key")
    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "phase11c-root-key")
    monkeypatch.setattr(config.settings, "PAYMENT_URL", "https://lnbits.test")
    monkeypatch.setattr(config.settings, "PAYMENT_KEY", "test-payment-key")
    monkeypatch.delenv("ENABLE_TEMPO", raising=False)
    monkeypatch.delenv("ENABLE_STRIPE", raising=False)
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")
    monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "")
    monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "")

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


def _www_payment_parts(resp) -> list[str]:
    return [
        v for k, v in resp.headers.multi_items()
        if k.lower() == "www-authenticate" and v.lower().startswith("payment ")
    ]


class TestWwwAuthenticatePayment:
    @pytest.mark.asyncio
    async def test_v1_post_402_emits_payment_www_authenticate(self, paid_client):
        """11c.1: unpaid POST /api/v1/post must carry WWW-Authenticate: Payment."""
        with patch("app.api_v1.create_invoice", new_callable=AsyncMock) as inv, \
             patch("app.api_v1.payments_enabled", return_value=True), \
             patch("app.l402.payments_enabled", return_value=True), \
             patch("app.payment.payments_enabled", return_value=True):
            inv.return_value = {
                "payment_hash": "a" * 64,
                "payment_request": "lnbc21u1ptesttestinvoice",
            }
            resp = await paid_client.post(
                "/api/v1/post", json={"content": "11c payment header"},
            )
        assert resp.status_code == 402
        payment_parts = _www_payment_parts(resp)
        assert payment_parts, (
            f"expected WWW-Authenticate: Payment; got "
            f"{[v for k, v in resp.headers.multi_items() if k.lower() == 'www-authenticate']}"
        )
        assert 'method="lightning"' in payment_parts[0]
        assert "request=" in payment_parts[0]

    @pytest.mark.asyncio
    async def test_v1_post_402_json_echoes_lightning_challenge(self, paid_client):
        """Browser multi-WWW-Authenticate is flaky — JSON must echo MPP challenge."""
        with patch("app.api_v1.create_invoice", new_callable=AsyncMock) as inv, \
             patch("app.api_v1.payments_enabled", return_value=True), \
             patch("app.l402.payments_enabled", return_value=True), \
             patch("app.payment.payments_enabled", return_value=True):
            inv.return_value = {
                "payment_hash": "b" * 64,
                "payment_request": "lnbc21u1ptestechochallenge",
            }
            resp = await paid_client.post(
                "/api/v1/post", json={"content": "11c challenge echo"},
            )
        assert resp.status_code == 402
        body = resp.json()
        ch = (body.get("lightning") or {}).get("challenge") or {}
        assert ch.get("id"), "lightning.challenge.id required for web MPP settle"
        assert ch.get("request"), "lightning.challenge.request required"
        assert ch.get("method") == "lightning"
        assert ch.get("expires")


class TestMppClientHelpers:
    def test_parse_payment_challenge_helper(self):
        src = _auth_src()
        assert "function parsePaymentChallenge" in src or "function parseMppChallenge" in src

    def test_build_lightning_payment_auth(self):
        src = _auth_src()
        assert "function buildLightningPaymentAuth" in src
        assert "preimage" in src
        assert "Payment " in src

    def test_build_tempo_payment_auth(self):
        """Tempo fallthrough also uses Authorization: Payment (not confirm)."""
        src = _auth_src()
        assert "function buildTempoPaymentAuth" in src
        assert "txHash" in src or "tx_hash" in src


class TestPostFlowMppPayment:
    def test_post_fallthrough_uses_payment_auth_not_confirm(self):
        """11c.4: Lightning/Tempo settle retries original POST with Payment auth."""
        index = _index_src()
        assert "buildLightningPaymentAuth" in index
        assert "buildTempoPaymentAuth" in index
        assert "/api/post/confirm" not in index

    def test_profile_post_does_not_use_confirm(self):
        profile = _profile_src()
        assert "/api/post/confirm" not in profile


class TestTempoTabKept:
    """11c.6: Tempo tab remains as manual paste fallback."""

    def test_widget_has_tempo_tab(self):
        widget = _widget_src()
        assert "pw-tab-tempo" in widget or "tempo" in widget.lower()
        assert "tx" in widget.lower() or "tx_hash" in widget or "txHash" in widget


class TestPostConfirmRemoved:
    @pytest.mark.asyncio
    async def test_post_confirm_returns_410(self, paid_client):
        resp = await paid_client.post(
            "/api/post/confirm",
            json={"token": "x", "method": "lightning", "payment_hash": "a" * 64},
        )
        assert resp.status_code == 410
        detail = resp.json().get("detail", "")
        assert "Payment" in detail or "Authorization" in detail or "410" in str(resp.status_code)

    def test_adversarial_index_has_no_confirm_fetch(self):
        index = _index_src()
        assert "post/confirm" not in index

    @pytest.mark.asyncio
    async def test_openapi_post_confirm_advertises_410(self, paid_client):
        """11c.8: OpenAPI must not advertise 200 for a 410 Gone endpoint."""
        from app.main import app

        app.openapi_schema = None
        try:
            resp = await paid_client.get("/openapi.json")
            assert resp.status_code == 200
            paths = resp.json().get("paths") or {}
            op = (paths.get("/api/post/confirm") or {}).get("post") or {}
            responses = op.get("responses") or {}
            assert "410" in responses, (
                f"OpenAPI must declare 410 for /api/post/confirm; got {sorted(responses)}"
            )
            assert "200" not in responses, (
                f"OpenAPI must not advertise success 200 for Gone confirm; got {sorted(responses)}"
            )
            assert op.get("deprecated") is True
        finally:
            app.openapi_schema = None


class TestPayInvoicePreimageSettle:
    """11c.7: QR/poll must not call onPaid(null) — preimage required after confirm→410."""

    def test_pay_invoice_uses_status_preimage_not_null(self):
        src = _auth_src()
        assert "payments/status" in src
        assert "preimage" in src
        # Must not silently settle with null after poll reports paid
        assert "onPaid(null)" not in src

    def test_pay_invoice_null_preimage_shows_error_not_settle(self):
        """Adversarial: paid-without-preimage must surface an explicit no-settle message."""
        src = _auth_src()
        assert "preimage unavailable" in src.lower() or "Preimage unavailable" in src
