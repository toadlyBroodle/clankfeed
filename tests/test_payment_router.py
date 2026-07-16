"""Phase 14.4: Unified payment router (satring require_payment pattern).

L402|LSAT primary; MPP co-accepted on the same 402; L402 documented as primary.
"""

import hashlib
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.l402 import mint_macaroon
from app.mpp import (
    _MPP_INTENT,
    _MPP_METHOD,
    _MPP_REALM,
    _b64url_encode,
    _compute_challenge_id,
)


MOCK_INVOICE = {
    "payment_hash": "ab" * 32,
    "payment_request": "lnbc210n1router",
}

# MPP verify requires 32-byte preimage (64 hex chars)
MPP_PREIMAGE = b"router-mpp-preimage-32-bytes!!!!"  # 32 bytes
assert len(MPP_PREIMAGE) == 32


def _request(auth: str | None = None) -> Request:
    headers = []
    if auth is not None:
        headers.append((b"authorization", auth.encode()))
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/events",
        "headers": headers,
    })


def _l402_auth(preimage: bytes, prefix: str = "L402") -> str:
    payment_hash = hashlib.sha256(preimage).hexdigest()
    mac = mint_macaroon(payment_hash)
    return f"{prefix} {mac}:{preimage.hex()}"


def _mpp_auth(preimage: bytes, amount_sats: int = 21) -> str:
    """Build Authorization: Payment <credential> for a valid Lightning MPP proof."""
    from app.mpp import _format_expires

    payment_hash = hashlib.sha256(preimage).hexdigest()
    expires = _format_expires(600)
    request_obj = {
        "amount": str(amount_sats),
        "currency": "sat",
        "recipient": _MPP_REALM,
        "methodDetails": {
            "invoice": "lnbc210n1mock",
            "paymentHash": payment_hash,
            "network": "mainnet",
        },
    }
    request_b64 = _b64url_encode(json.dumps(request_obj, separators=(",", ":")).encode())
    challenge_id = _compute_challenge_id(
        _MPP_REALM, _MPP_METHOD, _MPP_INTENT, request_b64, expires,
    )
    cred = {
        "challenge": {
            "id": challenge_id,
            "realm": _MPP_REALM,
            "method": _MPP_METHOD,
            "intent": _MPP_INTENT,
            "request": request_b64,
            "expires": expires,
        },
        "payload": {"preimage": preimage.hex()},
    }
    return "Payment " + _b64url_encode(json.dumps(cred, separators=(",", ":")).encode())


def _www_values(headers: dict) -> str:
    return headers.get("WWW-Authenticate", "") or headers.get("www-authenticate", "")


def _mock_402_invoice_stack(mock_settings):
    mock_settings.AUTH_ROOT_KEY = "router-challenge-root"
    mock_settings.POST_PRICE_SATS = 21
    mock_settings.BASE_URL = "wss://clankfeed.com"
    mock_settings.TEMPO_PRICE_USD = "0.02"


# ---------------------------------------------------------------------------
# require_payment exists and routes by Authorization scheme
# ---------------------------------------------------------------------------


class TestRequirePaymentRouting:
    @pytest.mark.asyncio
    async def test_require_payment_importable(self):
        from app.payment import require_payment

        assert callable(require_payment)

    @pytest.mark.asyncio
    async def test_payments_disabled_bypasses(self):
        from app.payment import require_payment

        with patch("app.payment.payments_enabled", return_value=False), \
             patch("app.payment.tempo_enabled", return_value=False):
            result = await require_payment(
                _request(), amount_sats=21, memo="test",
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_l402_header_routes_to_l402_success(self, monkeypatch):
        from app import config
        from app.payment import require_payment

        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "router-test-root")
        preimage = b"router-l402-preimage!!!!"
        auth = _l402_auth(preimage)

        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status:
            mock_status.return_value = (True, 21)
            result = await require_payment(
                _request(auth), amount_sats=21, memo="router l402",
            )
            assert result is not None
            assert result.get("_protocol") == "l402"

    @pytest.mark.asyncio
    async def test_lsat_prefix_accepted(self, monkeypatch):
        from app import config
        from app.payment import require_payment

        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "router-lsat-root")
        auth = _l402_auth(b"router-lsat-preimage!!!!!", prefix="LSAT")

        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status:
            mock_status.return_value = (True, 21)
            result = await require_payment(
                _request(auth), amount_sats=21, memo="router lsat",
            )
            assert result is not None
            assert result.get("_protocol") == "l402"

    @pytest.mark.asyncio
    async def test_mpp_payment_header_routes_to_mpp(self):
        from app.payment import require_payment

        auth = _mpp_auth(MPP_PREIMAGE)
        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_consume.return_value = True
            result = await require_payment(
                _request(auth), amount_sats=21, memo="router mpp", db=object(),
            )
            assert result is not None
            assert result.get("_protocol") == "mpp"
            assert result.get("payment_hash") == hashlib.sha256(MPP_PREIMAGE).hexdigest()

    @pytest.mark.asyncio
    async def test_mpp_underpay_raises_402(self):
        """Adversarial: credential amount below required sats → 402, not settle."""
        from app.payment import require_payment

        auth = _mpp_auth(MPP_PREIMAGE, amount_sats=10)
        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.create_invoice", new_callable=AsyncMock) as mock_inv, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_l402_inv, \
             patch("app.l402.settings") as mock_settings:
            _mock_402_invoice_stack(mock_settings)
            mock_inv.return_value = MOCK_INVOICE
            mock_l402_inv.return_value = MOCK_INVOICE

            with pytest.raises(HTTPException) as exc_info:
                await require_payment(
                    _request(auth), amount_sats=21, memo="underpay", db=object(),
                )
            assert exc_info.value.status_code == 402
            detail = exc_info.value.detail
            assert isinstance(detail, dict)
            assert "21" in str(detail.get("detail", detail))

    @pytest.mark.asyncio
    async def test_no_auth_raises_402_with_l402_and_mpp(self):
        from app.payment import require_payment

        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.create_invoice", new_callable=AsyncMock) as mock_inv, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_l402_inv, \
             patch("app.l402.settings") as mock_settings:
            _mock_402_invoice_stack(mock_settings)
            mock_inv.return_value = MOCK_INVOICE
            mock_l402_inv.return_value = MOCK_INVOICE

            with pytest.raises(HTTPException) as exc_info:
                await require_payment(
                    _request(), amount_sats=21, memo="router challenge",
                )

            assert exc_info.value.status_code == 402
            www = _www_values(exc_info.value.headers or {})
            assert "L402" in www and "macaroon=" in www and "invoice=" in www
            assert "Payment " in www  # MPP co-challenge
            detail = exc_info.value.detail
            assert isinstance(detail, dict)
            how = detail.get("how_to_pay") or {}
            assert "L402" in how, "L402 must be primary how_to_pay key"
            assert "MPP" in how
            keys = list(how.keys())
            assert keys.index("L402") < keys.index("MPP")
            assert how.get("primary") == "L402" or keys[0] == "L402"

    @pytest.mark.asyncio
    async def test_malformed_mpp_raises_402_not_500(self):
        from app.payment import require_payment

        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.create_invoice", new_callable=AsyncMock) as mock_inv, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_l402_inv, \
             patch("app.l402.settings") as mock_settings:
            _mock_402_invoice_stack(mock_settings)
            mock_inv.return_value = MOCK_INVOICE
            mock_l402_inv.return_value = MOCK_INVOICE

            with pytest.raises(HTTPException) as exc_info:
                await require_payment(
                    _request("Payment not-valid!!!"),
                    amount_sats=21,
                    memo="bad mpp",
                )
            assert exc_info.value.status_code == 402
            www = _www_values(exc_info.value.headers or {})
            assert "L402" in www


# ---------------------------------------------------------------------------
# Shared flat 402 helper (agent discovery body shape)
# ---------------------------------------------------------------------------


class TestPaymentRequiredResponse:
    @pytest.mark.asyncio
    async def test_payment_required_response_emits_l402_primary_and_mpp(self):
        from app.payment import payment_required_challenge

        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.create_invoice", new_callable=AsyncMock) as mock_inv, \
             patch("app.l402.settings") as mock_settings:
            _mock_402_invoice_stack(mock_settings)
            mock_inv.return_value = MOCK_INVOICE

            resp = await payment_required_challenge(
                {
                    "type": "https://paymentauth.org/problems/payment-required",
                    "title": "Payment required",
                    "detail": "Submit with Authorization: L402 or Payment header",
                },
                amount_sats=21,
                description="router probe",
            )
            assert resp.status_code == 402
            body = json.loads(resp.body)
            assert "how_to_pay" in body
            assert "L402" in body["how_to_pay"]
            assert "MPP" in body["how_to_pay"]
            keys = list(body["how_to_pay"].keys())
            assert keys.index("L402") < keys.index("MPP")
            assert body["how_to_pay"].get("primary") == "L402"
            www = []
            raw = resp.headers.get("www-authenticate")
            if raw:
                www.append(raw)
            getlist = getattr(resp.headers, "getlist", None)
            if callable(getlist):
                www = getlist("www-authenticate") or www
            assert any(h.strip().startswith("L402 ") for h in www), f"www={www}"
            assert any("Payment " in h for h in www), f"www={www}"


class TestHowToPayPrimary:
    def test_build_how_to_pay_marks_l402_primary(self):
        from app.l402 import build_how_to_pay

        how = build_how_to_pay(include_l402=True)
        assert how.get("primary") == "L402"
        assert list(how.keys())[0] == "primary" or list(how.keys()).index("L402") < list(how.keys()).index("MPP")


# ---------------------------------------------------------------------------
# 14.13: endpoint-level wiring — require_payment on live paid handlers
# ---------------------------------------------------------------------------

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine
from app.limiter import limiter
from app.main import app
from app.nostr import sign_event
from tests.conftest import kind1_tags

ROUTER_ROOT = "router-endpoint-root-key"
ROUTER_SK = "e" * 64


@pytest.fixture(autouse=True)
def _reset_limiter_for_router_endpoints():
    limiter.reset()
    yield
    limiter.reset()


@pytest_asyncio.fixture
async def router_paid_client(monkeypatch):
    """Payments on — AUTH_ROOT_KEY not test-mode."""
    monkeypatch.setenv("AUTH_ROOT_KEY", ROUTER_ROOT)
    from app import config

    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", ROUTER_ROOT)
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


def _signed_event(content: str = "router endpoint note") -> dict:
    return sign_event(ROUTER_SK, {
        "created_at": 1_700_000_100,
        "kind": 1,
        "tags": kind1_tags(ROUTER_SK),
        "content": content,
    })


def _www_list(resp) -> list[str]:
    if hasattr(resp.headers, "get_list"):
        return resp.headers.get_list("www-authenticate")
    return [v for k, v in resp.headers.multi_items() if k.lower() == "www-authenticate"]


class TestRequirePaymentEndpointWiring:
    """Paid handlers must settle via require_payment (underpay alive on live traffic)."""

    @pytest.mark.asyncio
    async def test_events_mpp_settle_through_router(self, router_paid_client):
        """Valid MPP Authorization on POST /api/v1/events stores the event."""
        event = _signed_event("mpp settle via router")
        auth = _mpp_auth(MPP_PREIMAGE, amount_sats=21)
        with patch("app.payment.check_and_consume_payment", new_callable=AsyncMock) as mock_consume, \
             patch("app.api_v1.check_and_consume_payment", new_callable=AsyncMock) as mock_consume2, \
             patch("app.lightning.check_and_consume_payment", new_callable=AsyncMock) as mock_consume3:
            mock_consume.return_value = True
            mock_consume2.return_value = True
            mock_consume3.return_value = True
            resp = await router_paid_client.post(
                "/api/v1/events",
                json={"event": event},
                headers={"Authorization": auth, "Content-Type": "application/json"},
            )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("paid") is True
        assert data["event"]["content"] == "mpp settle via router"

    @pytest.mark.asyncio
    async def test_events_mpp_underpay_rejected_via_router(self, router_paid_client):
        """Adversarial: MPP credential amount < required sats → 402 (not settle).

        Before 14.13, submit_event used inline MPP without extract_amount_from_credential,
        so underpay settled. Wiring require_payment makes underpay a live gate.
        """
        event = _signed_event("underpay should fail")
        auth = _mpp_auth(MPP_PREIMAGE, amount_sats=10)  # below POST_PRICE_SATS=21
        with patch("app.payment.create_invoice", new_callable=AsyncMock) as mock_inv, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_l402_inv, \
             patch("app.api_v1.create_invoice", new_callable=AsyncMock) as mock_api_inv, \
             patch("app.l402.settings") as mock_settings:
            _mock_402_invoice_stack(mock_settings)
            mock_inv.return_value = MOCK_INVOICE
            mock_l402_inv.return_value = MOCK_INVOICE
            mock_api_inv.return_value = MOCK_INVOICE
            resp = await router_paid_client.post(
                "/api/v1/events",
                json={"event": event},
                headers={"Authorization": auth, "Content-Type": "application/json"},
            )
        assert resp.status_code == 402, (
            f"underpay must 402 via require_payment; got {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        detail = body.get("detail", body)
        detail_str = json.dumps(detail) if not isinstance(detail, str) else detail
        assert "21" in detail_str or "requires" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_pay_post_mpp_underpay_rejected_via_router(self, router_paid_client):
        """Adversarial: underpay MPP on POST /pay must 402 through require_payment."""
        # Seed pending via legacy /api/post (returns token; /api/v1/post probes without token)
        with patch("app.payment.create_invoice", new_callable=AsyncMock, return_value=MOCK_INVOICE), \
             patch("app.l402.create_invoice", new_callable=AsyncMock, return_value=MOCK_INVOICE):
            seed = await router_paid_client.post(
                "/api/post", json={"content": "pending for underpay pay"},
            )
        assert seed.status_code == 402, seed.text
        token = seed.json().get("token")
        assert token, f"expected pending token; got {seed.text}"
        auth = _mpp_auth(b"pay-underpay-preimage-32bytess!!", amount_sats=5)
        with patch("app.payment.create_invoice", new_callable=AsyncMock, return_value=MOCK_INVOICE), \
             patch("app.l402.create_invoice", new_callable=AsyncMock, return_value=MOCK_INVOICE), \
             patch("app.l402.settings") as mock_settings:
            _mock_402_invoice_stack(mock_settings)
            resp = await router_paid_client.post(
                f"/pay?token={token}",
                headers={"Authorization": auth},
            )
        assert resp.status_code == 402, (
            f"POST /pay underpay must 402; got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_submit_event_and_pay_post_call_require_payment(self, router_paid_client):
        """Handlers must invoke require_payment (not try_l402+inline MPP dual-path)."""
        event = _signed_event("spy require_payment")
        called: list[str] = []

        async def _spy_require_payment(request, amount_sats, memo, db=None, **kwargs):
            called.append(memo)
            auth = request.headers.get("Authorization", "")
            if not auth:
                return None  # challenge_on_missing=False → pending/token flow
            return {"_protocol": "l402"}

        # Patch the module attribute so local `from app.payment import require_payment` binds the spy
        with patch("app.payment.require_payment", side_effect=_spy_require_payment):
            resp_events = await router_paid_client.post(
                "/api/v1/events",
                json={"event": event},
                headers={
                    "Authorization": "L402 spy:00",
                    "Content-Type": "application/json",
                },
            )
            assert resp_events.status_code == 200, resp_events.text

            with patch("app.payment.create_invoice", new_callable=AsyncMock, return_value=MOCK_INVOICE), \
                 patch("app.l402.create_invoice", new_callable=AsyncMock, return_value=MOCK_INVOICE):
                seed = await router_paid_client.post(
                    "/api/post", json={"content": "seed for pay spy"},
                )
            assert seed.status_code == 402, seed.text
            token = seed.json()["token"]
            resp_pay = await router_paid_client.post(
                f"/pay?token={token}",
                headers={"Authorization": "L402 spy:00"},
            )
            assert resp_pay.status_code == 200, resp_pay.text

        assert any("note posting" in m for m in called), (
            f"require_payment must be called from paid handlers; called={called}"
        )
        assert len(called) >= 2, f"expected events + pay_post to call require_payment; called={called}"
