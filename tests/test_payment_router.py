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
