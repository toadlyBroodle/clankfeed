"""Phase 7a: Stripe SPT (MPP method=stripe) — challenge/verify with mocked Stripe API."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import app.config as config
from app.mpp import _b64url_decode, _b64url_encode, _verify_challenge_id, _MPP_REALM


def _parse_challenge_header(header: str) -> dict:
    params = {}
    body = header.replace("Payment ", "", 1)
    for part in body.split(", "):
        key, val = part.split("=", 1)
        params[key] = val.strip('"')
    return params


def _stripe_auth_from_challenge(
    challenge_header: str,
    *,
    spt: str = "spt_test_abc123",
    payment_intent_id: str | None = None,
) -> str:
    """Build Authorization: Payment … echoing a real challenge + SPT payload."""
    params = _parse_challenge_header(challenge_header)
    credential = {
        "challenge": {
            "id": params["id"],
            "realm": params["realm"],
            "method": params["method"],
            "intent": params["intent"],
            "request": params["request"],
            "expires": params["expires"],
        },
        "payload": {"spt": spt},
    }
    if payment_intent_id:
        credential["payload"]["payment_intent_id"] = payment_intent_id
    return "Payment " + _b64url_encode(
        json.dumps(credential, separators=(",", ":")).encode()
    )


def _request(auth: str = "") -> Request:
    headers = []
    if auth:
        headers.append((b"authorization", auth.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/events",
        "raw_path": b"/api/v1/events",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 123),
        "server": ("test", 80),
    }
    return Request(scope)


class TestStripeEnabled:
    def test_disabled_without_secret(self, monkeypatch):
        from app.config import stripe_enabled

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_x")
        assert stripe_enabled() is False

    def test_disabled_without_profile(self, monkeypatch):
        from app.config import stripe_enabled

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "")
        assert stripe_enabled() is False

    def test_enabled_with_secret_and_profile(self, monkeypatch):
        from app.config import stripe_enabled

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_x")
        assert stripe_enabled() is True


class TestStripeChallenge:
    def test_build_challenge_format(self, monkeypatch):
        from app.stripe_pay import build_stripe_challenge

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        challenge = build_stripe_challenge("0.50", "test stripe")
        assert challenge.startswith("Payment ")
        assert 'method="stripe"' in challenge
        assert 'intent="charge"' in challenge
        assert f'realm="{_MPP_REALM}"' in challenge
        assert 'description="test stripe"' in challenge

        params = _parse_challenge_header(challenge)
        assert _verify_challenge_id(
            params["id"], params["realm"], params["method"],
            params["intent"], params["request"], params["expires"],
        )

    def test_request_contains_mpp_stripe_method_details(self, monkeypatch):
        """MPP stripe.charge request: amount in minor units + networkId + types."""
        from app.stripe_pay import build_stripe_challenge

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        challenge = build_stripe_challenge("0.50")
        params = _parse_challenge_header(challenge)
        request_json = json.loads(_b64url_decode(params["request"]))
        assert request_json["amount"] == "50"  # cents
        assert request_json["currency"] == "usd"
        assert request_json["decimals"] == 2
        md = request_json["methodDetails"]
        assert md["networkId"] == "profile_test_abc"
        assert "card" in md["paymentMethodTypes"]
        # Adversarial: must not leak PaymentIntent client_secret at challenge time
        assert "clientSecret" not in md
        assert "client_secret" not in md


class TestStripeExtract:
    def test_extract_spt(self):
        from app.stripe_pay import extract_stripe_spt

        assert extract_stripe_spt({"payload": {"spt": "spt_abc"}}) == "spt_abc"

    def test_extract_missing(self):
        from app.stripe_pay import extract_stripe_spt

        assert extract_stripe_spt({}) == ""

    def test_extract_payment_id_prefers_intent(self):
        from app.stripe_pay import extract_stripe_payment_id

        cred = {"payload": {"spt": "spt_abc", "payment_intent_id": "pi_abc"}}
        assert extract_stripe_payment_id(cred) == "pi_abc"


class TestStripeVerify:
    @pytest.mark.asyncio
    async def test_verify_succeeds_on_confirmed_intent(self, monkeypatch):
        from app.stripe_pay import build_stripe_challenge, verify_stripe_credential

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        header = build_stripe_challenge("0.50")
        auth = _stripe_auth_from_challenge(header)
        from app.mpp import parse_mpp_credential

        cred = parse_mpp_credential(auth)
        assert cred is not None

        mock_pi = MagicMock()
        mock_pi.id = "pi_test_succeeded"
        mock_pi.status = "succeeded"
        mock_pi.amount = 50
        mock_pi.currency = "usd"

        with patch("app.stripe_pay._create_payment_intent_from_spt", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_pi
            assert await verify_stripe_credential(cred) is True
            mock_create.assert_awaited_once()
            kwargs = mock_create.await_args.kwargs
            assert kwargs["spt"] == "spt_test_abc123"
            assert kwargs["amount_cents"] == 50

    @pytest.mark.asyncio
    async def test_verify_rejects_missing_spt(self, monkeypatch):
        from app.stripe_pay import build_stripe_challenge, verify_stripe_credential
        from app.mpp import parse_mpp_credential

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        header = build_stripe_challenge("0.50")
        auth = _stripe_auth_from_challenge(header, spt="")
        # empty spt in payload
        params = _parse_challenge_header(header)
        cred = {
            "challenge": {
                "id": params["id"],
                "realm": params["realm"],
                "method": params["method"],
                "intent": params["intent"],
                "request": params["request"],
                "expires": params["expires"],
            },
            "payload": {},
        }
        assert await verify_stripe_credential(cred) is False

    @pytest.mark.asyncio
    async def test_verify_rejects_failed_intent(self, monkeypatch):
        from app.stripe_pay import build_stripe_challenge, verify_stripe_credential
        from app.mpp import parse_mpp_credential

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        header = build_stripe_challenge("0.50")
        cred = parse_mpp_credential(_stripe_auth_from_challenge(header))
        mock_pi = MagicMock(id="pi_fail", status="requires_payment_method", amount=50, currency="usd")
        with patch("app.stripe_pay._create_payment_intent_from_spt", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_pi
            assert await verify_stripe_credential(cred) is False

    @pytest.mark.asyncio
    async def test_verify_rejects_underpay_intent(self, monkeypatch):
        """Adversarial: PI amount below challenge → reject."""
        from app.stripe_pay import build_stripe_challenge, verify_stripe_credential
        from app.mpp import parse_mpp_credential

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        header = build_stripe_challenge("0.50")
        cred = parse_mpp_credential(_stripe_auth_from_challenge(header))
        mock_pi = MagicMock(id="pi_low", status="succeeded", amount=10, currency="usd")
        with patch("app.stripe_pay._create_payment_intent_from_spt", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_pi
            assert await verify_stripe_credential(cred) is False


class TestStripeRequirePayment:
    @pytest.mark.asyncio
    async def test_stripe_settle_through_router(self, monkeypatch):
        from app.payment import require_payment
        from app.stripe_pay import build_stripe_challenge

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        header = build_stripe_challenge("0.50")
        auth = _stripe_auth_from_challenge(header)
        mock_pi = MagicMock(id="pi_router_ok", status="succeeded", amount=50, currency="usd")

        with patch("app.payment.payments_enabled", return_value=False), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.stripe_enabled", return_value=True), \
             patch("app.stripe_pay._create_payment_intent_from_spt", new_callable=AsyncMock) as mock_create, \
             patch("app.payment.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_create.return_value = mock_pi
            mock_consume.return_value = True
            db = object()
            result = await require_payment(
                _request(auth), amount_sats=21, memo="stripe settle",
                db=db, amount_usd="0.50",
            )
            assert result is not None
            assert result.get("_protocol") == "stripe"
            assert result.get("payment_hash") == "pi_router_ok"
            mock_consume.assert_awaited_once_with("pi_router_ok", db)

    @pytest.mark.asyncio
    async def test_no_auth_includes_stripe_challenge(self, monkeypatch):
        from app.payment import require_payment

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        with patch("app.payment.payments_enabled", return_value=False), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.stripe_enabled", return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                await require_payment(
                    _request(), amount_sats=21, memo="need stripe", amount_usd="0.50",
                )
            assert exc_info.value.status_code == 402
            www = list(getattr(exc_info.value, "www_authenticate", []) or [])
            assert any('method="stripe"' in h for h in www), www

    @pytest.mark.asyncio
    async def test_stripe_disabled_rejects_stripe_method(self, monkeypatch):
        """Adversarial: stripe credential when stripe_enabled=False → 402."""
        from app.payment import require_payment
        from app.stripe_pay import build_stripe_challenge

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")

        header = build_stripe_challenge("0.50")
        auth = _stripe_auth_from_challenge(header)

        with patch("app.payment.payments_enabled", return_value=True), \
             patch("app.payment.tempo_enabled", return_value=False), \
             patch("app.payment.stripe_enabled", return_value=False), \
             patch("app.payment.create_invoice", new_callable=AsyncMock) as mock_inv, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_l402_inv, \
             patch("app.l402.settings") as mock_settings:
            mock_inv.return_value = {
                "payment_hash": "a" * 64,
                "payment_request": "lnbc1test",
            }
            mock_l402_inv.return_value = mock_inv.return_value
            mock_settings.AUTH_ROOT_KEY = "stripe-hmac-root"
            mock_settings.POST_PRICE_SATS = 21

            with pytest.raises(HTTPException) as exc_info:
                await require_payment(
                    _request(auth), amount_sats=21, memo="stripe off", db=object(),
                )
            assert exc_info.value.status_code == 402
            detail = exc_info.value.detail
            assert "stripe" in str(detail).lower() or "not configured" in str(detail).lower()


class TestStripePaymentOptions:
    def test_build_payment_options_includes_stripe(self, monkeypatch):
        from app.api_v1 import _build_payment_options

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "STRIPE_PUBLISHABLE_KEY", "pk_test_x")

        with patch("app.api_v1.tempo_enabled", return_value=False), \
             patch("app.api_v1.payments_enabled", return_value=False), \
             patch("app.api_v1.stripe_enabled", return_value=True):
            opts = _build_payment_options(amount_usd="0.50")
            assert "stripe" in opts["methods"]
            assert opts["stripe"]["network_id"] == "profile_test_abc"
            assert opts["stripe"]["amount_usd"] == "0.50"
            assert opts["stripe"]["publishable_key"] == "pk_test_x"
