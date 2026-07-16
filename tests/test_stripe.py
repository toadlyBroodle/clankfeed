"""Phase 7a: Stripe SPT (MPP method=stripe) — challenge/verify with mocked Stripe API."""

import json
from pathlib import Path
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


# ---------------------------------------------------------------------------
# 7a.8: NIP-11 + OpenAPI advertise stripe when stripe_enabled()
# ---------------------------------------------------------------------------


class TestStripeDiscovery:
    """Agents must see stripe in NIP-11 / OpenAPI when Stripe SPT is configured."""

    @pytest.mark.asyncio
    async def test_nip11_includes_stripe_when_enabled(self, client, monkeypatch):
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_discovery")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_discovery")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "PAYMENT_URL", "")  # no lightning in NIP-11

        resp = await client.get("/", headers={"Accept": "application/nostr+json"})
        assert resp.status_code == 200
        data = resp.json()
        assert "stripe" in data["payments"]["methods"], data["payments"]
        assert data["payments"]["stripe"]["network_id"] == "profile_discovery"
        assert data["payments"]["stripe"]["amount_usd"] == "0.50"

    @pytest.mark.asyncio
    async def test_nip11_omits_stripe_when_disabled(self, client, monkeypatch):
        """Adversarial: empty Stripe config must not advertise stripe."""
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "")

        resp = await client.get("/", headers={"Accept": "application/nostr+json"})
        data = resp.json()
        assert "stripe" not in data["payments"]["methods"]
        assert "stripe" not in data["payments"]

    @pytest.mark.asyncio
    async def test_openapi_non_l402_guidance_names_stripe_when_enabled(
        self, client, monkeypatch,
    ):
        """When Lightning is off, x-guidance / 402 text must name Stripe if configured."""
        from app.main import app

        app.openapi_schema = None
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_discovery")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_discovery")
        # test-mode → payments_enabled() False (non-l402 OpenAPI path)
        assert config.payments_enabled() is False

        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        guidance = schema["info"].get("x-guidance", "")
        assert "Stripe" in guidance or "stripe" in guidance.lower(), guidance[:300]

        events_402 = (
            schema["paths"]["/api/v1/events"]["post"]
            .get("responses", {})
            .get("402", {})
            .get("description", "")
        )
        assert "Stripe" in events_402 or "stripe" in events_402.lower(), events_402
        app.openapi_schema = None

    @pytest.mark.asyncio
    async def test_openapi_non_l402_omits_stripe_when_disabled(
        self, client, monkeypatch,
    ):
        """Adversarial: without Stripe keys, non-l402 guidance must not claim Stripe live."""
        from app.main import app

        app.openapi_schema = None
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "")
        monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")

        resp = await client.get("/openapi.json")
        guidance = resp.json()["info"].get("x-guidance", "")
        # Forward-looking mention in L402-live branch is N/A; non-l402 must not claim Stripe live.
        assert "currently Tempo when configured" in guidance or "Lightning/L402 is not active" in guidance
        # Must not imply Stripe is a live option when disabled
        assert "Stripe when configured" not in guidance
        assert "and Stripe" not in guidance
        app.openapi_schema = None

    @pytest.mark.asyncio
    async def test_openapi_l402_live_omits_stripe_and_tempo_when_disabled(
        self, client, monkeypatch,
    ):
        """7a.9 adversarial: L402-live x-guidance must not hardcode Stripe/Tempo when off.

        Prod runs with payments_enabled() True, so the L402-live branch ships; without
        guards it advertises Stripe while NIP-11 correctly omits it.
        """
        from app.main import app

        app.openapi_schema = None
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "real-secret-key-for-testing")
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "")
        monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")
        assert config.payments_enabled() is True
        assert config.stripe_enabled() is False
        assert config.tempo_enabled() is False

        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        guidance = resp.json()["info"].get("x-guidance", "")
        assert "L402 (primary)" in guidance, guidance[:300]
        assert "and Stripe" not in guidance, guidance[:400]
        assert "Stripe" not in guidance, guidance[:400]
        assert "Tempo" not in guidance, guidance[:400]
        app.openapi_schema = None

    @pytest.mark.asyncio
    async def test_openapi_l402_live_names_stripe_when_enabled(
        self, client, monkeypatch,
    ):
        """7a.9: when payments + Stripe are on, L402-live Accepts-line names Stripe."""
        from app.main import app

        app.openapi_schema = None
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "real-secret-key-for-testing")
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_discovery")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_discovery")
        monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")
        assert config.payments_enabled() is True
        assert config.stripe_enabled() is True

        resp = await client.get("/openapi.json")
        guidance = resp.json()["info"].get("x-guidance", "")
        assert "L402 (primary)" in guidance, guidance[:300]
        assert "Stripe" in guidance, guidance[:400]
        assert "Tempo" not in guidance, guidance[:400]
        app.openapi_schema = None


# ---------------------------------------------------------------------------
# 7a.5: Web client Stripe.js / SPT tab + create-spt proxy
# ---------------------------------------------------------------------------

STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


class TestStripeWebClientWidget:
    """7a.5: payment widget shows Stripe tab when 402 includes stripe."""

    def test_widget_has_stripe_tab_and_panel(self):
        src = (STATIC / "payment-widget.js").read_text()
        assert "pw-tab-stripe" in src
        assert "pw-stripe" in src
        assert "methods.includes('stripe')" in src or 'methods.includes("stripe")' in src

    def test_widget_loads_stripe_js_when_stripe_present(self):
        src = (STATIC / "payment-widget.js").read_text()
        assert "js.stripe.com" in src or "loadStripe" in src or "Stripe(" in src
        assert "publishable_key" in src

    def test_widget_pay_builds_or_confirms_spt(self):
        """Pay path must mint SPT via create-spt (or paste) then settle as stripe."""
        src = (STATIC / "payment-widget.js").read_text()
        assert "/payments/stripe-spt" in src or "stripe-spt" in src
        assert "spt" in src.lower()
        # Confirm callback with method stripe (Tempo pattern) or Authorization Payment
        assert "'stripe'" in src or '"stripe"' in src

    def test_index_handles_stripe_settle(self):
        index = (STATIC / "index.js").read_text()
        # Must wire stripe into post confirm / Authorization retry
        assert "stripe" in index.lower()
        assert (
            "method === 'stripe'" in index
            or 'method === "stripe"' in index
            or "Payment " in index
            or "buildStripe" in index
            or "stripe-spt" in index
        )

    def test_adversarial_stripe_tab_hidden_by_default(self):
        """Tab must start hidden; only shown when methods includes stripe."""
        src = (STATIC / "payment-widget.js").read_text()
        # Initial markup hides the stripe tab (same pattern as Tempo)
        assert 'id="pw-tab-stripe"' in src
        tab_line = [ln for ln in src.splitlines() if 'id="pw-tab-stripe"' in ln][0]
        assert "hidden" in tab_line


class TestStripeChallengeEchoInBody:
    """Browser fetch collapses multi WWW-Authenticate; JSON must echo stripe challenge."""

    def test_build_payment_options_includes_challenge_echo(self, monkeypatch):
        from app.api_v1 import _build_payment_options

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PUBLISHABLE_KEY", "pk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "stripe-hmac-root")
        monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")

        with patch("app.api_v1.tempo_enabled", return_value=False), \
             patch("app.api_v1.payments_enabled", return_value=False), \
             patch("app.api_v1.stripe_enabled", return_value=True):
            opts = _build_payment_options(amount_usd="0.50")
            assert "stripe" in opts["methods"]
            stripe = opts["stripe"]
            # Challenge echo for MPP credential (id/realm/method/intent/request/expires)
            ch = stripe.get("challenge") or {}
            assert ch.get("id"), stripe
            assert ch.get("method") == "stripe"
            assert ch.get("request"), stripe
            assert ch.get("expires"), stripe
            assert ch.get("realm"), stripe
            assert ch.get("intent") == "charge"


class TestCreateStripeSptEndpoint:
    """7a.5: POST /api/v1/payments/stripe-spt — server-derived SPT mint proxy."""

    @pytest.mark.asyncio
    async def test_create_spt_returns_spt(self, client, monkeypatch):
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "test-mode")

        fake = MagicMock()
        fake.id = "spt_test_minted_xyz"

        with patch("app.stripe_pay.create_spt_from_payment_method", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = "spt_test_minted_xyz"
            resp = await client.post(
                "/api/v1/payments/stripe-spt",
                json={"payment_method": "pm_card_visa"},
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["spt"] == "spt_test_minted_xyz"
        mock_create.assert_awaited_once()
        # Server derives amount — must NOT pass client amount as authority
        kwargs = mock_create.await_args.kwargs if mock_create.await_args.kwargs else {}
        args = mock_create.await_args.args if mock_create.await_args else ()
        # payment_method is first positional or kw
        assert "pm_card_visa" in args or kwargs.get("payment_method") == "pm_card_visa"

    @pytest.mark.asyncio
    async def test_create_spt_rejects_client_amount(self, client, monkeypatch):
        """Adversarial: client-supplied amount/max_amount must not override server price."""
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_USD", "0.50")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "test-mode")

        with patch("app.stripe_pay.create_spt_from_payment_method", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = "spt_ok"
            resp = await client.post(
                "/api/v1/payments/stripe-spt",
                json={
                    "payment_method": "pm_card_visa",
                    "amount": "1",  # try underpay / override
                    "max_amount": 1,
                    "currency": "usd",
                },
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
        assert resp.status_code == 200
        # create must be called with server cents (50), not client 1
        call_kwargs = mock_create.await_args.kwargs
        call_args = mock_create.await_args.args
        # Look for amount_cents=50 somewhere
        combined = str(call_args) + str(call_kwargs)
        assert "50" in combined or call_kwargs.get("amount_cents") == 50, combined

    @pytest.mark.asyncio
    async def test_create_spt_disabled_when_stripe_off(self, client, monkeypatch):
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "test-mode")
        resp = await client.post(
            "/api/v1/payments/stripe-spt",
            json={"payment_method": "pm_card_visa"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code in (402, 503, 501)
        detail = str(resp.json()).lower()
        assert "stripe" in detail or "not configured" in detail or "disabled" in detail

    @pytest.mark.asyncio
    async def test_create_spt_requires_payment_method(self, client, monkeypatch):
        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setattr(config.settings, "STRIPE_PROFILE_ID", "profile_test_abc")
        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "test-mode")
        resp = await client.post(
            "/api/v1/payments/stripe-spt",
            json={},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 400


class TestStripeCspHosts:
    """7a.5: CSP must allow Stripe.js + Elements frames/connect."""

    @pytest.mark.asyncio
    async def test_csp_allows_stripe_js(self, client):
        resp = await client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        assert "js.stripe.com" in csp
        # Elements mounts iframes
        assert "frame-src" in csp
        assert "js.stripe.com" in csp
        assert "hooks.stripe.com" in csp or "js.stripe.com" in [
            p.strip() for p in csp.split(";") if "frame-src" in p
        ][0]
        assert "api.stripe.com" in csp  # connect-src for Stripe.js XHR
