"""Phase 14.2/14.3: L402 discovery — well-known, OpenAPI scheme, live how_to_pay.

After 14.3, paid endpoints emit L402 WWW-Authenticate challenges, so OpenAPI
and 402 how_to_pay advertise L402 (alongside MPP). well-known remains the
canonical L402 docs surface.
"""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine
from app.limiter import limiter
from app.main import app


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def _clear_openapi_cache():
    """OpenAPI schema is cached on the app; clear so scheme assertions stay fresh."""
    app.openapi_schema = None
    yield
    app.openapi_schema = None


# ---------------------------------------------------------------------------
# GET /.well-known/l402
# ---------------------------------------------------------------------------


class TestWellKnownL402:
    @pytest.mark.asyncio
    async def test_well_known_l402_returns_discovery_document(self, client):
        resp = await client.get("/.well-known/l402")
        assert resp.status_code == 200
        data = resp.json()
        assert data["protocol"] == "L402"
        assert data["auth_scheme"] == "L402"
        assert "Authorization: L402" in data["auth_header_format"]
        assert "<macaroon>" in data["auth_header_format"]
        assert "<preimage>" in data["auth_header_format"]
        assert "endpoints" in data
        assert "post" in data["endpoints"] or "events" in data["endpoints"]
        assert "pricing_sats" in data
        assert data["pricing_sats"].get("post") or data["pricing_sats"].get("events")
        assert "example" in data
        assert "code" in data["example"]
        assert "docs" in data
        assert "/.well-known/l402" in data.get("docs", "") or data["docs"].endswith("/docs") or "clankfeed" in data["docs"].lower() or "http" in data["docs"]

    @pytest.mark.asyncio
    async def test_well_known_l402_example_code_has_valid_python_braces(self, client):
        """14.2a: non-f-string continuation lines must not leave literal {{ braces."""
        resp = await client.get("/.well-known/l402")
        assert resp.status_code == 200
        code = resp.json()["example"]["code"]
        assert "{{" not in code, (
            f"example code has literal double-braces (non-f-string leak):\n{code}"
        )
        assert "{'content': 'hello'}" in code
        assert "f'L402 {macaroon}:{preimage}'" in code

    @pytest.mark.asyncio
    async def test_well_known_l402_adversarial_method_not_allowed(self, client):
        """POST must not mint invoices or mutate state via the discovery URL."""
        resp = await client.post("/.well-known/l402", json={"pay": True})
        assert resp.status_code in (404, 405, 422)


# ---------------------------------------------------------------------------
# OpenAPI L402 security scheme (forward-looking) + honest paid-route ads
# ---------------------------------------------------------------------------


class TestOpenApiL402Scheme:
    @pytest.mark.asyncio
    async def test_openapi_includes_l402_security_scheme(self, client):
        """securitySchemes.L402 is advertised for paid routes."""
        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        schemes = schema["components"]["securitySchemes"]
        assert "L402" in schemes
        l402 = schemes["L402"]
        assert l402["type"] == "http"
        assert l402["scheme"] == "L402"
        assert "macaroon" in l402["description"].lower() or "preimage" in l402["description"].lower()

    @pytest.mark.asyncio
    async def test_openapi_paid_routes_require_l402(self, client):
        """14.3: paid routes declare L402 as required security."""
        resp = await client.get("/openapi.json")
        schema = resp.json()
        events_post = schema["paths"]["/api/v1/events"]["post"]
        security = events_post.get("security", [])
        assert any("L402" in entry for entry in security), (
            f"POST /api/v1/events must require L402 after 14.3; got {security}"
        )
        assert "402" in events_post.get("responses", {})

    @pytest.mark.asyncio
    async def test_openapi_paid_routes_protocols_include_l402(self, client):
        """14.3: x-payment-info.protocols includes l402 (+ mpp alternate)."""
        resp = await client.get("/openapi.json")
        schema = resp.json()
        events_post = schema["paths"]["/api/v1/events"]["post"]
        protocols = events_post.get("x-payment-info", {}).get("protocols", [])
        assert "mpp" in protocols
        assert "l402" in protocols, (
            f"protocols must advertise l402 after 14.3; got {protocols}"
        )


# ---------------------------------------------------------------------------
# 402 bodies: MPP-only omit L402; require_l402 keeps L402
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def paid_client(monkeypatch):
    """Client with payments enabled (not test-mode) so 402 payment_required fires."""
    monkeypatch.setenv("AUTH_ROOT_KEY", "real-secret-key-for-testing")
    from app import config

    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "real-secret-key-for-testing")
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")

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


class TestHowToPayHonesty:
    @pytest.mark.asyncio
    async def test_payment_required_402_includes_how_to_pay_l402(self, paid_client):
        """14.3: live 402s emit L402 WWW-Authenticate and advertise how_to_pay.L402."""
        with patch(
            "app.api_v1.create_invoice",
            new_callable=AsyncMock,
            return_value={
                "payment_hash": "a" * 64,
                "payment_request": "lnbc210n1fake",
            },
        ), patch(
            "app.l402.create_invoice",
            new_callable=AsyncMock,
            return_value={
                "payment_hash": "a" * 64,
                "payment_request": "lnbc210n1fake",
            },
        ):
            resp = await paid_client.post(
                "/api/v1/post",
                json={"content": "l402 discovery how_to_pay"},
            )
        assert resp.status_code == 402
        body = resp.json()
        assert "how_to_pay" in body
        assert "L402" in body["how_to_pay"], (
            "gated 402 must advertise how_to_pay.L402 with L402 WWW-Authenticate"
        )
        assert "MPP" in body["how_to_pay"]
        assert "steps" in body["how_to_pay"]["L402"]
        www = resp.headers.get_list("www-authenticate") if hasattr(resp.headers, "get_list") else [
            v for k, v in resp.headers.multi_items() if k.lower() == "www-authenticate"
        ]
        assert www, "expected at least one WWW-Authenticate challenge"
        assert any(h.strip().startswith("L402 ") for h in www), (
            f"gated payment path must emit L402 challenge; got {www}"
        )

    @pytest.mark.asyncio
    async def test_require_l402_402_body_includes_how_to_pay(self):
        """require_l402 challenge detail must carry how_to_pay.L402 (emits L402 WWW-Authenticate)."""
        from fastapi import HTTPException, Request
        from app.l402 import require_l402

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/events",
            "headers": [],
            "query_string": b"",
        }
        request = Request(scope)

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_invoice:
            mock_settings.AUTH_ROOT_KEY = "test-root-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_settings.BASE_URL = "ws://localhost:8089"
            mock_invoice.return_value = {
                "payment_hash": "b" * 64,
                "payment_request": "lnbc210n1challenge",
            }
            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=request)

        assert exc_info.value.status_code == 402
        detail = exc_info.value.detail
        assert isinstance(detail, dict), f"expected dict detail with how_to_pay; got {type(detail)}"
        assert "how_to_pay" in detail
        assert "L402" in detail["how_to_pay"]
        assert "steps" in detail["how_to_pay"]["L402"]
        assert "/.well-known/l402" in detail["how_to_pay"]["L402"]["docs"]
        www = exc_info.value.headers.get("WWW-Authenticate", "")
        assert www.startswith("L402 "), f"require_l402 must emit L402 challenge; got {www}"
