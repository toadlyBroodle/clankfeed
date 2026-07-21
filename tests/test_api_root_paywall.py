"""GET /api/ agent index + GET paywall probes on write endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine
from app.limiter import limiter
from app.main import app

ROOT_KEY = "api-root-l402-key"


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


def _invoice_patches():
    fake = {
        "payment_hash": "ab" * 32,
        "payment_request": "lnbc210n1testinvoice",
    }
    return (
        patch("app.api_v1.create_invoice", new_callable=AsyncMock, return_value=fake),
        patch("app.l402.create_invoice", new_callable=AsyncMock, return_value=fake),
        patch("app.payment.create_invoice", new_callable=AsyncMock, return_value=fake),
    )


class TestApiRoot:
    @pytest.mark.asyncio
    async def test_api_root_has_agent_instructions(self, client):
        for path in ("/api/", "/api"):
            resp = await client.get(path)
            assert resp.status_code == 200, path
            data = resp.json()
            assert data["name"] == "clankfeed"
            assert "how_to_pay" in data
            assert "endpoints" in data
            assert "POST /api/v1/post" in data["endpoints"]["write"]
            assert "flow" in data and len(data["flow"]) >= 3
            assert data["pricing_sats"]["post"] >= 1


class TestGetPaywallProbes:
    @pytest.mark.asyncio
    async def test_get_post_returns_l402_402(self, paid_client):
        p1, p2, p3 = _invoice_patches()
        with p1, p2, p3:
            resp = await paid_client.get("/api/v1/post")
        assert resp.status_code == 402
        www = resp.headers.get_list("www-authenticate") or [resp.headers.get("www-authenticate", "")]
        joined = " ".join(www)
        assert "L402" in joined
        assert "macaroon=" in joined
        assert "invoice=" in joined
        body = resp.json()
        assert body.get("how_to_pay", {}).get("primary") == "L402"
        assert body.get("method") == "POST"

    @pytest.mark.asyncio
    async def test_get_post_no_longer_405(self, paid_client):
        p1, p2, p3 = _invoice_patches()
        with p1, p2, p3:
            resp = await paid_client.get("/api/v1/post")
        assert resp.status_code != 405

    @pytest.mark.asyncio
    async def test_get_events_challenge_returns_l402_402(self, paid_client):
        p1, p2, p3 = _invoice_patches()
        with p1, p2, p3:
            resp = await paid_client.get("/api/v1/events/challenge")
        assert resp.status_code == 402
        www = resp.headers.get_list("www-authenticate") or [resp.headers.get("www-authenticate", "")]
        assert any("L402" in h for h in www)

    @pytest.mark.asyncio
    async def test_get_events_feed_still_free(self, client):
        resp = await client.get("/api/v1/events")
        assert resp.status_code == 200
        assert "events" in resp.json()
