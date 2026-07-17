"""11c.7: payment status must surface LNBits preimage for QR/poll settle."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine
from app.main import app


@pytest_asyncio.fixture
async def status_client(monkeypatch):
    from app import config

    monkeypatch.setenv("AUTH_ROOT_KEY", "status-preimage-key")
    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "status-preimage-key")
    monkeypatch.setattr(config.settings, "PAYMENT_URL", "https://lnbits.test")
    monkeypatch.setattr(config.settings, "PAYMENT_KEY", "test-payment-key")

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


@pytest.mark.asyncio
async def test_get_payment_status_returns_lnbits_preimage():
    """Producer shape: LNBits GET /payments/{hash} includes top-level preimage when paid."""
    from app.lightning import get_payment_status

    preimage = "ab" * 32
    pay_hash = "cd" * 32
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"paid": True, "preimage": preimage, "amount": 21000}

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("app.lightning.httpx.AsyncClient", return_value=mock_client):
        result = await get_payment_status(pay_hash)

    assert result["paid"] is True
    assert result["preimage"] == preimage
    mock_client.get.assert_awaited()


@pytest.mark.asyncio
async def test_get_payment_status_unpaid_has_no_preimage():
    from app.lightning import get_payment_status

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"paid": False, "preimage": ""}

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("app.lightning.httpx.AsyncClient", return_value=mock_client):
        result = await get_payment_status("ee" * 32)

    assert result["paid"] is False
    assert not result.get("preimage")


@pytest.mark.asyncio
async def test_get_payment_status_rejects_all_zero_preimage():
    """Adversarial: LNBits sometimes returns 64 zero hex for unpaid — treat as absent."""
    from app.lightning import get_payment_status

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"paid": True, "preimage": "0" * 64}

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("app.lightning.httpx.AsyncClient", return_value=mock_client):
        result = await get_payment_status("ff" * 32)

    assert result["paid"] is True
    assert not result.get("preimage")


@pytest.mark.asyncio
async def test_v1_payments_status_includes_preimage(status_client):
    preimage = "11" * 32
    pay_hash = "22" * 32
    with patch(
        "app.api_v1.get_payment_status",
        new_callable=AsyncMock,
        return_value={"paid": True, "preimage": preimage},
    ):
        resp = await status_client.get(
            f"/api/v1/payments/status?payment_hash={pay_hash}"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["paid"] is True
    assert body["payment_hash"] == pay_hash
    assert body["preimage"] == preimage


@pytest.mark.asyncio
async def test_v1_payments_status_omits_preimage_when_absent(status_client):
    """Adversarial: paid without usable preimage must not invent one."""
    pay_hash = "33" * 32
    with patch(
        "app.api_v1.get_payment_status",
        new_callable=AsyncMock,
        return_value={"paid": True, "preimage": None},
    ):
        resp = await status_client.get(
            f"/api/v1/payments/status?payment_hash={pay_hash}"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["paid"] is True
    assert not body.get("preimage")
