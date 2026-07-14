import os

# Force test mode before any app imports
os.environ["AUTH_ROOT_KEY"] = "test-mode"
os.environ["EXTERNAL_INGEST"] = "false"  # no network in unit tests
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"  # in-memory
os.environ["RELAY_PRIVATE_KEY"] = "a" * 64  # test key
os.environ["TEMPO_RECIPIENT"] = ""  # disable Tempo in unit tests (no-payment mode)

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.main import app
from app.zaps import build_zap_split_tags, pubkey_from_privkey


def kind1_tags(privkey_hex: str, extra: list | None = None) -> list:
    """Tags for client-signed kind:1 — always includes required Phase 13 zap fee tags."""
    tags = list(extra or [])
    tags.extend(build_zap_split_tags(pubkey_from_privkey(privkey_hex)))
    return tags


@pytest_asyncio.fixture
async def client():
    """Async test client with fresh in-memory DB."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    # SECURITY H5: default X-Requested-With so POSTs without Origin still pass
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as c:
        yield c

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
