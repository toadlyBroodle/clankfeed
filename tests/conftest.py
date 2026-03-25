import os

# Force test mode before any app imports
os.environ["AUTH_ROOT_KEY"] = "test-mode"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"  # in-memory
os.environ["RELAY_PRIVATE_KEY"] = "a" * 64  # test key

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.main import app


@pytest_asyncio.fixture
async def client():
    """Async test client with fresh in-memory DB."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
