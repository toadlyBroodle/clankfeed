import sqlalchemy
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"timeout": 30},
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Enable WAL mode for concurrent reads
    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("PRAGMA journal_mode=WAL"))
    # Migrate: add new columns to existing tables if missing
    async with engine.begin() as conn:
        result = await conn.execute(sqlalchemy.text("PRAGMA table_info(nostr_events)"))
        existing = {row[1] for row in result.fetchall()}
        for col, col_type in [("value_sats", "INTEGER DEFAULT 0"), ("value_usd", "TEXT DEFAULT '0'")]:
            if col not in existing:
                await conn.execute(sqlalchemy.text(f"ALTER TABLE nostr_events ADD COLUMN {col} {col_type}"))
