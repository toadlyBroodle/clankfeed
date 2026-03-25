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
        for table, columns in [
            ("nostr_events", [("value_sats", "INTEGER DEFAULT 0"), ("value_usd", "TEXT DEFAULT '0'")]),
            ("pending_events", [("amount_sats", "INTEGER DEFAULT 0"), ("amount_usd", "TEXT DEFAULT '0'")]),
        ]:
            result = await conn.execute(sqlalchemy.text(f"PRAGMA table_info({table})"))
            existing = {row[1] for row in result.fetchall()}
            for col, col_type in columns:
                if col not in existing:
                    await conn.execute(sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
