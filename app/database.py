import logging

import sqlalchemy
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = logging.getLogger("clankfeed.database")

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
            ("accounts", [("nostr_privkey", "VARCHAR(64)"), ("nostr_pubkey", "VARCHAR(64)")]),
        ]:
            result = await conn.execute(sqlalchemy.text(f"PRAGMA table_info({table})"))
            existing = {row[1] for row in result.fetchall()}
            for col, col_type in columns:
                if col not in existing:
                    await conn.execute(sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))

    # Migrate: encrypt any plaintext private keys
    from app.crypto import encrypt_field, _fernet
    if _fernet is not None:
        async with engine.begin() as conn:
            rows = await conn.execute(
                sqlalchemy.text("SELECT id, nostr_privkey FROM accounts WHERE nostr_privkey IS NOT NULL AND nostr_privkey != '' AND nostr_privkey NOT LIKE 'enc:%'")
            )
            plaintext_rows = rows.fetchall()
            if plaintext_rows:
                logger.info("Encrypting %d plaintext private keys", len(plaintext_rows))
                for row_id, privkey in plaintext_rows:
                    encrypted = encrypt_field(privkey)
                    await conn.execute(
                        sqlalchemy.text("UPDATE accounts SET nostr_privkey = :enc WHERE id = :id"),
                        {"enc": encrypted, "id": row_id},
                    )
