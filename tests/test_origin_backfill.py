"""UI3.1 / UI3.2: origin backfill must run once (column-just-added), never every boot."""

import pytest
from sqlalchemy import text

from app.database import Base, engine, init_db


async def _drop_all():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def _create_legacy_nostr_events_without_origin():
    """Pre-origin schema: no origin column (simulates prod before UI-3)."""
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE nostr_events (
                id VARCHAR(64) PRIMARY KEY,
                pubkey VARCHAR(64) NOT NULL,
                created_at INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                tags TEXT NOT NULL,
                content TEXT NOT NULL,
                sig VARCHAR(128) NOT NULL,
                stored_at DATETIME,
                sats_clank INTEGER DEFAULT 0,
                value_usd TEXT DEFAULT '0',
                sats_ext INTEGER DEFAULT 0
            )
        """))


async def _insert_note(eid, *, kind=1, sats_clank=0, sats_ext=0, origin=None):
    cols = (
        "id, pubkey, created_at, kind, tags, content, sig, "
        "sats_clank, value_usd, sats_ext"
    )
    vals = (
        ":id, :pubkey, :created_at, :kind, :tags, :content, :sig, "
        ":sats_clank, :value_usd, :sats_ext"
    )
    params = {
        "id": eid,
        "pubkey": "a" * 64,
        "created_at": 1_700_000_000,
        "kind": kind,
        "tags": "[]",
        "content": f"note-{eid[:8]}",
        "sig": "b" * 128,
        "sats_clank": sats_clank,
        "value_usd": "0",
        "sats_ext": sats_ext,
    }
    if origin is not None:
        cols += ", origin"
        vals += ", :origin"
        params["origin"] = origin
    async with engine.begin() as conn:
        await conn.execute(
            text(f"INSERT INTO nostr_events ({cols}) VALUES ({vals})"),
            params,
        )


async def _get_origin(eid) -> str:
    async with engine.begin() as conn:
        row = (await conn.execute(
            text("SELECT origin FROM nostr_events WHERE id = :id"),
            {"id": eid},
        )).fetchone()
    assert row is not None, f"missing event {eid}"
    return row[0]


@pytest.mark.asyncio
async def test_backfill_reclassifies_misclassified_on_column_add():
    """When origin is first added, sats_clank=0 + sats_ext>0 → origin=external."""
    await _drop_all()
    await _create_legacy_nostr_events_without_origin()
    await _insert_note("e" * 64, sats_clank=0, sats_ext=100)

    await init_db()

    assert await _get_origin("e" * 64) == "external"


@pytest.mark.asyncio
async def test_backfill_keeps_positive_sats_clank_as_clankfeed():
    """Locals with sats_clank > 0 stay clankfeed after origin column is added."""
    await _drop_all()
    await _create_legacy_nostr_events_without_origin()
    await _insert_note("c" * 64, sats_clank=21, sats_ext=50)

    await init_db()

    assert await _get_origin("c" * 64) == "clankfeed"


@pytest.mark.asyncio
async def test_backfill_keeps_zero_ext_as_clankfeed():
    """Locals with sats_ext=0 stay clankfeed (no external-zap heuristic match)."""
    await _drop_all()
    await _create_legacy_nostr_events_without_origin()
    await _insert_note("z" * 64, sats_clank=0, sats_ext=0)

    await init_db()

    assert await _get_origin("z" * 64) == "clankfeed"


@pytest.mark.asyncio
async def test_backfill_not_rerun_on_subsequent_boot():
    """UI3.1: a local note later zeroed on sats_clank with sats_ext>0 must NOT be
    rewritten to external on every restart (every-boot backfill false positive)."""
    await _drop_all()
    await _create_legacy_nostr_events_without_origin()
    # First boot: column add + one-shot backfill
    await init_db()

    # Local paid note that later got external zaps + enough downvotes to zero sats_clank
    await _insert_note(
        "f" * 64,
        sats_clank=0,
        sats_ext=80,
        origin="clankfeed",
    )

    # Second boot must leave it alone
    await init_db()

    assert await _get_origin("f" * 64) == "clankfeed"
