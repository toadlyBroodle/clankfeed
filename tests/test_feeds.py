"""UI-3: dual feeds — origin marker + API filter for clankfeed vs external."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, patch

import pytest

from app.database import async_session
from app.ingest import _handle_target
from app.models import NostrEvent
from app.nostr import sign_event
from app.relay import store_event

AUTHOR_SK = "b" * 64


def _make_note(content="note", sk=AUTHOR_SK):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 1,
        "tags": [],
        "content": content,
    })


def _make_kind0(sk=AUTHOR_SK, name="Agent", lud16="a@example.com"):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 0,
        "tags": [],
        "content": json.dumps({"name": name, "lud16": lud16}),
    })


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, msg):
        self.sent.append(msg)


@pytest.mark.asyncio
async def test_local_post_has_origin_clankfeed(client):
    """Notes posted through clankfeed are marked origin=clankfeed."""
    resp = await client.post("/api/v1/post", json={"content": "paid local"})
    assert resp.status_code == 200
    event_id = resp.json()["event"]["id"]

    async with async_session() as db:
        row = await db.get(NostrEvent, event_id)
        assert row is not None
        assert getattr(row, "origin", None) == "clankfeed"

    listed = await client.get("/api/v1/events?kinds=1&origin=clankfeed")
    assert listed.status_code == 200
    ids = [e["id"] for e in listed.json()["events"]]
    assert event_id in ids
    assert listed.json()["events"][0].get("origin") == "clankfeed"


@pytest.mark.asyncio
async def test_ingest_marks_origin_external(client):
    """Notes stored via ingest path are marked origin=external (FEED-1: needs sats)."""
    note = _make_note("from nostr")
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="external")
        row = await db.get(NostrEvent, note["id"])
        row.sats_ext = 21
        await db.commit()

    resp = await client.get("/api/v1/events?kinds=1&origin=external")
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert len(events) == 1
    assert events[0]["id"] == note["id"]
    assert events[0].get("origin") == "external"

    # clankfeed-only filter must exclude it
    clank = await client.get("/api/v1/events?kinds=1&origin=clankfeed")
    assert note["id"] not in [e["id"] for e in clank.json()["events"]]


@pytest.mark.asyncio
async def test_feed1_zero_sats_external_hidden_from_listings(client):
    """FEED-1: origin=external with sats_ext=0 and sats_clank=0 is omitted from feeds."""
    zero = _make_note("zero sats external")
    valued = _make_note("valued external")
    async with async_session() as db:
        await store_event(db, zero, sats_clank=0, origin="external")
        await store_event(db, valued, sats_clank=0, origin="external")
        row = await db.get(NostrEvent, valued["id"])
        row.sats_ext = 42
        await db.commit()

    for qs in (
        "kinds=1&origin=external",
        "kinds=1&origin=all",
        "kinds=1",
    ):
        resp = await client.get(f"/api/v1/events?{qs}")
        assert resp.status_code == 200
        ids = {e["id"] for e in resp.json()["events"]}
        assert zero["id"] not in ids, f"zero-sats external leaked in ?{qs}"
        assert valued["id"] in ids, f"valued external missing from ?{qs}"

    # Direct get-by-id still works (listing filter only)
    one = await client.get(f"/api/v1/events/{zero['id']}")
    assert one.status_code == 200
    assert one.json()["event"]["id"] == zero["id"]


@pytest.mark.asyncio
async def test_feed1_zero_sats_clankfeed_still_listed(client):
    """FEED-1 adversarial: local origin=clankfeed with 0 sats still appears on clankfeed."""
    note = _make_note("local zero")
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="clankfeed")

    clank = await client.get("/api/v1/events?kinds=1&origin=clankfeed")
    assert note["id"] in {e["id"] for e in clank.json()["events"]}


@pytest.mark.asyncio
async def test_ingest_handle_target_sets_external(client):
    """_handle_target (ingest) stores notes with origin=external without callers passing it."""
    note = _make_note("ingested live")
    # Park a dummy receipt so _handle_target does not early-return on empty receipts
    pending = {note["id"]: [({"id": "r" * 64}, {"amount_sats": 1, "target_event_id": note["id"]})]}
    ws = FakeWS()

    # Monkeypatch apply path: empty receipts list after we force store — call with
    # receipts that will fail apply but note still stored first.
    # Simpler: call _handle_target with receipts that exist; apply_zap_receipt may
    # fail validation — we only care that the note was stored with origin=external.
    from unittest.mock import AsyncMock, patch

    with patch("app.ingest._apply_receipts", new_callable=AsyncMock) as mock_apply:
        await _handle_target(ws, f"t-{note['id']}", note, pending)
        mock_apply.assert_awaited()

    async with async_session() as db:
        row = await db.get(NostrEvent, note["id"])
        assert row is not None
        assert row.origin == "external"


@pytest.mark.asyncio
async def test_origin_all_returns_both(client):
    """origin=all (or omitted) returns both clankfeed and valued external notes."""
    local = await client.post("/api/v1/post", json={"content": "local a"})
    local_id = local.json()["event"]["id"]
    ext = _make_note("ext b")
    async with async_session() as db:
        await store_event(db, ext, sats_clank=0, origin="external")
        row = await db.get(NostrEvent, ext["id"])
        row.sats_ext = 21
        await db.commit()

    both = await client.get("/api/v1/events?kinds=1&origin=all")
    ids = {e["id"] for e in both.json()["events"]}
    assert local_id in ids and ext["id"] in ids

    default = await client.get("/api/v1/events?kinds=1")
    default_ids = {e["id"] for e in default.json()["events"]}
    assert local_id in default_ids and ext["id"] in default_ids


@pytest.mark.asyncio
async def test_origin_invalid_rejected(client):
    """Bad origin query param returns 400."""
    resp = await client.get("/api/v1/events?origin=bogus")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_store_event_default_origin_clankfeed(client):
    """store_event without origin defaults to clankfeed (local relay path)."""
    note = _make_note("default origin")
    async with async_session() as db:
        await store_event(db, note, sats_clank=21)

    async with async_session() as db:
        row = await db.get(NostrEvent, note["id"])
        assert row.origin == "clankfeed"


# ---------------------------------------------------------------------------
# EXT-1a.1 — store_event idempotent on duplicate id (ingest race)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_event_duplicate_pk_commit_idempotent(client):
    """If commit hits UNIQUE on event id, store_event must not raise (EXT-1a.1).

    Simulates the TOCTOU after the early db.get miss: another writer already
    inserted the same primary key. Kind:1 skips replaceable delete so the
    second insert always collides on PK.
    """
    note = _make_note("dup-pk")
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="external")

    async with async_session() as db:
        with patch.object(db, "get", new_callable=AsyncMock, return_value=None):
            await store_event(db, note, sats_clank=0, origin="external")

    async with async_session() as db:
        row = await db.get(NostrEvent, note["id"])
        assert row is not None
        assert row.origin == "external"


@pytest.mark.asyncio
async def test_store_event_concurrent_same_kind0_idempotent(client, tmp_path, monkeypatch):
    """Concurrent store_event of the same kind:0 must not raise IntegrityError.

    Prod: two EXTERNAL_RELAYS ingest paths fetch+store the same author kind:0;
    the loser used to UNIQUE-fail and reconnect the ingest loop.

    Uses a file-backed SQLite DB so concurrent sessions share one store
    (in-memory aiosqlite without StaticPool isolates per connection).
    """
    import app.database as database
    import app.relay as relay_mod
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine, AsyncSession

    db_path = tmp_path / "ext1a1_race.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(database, "async_session", session_factory)
    monkeypatch.setattr(relay_mod, "async_session", session_factory, raising=False)

    async with engine.begin() as conn:
        await conn.run_sync(NostrEvent.metadata.create_all)

    profile = _make_kind0(name="RaceAgent", lud16="race@example.com")

    async def _store():
        async with session_factory() as db:
            await store_event(db, profile, sats_clank=0, origin="external")

    results = await asyncio.gather(*[_store() for _ in range(16)], return_exceptions=True)
    errors = [r for r in results if isinstance(r, BaseException)]
    assert errors == [], f"store_event raised under concurrency: {errors!r}"

    async with session_factory() as db:
        row = await db.get(NostrEvent, profile["id"])
        assert row is not None
        assert row.kind == 0
        assert json.loads(row.content)["lud16"] == "race@example.com"

    await engine.dispose()
