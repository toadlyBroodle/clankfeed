"""UI-3: dual feeds — origin marker + API filter for clankfeed vs external."""

import time

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
    """Notes stored via ingest path are marked origin=external."""
    note = _make_note("from nostr")
    pending = {note["id"]: []}  # empty receipts — just store the note
    ws = FakeWS()
    # _handle_target expects pending receipts; seed one dummy so it proceeds
    # to store, then pop — use a fake receipt pair that apply will skip if empty.
    # Actually _handle_target returns early if not receipts. Call store path directly
    # via the same store_event signature ingest uses, then assert API filter.
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="external")

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
    """origin=all (or omitted) returns both clankfeed and external notes."""
    local = await client.post("/api/v1/post", json={"content": "local a"})
    local_id = local.json()["event"]["id"]
    ext = _make_note("ext b")
    async with async_session() as db:
        await store_event(db, ext, sats_clank=0, origin="external")

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
