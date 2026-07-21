"""Phase 17 follow-up: expand must return zero-sats external replies.

FEED-1 hides zero-sats external notes from feed listings, but GET
/events/{id}/replies used the same query_events path — so reply-counts
could show N while expand returned [] / “No replies yet.”
"""

from __future__ import annotations

import time

import pytest

from app.database import async_session
from app.nostr import sign_event
from app.relay import store_event
from tests.conftest import kind1_tags

PRIV = "c" * 64


@pytest.mark.asyncio
async def test_get_replies_includes_zero_sats_external(client):
    """Expand/thread fetch must not apply FEED-1 zero-sats filter."""
    parent = (
        await client.post("/api/v1/post", json={"content": "p17-zs-parent"})
    ).json()["event"]
    pid = parent["id"]

    reply = sign_event(
        PRIV,
        {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(PRIV, [["e", pid, "", "reply"]]),
            "content": "p17-zs-external-reply",
        },
    )
    async with async_session() as db:
        # sats_ext defaults to 0 on the row; sats_clank=0 + origin=external → FEED-1 hide
        await store_event(db, reply, sats_clank=0, origin="external")

    # Feed listing still hides the zero-sats external (FEED-1)
    feed = await client.get("/api/v1/events?kinds=1&origin=all&limit=100")
    assert feed.status_code == 200
    feed_ids = {e["id"] for e in feed.json().get("events", [])}
    assert reply["id"] not in feed_ids

    # Thread expand must still return it; count must match
    resp = await client.get(f"/api/v1/events/{pid}/replies")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1
    ids = {r["id"] for r in body.get("replies", [])}
    assert reply["id"] in ids
    assert any(r.get("content") == "p17-zs-external-reply" for r in body["replies"])

    counts = await client.post(
        "/api/v1/events/reply-counts", json={"event_ids": [pid]}
    )
    assert counts.status_code == 200
    assert counts.json()["counts"].get(pid, 0) >= 1
