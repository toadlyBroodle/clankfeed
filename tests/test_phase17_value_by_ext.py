"""External feed sat filters must use sats_ext (value_by=ext), not sats_clank.

Bug: min_value/max_value always filtered sats_clank, so the external tab
(origin=all) with a sats filter returned only clankfeed-paid notes.
"""

from __future__ import annotations

import time

import pytest

from app.database import async_session
from app.nostr import sign_event
from app.relay import store_event
from tests.conftest import kind1_tags

PRIV_EXT = "d" * 64
PRIV_LOCAL = "e" * 64


def _note(priv: str, content: str) -> dict:
    return sign_event(
        priv,
        {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(priv, []),
            "content": content,
        },
    )


@pytest.mark.asyncio
async def test_min_value_value_by_ext_includes_external(client):
    local = _note(PRIV_LOCAL, "vb-local-clank")
    external = _note(PRIV_EXT, "vb-external-zapped")
    async with async_session() as db:
        await store_event(db, local, sats_clank=50, origin="clankfeed")
        await store_event(db, external, sats_clank=0, origin="external")
        # credit sats_ext directly on the row (store_event has no sats_ext kw)
        from sqlalchemy import text

        await db.execute(
            text(
                "UPDATE nostr_events SET sats_ext = 80 WHERE id = :id"
            ),
            {"id": external["id"]},
        )
        await db.commit()

    # Default value_by=clank: only local (≥50 clank) matches min_value=40
    clank = await client.get(
        "/api/v1/events?kinds=1&origin=all&min_value=40&limit=100"
    )
    assert clank.status_code == 200
    clank_ids = {e["id"] for e in clank.json()["events"]}
    assert local["id"] in clank_ids
    assert external["id"] not in clank_ids

    # value_by=ext: external with sats_ext=80 matches; local sats_ext=0 does not
    ext = await client.get(
        "/api/v1/events?kinds=1&origin=all&min_value=40&value_by=ext&limit=100"
    )
    assert ext.status_code == 200
    ext_ids = {e["id"] for e in ext.json()["events"]}
    assert external["id"] in ext_ids
    assert local["id"] not in ext_ids


@pytest.mark.asyncio
async def test_value_by_invalid_rejected(client):
    resp = await client.get("/api/v1/events?kinds=1&value_by=nope")
    assert resp.status_code == 400


def test_index_js_passes_value_by_ext_on_external_feed():
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "app" / "static" / "index.js").read_text()
    assert "value_by=" in js
    assert "value_by=${currentFeed === 'external' ? 'ext' : 'clank'}" in js or (
        "value_by=" in js and "external" in js and "'ext'" in js
    )
