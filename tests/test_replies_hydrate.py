"""Hydrate thread replies from EXTERNAL_RELAYS on expand."""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, patch

import pytest

from app.database import async_session
from app.ingest import (
    clear_replies_hydrate_cache,
    fetch_and_store_replies,
)
from app.nostr import sign_event
from app.relay import store_event
from tests.conftest import kind1_tags

_PARENT_SK = "a" * 64
_REPLY_SK = "b" * 64


@pytest.fixture(autouse=True)
def _clear_hydrate_cache():
    clear_replies_hydrate_cache()
    yield
    clear_replies_hydrate_cache()


def _parent_and_reply():
    parent = sign_event(
        _PARENT_SK,
        {
            "created_at": int(time.time()) - 10,
            "kind": 1,
            "tags": kind1_tags(_PARENT_SK),
            "content": "hydrate-parent",
        },
    )
    reply = sign_event(
        _REPLY_SK,
        {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(_REPLY_SK, [["e", parent["id"], "", "reply"]]),
            "content": "hydrate-external-reply",
        },
    )
    return parent, reply


class _ReplyWS:
    """Relay that returns one #e reply then EOSE."""

    def __init__(self, parent_id: str, reply: dict, connect_log: list):
        self._sub = f"re-{parent_id[:16]}"
        self._reply = reply
        self._connect_log = connect_log
        self._phase = 0

    async def __aenter__(self):
        self._connect_log.append(1)
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, _msg):
        return None

    async def recv(self):
        if self._phase == 0:
            self._phase = 1
            return json.dumps(["EVENT", self._sub, self._reply])
        if self._phase == 1:
            self._phase = 2
            return json.dumps(["EOSE", self._sub])
        await asyncio.sleep(60)
        raise AssertionError("unexpected recv")


class _EmptyReplyWS:
    def __init__(self, parent_id: str):
        self._sub = f"re-{parent_id[:16]}"
        self._done = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, _msg):
        return None

    async def recv(self):
        if not self._done:
            self._done = True
            return json.dumps(["EOSE", self._sub])
        await asyncio.sleep(60)


@pytest.mark.asyncio
async def test_fetch_and_store_replies_persists_external(client, monkeypatch):
    parent, reply = _parent_and_reply()
    async with async_session() as db:
        await store_event(db, parent, sats_clank=21, origin="clankfeed")

    connect_log: list = []
    monkeypatch.setattr(
        "app.ingest.settings.EXTERNAL_INGEST", True
    )
    monkeypatch.setattr(
        "app.ingest.settings.EXTERNAL_RELAYS",
        "wss://relay.example/1,wss://relay.example/2",
    )

    def _connect(url, **kwargs):
        return _ReplyWS(parent["id"], reply, connect_log)

    with patch("app.ingest.websockets.connect", side_effect=_connect):
        n = await fetch_and_store_replies(parent["id"], limit=20)
    assert n == 1
    assert len(connect_log) == 2  # both relays probed (merge)

    resp = await client.get(f"/api/v1/events/{parent['id']}/replies")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1
    assert any(r["id"] == reply["id"] for r in body["replies"])
    assert any(r.get("content") == "hydrate-external-reply" for r in body["replies"])


@pytest.mark.asyncio
async def test_get_replies_hydrates_when_local_empty(client, monkeypatch):
    parent, reply = _parent_and_reply()
    async with async_session() as db:
        await store_event(db, parent, sats_clank=21, origin="clankfeed")

    monkeypatch.setattr("app.ingest.settings.EXTERNAL_INGEST", True)
    monkeypatch.setattr(
        "app.ingest.settings.EXTERNAL_RELAYS", "wss://relay.example/only"
    )
    connect_log: list = []

    def _connect(url, **kwargs):
        return _ReplyWS(parent["id"], reply, connect_log)

    with patch("app.ingest.websockets.connect", side_effect=_connect):
        resp = await client.get(f"/api/v1/events/{parent['id']}/replies")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["replies"][0]["id"] == reply["id"]
    assert connect_log  # hydrate contacted relays


@pytest.mark.asyncio
async def test_replies_hydrate_ttl_skips_second_fetch(client, monkeypatch):
    parent, reply = _parent_and_reply()
    async with async_session() as db:
        await store_event(db, parent, sats_clank=21, origin="clankfeed")

    monkeypatch.setattr("app.ingest.settings.EXTERNAL_INGEST", True)
    monkeypatch.setattr(
        "app.ingest.settings.EXTERNAL_RELAYS", "wss://relay.example/only"
    )
    connect_log: list = []

    def _connect(url, **kwargs):
        return _ReplyWS(parent["id"], reply, connect_log)

    with patch("app.ingest.websockets.connect", side_effect=_connect):
        assert await fetch_and_store_replies(parent["id"]) == 1
        n_after = len(connect_log)
        assert await fetch_and_store_replies(parent["id"]) == 0  # TTL
        assert len(connect_log) == n_after


@pytest.mark.asyncio
async def test_fetch_replies_noop_when_ingest_disabled(monkeypatch):
    monkeypatch.setattr("app.ingest.settings.EXTERNAL_INGEST", False)
    with patch("app.ingest.websockets.connect") as conn:
        n = await fetch_and_store_replies("ab" * 32)
    assert n == 0
    conn.assert_not_called()
