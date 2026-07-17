"""REQ #e / #p tag filters + ephemeral NWC (kinds 23194/23195) persistence.

BotFeed Phase 5 preflight (2026-07-17): NWC sub `#e:<req_id>` received a stale
kind:23195 with a different e-tag because query_events ignored NIP-01 tag filters.
"""

import time

import pytest

from app.database import async_session
from app.models import NostrEvent
from app.nostr import sign_event
from app.relay import (
    Connection,
    _handle_event,
    _matches_filter,
    connections,
    query_events,
    store_event,
)

SK = "c" * 64
REQ_A = "a" * 64
REQ_B = "b" * 64
PK_OTHER = "d" * 64


def _nwc_response(req_id: str, content: str = "resp", sk: str = SK, kind: int = 23195):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": kind,
        "tags": [["e", req_id], ["p", PK_OTHER]],
        "content": content,
    })


def _nwc_request(req_id: str, sk: str = SK):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 23194,
        "tags": [["e", req_id], ["p", PK_OTHER]],
        "content": "req",
    })


def _nwc_info(sk: str = SK):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 13194,
        "tags": [],
        "content": '{"methods":["pay_invoice"]}',
    })


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send_text(self, text: str):
        import json
        self.sent.append(json.loads(text))


class TestMatchesFilterTagFilters:
    def test_hash_e_requires_matching_e_tag(self):
        ev = {"id": "1", "pubkey": "p", "created_at": 1, "kind": 23195,
              "tags": [["e", REQ_A]], "content": "", "sig": ""}
        assert _matches_filter(ev, {"kinds": [23195], "#e": [REQ_A]}) is True
        assert _matches_filter(ev, {"kinds": [23195], "#e": [REQ_B]}) is False

    def test_hash_e_rejects_event_without_e_tag(self):
        ev = {"id": "1", "pubkey": "p", "created_at": 1, "kind": 1,
              "tags": [], "content": "", "sig": ""}
        assert _matches_filter(ev, {"#e": [REQ_A]}) is False

    def test_hash_p_requires_matching_p_tag(self):
        ev = {"id": "1", "pubkey": "p", "created_at": 1, "kind": 1,
              "tags": [["p", PK_OTHER]], "content": "", "sig": ""}
        assert _matches_filter(ev, {"#p": [PK_OTHER]}) is True
        assert _matches_filter(ev, {"#p": [REQ_A]}) is False


class TestQueryEventsTagFilters:
    @pytest.mark.asyncio
    async def test_hash_e_excludes_events_with_different_e_tag(self, client):
        """Stored 23195 for REQ_B must not appear under REQ `#e:REQ_A`."""
        match = _nwc_response(REQ_A, content="match")
        stale = _nwc_response(REQ_B, content="stale-balance-0")
        async with async_session() as db:
            await store_event(db, match)
            await store_event(db, stale)

        async with async_session() as db:
            results = await query_events(db, [{"kinds": [23195], "#e": [REQ_A]}])

        ids = [e["id"] for e in results]
        assert match["id"] in ids
        assert stale["id"] not in ids, (
            "query_events must honor #e: stale 23195 with different e-tag must not match"
        )
        for e in results:
            e_tags = [t[1] for t in e["tags"] if t[0] == "e"]
            assert REQ_A in e_tags
            assert REQ_B not in e_tags or REQ_A in e_tags

    @pytest.mark.asyncio
    async def test_hash_e_returns_empty_when_only_non_matching(self, client):
        stale = _nwc_response(REQ_B, content="only-stale")
        async with async_session() as db:
            await store_event(db, stale)

        async with async_session() as db:
            results = await query_events(db, [{"kinds": [23195], "#e": [REQ_A]}])

        assert results == []

    @pytest.mark.asyncio
    async def test_hash_p_filter_excludes_non_matching(self, client):
        # store_event bypasses kind:1 zap-fee validation (WS path enforces it)
        hit = sign_event(SK, {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": [["p", PK_OTHER]],
            "content": "hit",
        })
        miss = sign_event(SK, {
            "created_at": int(time.time()) + 1,
            "kind": 1,
            "tags": [["p", REQ_A]],
            "content": "miss",
        })
        async with async_session() as db:
            await store_event(db, hit, sats_clank=21)
            await store_event(db, miss, sats_clank=21)

        async with async_session() as db:
            results = await query_events(db, [{"kinds": [1], "#p": [PK_OTHER]}])

        ids = [e["id"] for e in results]
        assert hit["id"] in ids
        assert miss["id"] not in ids

    @pytest.mark.asyncio
    async def test_websocket_req_hash_e_does_not_return_stale(self, client):
        """End-to-end: REQ with #e must not surface a different-e 23195 from history."""
        from starlette.testclient import TestClient
        from app.main import app

        match = _nwc_response(REQ_A, content="ws-match")
        stale = _nwc_response(REQ_B, content="ws-stale")
        async with async_session() as db:
            await store_event(db, match)
            await store_event(db, stale)

        with TestClient(app) as tc:
            with tc.websocket_connect("/") as ws:
                ws.receive_json()  # AUTH
                ws.send_json([
                    "REQ", "nwc-sub",
                    {"kinds": [23195], "#e": [REQ_A], "limit": 50},
                ])
                seen = []
                while True:
                    msg = ws.receive_json()
                    if msg[0] == "EOSE":
                        break
                    if msg[0] == "EVENT":
                        seen.append(msg[2])

        ids = [e["id"] for e in seen]
        assert match["id"] in ids
        assert stale["id"] not in ids
        for e in seen:
            assert any(t[0] == "e" and t[1] == REQ_A for t in e["tags"])


class TestNwcEphemeralNoPersist:
    """NIP-01 ephemeral range: 23194/23195 SHOULD NOT be stored; 13194 may be."""

    @pytest.mark.asyncio
    async def test_23195_accepted_but_not_persisted(self, client):
        ev = _nwc_response(REQ_A, content="ephemeral-resp")
        ws = FakeWS()
        conn = Connection(ws)
        async with async_session() as db:
            await _handle_event(conn, ["EVENT", ev], db)

        assert any(m[0] == "OK" and m[1] == ev["id"] and m[2] is True for m in ws.sent)

        async with async_session() as db:
            row = await db.get(NostrEvent, ev["id"])
            assert row is None, "kind 23195 must not be persisted (NIP-01 ephemeral)"

        async with async_session() as db:
            results = await query_events(db, [{"kinds": [23195], "#e": [REQ_A]}])
        assert results == []

    @pytest.mark.asyncio
    async def test_23194_accepted_but_not_persisted(self, client):
        ev = _nwc_request(REQ_A)
        ws = FakeWS()
        conn = Connection(ws)
        async with async_session() as db:
            await _handle_event(conn, ["EVENT", ev], db)

        assert any(m[0] == "OK" and m[1] == ev["id"] and m[2] is True for m in ws.sent)
        async with async_session() as db:
            assert await db.get(NostrEvent, ev["id"]) is None

    @pytest.mark.asyncio
    async def test_13194_info_still_persisted(self, client):
        ev = _nwc_info()
        ws = FakeWS()
        conn = Connection(ws)
        async with async_session() as db:
            await _handle_event(conn, ["EVENT", ev], db)

        assert any(m[0] == "OK" and m[1] == ev["id"] and m[2] is True for m in ws.sent)
        async with async_session() as db:
            row = await db.get(NostrEvent, ev["id"])
            assert row is not None
            assert row.kind == 13194

    @pytest.mark.asyncio
    async def test_23195_broadcast_to_live_hash_e_subscriber(self, client):
        """Sole delivery path after no-persist: matching #e subscriber must get EVENT."""
        sub_ws = FakeWS()
        sub = Connection(sub_ws)
        sub.subscriptions["nwc-live"] = [{"kinds": [23195], "#e": [REQ_A]}]
        connections.add(sub)
        try:
            ev = _nwc_response(REQ_A, content="live-broadcast")
            pub_ws = FakeWS()
            pub = Connection(pub_ws)
            async with async_session() as db:
                await _handle_event(pub, ["EVENT", ev], db)

            assert any(m[0] == "OK" and m[1] == ev["id"] and m[2] is True for m in pub_ws.sent)
            delivered = [
                m for m in sub_ws.sent
                if m[0] == "EVENT" and m[1] == "nwc-live" and m[2]["id"] == ev["id"]
            ]
            assert delivered, (
                "ephemeral 23195 must reach live #e subscriber via broadcast_event "
                "(dropping broadcast breaks BotFeed NWC — nothing is stored to query)"
            )
            assert delivered[0][2]["content"] == "live-broadcast"

            async with async_session() as db:
                assert await db.get(NostrEvent, ev["id"]) is None
        finally:
            connections.discard(sub)

    @pytest.mark.asyncio
    async def test_23195_broadcast_skips_non_matching_hash_e(self, client):
        """Adversarial: subscriber on #e:REQ_A must not receive 23195 tagged REQ_B."""
        sub_ws = FakeWS()
        sub = Connection(sub_ws)
        sub.subscriptions["nwc-live"] = [{"kinds": [23195], "#e": [REQ_A]}]
        connections.add(sub)
        try:
            ev = _nwc_response(REQ_B, content="wrong-e")
            pub_ws = FakeWS()
            pub = Connection(pub_ws)
            async with async_session() as db:
                await _handle_event(pub, ["EVENT", ev], db)

            assert any(m[0] == "OK" and m[1] == ev["id"] and m[2] is True for m in pub_ws.sent)
            leaked = [
                m for m in sub_ws.sent
                if m[0] == "EVENT" and m[2].get("id") == ev["id"]
            ]
            assert leaked == [], "broadcast must honor #e filter (no cross-request leak)"
        finally:
            connections.discard(sub)

    @pytest.mark.asyncio
    async def test_websocket_e2e_ephemeral_23195_reaches_hash_e_sub(self, client):
        """WS e2e: REQ #e then EVENT on same conn → real-time EVENT push + not persisted.

        Same-connection avoids TestClient dual-WS deadlock; broadcast_event still
        delivers to every matching subscription on the connection registry.
        """
        from starlette.testclient import TestClient
        from app.main import app

        ev = _nwc_response(REQ_A, content="ws-e2e-live")

        with TestClient(app) as tc:
            with tc.websocket_connect("/") as ws:
                ws.receive_json()  # AUTH
                ws.send_json([
                    "REQ", "nwc-sub",
                    {"kinds": [23195], "#e": [REQ_A], "limit": 50},
                ])
                while True:
                    msg = ws.receive_json()
                    if msg[0] == "EOSE":
                        break

                ws.send_json(["EVENT", ev])
                ok = ws.receive_json()
                assert ok[0] == "OK" and ok[1] == ev["id"] and ok[2] is True

                got = ws.receive_json()
                assert got[0] == "EVENT"
                assert got[1] == "nwc-sub"
                assert got[2]["id"] == ev["id"]
                assert got[2]["content"] == "ws-e2e-live"
                assert any(t[0] == "e" and t[1] == REQ_A for t in got[2]["tags"])

        async with async_session() as db:
            assert await db.get(NostrEvent, ev["id"]) is None
