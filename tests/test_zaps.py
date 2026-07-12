"""Tests for NIP-57 zap receipt ingestion and the sats_ext fair ranking."""

import json
import time

import pytest
from sqlalchemy import select

from app.database import async_session
from app.models import NostrEvent, Vote
from app.nostr import sign_event
from app.relay import _handle_event, store_event
from app.zaps import bolt11_amount_msat

AUTHOR_SK = "b" * 64
SENDER_SK = "c" * 64
LNURL_SK = "d" * 64


class FakeConn:
    def __init__(self):
        self.sent = []
        self.subscriptions = {}

    async def send(self, msg):
        self.sent.append(msg)


def _make_note(content="zap me"):
    return sign_event(AUTHOR_SK, {
        "created_at": int(time.time()),
        "kind": 1,
        "tags": [],
        "content": content,
    })


def _make_zap_request(target_id: str, amount_msat: int = 21000):
    return sign_event(SENDER_SK, {
        "created_at": int(time.time()),
        "kind": 9734,
        "tags": [
            ["e", target_id],
            ["amount", str(amount_msat)],
            ["relays", "wss://clankfeed.com"],
        ],
        "content": "",
    })


def _make_receipt(zap_request: dict, bolt11: str = "lnbc210n1fakedata"):
    return sign_event(LNURL_SK, {
        "created_at": int(time.time()),
        "kind": 9735,
        "tags": [
            ["bolt11", bolt11],
            ["description", json.dumps(zap_request)],
        ],
        "content": "",
    })


async def _store_note(note: dict):
    async with async_session() as db:
        await store_event(db, note, sats_clank=0)


async def _send(event: dict) -> FakeConn:
    conn = FakeConn()
    async with async_session() as db:
        await _handle_event(conn, ["EVENT", event], db)
    return conn


async def _get_sats(event_id: str) -> tuple[int, int]:
    """Return (sats_clank, sats_ext) for an event."""
    async with async_session() as db:
        row = await db.get(NostrEvent, event_id)
        return row.sats_clank, row.sats_ext


def test_bolt11_amounts():
    assert bolt11_amount_msat("lnbc210n1abc") == 21000  # 21 sats
    assert bolt11_amount_msat("lnbc1m1abc") == 100_000_000
    assert bolt11_amount_msat("lnbc25u1abc") == 2_500_000
    assert bolt11_amount_msat("lnbc10p1abc") == 1
    assert bolt11_amount_msat("lnbc15p1abc") is None  # not whole msat
    assert bolt11_amount_msat("lnbc1abc") is None  # amountless
    assert bolt11_amount_msat("not an invoice") is None
    assert bolt11_amount_msat("lntb210n1abc") == 21000  # testnet prefix


@pytest.mark.asyncio
async def test_zap_receipt_credits_sats_ext_full(client):
    note = _make_note()
    await _store_note(note)

    receipt = _make_receipt(_make_zap_request(note["id"]))
    conn = await _send(receipt)

    assert conn.sent[-1][:3] == ["OK", receipt["id"], True]
    # 21 sats zapped -> 21 credited at face value, segregated from paid value
    clank, ext = await _get_sats(note["id"])
    assert ext == 21
    assert clank == 0  # external zaps never touch the clankfeed-paid ranking

    async with async_session() as db:
        vote = (await db.execute(
            select(Vote).where(Vote.payment_id == f"zap:{receipt['id']}")
        )).scalar_one()
        assert vote.amount_sats == 21
        assert vote.direction == 1
        stored = await db.get(NostrEvent, receipt["id"])
        assert stored is not None
        assert stored.sats_ext == 0  # receipt itself carries no rank value


@pytest.mark.asyncio
async def test_duplicate_receipt_credits_once(client):
    note = _make_note("dup target")
    await _store_note(note)

    receipt = _make_receipt(_make_zap_request(note["id"]))
    await _send(receipt)
    conn = await _send(receipt)

    assert conn.sent[-1][2] is True  # duplicate acked
    assert (await _get_sats(note["id"]))[1] == 21  # not 42


@pytest.mark.asyncio
async def test_amount_mismatch_rejected(client):
    note = _make_note("mismatch target")
    await _store_note(note)

    # zap request says 42000 msat, bolt11 says 21000
    receipt = _make_receipt(_make_zap_request(note["id"], amount_msat=42000))
    conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "amount" in conn.sent[-1][3]
    assert (await _get_sats(note["id"]))[1] == 0


@pytest.mark.asyncio
async def test_unknown_target_rejected(client):
    receipt = _make_receipt(_make_zap_request("e" * 64))
    conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "not found" in conn.sent[-1][3]


@pytest.mark.asyncio
async def test_tampered_zap_request_rejected(client):
    note = _make_note("tamper target")
    await _store_note(note)

    zap_request = _make_zap_request(note["id"])
    zap_request["content"] = "tampered"  # breaks id/sig
    receipt = _make_receipt(zap_request)
    conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert (await _get_sats(note["id"]))[1] == 0


@pytest.mark.asyncio
async def test_sort_ext_segregated_from_clank(client):
    zapped = _make_note("zapped note")
    unzapped = _make_note("plain note")
    await _store_note(zapped)
    await _store_note(unzapped)
    await _send(_make_receipt(_make_zap_request(zapped["id"])))

    resp = await client.get("/api/v1/events?sort=ext")
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert events[0]["id"] == zapped["id"]
    assert events[0]["sats_ext"] == 21
    assert "sats_clank" not in events[0]  # paid ranking untouched


@pytest.mark.asyncio
async def test_vote_credits_both_rankings(client):
    note = _make_note("voted note")
    await _store_note(note)

    resp = await client.post(f"/api/v1/events/{note['id']}/vote",
                             json={"direction": 1, "amount_sats": 50})
    assert resp.status_code == 200
    data = resp.json()
    assert data["new_sats_clank"] == 50
    assert data["new_sats_ext"] == 50  # fee-inclusive amount joins the fair ranking

    clank, ext = await _get_sats(note["id"])
    assert (clank, ext) == (50, 50)


@pytest.mark.asyncio
async def test_receipt_without_description_rejected(client):
    receipt = sign_event(LNURL_SK, {
        "created_at": int(time.time()),
        "kind": 9735,
        "tags": [["bolt11", "lnbc210n1abc"]],
        "content": "",
    })
    conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "description" in conn.sent[-1][3]
