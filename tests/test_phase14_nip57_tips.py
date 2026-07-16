"""Phase 14.7 + EXT-1a: NIP-57 tip path — fee/author-leg ranking, no upvote tip."""

import json
import time
from unittest.mock import AsyncMock, patch

import pytest

from app.database import async_session
from app.nostr import sign_event
from app.relay import _handle_event, store_event
from app.zaps import pubkey_from_privkey, relay_pubkey_hex

AUTHOR_SK = "b" * 64
SENDER_SK = "c" * 64
AUTHOR_LNURL_SK = "d" * 64
RELAY_LNURL_SK = "12" * 32  # distinct valid secp256k1 scalar
FORGER_SK = "e" * 64

AUTHOR_PUBKEY = pubkey_from_privkey(AUTHOR_SK)
AUTHOR_LNURL_PUBKEY = pubkey_from_privkey(AUTHOR_LNURL_SK)
RELAY_LNURL_PUBKEY = pubkey_from_privkey(RELAY_LNURL_SK)
RELAY_PK = relay_pubkey_hex()  # conftest RELAY_PRIVATE_KEY = "a"*64

AUTHOR_LUD16 = "alice@example.com"
RELAY_LUD16 = "relay@example.com"


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


def _make_profile(lud16: str = AUTHOR_LUD16, sk: str = AUTHOR_SK):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 0,
        "tags": [],
        "content": json.dumps({"name": "alice", "lud16": lud16}),
    })


def _make_zap_request(target_id: str, recipient: str, amount_msat: int = 21000):
    return sign_event(SENDER_SK, {
        "created_at": int(time.time()),
        "kind": 9734,
        "tags": [
            ["e", target_id],
            ["p", recipient],
            ["amount", str(amount_msat)],
            ["relays", "wss://clankfeed.com"],
        ],
        "content": "",
    })


def _make_receipt(zap_request: dict, *, recipient_tag: str, sk: str, bolt11: str = "lnbc210n1fakedata"):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 9735,
        "tags": [
            ["p", recipient_tag],
            ["bolt11", bolt11],
            ["description", json.dumps(zap_request)],
        ],
        "content": "",
    })


async def _store_note(note: dict):
    async with async_session() as db:
        await store_event(db, note, sats_clank=0)


async def _store_author_profile(lud16: str = AUTHOR_LUD16):
    async with async_session() as db:
        await store_event(db, _make_profile(lud16), sats_clank=0)


def _mock_lnurl(pubkey: str):
    return patch(
        "app.zaps.fetch_lnurl_nostr_pubkey",
        new_callable=AsyncMock,
        return_value=pubkey,
    )


async def _send(event: dict) -> FakeConn:
    conn = FakeConn()
    async with async_session() as db:
        await _handle_event(conn, ["EVENT", event], db)
    return conn


async def _get_sats(event_id: str) -> tuple[int, int]:
    from app.models import NostrEvent
    async with async_session() as db:
        row = await db.get(NostrEvent, event_id)
        return row.sats_clank or 0, row.sats_ext or 0


# ---------------------------------------------------------------------------
# 14.7 — receipt ranking: author-leg vs fee-leg
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_author_leg_credits_sats_ext_only(client, monkeypatch):
    """Author-leg (p = note author): sats_ext += amount; sats_clank untouched."""
    monkeypatch.setattr("app.config.settings.RELAY_LUD16", RELAY_LUD16)
    note = _make_note("author leg")
    await _store_note(note)
    await _store_author_profile()

    zr = _make_zap_request(note["id"], AUTHOR_PUBKEY)
    receipt = _make_receipt(zr, recipient_tag=AUTHOR_PUBKEY, sk=AUTHOR_LNURL_SK)
    with _mock_lnurl(AUTHOR_LNURL_PUBKEY):
        conn = await _send(receipt)

    assert conn.sent[-1][2] is True
    clank, ext = await _get_sats(note["id"])
    assert (clank, ext) == (0, 21)


@pytest.mark.asyncio
async def test_fee_leg_credits_sats_clank_and_sats_ext(client, monkeypatch):
    """Fee-leg (p = relay): sats_clank += amount AND sats_ext += amount."""
    monkeypatch.setattr("app.config.settings.RELAY_LUD16", RELAY_LUD16)
    note = _make_note("fee leg")
    await _store_note(note)

    zr = _make_zap_request(note["id"], RELAY_PK, amount_msat=21000)
    receipt = _make_receipt(zr, recipient_tag=RELAY_PK, sk=RELAY_LNURL_SK)
    with _mock_lnurl(RELAY_LNURL_PUBKEY):
        conn = await _send(receipt)

    assert conn.sent[-1][2] is True, conn.sent[-1]
    clank, ext = await _get_sats(note["id"])
    assert (clank, ext) == (21, 21)


@pytest.mark.asyncio
async def test_fee_leg_rejected_without_relay_lud16(client, monkeypatch):
    """Fail-closed: fee-leg needs RELAY_LUD16 configured."""
    monkeypatch.setattr("app.config.settings.RELAY_LUD16", "")
    note = _make_note("no relay lud16")
    await _store_note(note)

    zr = _make_zap_request(note["id"], RELAY_PK)
    receipt = _make_receipt(zr, recipient_tag=RELAY_PK, sk=RELAY_LNURL_SK)
    with _mock_lnurl(RELAY_LNURL_PUBKEY):
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "lud16" in conn.sent[-1][3].lower() or "relay" in conn.sent[-1][3].lower()
    assert (await _get_sats(note["id"])) == (0, 0)


@pytest.mark.asyncio
async def test_fee_leg_forged_signer_rejected(client, monkeypatch):
    """Adversarial: fee-leg receipt not signed by RELAY_LUD16 nostrPubkey."""
    monkeypatch.setattr("app.config.settings.RELAY_LUD16", RELAY_LUD16)
    note = _make_note("forge fee")
    await _store_note(note)

    zr = _make_zap_request(note["id"], RELAY_PK)
    receipt = _make_receipt(zr, recipient_tag=RELAY_PK, sk=FORGER_SK)
    with _mock_lnurl(RELAY_LNURL_PUBKEY):
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert (await _get_sats(note["id"])) == (0, 0)


@pytest.mark.asyncio
async def test_author_plus_fee_legs_accumulate(client, monkeypatch):
    """Both legs of a 90/10 split credit independently."""
    monkeypatch.setattr("app.config.settings.RELAY_LUD16", RELAY_LUD16)
    note = _make_note("split")
    await _store_note(note)
    await _store_author_profile()

    author_zr = _make_zap_request(note["id"], AUTHOR_PUBKEY, amount_msat=90000)  # 90 sats
    fee_zr = _make_zap_request(note["id"], RELAY_PK, amount_msat=10000)  # 10 sats
    author_receipt = _make_receipt(
        author_zr, recipient_tag=AUTHOR_PUBKEY, sk=AUTHOR_LNURL_SK, bolt11="lnbc900n1fake"
    )
    fee_receipt = _make_receipt(
        fee_zr, recipient_tag=RELAY_PK, sk=RELAY_LNURL_SK, bolt11="lnbc100n1fake"
    )

    async def lnurl_side(lud16):
        if lud16 == AUTHOR_LUD16:
            return AUTHOR_LNURL_PUBKEY
        if lud16 == RELAY_LUD16:
            return RELAY_LNURL_PUBKEY
        return None

    with patch("app.zaps.fetch_lnurl_nostr_pubkey", new_callable=AsyncMock, side_effect=lnurl_side):
        c1 = await _send(author_receipt)
        c2 = await _send(fee_receipt)

    assert c1.sent[-1][2] is True
    assert c2.sent[-1][2] is True
    clank, ext = await _get_sats(note["id"])
    assert clank == 10
    assert ext == 100  # 90 author + 10 fee


# ---------------------------------------------------------------------------
# 14.7 — drop custodial upvote invoice-as-tip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upvote_rejected_use_nip57(client):
    """direction=1 must not invoice the relay as a tip — use NIP-57 zap."""
    resp = await client.post("/api/v1/post", json={"content": "no upvote tip"})
    eid = resp.json()["event"]["id"]

    resp = await client.post(
        f"/api/v1/events/{eid}/vote",
        json={"direction": 1, "amount_sats": 50},
    )
    assert resp.status_code in (400, 410)
    detail = str(resp.json().get("detail", "")).lower()
    assert "nip-57" in detail or "zap" in detail or "upvote" in detail


@pytest.mark.asyncio
async def test_downvote_still_accepted(client):
    """Downvote (anti-signal) remains L402/MPP-gated; free in test-mode."""
    resp = await client.post("/api/v1/post", json={"content": "down me", "amount_sats": 100})
    eid = resp.json()["event"]["id"]

    resp = await client.post(
        f"/api/v1/events/{eid}/vote",
        json={"direction": -1, "amount_sats": 30},
    )
    assert resp.status_code == 200
    assert resp.json()["new_sats_clank"] == 70


@pytest.mark.asyncio
async def test_confirm_upvote_rejected(client):
    """14.18: direction=1 confirm → 410 before status/consume; pending deleted."""
    import secrets
    from datetime import datetime, timedelta, timezone

    from app.models import PendingEvent

    resp = await client.post("/api/v1/post", json={"content": "confirm upvote"})
    eid = resp.json()["event"]["id"]
    token = secrets.token_hex(16)
    payment_hash = "ab" * 32
    vote_data = {
        "vote_event_id": eid,
        "direction": 1,
        "amount_sats": 50,
        "amount_usd": "0.01",
    }
    async with async_session() as db:
        db.add(PendingEvent(
            token=token,
            event_json=json.dumps(vote_data),
            payment_hash=payment_hash,
            amount_sats=50,
            amount_usd="0.01",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ))
        await db.commit()

    mock_status = AsyncMock(return_value=True)
    mock_consume = AsyncMock(return_value=True)
    with patch("app.api_v1.check_payment_status", mock_status), \
         patch("app.api_v1.check_and_consume_payment", mock_consume):
        resp = await client.post(
            f"/api/v1/events/{eid}/vote/confirm",
            json={"token": token, "method": "lightning", "payment_hash": payment_hash},
        )

    assert resp.status_code == 410
    detail = (resp.json().get("detail") or "").lower()
    assert "nip-57" in detail or "zap" in detail or "upvote" in detail
    # Must not burn a paid Lightning hash on a legacy upvote PendingEvent
    mock_status.assert_not_called()
    mock_consume.assert_not_called()
    clank, _ = await _get_sats(eid)
    assert clank == 21  # initial post only — no +50 upvote tip
    async with async_session() as db:
        assert await db.get(PendingEvent, token) is None


# ---------------------------------------------------------------------------
# EXT-1a — fetch kind:0 when lud16 missing locally
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ext1a_fetches_kind0_when_lud16_missing(client):
    """Ingest: missing local kind:0 → fetch+store profile, then credit receipt."""
    from app.ingest import _handle_receipt
    from app.models import NostrEvent

    note = _make_note("ext1a fetch")
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="external")

    profile = _make_profile(AUTHOR_LUD16)
    receipt = _make_receipt(
        _make_zap_request(note["id"], AUTHOR_PUBKEY),
        recipient_tag=AUTHOR_PUBKEY,
        sk=AUTHOR_LNURL_SK,
    )

    class FakeWS:
        async def send(self, msg):
            pass

    async def fake_fetch(pubkey: str):
        assert pubkey == AUTHOR_PUBKEY
        return profile

    with (
        patch(
            "app.ingest.fetch_author_kind0",
            new_callable=AsyncMock,
            side_effect=fake_fetch,
            create=True,
        ),
        _mock_lnurl(AUTHOR_LNURL_PUBKEY),
    ):
        await _handle_receipt(FakeWS(), receipt, {})

    clank, ext = await _get_sats(note["id"])
    assert ext == 21
    async with async_session() as db:
        from sqlalchemy import select
        rows = (await db.execute(
            select(NostrEvent).where(
                NostrEvent.pubkey == AUTHOR_PUBKEY, NostrEvent.kind == 0
            )
        )).scalars().all()
        assert len(rows) >= 1


@pytest.mark.asyncio
async def test_ext1a_fail_closed_when_kind0_fetch_fails(client):
    """Adversarial: no local lud16 and fetch returns None → drop receipt."""
    from app.ingest import _handle_receipt

    note = _make_note("ext1a fail")
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="external")

    receipt = _make_receipt(
        _make_zap_request(note["id"], AUTHOR_PUBKEY),
        recipient_tag=AUTHOR_PUBKEY,
        sk=AUTHOR_LNURL_SK,
    )

    class FakeWS:
        async def send(self, msg):
            pass

    with (
        patch(
            "app.ingest.fetch_author_kind0",
            new_callable=AsyncMock,
            return_value=None,
            create=True,
        ),
        _mock_lnurl(AUTHOR_LNURL_PUBKEY),
    ):
        await _handle_receipt(FakeWS(), receipt, {})

    assert (await _get_sats(note["id"])) == (0, 0)
