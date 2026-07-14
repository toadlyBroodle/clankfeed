"""Tests for NIP-57 zap receipt ingestion and the sats_ext fair ranking."""

import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.database import async_session
from app.models import NostrEvent, Vote
from app.nostr import sign_event
from app.relay import _handle_event, store_event
from app.zaps import bolt11_amount_msat, lud16_to_lnurlp_url

AUTHOR_SK = "b" * 64
SENDER_SK = "c" * 64
LNURL_SK = "d" * 64
FORGER_SK = "e" * 64

# Derived once for fixtures that need the LNURL server's nostrPubkey hex.
LNURL_PUBKEY = sign_event(LNURL_SK, {
    "created_at": 1, "kind": 1, "tags": [], "content": "",
})["pubkey"]
AUTHOR_PUBKEY = sign_event(AUTHOR_SK, {
    "created_at": 1, "kind": 1, "tags": [], "content": "",
})["pubkey"]

AUTHOR_LUD16 = "alice@example.com"


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


def _make_zap_request(target_id: str, amount_msat: int = 21000, recipient: str = AUTHOR_PUBKEY):
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


def _make_receipt(zap_request: dict, bolt11: str = "lnbc210n1fakedata", sk: str = LNURL_SK):
    return sign_event(sk, {
        "created_at": int(time.time()),
        "kind": 9735,
        "tags": [
            ["p", AUTHOR_PUBKEY],
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


def _mock_lnurl_pubkey(pubkey: str = LNURL_PUBKEY):
    """Patch the LNURL metadata fetch used by signer verification."""
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


def test_lud16_to_lnurlp_url():
    assert lud16_to_lnurlp_url("alice@example.com") == (
        "https://example.com/.well-known/lnurlp/alice"
    )
    assert lud16_to_lnurlp_url("bob@ln.example.org") == (
        "https://ln.example.org/.well-known/lnurlp/bob"
    )
    assert lud16_to_lnurlp_url("not-an-address") is None
    assert lud16_to_lnurlp_url("") is None
    assert lud16_to_lnurlp_url("a@b@c") is None


@pytest.mark.asyncio
async def test_zap_receipt_credits_sats_ext_full(client):
    note = _make_note()
    await _store_note(note)
    await _store_author_profile()

    receipt = _make_receipt(_make_zap_request(note["id"]))
    with _mock_lnurl_pubkey():
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
    await _store_author_profile()

    receipt = _make_receipt(_make_zap_request(note["id"]))
    with _mock_lnurl_pubkey():
        await _send(receipt)
        conn = await _send(receipt)

    assert conn.sent[-1][2] is True  # duplicate acked
    assert (await _get_sats(note["id"]))[1] == 21  # not 42


@pytest.mark.asyncio
async def test_amount_mismatch_rejected(client):
    note = _make_note("mismatch target")
    await _store_note(note)
    await _store_author_profile()

    # zap request says 42000 msat, bolt11 says 21000
    receipt = _make_receipt(_make_zap_request(note["id"], amount_msat=42000))
    with _mock_lnurl_pubkey():
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "amount" in conn.sent[-1][3]
    assert (await _get_sats(note["id"]))[1] == 0


@pytest.mark.asyncio
async def test_unknown_target_rejected(client):
    receipt = _make_receipt(_make_zap_request("e" * 64))
    with _mock_lnurl_pubkey():
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "not found" in conn.sent[-1][3]


@pytest.mark.asyncio
async def test_tampered_zap_request_rejected(client):
    note = _make_note("tamper target")
    await _store_note(note)
    await _store_author_profile()

    zap_request = _make_zap_request(note["id"])
    zap_request["content"] = "tampered"  # breaks id/sig
    receipt = _make_receipt(zap_request)
    with _mock_lnurl_pubkey():
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert (await _get_sats(note["id"]))[1] == 0


@pytest.mark.asyncio
async def test_sort_ext_segregated_from_clank(client):
    zapped = _make_note("zapped note")
    unzapped = _make_note("plain note")
    await _store_note(zapped)
    await _store_note(unzapped)
    await _store_author_profile()
    with _mock_lnurl_pubkey():
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


# --- EXT-1: LNURL nostrPubkey signer verification ---


@pytest.mark.asyncio
async def test_forged_receipt_signer_rejected(client):
    """Adversarial: well-formed receipt signed by a non-LNURL key must not credit."""
    note = _make_note("forge target")
    await _store_note(note)
    await _store_author_profile()

    receipt = _make_receipt(_make_zap_request(note["id"]), sk=FORGER_SK)
    with _mock_lnurl_pubkey(LNURL_PUBKEY):
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "nostrPubkey" in conn.sent[-1][3] or "signer" in conn.sent[-1][3].lower()
    assert (await _get_sats(note["id"]))[1] == 0


@pytest.mark.asyncio
async def test_receipt_without_author_lud16_rejected(client):
    """Fail closed: no kind:0 lud16 for the zapped author → drop receipt."""
    note = _make_note("no lud16")
    await _store_note(note)
    # deliberately no profile

    receipt = _make_receipt(_make_zap_request(note["id"]))
    with _mock_lnurl_pubkey():
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "lud16" in conn.sent[-1][3].lower()
    assert (await _get_sats(note["id"]))[1] == 0


@pytest.mark.asyncio
async def test_receipt_when_lnurl_fetch_fails_rejected(client):
    """Fail closed: LNURL metadata unreachable / no nostrPubkey → drop."""
    note = _make_note("lnurl down")
    await _store_note(note)
    await _store_author_profile()

    receipt = _make_receipt(_make_zap_request(note["id"]))
    with patch("app.zaps.fetch_lnurl_nostr_pubkey", new_callable=AsyncMock, return_value=None):
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert (await _get_sats(note["id"]))[1] == 0


@pytest.mark.asyncio
async def test_fetch_lnurl_nostr_pubkey_http_and_cache(client):
    """Real fetch path: HTTP GET lud16 → nostrPubkey; second call hits cache."""
    import socket

    from app.zaps import clear_lnurl_cache, fetch_lnurl_nostr_pubkey

    clear_lnurl_cache()
    calls = []

    async def fake_get(url, pinned_ip):
        calls.append((url, pinned_ip))
        return (
            200,
            {
                "allowsNostr": True,
                "nostrPubkey": LNURL_PUBKEY,
                "callback": "https://example.com/cb",
            },
        )

    public = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
    ]
    with (
        patch("app.zaps.socket.getaddrinfo", return_value=public),
        patch("app.zaps.lnurl_http_get", side_effect=fake_get),
    ):
        pk1 = await fetch_lnurl_nostr_pubkey(AUTHOR_LUD16)
        pk2 = await fetch_lnurl_nostr_pubkey(AUTHOR_LUD16)

    assert pk1 == LNURL_PUBKEY
    assert pk2 == LNURL_PUBKEY
    assert calls == [
        ("https://example.com/.well-known/lnurlp/alice", "8.8.8.8")
    ]  # cached; single pinned GET


@pytest.mark.asyncio
async def test_ingest_drops_forged_receipt(client):
    """Ingest path: forged receipt must not credit sats_ext on an external note."""
    from app.ingest import _handle_receipt

    note = _make_note("ingest forge")
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="external")
    await _store_author_profile()

    class FakeWS:
        def __init__(self):
            self.sent = []

        async def send(self, msg):
            self.sent.append(msg)

    receipt = _make_receipt(_make_zap_request(note["id"]), sk=FORGER_SK)
    pending = {}
    with _mock_lnurl_pubkey(LNURL_PUBKEY):
        await _handle_receipt(FakeWS(), receipt, pending)

    assert (await _get_sats(note["id"]))[1] == 0
    assert pending == {}  # not parked either


@pytest.mark.asyncio
async def test_ingest_credits_verified_receipt(client):
    """Ingest path: receipt signed by LNURL nostrPubkey credits sats_ext."""
    from app.ingest import _handle_receipt

    note = _make_note("ingest ok")
    async with async_session() as db:
        await store_event(db, note, sats_clank=0, origin="external")
    await _store_author_profile()

    class FakeWS:
        async def send(self, msg):
            pass

    receipt = _make_receipt(_make_zap_request(note["id"]))
    with _mock_lnurl_pubkey(LNURL_PUBKEY):
        await _handle_receipt(FakeWS(), receipt, {})

    assert (await _get_sats(note["id"]))[1] == 21


# --- EXT-1b: SSRF block on lud16 LNURL targets ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "lud16",
    [
        "x@127.0.0.1",
        "x@10.0.0.1",
        "x@192.168.1.1",
        "x@169.254.169.254",
        "x@localhost",
        "x@metadata.google.internal",
    ],
)
async def test_fetch_lnurl_rejects_non_public_targets(lud16, client):
    """Adversarial: loopback/private/link-local/metadata lud16 must not HTTP GET."""
    from app.zaps import clear_lnurl_cache, fetch_lnurl_nostr_pubkey

    clear_lnurl_cache()
    get_calls = []

    async def fake_get(url, pinned_ip):
        get_calls.append((url, pinned_ip))
        raise AssertionError(f"SSRF: must not GET {url} via {pinned_ip}")

    with patch("app.zaps.lnurl_http_get", side_effect=fake_get):
        pk = await fetch_lnurl_nostr_pubkey(lud16)

    assert pk is None
    assert get_calls == []


@pytest.mark.asyncio
async def test_fetch_lnurl_rejects_hostname_resolving_to_private_ip(client):
    """Hostname that DNS-resolves to a private address must not be fetched."""
    import socket

    from app.zaps import clear_lnurl_cache, fetch_lnurl_nostr_pubkey

    clear_lnurl_cache()
    get_calls = []

    async def fake_get(url, pinned_ip):
        get_calls.append((url, pinned_ip))
        raise AssertionError(f"SSRF: must not GET {url} via {pinned_ip}")

    # (family, type, proto, canonname, sockaddr)
    private_addrs = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443)),
    ]

    with (
        patch("app.zaps.socket.getaddrinfo", return_value=private_addrs),
        patch("app.zaps.lnurl_http_get", side_effect=fake_get),
    ):
        pk = await fetch_lnurl_nostr_pubkey("alice@evil.example.com")

    assert pk is None
    assert get_calls == []


# --- EXT-1c: short TTL for negative/error LNURL cache ---


@pytest.mark.asyncio
async def test_fetch_lnurl_negative_cache_short_ttl(client):
    """Transport/HTTP failure caches None briefly; success keeps long TTL."""
    import socket

    from app.zaps import (
        _LNURL_CACHE_TTL,
        _LNURL_NEGATIVE_CACHE_TTL,
        clear_lnurl_cache,
        fetch_lnurl_nostr_pubkey,
    )

    assert _LNURL_NEGATIVE_CACHE_TTL <= 60
    assert _LNURL_CACHE_TTL >= 3600

    clear_lnurl_cache()
    calls = []
    mode = {"v": "fail"}

    async def fake_get(url, pinned_ip):
        calls.append(url)
        if mode["v"] == "fail":
            return (503, None)
        return (
            200,
            {
                "allowsNostr": True,
                "nostrPubkey": LNURL_PUBKEY,
                "callback": "https://example.com/cb",
            },
        )

    public = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
    ]
    with (
        patch("app.zaps.socket.getaddrinfo", return_value=public),
        patch("app.zaps.lnurl_http_get", side_effect=fake_get),
    ):
        assert await fetch_lnurl_nostr_pubkey(AUTHOR_LUD16) is None
        assert await fetch_lnurl_nostr_pubkey(AUTHOR_LUD16) is None  # negative cache hit
        assert len(calls) == 1

        # Advance past negative TTL → retry
        with patch("app.zaps.time.time", return_value=time.time() + _LNURL_NEGATIVE_CACHE_TTL + 1):
            mode["v"] = "ok"
            pk = await fetch_lnurl_nostr_pubkey(AUTHOR_LUD16)
            assert pk == LNURL_PUBKEY
            assert len(calls) == 2

            # Success cache still valid within long TTL (far short of 1h)
            with patch(
                "app.zaps.time.time",
                return_value=time.time() + _LNURL_NEGATIVE_CACHE_TTL + 30,
            ):
                assert await fetch_lnurl_nostr_pubkey(AUTHOR_LUD16) == LNURL_PUBKEY
                assert len(calls) == 2  # no third GET


# --- EXT-1d: zap-request p ≠ note author ---


@pytest.mark.asyncio
async def test_receipt_p_tag_mismatch_rejected(client):
    """Adversarial: zap-request p ≠ target note author → OK false, sats_ext unchanged."""
    other_pk = sign_event(FORGER_SK, {
        "created_at": 1, "kind": 1, "tags": [], "content": "",
    })["pubkey"]

    note = _make_note("wrong p target")
    await _store_note(note)
    await _store_author_profile()

    # Valid LNURL signer, but p points at a different pubkey than the note author
    receipt = _make_receipt(_make_zap_request(note["id"], recipient=other_pk))
    with _mock_lnurl_pubkey(LNURL_PUBKEY):
        conn = await _send(receipt)

    assert conn.sent[-1][2] is False
    assert "p" in conn.sent[-1][3].lower() or "author" in conn.sent[-1][3].lower()
    assert (await _get_sats(note["id"]))[1] == 0


# --- EXT-1e: pin validated IP (DNS rebinding TOCTOU) ---


@pytest.mark.asyncio
async def test_fetch_lnurl_pins_ip_against_dns_rebinding(client):
    """Adversarial: DNS public→private rebind must not SSRF; GET uses pinned IP."""
    import socket

    from app.zaps import clear_lnurl_cache, fetch_lnurl_nostr_pubkey

    clear_lnurl_cache()
    # Use a globally-routable IP: 203.0.113.0/24 is is_private under ipaddress.
    public_ip = "8.8.8.8"
    resolve_calls = []
    get_meta = []  # (pinned_ip, url_hostname)

    def rebinding_gai(host, *a, **k):
        resolve_calls.append(host)
        if len(resolve_calls) == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (public_ip, 443))]
        # TOCTOU rebind: second lookup would SSRF if used for connect
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    async def fake_get(url, pinned_ip):
        from urllib.parse import urlparse

        hostname = urlparse(url).hostname
        get_meta.append((pinned_ip, hostname))
        if pinned_ip in ("127.0.0.1", "::1") or pinned_ip.startswith("10."):
            raise AssertionError(f"SSRF: GET connected via private host {pinned_ip}")
        return (
            200,
            {
                "allowsNostr": True,
                "nostrPubkey": LNURL_PUBKEY,
                "callback": "https://evil.example.com/cb",
            },
        )

    with (
        patch("app.zaps.socket.getaddrinfo", side_effect=rebinding_gai),
        patch("app.zaps.lnurl_http_get", side_effect=fake_get),
    ):
        pk = await fetch_lnurl_nostr_pubkey("alice@evil.example.com")

    assert pk == LNURL_PUBKEY
    assert len(resolve_calls) == 1, "must resolve DNS once (no second lookup for connect)"
    assert get_meta == [(public_ip, "evil.example.com")], (
        "GET must pin validated public IP with URL host=original hostname"
    )


# --- EXT-1f: async DNS (do not block the event loop) ---


@pytest.mark.asyncio
async def test_lnurl_dns_not_on_event_loop_thread(client):
    """socket.getaddrinfo must not run on the asyncio event-loop thread."""
    import socket
    import threading

    from app.zaps import clear_lnurl_cache, fetch_lnurl_nostr_pubkey

    clear_lnurl_cache()
    loop_ident = threading.get_ident()
    called_on_loop = []

    def tracking_gai(host, *a, **k):
        called_on_loop.append(threading.get_ident() == loop_ident)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    async def fake_get(url, pinned_ip):
        return (
            200,
            {
                "allowsNostr": True,
                "nostrPubkey": LNURL_PUBKEY,
            },
        )

    with (
        patch("app.zaps.socket.getaddrinfo", side_effect=tracking_gai),
        patch("app.zaps.lnurl_http_get", side_effect=fake_get),
    ):
        pk = await fetch_lnurl_nostr_pubkey("alice@example.com")

    assert pk == LNURL_PUBKEY
    assert called_on_loop, "expected getaddrinfo to run during fetch"
    assert called_on_loop == [False], (
        "getaddrinfo must run off the event-loop thread (asyncio.to_thread)"
    )


# --- EXT-1g: IDN Host header must use punycode (not UnicodeEncodeError) ---


@pytest.mark.asyncio
async def test_lnurl_http_get_idn_host_uses_punycode():
    """IDN hostname must go out as IDNA/punycode Host; ascii encode must not fail."""
    from app.zaps import lnurl_http_get

    idn_host = "münchen.de"
    punycode = idn_host.encode("idna").decode("ascii")
    assert punycode.startswith("xn--"), "fixture sanity: expect A-label"

    written = []
    open_kwargs = {}

    class FakeWriter:
        def write(self, data):
            written.append(data)

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    class FakeReader:
        async def read(self, n):
            body = b'{"allowsNostr":true,"nostrPubkey":"' + LNURL_PUBKEY.encode() + b'"}'
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )

    async def fake_open(*args, **kwargs):
        open_kwargs.update(kwargs)
        open_kwargs["_args"] = args
        return FakeReader(), FakeWriter()

    with patch("app.zaps.asyncio.open_connection", side_effect=fake_open):
        status, data = await lnurl_http_get(
            f"https://{idn_host}/.well-known/lnurlp/alice",
            "8.8.8.8",
        )

    assert status == 200
    assert data is not None
    assert written, "expected HTTP request bytes written"
    req = written[0].decode("ascii")  # must be pure ASCII (punycode Host)
    assert f"Host: {punycode}\r\n" in req, f"Host must be punycode, got:\n{req}"
    assert idn_host not in req, "Unicode U-label must not appear in Host header"
    assert open_kwargs.get("server_hostname") == punycode


# --- EXT-1h: open_connection must use pinned IP + SNI hostname ---


@pytest.mark.asyncio
async def test_lnurl_http_get_opens_connection_to_pinned_ip():
    """CI must assert connect host=pinned_ip and server_hostname=URL host."""
    from app.zaps import lnurl_http_get

    pinned_ip = "203.0.113.50"
    hostname = "lnurl.example.com"
    open_calls = []

    class FakeWriter:
        def write(self, data):
            return None

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    class FakeReader:
        async def read(self, n):
            body = b'{"ok":true}'
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )

    async def fake_open(*args, **kwargs):
        open_calls.append((args, kwargs))
        return FakeReader(), FakeWriter()

    with patch("app.zaps.asyncio.open_connection", side_effect=fake_open):
        status, _ = await lnurl_http_get(
            f"https://{hostname}/.well-known/lnurlp/bob",
            pinned_ip,
        )

    assert status == 200
    assert len(open_calls) == 1
    args, kwargs = open_calls[0]
    # asyncio.open_connection(host, port, ..., server_hostname=...)
    assert args[0] == pinned_ip, f"must connect to pinned IP, got {args[0]!r}"
    assert args[0] != hostname, "must not reconnect by hostname (DNS rebinding)"
    assert kwargs.get("server_hostname") == hostname
    assert "ssl" in kwargs and kwargs["ssl"] is not None
