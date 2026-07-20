"""16.22: bound EXTERNAL_RELAYS kind:0 miss fan-out.

Acceptance:
  (1) Miss wall time ≤ KIND0_FETCH_OVERALL_TIMEOUT (not N × KIND0_FETCH_TIMEOUT).
  (2) Short-TTL negative cache: repeated miss for same pubkey does not re-connect.
  (3) Adversarial: invalid pubkey → None without touching relays.
  (4) Hit still returns when one relay answers within the overall budget.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import patch

import pytest

from app.config import settings
from app.nostr import sign_event
from app.zaps import pubkey_from_privkey

_SK = "d" * 64
_PK = pubkey_from_privkey(_SK)


class _HangWS:
    """Async context manager that never yields a usable relay response."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, _msg):
        return None

    async def recv(self):
        await asyncio.sleep(60)
        raise AssertionError("recv should have been cancelled by overall deadline")


class _EmptyEOSE:
    """Relay that immediately EOSE with no EVENT (cache miss)."""

    def __init__(self, pubkey: str, connect_log: list):
        self._sub = f"k0-{pubkey[:16]}"
        self._connect_log = connect_log
        self._eos_sent = False

    async def __aenter__(self):
        self._connect_log.append(1)
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, _msg):
        return None

    async def recv(self):
        if not self._eos_sent:
            self._eos_sent = True
            return json.dumps(["EOSE", self._sub])
        await asyncio.sleep(60)
        raise AssertionError("unexpected second recv")


class _HitWS:
    """Relay that returns one valid kind:0 then EOSE."""

    def __init__(self, event: dict, pubkey: str):
        self._event = event
        self._sub = f"k0-{pubkey[:16]}"
        self._step = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, _msg):
        return None

    async def recv(self):
        self._step += 1
        if self._step == 1:
            return json.dumps(["EVENT", self._sub, self._event])
        if self._step == 2:
            return json.dumps(["EOSE", self._sub])
        await asyncio.sleep(60)
        raise AssertionError("unexpected recv")


@pytest.fixture(autouse=True)
def _clear_kind0_miss_cache():
    from app import ingest

    clear = getattr(ingest, "clear_kind0_miss_cache", None)
    if clear:
        clear()
    yield
    if clear:
        clear()


@pytest.mark.asyncio
async def test_kind0_miss_respects_overall_deadline_not_n_times_per_relay():
    """Serial N×per-relay timeout must not apply; overall budget caps wall time."""
    from app import ingest
    from app.ingest import (
        KIND0_FETCH_OVERALL_TIMEOUT,
        KIND0_FETCH_TIMEOUT,
        fetch_author_kind0,
    )

    assert KIND0_FETCH_OVERALL_TIMEOUT <= KIND0_FETCH_TIMEOUT
    assert KIND0_FETCH_OVERALL_TIMEOUT <= 8

    def hang_connect(*_a, **_k):
        return _HangWS()

    with (
        patch.object(settings, "EXTERNAL_RELAYS", "wss://a.example,wss://b.example,wss://c.example"),
        patch.object(ingest, "KIND0_FETCH_TIMEOUT", 5.0),
        patch.object(ingest, "KIND0_FETCH_OVERALL_TIMEOUT", 1.2),
        patch("app.ingest.websockets.connect", side_effect=hang_connect),
    ):
        t0 = time.monotonic()
        result = await fetch_author_kind0(_PK)
        elapsed = time.monotonic() - t0

    assert result is None
    # Without overall budget, 3×5s = 15s. With budget 1.2s, must finish well under serial.
    assert elapsed < 3.0, f"miss took {elapsed:.2f}s — still serial fan-out?"
    assert elapsed >= 1.0, f"miss finished too fast ({elapsed:.2f}s); deadline not exercised"


@pytest.mark.asyncio
async def test_kind0_negative_cache_skips_relay_reconnect_within_ttl():
    """Second miss for same pubkey must not re-open WebSockets within TTL."""
    from app import ingest
    from app.ingest import (
        KIND0_NEGATIVE_CACHE_TTL,
        clear_kind0_miss_cache,
        fetch_author_kind0,
    )

    assert KIND0_NEGATIVE_CACHE_TTL <= 60
    assert KIND0_NEGATIVE_CACHE_TTL >= 5

    connect_log: list = []

    def empty_connect(*_a, **_k):
        return _EmptyEOSE(_PK, connect_log)

    clear_kind0_miss_cache()
    with (
        patch.object(settings, "EXTERNAL_RELAYS", "wss://a.example,wss://b.example"),
        patch.object(ingest, "KIND0_FETCH_OVERALL_TIMEOUT", 3.0),
        patch("app.ingest.websockets.connect", side_effect=empty_connect),
    ):
        assert await fetch_author_kind0(_PK) is None
        first_calls = len(connect_log)
        assert first_calls >= 1

        assert await fetch_author_kind0(_PK) is None
        assert len(connect_log) == first_calls, "negative cache must skip reconnect"

        # Past TTL → fan-out again
        with patch("app.ingest.time.time", return_value=time.time() + KIND0_NEGATIVE_CACHE_TTL + 1):
            assert await fetch_author_kind0(_PK) is None
            assert len(connect_log) > first_calls


@pytest.mark.asyncio
async def test_kind0_invalid_pubkey_skips_relays():
    from app.ingest import fetch_author_kind0

    calls = []

    def boom(*_a, **_k):
        calls.append(1)
        raise AssertionError("must not connect for bad pubkey")

    with patch("app.ingest.websockets.connect", side_effect=boom):
        assert await fetch_author_kind0("not-a-pubkey") is None
        assert await fetch_author_kind0("ab") is None
        assert await fetch_author_kind0("") is None
    assert calls == []


@pytest.mark.asyncio
async def test_kind0_hit_returns_within_overall_budget():
    """First successful EVENT still wins inside the overall deadline."""
    from app import ingest
    from app.ingest import fetch_author_kind0

    event = sign_event(
        _SK,
        {
            "kind": 0,
            "created_at": int(time.time()) - 5,
            "tags": [],
            "content": json.dumps({"name": "FanoutHit", "lud16": "hit@example.com"}),
        },
    )

    def hit_connect(*_a, **_k):
        return _HitWS(event, _PK)

    with (
        patch.object(settings, "EXTERNAL_RELAYS", "wss://hit.example,wss://slow.example"),
        patch.object(ingest, "KIND0_FETCH_OVERALL_TIMEOUT", 2.0),
        patch("app.ingest.websockets.connect", side_effect=hit_connect),
    ):
        t0 = time.monotonic()
        got = await fetch_author_kind0(_PK)
        elapsed = time.monotonic() - t0

    assert got is not None
    assert got["id"] == event["id"]
    assert elapsed < 2.0
