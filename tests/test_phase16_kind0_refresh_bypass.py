"""16.23: ?refresh=1 must bypass _kind0_miss_cache.

Acceptance:
  (1) After a confirmed miss is negative-cached, fetch_author_kind0(...,
      bypass_negative_cache=True) re-opens EXTERNAL_RELAYS.
  (2) GET /api/v1/profile/{pk}?refresh=1 after a cached miss contacts relays
      (does not return found:false solely from the TTL gate).
  (3) Adversarial: default (no bypass) still honors the negative cache.
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

_SK = "e" * 64
_PK = pubkey_from_privkey(_SK)


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

    def __init__(self, event: dict, pubkey: str, connect_log: list):
        self._event = event
        self._sub = f"k0-{pubkey[:16]}"
        self._connect_log = connect_log
        self._step = 0

    async def __aenter__(self):
        self._connect_log.append(1)
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
async def test_bypass_negative_cache_reopens_relays_after_miss():
    """Cached miss + bypass_negative_cache=True → reconnect; default still skips."""
    from app import ingest
    from app.ingest import clear_kind0_miss_cache, fetch_author_kind0

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

        # Default path still honors negative cache
        assert await fetch_author_kind0(_PK) is None
        assert len(connect_log) == first_calls

        # Forced re-fetch must bypass TTL and re-open relays
        assert await fetch_author_kind0(_PK, bypass_negative_cache=True) is None
        assert len(connect_log) > first_calls, (
            "bypass_negative_cache must re-contact EXTERNAL_RELAYS after a cached miss"
        )


@pytest.mark.asyncio
async def test_profile_refresh_bypasses_miss_cache_and_returns_hit(client):
    """After miss caches, ?refresh=1 must fetch EXTERNAL_RELAYS and can return found."""
    from app import ingest
    from app.ingest import clear_kind0_miss_cache, fetch_author_kind0

    event = sign_event(
        _SK,
        {
            "kind": 0,
            "created_at": int(time.time()) - 5,
            "tags": [],
            "content": json.dumps({"name": "RefreshHit", "lud16": "refresh@example.com"}),
        },
    )
    connect_log: list = []
    mode = {"hit": False}

    def connect_factory(*_a, **_k):
        if mode["hit"]:
            return _HitWS(event, _PK, connect_log)
        return _EmptyEOSE(_PK, connect_log)

    clear_kind0_miss_cache()
    with (
        patch.object(settings, "EXTERNAL_RELAYS", "wss://refresh.example"),
        patch.object(ingest, "KIND0_FETCH_OVERALL_TIMEOUT", 3.0),
        patch("app.ingest.websockets.connect", side_effect=connect_factory),
    ):
        # Populate negative cache via real fetch (no local kind:0)
        assert await fetch_author_kind0(_PK) is None
        miss_calls = len(connect_log)
        assert miss_calls >= 1

        # Without refresh, endpoint should not re-open relays (cached miss)
        resp_cached = await client.get(f"/api/v1/profile/{_PK}")
        assert resp_cached.status_code == 200
        assert resp_cached.json().get("found") is False
        assert len(connect_log) == miss_calls

        # ?refresh=1 must bypass cache and contact relays; profile appears
        mode["hit"] = True
        resp = await client.get(f"/api/v1/profile/{_PK}?refresh=1")

    assert resp.status_code == 200
    body = resp.json()
    assert body.get("found") is True, (
        "refresh=1 after cached miss must re-fetch EXTERNAL_RELAYS, not return found:false from TTL"
    )
    assert body["profile"]["name"] == "RefreshHit"
    assert len(connect_log) > miss_calls


@pytest.mark.asyncio
async def test_bypass_false_keeps_negative_cache_default():
    """Adversarial: explicit bypass_negative_cache=False still skips reconnect."""
    from app import ingest
    from app.ingest import clear_kind0_miss_cache, fetch_author_kind0

    connect_log: list = []

    def empty_connect(*_a, **_k):
        return _EmptyEOSE(_PK, connect_log)

    clear_kind0_miss_cache()
    with (
        patch.object(settings, "EXTERNAL_RELAYS", "wss://a.example"),
        patch.object(ingest, "KIND0_FETCH_OVERALL_TIMEOUT", 3.0),
        patch("app.ingest.websockets.connect", side_effect=empty_connect),
    ):
        assert await fetch_author_kind0(_PK) is None
        n = len(connect_log)
        assert await fetch_author_kind0(_PK, bypass_negative_cache=False) is None
        assert len(connect_log) == n
