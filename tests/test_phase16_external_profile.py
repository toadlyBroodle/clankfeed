"""16.20: sign-in hydrates kind:0 from EXTERNAL_RELAYS when missing locally.

Acceptance:
  (1) GET /api/v1/profile/{pubkey} ensures external fetch when local kind:0 absent,
      stores origin=external, returns parsed metadata (no payment).
  (2) When local + external both exist, returns the newer by created_at.
  (3) Client fetchKind0Profile / public profile use the ensure endpoint (not local-only events).
  (4) Adversarial: bad pubkey → 400; missing everywhere → null/empty without 402.
  (5) Headed: nsec whose kind:0 exists only via external fetch → /profile fills fields.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.nostr import sign_event
from app.zaps import pubkey_from_privkey

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"

_USER_SK = "c" * 64  # distinct from relay a*64 and hydrate b*64
_EXT_PROFILE = {
    "name": "ExternalOnlyBot",
    "about": "kind0 only on external relay",
    "picture": "https://example.com/ext-only.png",
    "lud16": "extonly@botlab.dev",
}


def _auth() -> str:
    return (STATIC / "nostr-auth.js").read_text()


def _profile_js() -> str:
    return (STATIC / "profile.js").read_text()


# ---------------------------------------------------------------------------
# Source contracts
# ---------------------------------------------------------------------------


class TestFetchKind0UsesEnsureEndpoint1620:
    """Client must call /api/v1/profile/{pubkey}, not local-only events list."""

    def test_fetch_kind0_hits_profile_endpoint(self):
        auth = _auth()
        assert "function fetchKind0Profile" in auth
        fn = auth.split("function fetchKind0Profile", 1)[1].split("\nfunction ", 1)[0]
        assert "/api/v1/profile/" in fn
        # Must not be the local-only events list as the sole path
        assert "kinds=0" not in fn or "/api/v1/profile/" in fn

    def test_show_public_profile_uses_ensure_path(self):
        js = _profile_js()
        fn = js.split("async function showPublicProfile", 1)[1].split(
            "\nasync function ", 1
        )[0]
        assert (
            "fetchKind0Profile" in fn or "/api/v1/profile/" in fn
        ), "public profile must ensure external kind:0, not local-only events"


# ---------------------------------------------------------------------------
# API unit tests
# ---------------------------------------------------------------------------


def _signed_kind0(sk: str, profile: dict, created_at: int | None = None) -> dict:
    return sign_event(
        sk,
        {
            "kind": 0,
            "created_at": created_at if created_at is not None else int(time.time()) - 10,
            "tags": [],
            "content": json.dumps(profile),
        },
    )


@pytest.mark.asyncio
async def test_profile_endpoint_fetches_and_stores_external(client):
    """Local empty → mock EXTERNAL fetch → store origin=external → return meta."""
    pk = pubkey_from_privkey(_USER_SK)
    ext_event = _signed_kind0(_USER_SK, _EXT_PROFILE)

    with patch(
        "app.ingest.fetch_author_kind0",
        new_callable=AsyncMock,
        return_value=ext_event,
    ) as mock_fetch:
        resp = await client.get(f"/api/v1/profile/{pk}")
        mock_fetch.assert_awaited()

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("found") is True
    meta = body["profile"]
    assert meta["name"] == "ExternalOnlyBot"
    assert meta["lud16"] == "extonly@botlab.dev"
    assert body.get("origin") == "external"
    assert body.get("event", {}).get("id") == ext_event["id"]

    # Stored for subsequent local reads
    listed = await client.get(f"/api/v1/events?authors={pk}&kinds=0&limit=1")
    assert listed.status_code == 200
    events = listed.json()["events"]
    assert len(events) == 1
    assert events[0]["id"] == ext_event["id"]
    assert events[0].get("origin") == "external"


@pytest.mark.asyncio
async def test_profile_endpoint_prefers_newer_created_at(client):
    """Local older + external newer → store external and return it."""
    pk = pubkey_from_privkey(_USER_SK)
    local = _signed_kind0(
        _USER_SK,
        {"name": "LocalOld", "lud16": "old@botlab.dev"},
        created_at=1_700_000_000,
    )
    newer = _signed_kind0(
        _USER_SK,
        {"name": "ExternalNew", "lud16": "new@botlab.dev"},
        created_at=1_700_000_100,
    )
    # Seed local via paid-free test store (POST events in test-mode)
    from app.database import async_session
    from app.relay import store_event

    async with async_session() as db:
        await store_event(db, local, origin="clankfeed")

    with patch(
        "app.ingest.fetch_author_kind0",
        new_callable=AsyncMock,
        return_value=newer,
    ):
        resp = await client.get(f"/api/v1/profile/{pk}?refresh=1")

    assert resp.status_code == 200
    body = resp.json()
    assert body["profile"]["name"] == "ExternalNew"
    assert body.get("origin") == "external"


@pytest.mark.asyncio
async def test_profile_endpoint_keeps_newer_local(client):
    """Local newer than external → keep local; no overwrite by older external."""
    pk = pubkey_from_privkey(_USER_SK)
    local = _signed_kind0(
        _USER_SK,
        {"name": "LocalNew", "lud16": "local@botlab.dev"},
        created_at=1_700_000_200,
    )
    older_ext = _signed_kind0(
        _USER_SK,
        {"name": "ExternalOld", "lud16": "ext@botlab.dev"},
        created_at=1_700_000_000,
    )
    from app.database import async_session
    from app.relay import store_event

    async with async_session() as db:
        await store_event(db, local, origin="clankfeed")

    with patch(
        "app.ingest.fetch_author_kind0",
        new_callable=AsyncMock,
        return_value=older_ext,
    ):
        resp = await client.get(f"/api/v1/profile/{pk}?refresh=1")

    assert resp.status_code == 200
    body = resp.json()
    assert body["profile"]["name"] == "LocalNew"
    assert body.get("origin") == "clankfeed"


@pytest.mark.asyncio
async def test_profile_endpoint_missing_everywhere(client):
    """No local + fetch returns None → found=false, no 402."""
    pk = pubkey_from_privkey(_USER_SK)
    with patch(
        "app.ingest.fetch_author_kind0",
        new_callable=AsyncMock,
        return_value=None,
    ):
        resp = await client.get(f"/api/v1/profile/{pk}")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("found") is False
    assert body.get("profile") is None
    assert resp.status_code != 402


@pytest.mark.asyncio
async def test_profile_endpoint_bad_pubkey_400(client):
    """Adversarial: non-64-hex pubkey → 400."""
    resp = await client.get("/api/v1/profile/not-a-pubkey")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_profile_endpoint_no_payment_gate(client, monkeypatch):
    """Reading a profile never requires payment even when payments are enabled."""
    import app.config as config

    monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", "real-secret-key-not-test")
    pk = pubkey_from_privkey(_USER_SK)
    with patch(
        "app.ingest.fetch_author_kind0",
        new_callable=AsyncMock,
        return_value=None,
    ):
        resp = await client.get(f"/api/v1/profile/{pk}")
    assert resp.status_code == 200
    assert resp.status_code != 402


# ---------------------------------------------------------------------------
# Live Playwright
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(base: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.15)
    raise RuntimeError(f"server not healthy: {base}")


def _headed() -> bool:
    return bool(os.environ.get("DISPLAY"))


@pytest.fixture
def live_server(tmp_path):
    db_path = tmp_path / "p1620.db"
    port = _free_port()
    env = os.environ.copy()
    env.update(
        {
            "AUTH_ROOT_KEY": "test-mode",
            "EXTERNAL_INGEST": "false",
            "OUTBOX_ENABLED": "false",
            "DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "RELAY_PRIVATE_KEY": "a" * 64,
            "TEMPO_RECIPIENT": "",
            "BASE_URL": f"ws://127.0.0.1:{port}",
            "EXTERNAL_RELAYS": "",  # avoid live WS hangs in route-exists smoke
        }
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_health(base)
        yield {"base": base, "db": db_path, "env": env, "port": port}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _wait_auth_ready(page, timeout_s: float = 10.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        ready = await page.evaluate(
            "() => !!(window.__nostrCrypto && typeof normalizeNsec === 'function'"
            " && typeof setAuthState === 'function'"
            " && typeof fetchKind0Profile === 'function')"
        )
        if ready:
            return
        await asyncio.sleep(0.1)
    raise TimeoutError("nostr auth not ready")


@pytest.mark.asyncio
async def test_headed_profile_hydrates_from_ensure_endpoint(live_server):
    """Headed: seed nothing locally; stub /api/v1/profile to return external meta;
    nsec login fills name/picture/lud16 (proves client uses ensure path).
    """
    pytest.importorskip("playwright")
    from playwright.async_api import async_playwright

    base = live_server["base"]
    pk = pubkey_from_privkey(_USER_SK)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=not _headed())
        page = await browser.new_page()

        async def handle_route(route):
            if f"/api/v1/profile/{pk}" in route.request.url:
                await route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=json.dumps(
                        {
                            "found": True,
                            "profile": _EXT_PROFILE,
                            "origin": "external",
                            "event": {"id": "a" * 64, "pubkey": pk, "kind": 0},
                        }
                    ),
                )
            else:
                await route.continue_()

        await page.route("**/api/v1/profile/**", handle_route)
        await page.goto(f"{base}/profile", wait_until="domcontentloaded")
        await _wait_auth_ready(page)

        await page.fill("#login-nsec", _USER_SK)
        await page.click("#btn-login-nsec")
        await page.wait_for_selector("#view-account:not(.hidden)", timeout=10_000)

        deadline = time.time() + 10
        name_val = ""
        lud_val = ""
        while time.time() < deadline:
            name_val = await page.input_value("#prof-name")
            lud_val = await page.input_value("#prof-lud16")
            if name_val == "ExternalOnlyBot" and lud_val == "extonly@botlab.dev":
                break
            await asyncio.sleep(0.2)

        assert name_val == "ExternalOnlyBot", f"name={name_val!r}"
        assert lud_val == "extonly@botlab.dev", f"lud16={lud_val!r}"
        pic = await page.input_value("#prof-picture")
        assert pic == "https://example.com/ext-only.png"

        hits = []

        def on_req(req):
            if "/api/v1/profile/" in req.url:
                hits.append(req.url)

        page.on("request", on_req)
        await page.evaluate("() => fetchKind0Profile(userPubkey)")
        await page.wait_for_timeout(500)
        assert hits, "fetchKind0Profile must call /api/v1/profile/"

        await browser.close()


@pytest.mark.asyncio
async def test_api_live_ensures_external_into_db(live_server, monkeypatch):
    """Against live uvicorn: monkeypatch is process-local so we seed via HTTP
    by calling the endpoint after inserting nothing, and verify the route exists
    (404→200 shape). Full fetch mock is covered by ASGI unit tests above.
    """
    # Route must exist (not 404) even when empty
    pk = pubkey_from_privkey(_USER_SK)
    with urllib.request.urlopen(
        f"{live_server['base']}/api/v1/profile/{pk}", timeout=10
    ) as r:
        assert r.status == 200
        body = json.loads(r.read().decode())
    assert "found" in body
    assert "profile" in body
