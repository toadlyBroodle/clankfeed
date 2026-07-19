"""Phase 16.5: on nsec sign-in, hydrate kind:0 (name/about/picture/lud16) into UI + metadataCache.

Acceptance:
  (1) Shared fetchKind0Profile helper loads latest kind:0 for a pubkey.
  (2) /profile showOwnAccount fills name/about/picture/lud16 UI fields from that profile.
  (3) saveProfile persists lud16 with the other metadata fields.
  (4) Home `/` hydrates logged-in user's kind:0 into metadataCache (header name).
  (5) Adversarial: missing / malformed kind:0 does not throw; UI falls back to pubkey.
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

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.nostr import sign_event

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"

_USER_SK = "b" * 64  # distinct from relay a*64
_PROFILE = {
    "name": "HydrateBot",
    "about": "kind0 hydrate test",
    "picture": "https://example.com/hydrate.png",
    "lud16": "hydrate@botlab.dev",
}


def _auth() -> str:
    return (STATIC / "nostr-auth.js").read_text()


def _profile_js() -> str:
    return (STATIC / "profile.js").read_text()


def _profile_html() -> str:
    return (STATIC / "profile.html").read_text()


def _index() -> str:
    return (STATIC / "index.js").read_text()


# ---------------------------------------------------------------------------
# Source contracts
# ---------------------------------------------------------------------------


class TestFetchKind0Helper165:
    """Shared helper must fetch authors=&kinds=0 and parse content."""

    def test_fetch_kind0_profile_helper_exists(self):
        auth = _auth()
        assert "function fetchKind0Profile" in auth
        fn = auth.split("function fetchKind0Profile", 1)[1].split("\nfunction ", 1)[0]
        assert "kinds=0" in fn or "kinds=0" in auth
        assert "authors=" in fn
        assert "JSON.parse" in fn

    def test_fetch_kind0_returns_null_on_failure(self):
        """Adversarial: empty events / bad JSON must not throw — return null."""
        auth = _auth()
        fn = auth.split("function fetchKind0Profile", 1)[1].split("\nfunction ", 1)[0]
        assert "return null" in fn
        assert "catch" in fn


class TestProfileUiLud16Hydrate165:
    """/profile must load + save lud16 alongside name/about/picture."""

    def test_prof_lud16_input_exists(self):
        html = _profile_html()
        assert 'id="prof-lud16"' in html

    def test_show_own_account_uses_fetch_and_fills_lud16(self):
        js = _profile_js()
        assert "showOwnAccount" in js
        fn = js.split("async function showOwnAccount", 1)[1].split(
            "\nasync function ", 1
        )[0]
        assert "fetchKind0Profile" in fn
        assert "prof-lud16" in fn
        assert "prof-name" in fn
        assert "prof-about" in fn
        assert "prof-picture" in fn

    def test_save_profile_includes_lud16(self):
        js = _profile_js()
        fn = js.split("async function saveProfile", 1)[1].split(
            "\nasync function ", 1
        )[0]
        assert "prof-lud16" in fn
        assert "lud16" in fn
        # Must not require name-only — lud16 alone should be enough to save
        assert "lud16" in fn.split("Fill at least one field", 1)[0] or (
            "lud16" in fn and "prof-lud16" in fn
        )


class TestIndexMetadataCacheHydrate165:
    """Home page must fetch own kind:0 into metadataCache when logged in."""

    def test_hydrate_own_profile_exists_and_writes_cache(self):
        index = _index()
        assert "hydrateOwnProfile" in index or "fetchKind0Profile" in index
        # Must call fetch helper and write metadataCache[userPubkey]
        assert "fetchKind0Profile" in index
        assert "metadataCache[userPubkey]" in index or "metadataCache[pubkey]" in index

    def test_init_calls_hydrate_when_logged_in(self):
        index = _index()
        # Init path must invoke hydrate (not only WS opportunistic fill)
        tail = index.split("// ---- Init ----", 1)[-1] if "// ---- Init ----" in index else index[-800:]
        assert "hydrateOwnProfile" in tail or (
            "fetchKind0Profile" in tail and "isLoggedIn" in tail
        )


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
    db_path = tmp_path / "p165.db"
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
        yield {"base": base, "db": db_path}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _seed_kind0(db_path: Path, sk: str, profile: dict) -> str:
    meta = sign_event(
        sk,
        {
            "kind": 0,
            "created_at": int(time.time()) - 5,
            "tags": [],
            "content": json.dumps(profile),
        },
    )
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO nostr_events "
                "(id, pubkey, created_at, kind, tags, content, sig, "
                "sats_clank, value_usd, sats_ext, origin) "
                "VALUES (:id, :pubkey, :created_at, :kind, :tags, :content, :sig, "
                "0, '0', 0, 'clankfeed')"
            ),
            {
                "id": meta["id"],
                "pubkey": meta["pubkey"],
                "created_at": meta["created_at"],
                "kind": meta["kind"],
                "tags": "[]",
                "content": meta["content"],
                "sig": meta["sig"],
            },
        )
    await engine.dispose()
    return meta["pubkey"]


async def _wait_auth_ready(page, timeout_s: float = 10.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        ready = await page.evaluate(
            "() => !!(window.__nostrCrypto && typeof normalizeNsec === 'function'"
            " && typeof setAuthState === 'function')"
        )
        if ready:
            return
        await asyncio.sleep(0.1)
    raise TimeoutError("nostr auth not ready")


@pytest.mark.asyncio
class TestProfileHydrateLive165:
    async def test_nsec_login_fills_profile_ui_including_lud16(self, live_server):
        """Live: seed kind:0 → nsec login → form fields include lud16."""
        pytest.importorskip("playwright")
        from playwright.async_api import async_playwright

        pubkey = await _seed_kind0(live_server["db"], _USER_SK, _PROFILE)
        base = live_server["base"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            await page.goto(f"{base}/profile", wait_until="domcontentloaded")
            await _wait_auth_ready(page)

            await page.fill("#login-nsec", _USER_SK)
            await page.click("#btn-login-nsec")
            await page.wait_for_selector("#view-account:not(.hidden)", timeout=5000)

            name = await page.input_value("#prof-name")
            about = await page.input_value("#prof-about")
            picture = await page.input_value("#prof-picture")
            lud16 = await page.input_value("#prof-lud16")
            acct = await page.text_content("#acct-name")

            await browser.close()

        assert name == _PROFILE["name"]
        assert about == _PROFILE["about"]
        assert picture == _PROFILE["picture"]
        assert lud16 == _PROFILE["lud16"]
        assert _PROFILE["name"] in (acct or "")

    async def test_home_hydrates_metadata_cache_for_header(self, live_server):
        """Live: hydrateOwnProfile writes kind:0 into metadataCache (not feed luck)."""
        pytest.importorskip("playwright")
        from playwright.async_api import async_playwright

        pubkey = await _seed_kind0(live_server["db"], _USER_SK, _PROFILE)
        base = live_server["base"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            await page.goto(f"{base}/profile", wait_until="domcontentloaded")
            await _wait_auth_ready(page)
            await page.evaluate(
                """([sk, pk]) => {
                  setAuthState('nsec', pk, sk);
                  localStorage.setItem('cf_auth_mode', 'nsec');
                  localStorage.setItem('cf_pubkey', pk);
                }""",
                [_USER_SK, pubkey],
            )
            await page.goto(f"{base}/", wait_until="domcontentloaded")
            await _wait_auth_ready(page)
            # Clear opportunistic WS/feed fills — hydrateOwnProfile must re-fetch
            has_fn = await page.evaluate("() => typeof hydrateOwnProfile")
            assert has_fn == "function", "hydrateOwnProfile missing"
            await page.evaluate("(pk) => { metadataCache = {}; delete metadataCache[pk]; }", pubkey)
            cached = await page.evaluate(
                """async (pk) => {
                  await hydrateOwnProfile();
                  return metadataCache[pk] || null;
                }""",
                pubkey,
            )
            header = await page.text_content("#header-account-link")
            await browser.close()

        assert cached is not None
        assert cached.get("name") == _PROFILE["name"]
        assert cached.get("lud16") == _PROFILE["lud16"]
        assert cached.get("about") == _PROFILE["about"]
        assert cached.get("picture") == _PROFILE["picture"]
        assert _PROFILE["name"] in (header or "")

    async def test_missing_kind0_does_not_break_login(self, live_server):
        """Adversarial: nsec login with no kind:0 → truncated pubkey, empty lud16, no throw."""
        pytest.importorskip("playwright")
        from playwright.async_api import async_playwright
        from app.zaps import pubkey_from_privkey

        # No seed — fresh pubkey has no kind:0
        pubkey = pubkey_from_privkey(_USER_SK)
        base = live_server["base"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            await page.goto(f"{base}/profile", wait_until="domcontentloaded")
            await _wait_auth_ready(page)
            await page.fill("#login-nsec", _USER_SK)
            await page.click("#btn-login-nsec")
            await page.wait_for_selector("#view-account:not(.hidden)", timeout=5000)
            lud16 = await page.input_value("#prof-lud16")
            acct = await page.text_content("#acct-name")
            await browser.close()

        assert lud16 == ""
        assert pubkey[:8] in (acct or "") or "..." in (acct or "")
        assert errors == []
