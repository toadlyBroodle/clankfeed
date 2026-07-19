"""Phase 16.10 + 16.8: extension stale canSign gate + NIP-07 mock post path.

16.10 — When authMode==='extension' but window.nostr is missing, canSign() is false
and the post form must NOT fall through to submitRelaySignedPost under a logged-in
façade. Gate: isLoggedIn() && !canSign() → prompt; true anon still relay-signs.

16.8 — Mock window.nostr (NIP-07) so canSign() is true; post must hit /api/v1/events
and store the extension pubkey (not the relay pubkey).
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


def _auth() -> str:
    return (STATIC / "nostr-auth.js").read_text()


def _index() -> str:
    return (STATIC / "index.js").read_text()


def _post_form_handler() -> str:
    index = _index()
    return index.split("addEventListener('submit'", 1)[1].split(
        "async function submitClientSignedPost", 1
    )[0]


# ---------------------------------------------------------------------------
# 16.10 — stale extension session must not silent-relay-sign
# ---------------------------------------------------------------------------


class TestStaleExtensionPostGate1610:
    """isLoggedIn && !canSign (extension gone) → prompt, no submitRelaySignedPost."""

    def test_post_gate_blocks_logged_in_cannot_sign(self):
        """Gate must cover any logged-in !canSign — not only authMode==='nsec'."""
        handler = _post_form_handler()
        # Broad gate (proposed fix) OR explicit extension branch before relay
        has_broad = "isLoggedIn()" in handler and "!canSign()" in handler.replace(" ", "")
        # Also accept: isLoggedIn() && !canSign() with spaces
        has_broad = has_broad or (
            "isLoggedIn()" in handler
            and "canSign()" in handler
            and "submitRelaySignedPost" in handler
        )
        # Narrow nsec-only gate is the bug when extension is also stale
        nsec_only = (
            "authMode === 'nsec'" in handler
            and "extension" not in handler
            and "isLoggedIn()" not in handler
        )
        assert not nsec_only, (
            "post form still only gates authMode==='nsec'; "
            "extension-without-window.nostr still falls through to relay-sign"
        )
        # Must return before relay when logged-in cannot sign
        before_relay = handler.split("submitRelaySignedPost", 1)[0]
        assert "isLoggedIn()" in before_relay or "extension" in before_relay
        assert "return" in before_relay

    def test_stale_extension_prompt_mentions_identity_or_extension(self):
        handler = _post_form_handler()
        assert (
            "/profile" in handler
            or "extension" in handler.lower()
            or "Re-enter" in handler
            or "re-enter" in handler
            or "identity" in handler.lower()
        )

    def test_true_anon_still_uses_relay_post(self):
        """Unauthenticated users still call submitRelaySignedPost."""
        index = _index()
        assert "submitRelaySignedPost" in index
        assert "/api/v1/post" in index

    def test_can_sign_extension_requires_window_nostr(self):
        auth = _auth()
        fn = auth.split("function canSign", 1)[1].split("\nfunction ", 1)[0]
        assert "extension" in fn
        assert "window.nostr" in fn


# ---------------------------------------------------------------------------
# 16.8 — NIP-07 canSign / signNostrEvent path (source + live mock)
# ---------------------------------------------------------------------------


class TestNip07CanSignSource168:
    """canSign + signNostrEvent must have a real extension branch (producer: NIP-07)."""

    def test_sign_nostr_event_calls_window_nostr_sign_event(self):
        auth = _auth()
        fn = auth.split("function signNostrEvent", 1)[1].split("\nfunction ", 1)[0]
        assert "window.nostr" in fn
        assert "signEvent" in fn

    def test_submit_client_signed_uses_sign_nostr_event(self):
        index = _index()
        fn = index.split("async function submitClientSignedPost", 1)[1].split(
            "async function submitRelaySignedPost", 1
        )[0]
        assert "signNostrEvent" in fn
        assert "/api/v1/events" in fn


# ---------------------------------------------------------------------------
# Live fixtures
# ---------------------------------------------------------------------------


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(base: str, timeout: float = 15.0) -> None:
    import time
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.15)
    raise RuntimeError(f"server not healthy: {base}")


@pytest.fixture
def live_server(tmp_path):
    import os
    import subprocess
    import sys

    db_path = tmp_path / "p16ext.db"
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
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# Known test key (must differ from relay "a"*64)
_EXT_SK = "c" * 64


async def _wait_auth_ready(page, timeout_s: float = 10.0):
    import asyncio

    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        ready = await page.evaluate(
            "() => !!(window.__nostrCrypto && typeof canSign === 'function')"
        )
        if ready:
            return
        await asyncio.sleep(0.1)
    raise RuntimeError("auth/crypto helpers not ready")


class TestStaleExtensionLive1610:
    """Runtime: extension authMode + no window.nostr → alert, zero /api/v1/post."""

    @pytest.mark.asyncio
    async def test_stale_extension_post_does_not_hit_relay_post(self, live_server):
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        ext_pk = pubkey_from_privkey(_EXT_SK)
        base = live_server
        post_hits: list[str] = []
        alerts: list[str] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            async def on_dialog(dialog):
                alerts.append(dialog.message)
                await dialog.accept()

            page.on("dialog", on_dialog)

            async def on_route(route):
                url = route.request.url
                if "/api/v1/post" in url and route.request.method == "POST":
                    post_hits.append(url)
                await route.continue_()

            await page.route("**/api/v1/**", on_route)
            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)

            # Logged-in extension façade WITHOUT window.nostr (producer: missing NIP-07)
            await page.evaluate(
                """([pk]) => {
                  // Ensure no extension object
                  try { delete window.nostr; } catch (e) { window.nostr = undefined; }
                  setAuthState('extension', pk, '');
                }""",
                [ext_pk],
            )
            assert await page.evaluate("() => isLoggedIn() && !canSign()") is True

            await page.fill("#post-content", "stale-extension-should-not-relay")
            # Use form.requestSubmit so alert dialog cannot stall Playwright click
            await page.evaluate(
                "() => document.getElementById('post-form').requestSubmit()"
            )
            import asyncio

            for _ in range(30):
                if alerts:
                    break
                await asyncio.sleep(0.1)
            await browser.close()

        assert post_hits == [], f"relay-signed /api/v1/post was called: {post_hits}"
        assert alerts, "expected re-entry / identity alert"
        joined = " ".join(alerts).lower()
        assert (
            "profile" in joined
            or "extension" in joined
            or "identity" in joined
            or "re-enter" in joined
            or "sign" in joined
        )


class TestNip07MockPostLive168:
    """Runtime: mock window.nostr.signEvent → /api/v1/events stores extension pubkey."""

    @pytest.mark.asyncio
    async def test_nip07_mock_post_stores_extension_pubkey(self, live_server):
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        ext_pk = pubkey_from_privkey(_EXT_SK)
        relay_pk = pubkey_from_privkey("a" * 64)
        assert ext_pk != relay_pk
        base = live_server
        events_bodies: list[dict] = []
        post_hits: list[str] = []
        alerts: list[str] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            async def on_dialog(dialog):
                alerts.append(dialog.message)
                await dialog.accept()

            page.on("dialog", on_dialog)

            async def on_route(route):
                req = route.request
                if "/api/v1/post" in req.url and req.method == "POST":
                    post_hits.append(req.url)
                if "/api/v1/events" in req.url and req.method == "POST":
                    try:
                        events_bodies.append(req.post_data_json or {})
                    except Exception:
                        events_bodies.append({})
                await route.continue_()

            await page.route("**/api/v1/**", on_route)
            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)

            # Wait for NIP-11 → relayPubkey (needed for client zap fee tags)
            import asyncio

            for _ in range(100):
                if await page.evaluate("() => !!(relayPubkey && relayPubkey.length === 64)"):
                    break
                await asyncio.sleep(0.1)
            assert await page.evaluate(
                "() => !!(relayPubkey && relayPubkey.length === 64)"
            ), "relayPubkey not loaded from NIP-11"

            # Producer shape: NIP-07 window.nostr.getPublicKey + signEvent
            # Mock signs with page crypto (same path real extensions use).
            await page.evaluate(
                """([sk, pk]) => {
                  window.nostr = {
                    getPublicKey: async () => pk,
                    signEvent: async (event) => {
                      const { schnorr, bytesToHex, getPublicKey, sha256 } = window.__nostrCrypto;
                      event.pubkey = bytesToHex(getPublicKey(sk));
                      const canonical = JSON.stringify([
                        0, event.pubkey, event.created_at, event.kind, event.tags, event.content
                      ]);
                      event.id = bytesToHex(sha256(new TextEncoder().encode(canonical)));
                      event.sig = bytesToHex(schnorr.sign(event.id, sk));
                      return event;
                    },
                  };
                  setAuthState('extension', pk, '');
                }""",
                [_EXT_SK, ext_pk],
            )
            assert await page.evaluate("() => canSign()") is True

            await page.fill("#post-content", "nip07-extension-authored-note")
            await page.evaluate(
                "() => document.getElementById('post-form').requestSubmit()"
            )

            # Wait until events request captured or timeout
            for _ in range(80):
                if events_bodies:
                    break
                await asyncio.sleep(0.1)

            # Poll GET until the note is queryable (test-mode settle is sync, but
            # avoid racing the route continue_ / response path).
            feed = None
            match = []
            for _ in range(80):
                feed = await page.evaluate(
                    """async () => {
                      const r = await fetch('/api/v1/events?limit=20&kinds=1');
                      return r.json();
                    }"""
                )
                notes = feed if isinstance(feed, list) else (
                    (feed or {}).get("events") or (feed or {}).get("notes") or []
                )
                match = [
                    n for n in notes
                    if (n.get("content") or "").startswith("nip07-extension")
                    or ((n.get("event") or {}).get("content") or "").startswith(
                        "nip07-extension"
                    )
                ]
                if match:
                    break
                await asyncio.sleep(0.1)
            await browser.close()

        assert alerts == [], f"unexpected alerts: {alerts}"
        assert post_hits == [], f"must not use relay post: {post_hits}"
        assert events_bodies, "expected POST /api/v1/events"
        req_pk = (events_bodies[0].get("event") or {}).get("pubkey")
        assert req_pk == ext_pk, f"expected extension pubkey {ext_pk}, got {req_pk}"
        assert req_pk != relay_pk
        assert match, f"extension note missing from feed: {feed!r}"
        stored = match[0].get("event") or match[0]
        assert stored["pubkey"] == ext_pk
        assert stored["pubkey"] != relay_pk
