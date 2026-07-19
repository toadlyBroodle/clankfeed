"""Phase 16.7: Playwright e2e for web identity authorship runtime paths.

Covers the four acceptance flows that static/source suites cannot prove:
  (1) in-memory nsec → POST /api/v1/events + note card shows user pubkey
  (2) /profile→/ nsec drop → alert + zero /api/v1/post
  (3) stale-session zap re-entry (nsec scrub; extension without window.nostr)
  (4) /profile [copy] privkey when clipboard.writeText denied → execCommand fallback
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_NSEC_SK = "b" * 64  # must differ from relay "a"*64 and extension "c"*64


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
    """Prefer headed Chromium when a display exists (spec: headed e2e)."""
    return bool(os.environ.get("DISPLAY"))


@pytest.fixture
def live_server(tmp_path):
    db_path = tmp_path / "p16e2e.db"
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


async def _wait_auth_ready(page, timeout_s: float = 10.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        ready = await page.evaluate(
            "() => !!(window.__nostrCrypto && typeof canSign === 'function'"
            " && typeof setAuthState === 'function')"
        )
        if ready:
            return
        await asyncio.sleep(0.1)
    raise RuntimeError("auth/crypto helpers not ready")


async def _wait_relay_pubkey(page, timeout_s: float = 10.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        if await page.evaluate(
            "() => !!(relayPubkey && relayPubkey.length === 64)"
        ):
            return
        await asyncio.sleep(0.1)
    raise RuntimeError("relayPubkey not loaded from NIP-11")


# ---------------------------------------------------------------------------
# (1) in-memory nsec → /api/v1/events + user pubkey on note card
# ---------------------------------------------------------------------------


class TestClientSignedNsecPostLive167:
    @pytest.mark.asyncio
    async def test_nsec_post_hits_events_and_card_shows_user_pubkey(self, live_server):
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        user_pk = pubkey_from_privkey(_NSEC_SK)
        relay_pk = pubkey_from_privkey("a" * 64)
        assert user_pk != relay_pk
        base = live_server
        events_bodies: list[dict] = []
        post_hits: list[str] = []
        alerts: list[str] = []
        content = "p16-7-nsec-client-signed"

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
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
            await _wait_relay_pubkey(page)

            await page.evaluate(
                """([sk, pk]) => {
                  try { delete window.nostr; } catch (e) { window.nostr = undefined; }
                  setAuthState('nsec', pk, sk);
                }""",
                [_NSEC_SK, user_pk],
            )
            assert await page.evaluate("() => canSign() && authMode === 'nsec'") is True

            await page.fill("#post-content", content)
            await page.evaluate(
                "() => document.getElementById('post-form').requestSubmit()"
            )

            for _ in range(80):
                if events_bodies:
                    break
                await asyncio.sleep(0.1)

            # Wait for WS-driven note card (producer: addNote → #note-{id})
            card_html = ""
            note_id = None
            for _ in range(100):
                if events_bodies and not note_id:
                    note_id = (events_bodies[0].get("event") or {}).get("id")
                if note_id:
                    loc = page.locator(f"#note-{note_id}")
                    if await loc.count() > 0:
                        card_html = (await loc.inner_html()) or ""
                        if user_pk[:4] in card_html:
                            break
                await asyncio.sleep(0.1)
            await browser.close()

        assert alerts == [], f"unexpected alerts: {alerts}"
        assert post_hits == [], f"must not use relay /api/v1/post: {post_hits}"
        assert events_bodies, "expected POST /api/v1/events"
        req_pk = (events_bodies[0].get("event") or {}).get("pubkey")
        assert req_pk == user_pk, f"expected user pubkey {user_pk}, got {req_pk}"
        assert req_pk != relay_pk
        assert note_id, "signed event missing id"
        assert card_html, f"note card #note-{note_id} never appeared"
        # Card abbreviates as first4...last4 (producer: index.js renderNotes)
        abbrev = f"{user_pk[:4]}...{user_pk[-4:]}"
        assert abbrev in card_html or user_pk[:4] in card_html, (
            f"user pubkey not on card: {card_html[:400]!r}"
        )
        assert "anon" not in card_html.lower() or user_pk[:4] in card_html


# ---------------------------------------------------------------------------
# (2) /profile → / nsec drop: alert + zero /api/v1/post
# ---------------------------------------------------------------------------


class TestProfileHomeNsecDropLive167:
    @pytest.mark.asyncio
    async def test_profile_to_home_nsec_drop_alerts_zero_relay_post(self, live_server):
        """Runtime RESULT: after /profile login, navigating to / drops in-memory
        userNsec (H2); post must alert re-entry and never hit /api/v1/post.
        """
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        user_pk = pubkey_from_privkey(_NSEC_SK)
        base = live_server
        post_hits: list[str] = []
        events_hits: list[str] = []
        alerts: list[str] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            context = await browser.new_context()
            page = await context.new_page()

            async def on_dialog(dialog):
                alerts.append(dialog.message)
                await dialog.accept()

            page.on("dialog", on_dialog)

            async def on_route(route):
                req = route.request
                if "/api/v1/post" in req.url and req.method == "POST":
                    post_hits.append(req.url)
                if "/api/v1/events" in req.url and req.method == "POST":
                    events_hits.append(req.url)
                await route.continue_()

            await page.route("**/api/v1/**", on_route)

            # Login on /profile with in-memory nsec (producer: loginWithNsec → setAuthState)
            await page.goto(
                f"{base}/profile", wait_until="domcontentloaded", timeout=30_000
            )
            await _wait_auth_ready(page)
            await page.fill("#login-nsec", _NSEC_SK)
            await page.click("#btn-login-nsec")
            for _ in range(50):
                if await page.evaluate("() => isLoggedIn() && canSign()"):
                    break
                await asyncio.sleep(0.1)
            assert await page.evaluate("() => canSign()") is True

            # Navigate home — userNsec is memory-only, so it must drop
            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)
            # Persist mode+pubkey from localStorage; nsec must be gone
            assert await page.evaluate(
                "() => isLoggedIn() && authMode === 'nsec' && !canSign()"
            ) is True

            await page.fill("#post-content", "p16-7-stale-nsec-must-not-relay")
            await page.evaluate(
                "() => document.getElementById('post-form').requestSubmit()"
            )
            for _ in range(40):
                if alerts:
                    break
                await asyncio.sleep(0.1)
            await browser.close()

        assert post_hits == [], f"relay-signed /api/v1/post was called: {post_hits}"
        assert events_hits == [], f"client-signed /api/v1/events fired without nsec: {events_hits}"
        assert alerts, "expected re-entry alert after nsec drop"
        joined = " ".join(alerts).lower()
        assert (
            "profile" in joined
            or "re-enter" in joined
            or "private key" in joined
            or "sign" in joined
        ), f"unexpected alert copy: {alerts}"


# ---------------------------------------------------------------------------
# (3) stale-session zap re-entry (nsec scrub OR extension without window.nostr)
# ---------------------------------------------------------------------------


class TestStaleZapReentryLive167:
    @pytest.mark.asyncio
    async def test_stale_nsec_zap_shows_reentry_status(self, live_server):
        import httpx
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        user_pk = pubkey_from_privkey(_NSEC_SK)
        base = live_server

        with httpx.Client(
            base_url=base,
            timeout=10.0,
            headers={"X-Requested-With": "XMLHttpRequest"},
        ) as c:
            note = c.post(
                "/api/v1/post", json={"content": "p16-7-stale-nsec-zap"}
            ).json()["event"]["id"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)
            await page.wait_for_selector(f"#note-{note}", timeout=15_000)

            # Producer: cached nsec authMode + pubkey, empty userNsec (post-nav scrub)
            await page.evaluate(
                """([pk]) => {
                  try { delete window.nostr; } catch (e) { window.nostr = undefined; }
                  setAuthState('nsec', pk, '');
                  window.__zapSignCalls = 0;
                  const orig = window.signNostrEvent;
                  window.signNostrEvent = async function (...args) {
                    window.__zapSignCalls = (window.__zapSignCalls || 0) + 1;
                    if (typeof orig === 'function') return orig.apply(this, args);
                    return null;
                  };
                }""",
                [user_pk],
            )
            assert await page.evaluate("() => isLoggedIn() && !canSign()") is True

            await page.click(f'#note-{note} button[data-action="zap"]')
            await page.wait_for_selector(
                f"#vote-prompt-{note}.active", timeout=5_000
            )
            await page.click(f'#note-{note} button[data-action="submit-vote"]')

            status = ""
            for _ in range(50):
                status = (
                    await page.locator(f"#vote-status-{note}").text_content()
                ) or ""
                if "re-enter" in status.lower() or "profile" in status.lower():
                    break
                await asyncio.sleep(0.1)
            sign_count = await page.evaluate("() => window.__zapSignCalls || 0")
            await browser.close()

        assert status.strip(), "vote-status stayed empty"
        low = status.lower()
        assert "re-enter" in low and "private key" in low, f"unexpected: {status!r}"
        assert "/profile" in status or "profile" in low
        assert sign_count == 0
        assert "restore" not in low  # extension copy must not leak onto nsec path
        assert "extension" not in low

    @pytest.mark.asyncio
    async def test_stale_extension_zap_shows_restore_status(self, live_server):
        """Adversarial twin of nsec path: extension façade without window.nostr."""
        import httpx
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        ext_pk = pubkey_from_privkey("c" * 64)
        base = live_server

        with httpx.Client(
            base_url=base,
            timeout=10.0,
            headers={"X-Requested-With": "XMLHttpRequest"},
        ) as c:
            note = c.post(
                "/api/v1/post", json={"content": "p16-7-stale-ext-zap"}
            ).json()["event"]["id"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)
            await page.wait_for_selector(f"#note-{note}", timeout=15_000)

            await page.evaluate(
                """([pk]) => {
                  try { delete window.nostr; } catch (e) { window.nostr = undefined; }
                  setAuthState('extension', pk, '');
                  window.__zapSignCalls = 0;
                  const orig = window.signNostrEvent;
                  window.signNostrEvent = async function (...args) {
                    window.__zapSignCalls += 1;
                    if (typeof orig === 'function') return orig.apply(this, args);
                    return null;
                  };
                }""",
                [ext_pk],
            )
            assert await page.evaluate("() => isLoggedIn() && !canSign()") is True

            await page.click(f'#note-{note} button[data-action="zap"]')
            await page.wait_for_selector(
                f"#vote-prompt-{note}.active", timeout=5_000
            )
            await page.click(f'#note-{note} button[data-action="submit-vote"]')

            status = ""
            for _ in range(50):
                status = (
                    await page.locator(f"#vote-status-{note}").text_content()
                ) or ""
                if "extension" in status.lower():
                    break
                await asyncio.sleep(0.1)
            sign_count = await page.evaluate("() => window.__zapSignCalls || 0")
            await browser.close()

        assert status.strip(), "vote-status stayed empty"
        low = status.lower()
        assert "restore" in low and "extension" in low, f"unexpected: {status!r}"
        assert sign_count == 0
        assert "re-enter your private key" not in low


# ---------------------------------------------------------------------------
# (4) /profile [copy] privkey: clipboard denied → execCommand fallback
# ---------------------------------------------------------------------------


class TestClipboardFallbackLive167:
    @pytest.mark.asyncio
    async def test_copy_privkey_falls_back_to_exec_command(self, live_server):
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        user_pk = pubkey_from_privkey(_NSEC_SK)
        base = live_server

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            await page.goto(
                f"{base}/profile", wait_until="domcontentloaded", timeout=30_000
            )
            await _wait_auth_ready(page)

            # Deny clipboard.writeText (producer shape: permission / insecure context)
            result = await page.evaluate(
                """([sk, pk]) => {
                  let execCalls = 0;
                  const origExec = document.execCommand.bind(document);
                  document.execCommand = function (cmd, ...rest) {
                    if (cmd === 'copy') execCalls += 1;
                    return origExec(cmd, ...rest);
                  };
                  // Force clipboard path to reject so copyToClipboard falls through
                  Object.defineProperty(navigator, 'clipboard', {
                    configurable: true,
                    get() {
                      return {
                        writeText: async () => {
                          throw new Error('Clipboard permission denied');
                        },
                      };
                    },
                  });
                  setAuthState('nsec', pk, sk);
                  return (async () => {
                    // Drive account view so #key-priv is populated
                    if (typeof showOwnAccount === 'function') {
                      await showOwnAccount();
                    }
                    const priv = document.getElementById('key-priv');
                    if (!priv || !priv.value) {
                      return { ok: false, reason: 'key-priv empty', execCalls };
                    }
                    const ok = await copyToClipboard(priv.value);
                    return {
                      ok,
                      execCalls,
                      privLen: priv.value.length,
                      privMatches: priv.value.toLowerCase() === sk.toLowerCase(),
                    };
                  })();
                }""",
                [_NSEC_SK, user_pk],
            )
            await browser.close()

        assert result.get("privMatches") is True, f"privkey not loaded: {result}"
        assert result.get("ok") is True, f"copyToClipboard returned false: {result}"
        assert result.get("execCalls", 0) >= 1, (
            f"execCommand('copy') was not used after clipboard denial: {result}"
        )
