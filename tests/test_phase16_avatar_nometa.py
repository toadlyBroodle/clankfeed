"""Phase 16.16: !meta / empty-events / catch must clear stale avatar (+ pub-about).

Bug: setAvatarPlaceholder only runs on `meta && !meta.picture`. When
showOwnAccount gets !meta, or showPublicProfile hits empty events / catch,
#acct-avatar / #pub-avatar (and pub-about) are left untouched — so
pictured → no-kind0 peer still shows the prior avatar.

Acceptance:
  (1) Source: !meta / empty-events / catch branches call setAvatarPlaceholder
      (and clear pub-about on public paths).
  (2) Live: pictured public → pubkey with zero kind:0 → #pub-avatar is
      placeholder '?', not prior <img>; pub-about cleared.
  (3) Adversarial: pictured own-account then showOwnAccount with no kind:0
      → #acct-avatar placeholder '?'.
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

_USER_SK = "9" * 64  # distinct from 16.15 d/e*64; must be < secp256k1 order
_PEER_SK = "8" * 64
_NO_KIND0_SK = "7" * 64
_PICTURE = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
_PROFILE = {
    "name": "NoMetaPicBot",
    "about": "has picture and about",
    "picture": _PICTURE,
    "lud16": "nometa@botlab.dev",
}


def _profile_js() -> str:
    return (STATIC / "profile.js").read_text()


def _show_own_else_branch(js: str) -> str:
    """Body of showOwnAccount's `} else {` (!meta) branch before closing the function."""
    fn = js.split("async function showOwnAccount", 1)[1].split(
        "\n// ---- Profile Save", 1
    )[0]
    # Last "} else {" in the function is the !meta branch
    parts = fn.rsplit("} else {", 1)
    assert len(parts) == 2, "showOwnAccount missing } else { (!meta) branch"
    return parts[1]


def _show_public_empty_and_catch(js: str) -> str:
    """Metadata fetch block of showPublicProfile (through catch), before notes fetch."""
    return js.split("async function showPublicProfile", 1)[1].split(
        "\n  // Fetch notes", 1
    )[0]


# ---------------------------------------------------------------------------
# Source contracts
# ---------------------------------------------------------------------------


class TestNoMetaAvatarClear1616:
    """!meta / empty / catch must restore placeholder (and clear pub-about)."""

    def test_show_own_account_nometa_calls_set_avatar_placeholder(self):
        else_body = _show_own_else_branch(_profile_js())
        assert "setAvatarPlaceholder(" in else_body, (
            "showOwnAccount !meta branch must call setAvatarPlaceholder "
            "so a leftover <img> from a prior pictured view is cleared"
        )
        assert "'?'" in else_body or '"?"' in else_body

    def test_show_public_empty_events_clears_avatar_and_about(self):
        block = _show_public_empty_and_catch(_profile_js())
        # Isolate the !meta / empty-profile else (16.20 uses fetchKind0Profile)
        try_body = block.split("try {", 1)[1]
        # Prefer new ensure-path shape; fall back to legacy events.length
        if "if (meta)" in try_body:
            parts = try_body.split("if (meta)", 1)
            assert len(parts) == 2, "missing if (meta) check"
            else_body = parts[1].rsplit("} else {", 1)[1].split("} catch", 1)[0]
        else:
            events_if = try_body.split("if (data.events && data.events.length > 0)", 1)
            assert len(events_if) == 2, "missing events.length or if (meta) check"
            else_body = events_if[1].rsplit("} else {", 1)[1].split("} catch", 1)[0]
        assert "setAvatarPlaceholder(" in else_body, (
            "showPublicProfile empty-profile else must call setAvatarPlaceholder"
        )
        assert "pub-about" in else_body and (
            ".textContent = ''" in else_body or '.textContent = ""' in else_body
        ), "showPublicProfile empty-profile else must clear #pub-about"

    def test_show_public_catch_clears_avatar(self):
        block = _show_public_empty_and_catch(_profile_js())
        catch = block.split("} catch", 1)
        assert len(catch) == 2, "showPublicProfile missing catch"
        catch_body = catch[1]
        assert "setAvatarPlaceholder(" in catch_body, (
            "showPublicProfile catch must call setAvatarPlaceholder"
        )
        assert "pub-about" in catch_body and (
            ".textContent = ''" in catch_body or '.textContent = ""' in catch_body
        ), "showPublicProfile catch must clear #pub-about"


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
    db_path = tmp_path / "p1616.db"
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
            "EXTERNAL_RELAYS": "",
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


def _pubkey_from_sk(sk: str) -> str:
    """Derive pubkey without seeding a kind:0 (zero-event peer)."""
    ev = sign_event(
        sk,
        {
            "kind": 1,
            "created_at": int(time.time()),
            "tags": [],
            "content": "derive-only",
        },
    )
    return ev["pubkey"]


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


async def _delete_kind0(db_path: Path, pubkey: str) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.execute(
            text("DELETE FROM nostr_events WHERE pubkey = :pk AND kind = 0"),
            {"pk": pubkey},
        )
    await engine.dispose()


@pytest.mark.asyncio
class TestNoMetaAvatarLive1616:
    async def test_pictured_public_then_zero_kind0_shows_placeholder_q(
        self, live_server
    ):
        """Live: pictured public → pubkey with zero kind:0 → placeholder '?', about cleared."""
        pytest.importorskip("playwright")
        from playwright.async_api import async_playwright

        pictured_pk = await _seed_kind0(live_server["db"], _USER_SK, _PROFILE)
        bare_pk = _pubkey_from_sk(_NO_KIND0_SK)
        base = live_server["base"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            await page.goto(
                f"{base}/profile?pubkey={pictured_pk}", wait_until="domcontentloaded"
            )
            await page.wait_for_selector("#view-public:not(.hidden)", timeout=5000)
            deadline = asyncio.get_event_loop().time() + 5.0
            before = None
            while asyncio.get_event_loop().time() < deadline:
                before = await page.evaluate(
                    """() => {
                      const el = document.getElementById('pub-avatar');
                      const about = document.getElementById('pub-about');
                      return el && {
                        tag: el.tagName,
                        src: el.tagName === 'IMG' ? el.getAttribute('src') : null,
                        about: about ? (about.textContent || '') : null,
                      };
                    }"""
                )
                if before and before.get("tag") == "IMG":
                    break
                await asyncio.sleep(0.1)
            assert before and before["tag"] == "IMG", f"expected img first: {before}"
            assert before["about"] == _PROFILE["about"]

            after = await page.evaluate(
                """async (barePk) => {
                  await showPublicProfile(barePk);
                  const el = document.getElementById('pub-avatar');
                  const about = document.getElementById('pub-about');
                  if (!el) return null;
                  return {
                    tag: el.tagName,
                    id: el.id,
                    className: el.className,
                    text: (el.textContent || '').trim(),
                    src: el.tagName === 'IMG' ? el.getAttribute('src') : null,
                    about: about ? (about.textContent || '') : null,
                  };
                }""",
                bare_pk,
            )
            await browser.close()

        assert after is not None
        assert after["id"] == "pub-avatar"
        assert after["tag"] == "DIV", (
            f"expected placeholder DIV for zero-kind0 peer, got {after}"
        )
        assert "avatar-placeholder" in after["className"]
        assert after["text"] == "?", f"expected '?', got {after['text']!r}"
        assert after["src"] is None
        assert after["about"] == "", f"pub-about must clear, got {after['about']!r}"
        assert errors == [], f"pageerrors: {errors}"

    async def test_own_account_pictured_then_deleted_kind0_shows_placeholder_q(
        self, live_server
    ):
        """Adversarial: pictured own hydrate → delete kind:0 → showOwnAccount → '?'."""
        pytest.importorskip("playwright")
        from playwright.async_api import async_playwright

        pubkey = await _seed_kind0(live_server["db"], _PEER_SK, _PROFILE)
        base = live_server["base"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            await page.goto(f"{base}/profile", wait_until="domcontentloaded")
            await _wait_auth_ready(page)
            await page.fill("#login-nsec", _PEER_SK)
            await page.click("#btn-login-nsec")
            await page.wait_for_selector("#view-account:not(.hidden)", timeout=5000)

            deadline = asyncio.get_event_loop().time() + 5.0
            before = None
            while asyncio.get_event_loop().time() < deadline:
                before = await page.evaluate(
                    """() => {
                      const el = document.getElementById('acct-avatar');
                      return el && {
                        tag: el.tagName,
                        src: el.tagName === 'IMG' ? el.getAttribute('src') : null,
                      };
                    }"""
                )
                if before and before.get("tag") == "IMG":
                    break
                await asyncio.sleep(0.1)
            assert before and before["tag"] == "IMG", f"expected img hydrate: {before}"

            await _delete_kind0(live_server["db"], pubkey)

            after = await page.evaluate(
                """async () => {
                  await showOwnAccount();
                  const el = document.getElementById('acct-avatar');
                  if (!el) return null;
                  return {
                    tag: el.tagName,
                    id: el.id,
                    className: el.className,
                    text: (el.textContent || '').trim(),
                    src: el.tagName === 'IMG' ? el.getAttribute('src') : null,
                  };
                }"""
            )
            await browser.close()

        assert after is not None
        assert after["id"] == "acct-avatar"
        assert after["tag"] == "DIV", f"expected placeholder DIV on !meta, got {after}"
        assert "avatar-placeholder" in after["className"]
        assert after["text"] == "?"
        assert after["src"] is None
        assert errors == [], f"pageerrors: {errors}"
