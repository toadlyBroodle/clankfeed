"""Phase 16.15: no-picture branch must restore avatar-placeholder after setAvatarImg.

Bug: after setAvatarImg leaves #acct-avatar / #pub-avatar as <img>, the
no-picture branch only sets textContent on that img (does not clear src or
restore the placeholder div), so clearing picture + Save (or a peer without
picture after a pictured view) still shows the old image.

Acceptance:
  (1) Source: no-picture paths restore an id-preserving avatar-placeholder
      (not bare textContent on a leftover <img>).
  (2) Live: picture hydrate → clear #prof-picture → Save → #acct-avatar is a
      placeholder div with the name initial, not the prior <img>.
  (3) Adversarial: pictured own-account then public peer without picture →
      #pub-avatar is placeholder, not stale img src.
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

_USER_SK = "d" * 64  # distinct from 16.14 c*64 / hydrate b*64 / relay a*64
_PEER_SK = "e" * 64
_PICTURE = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
_PROFILE = {
    "name": "AvatarClearBot",
    "about": "avatar clear restore",
    "picture": _PICTURE,
    "lud16": "clear@clankwright.com",
}
_PEER_NO_PIC = {
    "name": "PeerNoPic",
    "about": "no picture",
}


def _profile_js() -> str:
    return (STATIC / "profile.js").read_text()


def _no_picture_restore_helper_present(js: str) -> bool:
    """True if a dedicated placeholder restore helper exists (preferred fix)."""
    return (
        "function setAvatarPlaceholder" in js
        or "function restoreAvatarPlaceholder" in js
        or "function clearAvatarImg" in js
    )


def _else_branch_restores_placeholder(fn_body: str) -> bool:
    """True if a no-picture else branch rebuilds avatar-placeholder, not textContent-only."""
    # Prefer helper call
    if (
        "setAvatarPlaceholder(" in fn_body
        or "restoreAvatarPlaceholder(" in fn_body
        or "clearAvatarImg(" in fn_body
    ):
        return True
    # Or inline: createElement('div') + avatar-placeholder + replaceWith
    if (
        "avatar-placeholder" in fn_body
        and "createElement" in fn_body
        and "replaceWith" in fn_body
    ):
        return True
    return False


# ---------------------------------------------------------------------------
# Source contracts
# ---------------------------------------------------------------------------


class TestNoPictureAvatarRestore1615:
    """no-picture branches must restore placeholder after an <img> was left behind."""

    def test_show_own_account_no_picture_restores_placeholder(self):
        js = _profile_js()
        fn = js.split("async function showOwnAccount", 1)[1].split(
            "\n// ---- Profile Save", 1
        )[0]
        # Must not leave a bare textContent assignment as the only no-picture action
        # once an <img> may occupy #acct-avatar.
        assert _no_picture_restore_helper_present(js) or _else_branch_restores_placeholder(
            fn
        ), (
            "showOwnAccount no-picture branch must restore avatar-placeholder "
            "(helper or createElement+replaceWith), not textContent-only on leftover <img>"
        )

    def test_show_public_profile_no_picture_restores_placeholder(self):
        js = _profile_js()
        fn = js.split("async function showPublicProfile", 1)[1].split(
            "\n  // Fetch notes", 1
        )[0]
        assert _no_picture_restore_helper_present(js) or _else_branch_restores_placeholder(
            fn
        ), (
            "showPublicProfile no-picture branch must restore avatar-placeholder "
            "(helper or createElement+replaceWith), not textContent-only on leftover <img>"
        )

    def test_helper_preserves_element_id(self):
        js = _profile_js()
        if not _no_picture_restore_helper_present(js):
            # Inline restore must still copy id — covered by live tests; skip helper id check
            pytest.skip("no dedicated helper yet; live tests cover id preserve")
        # Extract first matching helper body
        for name in (
            "setAvatarPlaceholder",
            "restoreAvatarPlaceholder",
            "clearAvatarImg",
        ):
            marker = f"function {name}"
            if marker in js:
                body = js.split(marker, 1)[1].split("\nfunction ", 1)[0]
                assert "el.id" in body or "keepId" in body
                return
        pytest.fail("helper name present but body not found")


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
    db_path = tmp_path / "p1615.db"
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
class TestAvatarClearLive1615:
    async def test_clear_picture_save_restores_placeholder(self, live_server):
        """Live: picture hydrate → clear #prof-picture → Save → placeholder, not stale img."""
        pytest.importorskip("playwright")
        from playwright.async_api import async_playwright

        await _seed_kind0(live_server["db"], _USER_SK, _PROFILE)
        base = live_server["base"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            await page.goto(f"{base}/profile", wait_until="domcontentloaded")
            await _wait_auth_ready(page)
            await page.fill("#login-nsec", _USER_SK)
            await page.click("#btn-login-nsec")
            await page.wait_for_selector("#view-account:not(.hidden)", timeout=5000)

            # Wait for kind:0 hydrate (picture into form + img avatar)
            deadline = asyncio.get_event_loop().time() + 5.0
            picture = ""
            while asyncio.get_event_loop().time() < deadline:
                picture = await page.input_value("#prof-picture")
                if picture == _PROFILE["picture"]:
                    break
                await asyncio.sleep(0.1)
            assert picture == _PROFILE["picture"]

            # Confirm avatar is currently an <img> with the seeded picture
            before = await page.evaluate(
                """() => {
                  const el = document.getElementById('acct-avatar');
                  return el && {
                    tag: el.tagName,
                    src: el.tagName === 'IMG' ? el.getAttribute('src') : null,
                  };
                }"""
            )
            assert before and before["tag"] == "IMG", f"expected img after hydrate: {before}"
            assert before["src"] == _PICTURE

            # Clear picture and Save
            await page.fill("#prof-picture", "")
            await page.click("#btn-save-profile")
            deadline = asyncio.get_event_loop().time() + 10.0
            status = ""
            while asyncio.get_event_loop().time() < deadline:
                status = (await page.text_content("#prof-status")) or ""
                if "Saved" in status:
                    break
                await asyncio.sleep(0.1)
            assert "Saved" in status, f"save did not complete: {status!r}"

            after = await page.evaluate(
                """() => {
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

        assert after is not None, "#acct-avatar missing after clear+Save"
        assert after["id"] == "acct-avatar"
        assert after["tag"] == "DIV", (
            f"expected placeholder DIV after clearing picture, got {after}"
        )
        assert "avatar-placeholder" in after["className"]
        assert after["text"] == "A", f"expected name initial 'A', got {after['text']!r}"
        assert after["src"] is None
        assert errors == [], f"pageerrors after clear+Save: {errors}"

    async def test_public_no_picture_after_pictured_peer_clears_stale_img(
        self, live_server
    ):
        """Adversarial: pictured public peer then no-pic peer (same DOM) → placeholder."""
        pytest.importorskip("playwright")
        from playwright.async_api import async_playwright

        pictured_pk = await _seed_kind0(live_server["db"], _USER_SK, _PROFILE)
        peer_pk = await _seed_kind0(live_server["db"], _PEER_SK, _PEER_NO_PIC)
        base = live_server["base"]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            # Load pictured peer first so #pub-avatar becomes <img>
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
                      return el && {
                        tag: el.tagName,
                        src: el.tagName === 'IMG' ? el.getAttribute('src') : null,
                      };
                    }"""
                )
                if before and before.get("tag") == "IMG":
                    break
                await asyncio.sleep(0.1)
            assert before and before["tag"] == "IMG", f"expected img first: {before}"

            # Same-page switch to no-picture peer (no full reload — exercises stale img)
            after = await page.evaluate(
                """async (peerPk) => {
                  await showPublicProfile(peerPk);
                  const el = document.getElementById('pub-avatar');
                  if (!el) return null;
                  return {
                    tag: el.tagName,
                    id: el.id,
                    className: el.className,
                    text: (el.textContent || '').trim(),
                    src: el.tagName === 'IMG' ? el.getAttribute('src') : null,
                  };
                }""",
                peer_pk,
            )
            await browser.close()

        assert after is not None
        assert after["id"] == "pub-avatar"
        assert after["tag"] == "DIV", f"expected placeholder DIV for peer, got {after}"
        assert "avatar-placeholder" in after["className"]
        assert after["text"] == "P"
        assert after["src"] is None
        assert errors == [], f"pageerrors on public no-pic: {errors}"
