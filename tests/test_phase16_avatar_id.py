"""Phase 16.14: setAvatarImg must preserve #acct-avatar across hydrate + Save.

Bug: el.replaceWith(img) drops id="acct-avatar"; img onerror replaces with an
id-less placeholder; second showOwnAccount (Save success / re-login) does
getElementById('acct-avatar') → null → TypeError on replaceWith.

Acceptance:
  (1) setAvatarImg null-guards missing el; preserves el.id on img + error placeholder.
  (2) Live: seed kind:0 with picture → nsec login → Save Profile → zero pageerror
      and #acct-avatar still present.
  (3) Adversarial: second showOwnAccount with picture does not throw.
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

_USER_SK = "c" * 64  # distinct from hydrate b*64 / relay a*64
_PICTURE = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
_PROFILE = {
    "name": "AvatarIdBot",
    "about": "avatar id preserve",
    "picture": _PICTURE,
    "lud16": "avatar@botlab.dev",
}


def _profile_js() -> str:
    return (STATIC / "profile.js").read_text()


# ---------------------------------------------------------------------------
# Source contracts
# ---------------------------------------------------------------------------


class TestSetAvatarImgIdPreserve1614:
    """setAvatarImg must keep the original element id through replace + onerror."""

    def test_set_avatar_img_null_guards(self):
        js = _profile_js()
        fn = js.split("function setAvatarImg", 1)[1].split("\nfunction ", 1)[0]
        assert "if (!el)" in fn or "if (el == null)" in fn or "if (el === null)" in fn

    def test_set_avatar_img_preserves_id_on_img(self):
        js = _profile_js()
        fn = js.split("function setAvatarImg", 1)[1].split("\nfunction ", 1)[0]
        assert "el.id" in fn
        assert "img.id" in fn

    def test_set_avatar_img_preserves_id_on_error_placeholder(self):
        js = _profile_js()
        fn = js.split("function setAvatarImg", 1)[1].split("\nfunction ", 1)[0]
        assert "error" in fn
        # Placeholder must inherit id from img (or el) so getElementById still works
        assert "div.id" in fn


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
    db_path = tmp_path / "p1614.db"
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
class TestAvatarIdPreserveLive1614:
    async def test_save_profile_with_picture_keeps_acct_avatar_no_pageerror(
        self, live_server
    ):
        """Live: picture hydrate → Save → zero pageerror; #acct-avatar still present."""
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

            # Wait for kind:0 hydrate into form (CSP blocks wait_for_function strings)
            deadline = asyncio.get_event_loop().time() + 5.0
            picture = ""
            while asyncio.get_event_loop().time() < deadline:
                picture = await page.input_value("#prof-picture")
                if picture == _PROFILE["picture"]:
                    break
                await asyncio.sleep(0.1)
            assert picture == _PROFILE["picture"]

            await page.click("#btn-save-profile")
            deadline = asyncio.get_event_loop().time() + 10.0
            status = ""
            while asyncio.get_event_loop().time() < deadline:
                status = (await page.text_content("#prof-status")) or ""
                if "Saved" in status:
                    break
                await asyncio.sleep(0.1)
            assert "Saved" in status, f"save did not complete: {status!r}"

            # Second showOwnAccount (post-save) must not throw; id must survive
            avatar = await page.query_selector("#acct-avatar")
            await browser.close()

        assert avatar is not None, "#acct-avatar missing after Save (id dropped by setAvatarImg)"
        assert errors == [], f"pageerrors after Save: {errors}"

    async def test_second_show_own_account_with_picture_no_throw(self, live_server):
        """Adversarial: two consecutive showOwnAccount calls with picture must not throw."""
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

            result = await page.evaluate(
                """async () => {
                  await showOwnAccount();
                  const afterFirst = !!document.getElementById('acct-avatar');
                  await showOwnAccount();
                  const afterSecond = !!document.getElementById('acct-avatar');
                  return { afterFirst, afterSecond };
                }"""
            )
            await browser.close()

        assert result["afterFirst"] is True
        assert result["afterSecond"] is True
        assert errors == [], f"pageerrors on double showOwnAccount: {errors}"
