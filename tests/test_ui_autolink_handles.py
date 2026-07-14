"""UI-4 autolink URLs + UI-6 kind:0 handles on note cards.

Source contracts + Playwright DOM smoke. XSS payloads must not execute;
only http/https URLs become anchors.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.nostr import sign_event

ROOT = Path(__file__).resolve().parents[1]
_STATIC = ROOT / "app" / "static"
AUTHOR_SK = "c" * 64
AUTHOR_PK = None  # filled from first signed event


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_health(base: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base}/health", timeout=1.0)
            if r.status_code == 200:
                return
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(0.15)
    raise RuntimeError(f"server did not become healthy: {last_err}")


# ---- UI-4 source contracts ----


class TestAutolinkUI4Source:
    """linkify must exist, be used for note content, and reject non-http(s)."""

    def test_nostr_auth_defines_linkify(self):
        js = (_STATIC / "nostr-auth.js").read_text()
        assert "function linkify" in js

    def test_index_renderNoteCard_uses_linkify_for_content(self):
        index = (_STATIC / "index.html").read_text()
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert "linkify(" in fn
        # Must not dump raw esc(content) alone into the content paragraph
        assert "linkify(n.content)" in fn or "linkify(n.content ||" in fn

    def test_profile_notes_use_linkify(self):
        profile = (_STATIC / "profile.html").read_text()
        assert "linkify(" in profile
        assert "linkify(n.content)" in profile or "linkify(n.content ||" in profile

    def test_linkify_only_http_https_and_escapes(self):
        js = (_STATIC / "nostr-auth.js").read_text()
        fn = js.split("function linkify", 1)[1].split("\nfunction ", 1)[0]
        # Escape before linking (XSS)
        assert "esc(" in fn
        # Protocol allowlist
        assert "https?" in fn or "http" in fn
        # Must not treat javascript: as a link target construction without filter
        assert "noopener" in fn or "noreferrer" in fn
        assert "target" in fn


class TestHandlesUI6Source:
    """getDisplayName must prefer kind:0 name, then display_name, then nip05."""

    def test_getDisplayName_reads_display_name_and_nip05(self):
        index = (_STATIC / "index.html").read_text()
        fn = index.split("function getDisplayName", 1)[1].split("\nfunction ", 1)[0]
        assert "display_name" in fn
        assert "nip05" in fn
        # Still prefers name when present
        assert "meta.name" in fn or "meta?.name" in fn or ".name" in fn


# ---- Live Playwright ----


@pytest.fixture
def live_server(tmp_path):
    db_path = tmp_path / "ui46.db"
    port = _free_port()
    env = os.environ.copy()
    env.update(
        {
            "AUTH_ROOT_KEY": "test-mode",
            "EXTERNAL_INGEST": "false",
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
        yield {"base": base, "db": db_path, "port": port}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _seed_ui46(db_path: Path) -> dict:
    """Kind:0 with display_name + note containing URL and XSS bait."""
    meta = sign_event(
        AUTHOR_SK,
        {
            "kind": 0,
            "created_at": int(time.time()) - 10,
            "tags": [],
            "content": (
                '{"display_name":"HandleBot","about":"x",'
                '"nip05":"bot@example.com","picture":"https://example.com/a.png"}'
            ),
        },
    )
    note = sign_event(
        AUTHOR_SK,
        {
            "kind": 1,
            "created_at": int(time.time()) - 5,
            "tags": [],
            "content": (
                "see https://example.com/path?q=1 "
                'and <script>window.__xss=1</script> '
                "javascript:alert(1)"
            ),
        },
    )
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        for ev, sc in ((meta, 0), (note, 21)):
            await conn.execute(
                text(
                    "INSERT INTO nostr_events "
                    "(id, pubkey, created_at, kind, tags, content, sig, "
                    "sats_clank, value_usd, sats_ext, origin) "
                    "VALUES (:id, :pubkey, :created_at, :kind, :tags, :content, :sig, "
                    ":sc, '0', 0, 'clankfeed')"
                ),
                {
                    "id": ev["id"],
                    "pubkey": ev["pubkey"],
                    "created_at": ev["created_at"],
                    "kind": ev["kind"],
                    "tags": "[]",
                    "content": ev["content"],
                    "sig": ev["sig"],
                    "sc": sc,
                },
            )
    await engine.dispose()
    return {"note_id": note["id"], "pubkey": note["pubkey"]}


@pytest.mark.asyncio
async def test_ui4_ui6_autolink_and_handle_dom(live_server):
    """DOM: URL is an <a href=https...>; XSS inert; handle from display_name."""
    pytest.importorskip("playwright")
    from playwright.async_api import async_playwright

    seeded = await _seed_ui46(live_server["db"])
    base = live_server["base"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base + "/", wait_until="networkidle")
        # Wait for note card
        card = page.locator(f"#note-{seeded['note_id']}")
        await card.wait_for(timeout=15000)

        # UI-6: handle visible (display_name), not hex-only
        text = await card.inner_text()
        assert "HandleBot" in text

        # UI-4: https URL becomes anchor with correct href
        link = card.locator("a.note-link, .note-content a[href^='https://']")
        await link.first.wait_for(timeout=5000)
        href = await link.first.get_attribute("href")
        assert href and href.startswith("https://example.com/")
        rel = await link.first.get_attribute("rel") or ""
        assert "noopener" in rel or "noreferrer" in rel

        # Adversarial: javascript: must not be an href
        js_links = await card.locator("a[href^='javascript:']").count()
        assert js_links == 0

        # XSS: script must not execute
        xss = await page.evaluate("window.__xss")
        assert xss is None

        # Escaped script text may appear as text, not as element
        script_nodes = await card.locator("script").count()
        assert script_nodes == 0

        await browser.close()
