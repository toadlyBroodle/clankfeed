"""UI3.4: Playwright/DOM smoke for dual-feed tabs + external Top (sort=ext) order.

Source-only greps in TestTwoFeedsUI3 cannot catch a broken setFeed fetch.
These drive a real browser against a live ASGI server.
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
AUTHOR_SK = "b" * 64


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
        except Exception as e:  # noqa: BLE001 — poll until up
            last_err = e
        time.sleep(0.15)
    raise RuntimeError(f"server did not become healthy: {last_err}")


@pytest.fixture
def live_server(tmp_path):
    """Uvicorn subprocess with file SQLite (shared with seed helpers)."""
    db_path = tmp_path / "ui34.db"
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


async def _seed_notes(base: str, db_path: Path) -> dict:
    """Local clankfeed note + two external notes with distinct sats_ext."""
    with httpx.Client(base_url=base, timeout=10.0) as c:
        local = c.post("/api/v1/post", json={"content": "local-ui34-only"}).json()
        local_id = local["event"]["id"]

    high = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 10,
            "kind": 1,
            "tags": [],
            "content": "ext-high-ui34",
        },
    )
    low = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 5,
            "kind": 1,
            "tags": [],
            "content": "ext-low-ui34",
        },
    )

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        for note, sats_ext in ((high, 500), (low, 50)):
            await conn.execute(
                text(
                    "INSERT INTO nostr_events "
                    "(id, pubkey, created_at, kind, tags, content, sig, "
                    "sats_clank, value_usd, sats_ext, origin) "
                    "VALUES (:id, :pubkey, :created_at, :kind, :tags, :content, :sig, "
                    "0, '0', :sats_ext, 'external')"
                ),
                {
                    "id": note["id"],
                    "pubkey": note["pubkey"],
                    "created_at": note["created_at"],
                    "kind": note["kind"],
                    "tags": "[]",
                    "content": note["content"],
                    "sig": note["sig"],
                    "sats_ext": sats_ext,
                },
            )
    await engine.dispose()

    # Sanity: API membership + ext order before browser
    with httpx.Client(base_url=base, timeout=10.0) as c:
        clank = c.get("/api/v1/events?kinds=1&origin=clankfeed").json()["events"]
        clank_ids = {e["id"] for e in clank}
        assert local_id in clank_ids
        assert high["id"] not in clank_ids
        assert low["id"] not in clank_ids

        ext = c.get("/api/v1/events?kinds=1&origin=all&sort=ext").json()["events"]
        kind1 = [e for e in ext if e["kind"] == 1]
        ids = [e["id"] for e in kind1]
        assert high["id"] in ids and low["id"] in ids
        assert ids.index(high["id"]) < ids.index(low["id"])

    return {
        "local_id": local_id,
        "high_id": high["id"],
        "low_id": low["id"],
    }


@pytest.mark.asyncio
async def test_ui34_tab_membership_and_ext_top_order(live_server):
    """Click tabs: clankfeed hides external; external Top orders by sats_ext."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    ids = await _seed_notes(live_server["base"], live_server["db"])
    base = live_server["base"]
    seen_urls: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        def _on_request(req):
            if "/api/v1/events" in req.url:
                seen_urls.append(req.url)

        page.on("request", _on_request)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#feed-clankfeed", timeout=10_000)
        # Default load: setFeed('clankfeed')
        await page.wait_for_selector(f"#note-{ids['local_id']}", timeout=15_000)

        assert await page.locator(f"#note-{ids['local_id']}").count() == 1
        assert await page.locator(f"#note-{ids['high_id']}").count() == 0
        assert await page.locator(f"#note-{ids['low_id']}").count() == 0

        await page.click("#feed-external")
        await page.wait_for_selector(f"#note-{ids['high_id']}", timeout=15_000)
        assert await page.locator(f"#note-{ids['local_id']}").count() == 1
        assert await page.locator(f"#note-{ids['high_id']}").count() == 1
        assert await page.locator(f"#note-{ids['low_id']}").count() == 1

        # External + Top → sort=ext order (high before low in DOM)
        await page.click("#sort-value")
        await page.wait_for_function(
            """([high, low]) => {
              const cards = [...document.querySelectorAll('#notes-feed .note-card')];
              const ids = cards.map(c => c.id.replace(/^note-/, ''));
              return ids.includes(high) && ids.includes(low)
                && ids.indexOf(high) < ids.indexOf(low);
            }""",
            arg=[ids["high_id"], ids["low_id"]],
            timeout=15_000,
        )

        ext_top_urls = [
            u
            for u in seen_urls
            if "sort=ext" in u and "origin=all" in u
        ]
        assert ext_top_urls, f"expected sort=ext&origin=all fetch; saw: {seen_urls}"

        # Adversarial: switch back to clankfeed Top — must not keep external notes
        # or reuse sort=ext/origin=all from the previous tab.
        await page.click("#feed-clankfeed")
        await page.click("#sort-value")
        await page.wait_for_selector(f"#note-{ids['local_id']}", timeout=15_000)
        # Give the fetch a moment to settle membership
        for _ in range(50):
            if await page.locator(f"#note-{ids['high_id']}").count() == 0:
                break
            await page.wait_for_timeout(100)
        assert await page.locator(f"#note-{ids['high_id']}").count() == 0
        assert await page.locator(f"#note-{ids['low_id']}").count() == 0
        clank_top = [
            u for u in seen_urls if "sort=value" in u and "origin=clankfeed" in u
        ]
        assert clank_top, f"expected sort=value&origin=clankfeed; saw: {seen_urls}"

        await browser.close()


async def _seed_external_only(base: str, db_path: Path) -> str:
    """One external note; zero clankfeed locals — empty-state repro for UI3.6."""
    note = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 3,
            "kind": 1,
            "tags": [],
            "content": "ext-only-ui36",
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
                "0, '0', :sats_ext, 'external')"
            ),
            {
                "id": note["id"],
                "pubkey": note["pubkey"],
                "created_at": note["created_at"],
                "kind": note["kind"],
                "tags": "[]",
                "content": note["content"],
                "sig": note["sig"],
                "sats_ext": 42,
            },
        )
    await engine.dispose()

    with httpx.Client(base_url=base, timeout=10.0) as c:
        clank = c.get("/api/v1/events?kinds=1&origin=clankfeed").json()["events"]
        assert all(e["id"] != note["id"] for e in clank)
        assert len(clank) == 0
        all_ev = c.get("/api/v1/events?kinds=1&origin=all").json()["events"]
        assert note["id"] in {e["id"] for e in all_ev}

    return note["id"]


@pytest.mark.asyncio
async def test_ui36_empty_clankfeed_shows_empty_state(live_server):
    """UI3.6: empty clankfeed tab must keep #empty-feed visible after renderNotes.

    Prod default: zero locals + many externals. Prior bug: renderNotes wiped
    #empty-feed via innerHTML so the tab went blank.
    Avoid page.wait_for_function — CSP script-src lacks unsafe-eval.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    ext_id = await _seed_external_only(live_server["base"], live_server["db"])
    base = live_server["base"]

    async def _empty_visible() -> bool:
        loc = page.locator("#empty-feed")
        if await loc.count() != 1:
            return False
        return await loc.is_visible()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#feed-clankfeed", timeout=10_000)

        # Wait for setFeed('clankfeed') REST round-trip (empty result → empty state)
        for _ in range(100):
            if await _empty_visible() and await page.locator("#notes-feed .note-card").count() == 0:
                break
            await page.wait_for_timeout(100)
        else:
            raise AssertionError(
                "#empty-feed not visible after empty clankfeed load "
                f"(count={await page.locator('#empty-feed').count()})"
            )

        empty = page.locator("#empty-feed")
        assert await empty.count() == 1
        assert await empty.is_visible()
        text = (await empty.inner_text()).strip()
        assert "No notes yet" in text or "first to post" in text.lower()
        assert await page.locator("#notes-feed .note-card").count() == 0
        assert await page.locator(f"#note-{ext_id}").count() == 0

        # External tab: empty hides, external note appears
        await page.click("#feed-external")
        await page.wait_for_selector(f"#note-{ext_id}", timeout=15_000)
        assert await page.locator("#empty-feed").is_hidden()
        assert await page.locator(f"#note-{ext_id}").count() == 1

        # Adversarial: back to empty clankfeed — empty-feed must still exist + show
        await page.click("#feed-clankfeed")
        for _ in range(100):
            if await _empty_visible() and await page.locator(f"#note-{ext_id}").count() == 0:
                break
            await page.wait_for_timeout(100)
        else:
            raise AssertionError("empty-feed not restored after return to clankfeed")
        assert await page.locator("#empty-feed").is_visible()
        assert await page.locator(f"#note-{ext_id}").count() == 0

        await browser.close()
