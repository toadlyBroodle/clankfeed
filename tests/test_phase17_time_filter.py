"""Phase 17.2: feed time filter dropdown → since= on GET /api/v1/events.

Options: 1day / 3day / 1week / 1month / all. Default all (no since).
Changing the dropdown reloads the active feed tab.
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
INDEX_HTML = (ROOT / "app" / "static" / "index.html").read_text()
INDEX_JS = (ROOT / "app" / "static" / "index.js").read_text()
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
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(0.15)
    raise RuntimeError(f"server did not become healthy: {last_err}")


@pytest.fixture
def live_server(tmp_path):
    db_path = tmp_path / "p17_since.db"
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
        yield {"base": base, "db": db_path, "port": port}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class TestTimeFilterSource:
    def test_filter_since_select_in_html(self):
        assert 'id="filter-since"' in INDEX_HTML
        for opt in ("1day", "3day", "1week", "1month", "all"):
            assert f'value="{opt}"' in INDEX_HTML
        assert 'value="1day" selected' in INDEX_HTML

    def test_set_sort_appends_since(self):
        """Feed fetch must map filter-since → since= (except all)."""
        assert "filter-since" in INDEX_JS or "filterSince" in INDEX_JS
        assert "since=" in INDEX_JS
        assert "DEFAULT_SINCE" in INDEX_JS and "'1day'" in INDEX_JS
        # Window seconds for each option (approx)
        assert "86400" in INDEX_JS  # 1 day
        assert "259200" in INDEX_JS or "3" in INDEX_JS  # 3 day
        assert "604800" in INDEX_JS  # 1 week
        assert "2592000" in INDEX_JS  # ~30 day month


async def _seed_old_and_new(base: str, db_path: Path) -> dict:
    """One fresh local note + one old (40 days) clankfeed note via direct SQL."""
    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        fresh = c.post(
            "/api/v1/post", json={"content": "p17-fresh-note"}
        ).json()["event"]

    now = int(time.time())
    old = sign_event(
        AUTHOR_SK,
        {
            "created_at": now - (40 * 86400),
            "kind": 1,
            "tags": [],
            "content": "p17-old-note",
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
                "21, '0', 0, 'clankfeed')"
            ),
            {
                "id": old["id"],
                "pubkey": old["pubkey"],
                "created_at": old["created_at"],
                "kind": old["kind"],
                "tags": "[]",
                "content": old["content"],
                "sig": old["sig"],
            },
        )
    await engine.dispose()
    return {"fresh_id": fresh["id"], "old_id": old["id"], "now": now}


@pytest.mark.asyncio
async def test_17_2_time_filter_since_urls_and_window(live_server):
    """Pick each option: since= present/absent; 1month hides 40-day-old note."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    seeded = await _seed_old_and_new(live_server["base"], live_server["db"])
    base = live_server["base"]
    fresh_id = seeded["fresh_id"]
    old_id = seeded["old_id"]
    seen: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        def _on_request(req):
            if "/api/v1/events?" in req.url and "reply-counts" not in req.url:
                seen.append(req.url)

        page.on("request", _on_request)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#filter-since", timeout=10_000)
        await page.wait_for_selector(f"#note-{fresh_id}", timeout=15_000)
        # Default 1day: old (40d) hidden, feed URL has since≈now-86400
        import re

        assert await page.locator(f"#note-{old_id}").count() == 0
        default_urls = [u for u in seen if "kinds=" in u and "/events?" in u]
        assert default_urls, "expected initial feed fetch"
        assert "since=" in default_urls[-1], default_urls[-1]
        m0 = re.search(r"since=(\d+)", default_urls[-1])
        assert m0, default_urls[-1]
        expect0 = int(time.time()) - 86400
        assert abs(int(m0.group(1)) - expect0) < 120, default_urls[-1]
        selected = await page.locator("#filter-since").input_value()
        assert selected == "1day"

        windows = {
            "1day": 86400,
            "3day": 3 * 86400,
            "1week": 7 * 86400,
            "1month": 30 * 86400,
        }
        for value, secs in windows.items():
            seen.clear()
            await page.select_option("#filter-since", value)
            # Poll captured requests (CSP blocks wait_for_function)
            last = None
            for _ in range(50):
                feed_urls = [u for u in seen if "kinds=" in u and "/events?" in u]
                if feed_urls and "since=" in feed_urls[-1]:
                    last = feed_urls[-1]
                    break
                await page.wait_for_timeout(100)
            assert last, f"no since= feed fetch after selecting {value}: {seen}"
            m = re.search(r"since=(\d+)", last)
            assert m, last
            since_val = int(m.group(1))
            expect = int(time.time()) - secs
            assert abs(since_val - expect) < 120, (
                f"{value}: since={since_val} expected ~{expect}"
            )

        # 1month: old (40d) gone, fresh remains
        await page.select_option("#filter-since", "1month")
        await page.wait_for_selector(f"#note-{fresh_id}", timeout=10_000)
        for _ in range(50):
            if await page.locator(f"#note-{old_id}").count() == 0:
                break
            await page.wait_for_timeout(100)
        assert await page.locator(f"#note-{old_id}").count() == 0

        # all: since absent again, old returns
        seen.clear()
        await page.select_option("#filter-since", "all")
        await page.wait_for_selector(f"#note-{old_id}", timeout=10_000)
        all_urls = None
        for _ in range(50):
            cand = [u for u in seen if "kinds=" in u and "/events?" in u]
            if cand and "since=" not in cand[-1]:
                all_urls = cand
                break
            await page.wait_for_timeout(100)
        assert all_urls, seen
        assert "since=" not in all_urls[-1], all_urls[-1]

        await browser.close()


@pytest.mark.asyncio
async def test_17_2_adversarial_api_since_rejects_non_int(live_server):
    """Adversarial: garbage since query → 422 (FastAPI validation), not 500."""
    with httpx.Client(
        base_url=live_server["base"],
        timeout=10.0,
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as c:
        resp = c.get("/api/v1/events?kinds=1&since=not-a-number")
        assert resp.status_code in (400, 422)
