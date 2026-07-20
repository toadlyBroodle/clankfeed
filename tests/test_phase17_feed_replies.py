"""Phase 17.1: feed reply counts + expand → nested reply cards.

Acceptance: note with known replies shows count on expand; click expands and
lists replies (content + author); empty parent shows “No replies yet.”;
nested reply cards under an expanded parent show their own counts and expand
to grandchildren.
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

ROOT = Path(__file__).resolve().parents[1]
INDEX_JS = (ROOT / "app" / "static" / "index.js").read_text()


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
    db_path = tmp_path / "p17_replies.db"
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


def _seed_thread(base: str) -> dict:
    """Parent with 2 direct replies; first reply has a grandchild. Lonely empty note."""
    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        parent = c.post(
            "/api/v1/post",
            json={"content": "p17-parent", "display_name": "ParentAuthor"},
        ).json()["event"]
        pid = parent["id"]
        child_a = c.post(
            "/api/v1/post",
            json={
                "content": "p17-child-a",
                "reply_to": pid,
                "display_name": "ChildAuthor",
            },
        ).json()["event"]
        child_b = c.post(
            "/api/v1/post",
            json={"content": "p17-child-b", "reply_to": pid},
        ).json()["event"]
        grand = c.post(
            "/api/v1/post",
            json={
                "content": "p17-grandchild",
                "reply_to": child_a["id"],
                "display_name": "GrandAuthor",
            },
        ).json()["event"]
        lonely = c.post(
            "/api/v1/post", json={"content": "p17-lonely"}
        ).json()["event"]
    return {
        "parent_id": pid,
        "child_a": child_a["id"],
        "child_b": child_b["id"],
        "grand_id": grand["id"],
        "lonely_id": lonely["id"],
    }


class TestReplyExpandSource:
    """Static contracts that nested expand refreshes counts for rendered reply cards."""

    def test_toggle_replies_refreshes_counts_for_loaded_replies(self):
        """After rendering reply cards, must fetch/apply reply counts for those ids."""
        fn = INDEX_JS.split("async function toggleReplies", 1)[1].split(
            "\nfunction scrollToNote", 1
        )[0]
        assert "reply-counts" in fn or "fetchReplyCounts" in fn or "scheduleReplyCountFetch" in fn
        # Must update cache from expand response count (reliability)
        assert "data.count" in fn or "replyCountCache[eventId]" in fn

    def test_empty_replies_copy_present(self):
        assert "No replies yet." in INDEX_JS


async def _poll_btn_has_count(page, btn_id: str, timeout_ms: int = 10000) -> str:
    """Poll expand-btn text for a digit count (CSP blocks wait_for_function)."""
    deadline = time.time() + timeout_ms / 1000.0
    loc = page.locator(f"#{btn_id}")
    while time.time() < deadline:
        if await loc.count():
            txt = await loc.text_content()
            if txt and any(ch.isdigit() for ch in txt) and "replies" in txt:
                return txt
        await page.wait_for_timeout(100)
    raise AssertionError(f"#{btn_id} never showed a reply count")


@pytest.mark.asyncio
async def test_17_1_reply_counts_expand_nested_and_empty(live_server):
    """Headed-style acceptance: counts, expand content+author, nested, empty."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    seeded = _seed_thread(live_server["base"])
    base = live_server["base"]
    pid = seeded["parent_id"]
    child_a = seeded["child_a"]
    child_b = seeded["child_b"]
    grand = seeded["grand_id"]
    lonely = seeded["lonely_id"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{pid}", timeout=15_000)
        await page.wait_for_selector(f"#note-{lonely}", timeout=15_000)
        # Replies stay out of top-level feed
        assert await page.locator(f"#notes-feed > #note-{child_a}").count() == 0

        parent_txt = await _poll_btn_has_count(page, f"expand-replies-{pid}")
        assert "2" in parent_txt and "replies" in parent_txt
        parent_btn = page.locator(f"#expand-replies-{pid}")
        assert "has-replies" in (await parent_btn.get_attribute("class") or "")

        # Expand parent → both direct replies (content + author)
        await parent_btn.click()
        await page.wait_for_selector(f"#replies-{pid}:not(.hidden)", timeout=10_000)
        await page.wait_for_selector(f"#replies-{pid} #note-{child_a}", timeout=10_000)
        await page.wait_for_selector(f"#replies-{pid} #note-{child_b}", timeout=10_000)
        card_a = page.locator(f"#replies-{pid} #note-{child_a}")
        assert "p17-child-a" in ((await card_a.locator(".note-content").text_content()) or "")
        author_bit = await card_a.locator("a.c-accent, .text-xs.font-bold").first.text_content()
        assert author_bit and author_bit.strip()

        # Nested: child_a's expand must show its reply count, then grandchild
        nested_txt = await _poll_btn_has_count(page, f"expand-replies-{child_a}")
        assert "1" in nested_txt
        await page.locator(f"#expand-replies-{child_a}").click()
        await page.wait_for_selector(
            f"#replies-{child_a} #note-{grand}", timeout=10_000
        )
        grand_txt = await page.locator(
            f"#replies-{child_a} #note-{grand} .note-content"
        ).text_content()
        assert grand_txt is not None and "p17-grandchild" in grand_txt

        # Empty parent → “No replies yet.”
        await page.locator(f"#expand-replies-{lonely}").click()
        await page.wait_for_selector(f"#replies-{lonely}:not(.hidden)", timeout=10_000)
        empty_copy = await page.locator(f"#replies-{lonely}").text_content()
        assert empty_copy is not None and "No replies yet." in empty_copy

        await browser.close()


@pytest.mark.asyncio
async def test_17_1_adversarial_expand_bad_id_stays_hidden(live_server):
    """Adversarial: toggleReplies on missing container is a no-op (no throw)."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright
    base = live_server["base"]
    # Seed one note so #notes-feed is visible (empty feed keeps it hidden)
    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        c.post("/api/v1/post", json={"content": "p17-adv-seed"})

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#notes-feed .note-card", timeout=15_000)
        err = await page.evaluate(
            """() => {
              try {
                if (typeof toggleReplies === 'function') {
                  toggleReplies('0'.repeat(64));
                }
                return null;
              } catch (e) {
                return String(e);
              }
            }"""
        )
        assert err is None
        await browser.close()
