"""Phase 17.3: expand must not clobber replyCountCache with capped GET /replies count.

Bug: toggleReplies assigns replyCountCache[eventId] = data.count from
GET .../replies?limit=50, but get_replies returns count: len(replies) (page size),
so a prior accurate batch count from POST /events/reply-counts is lowered to ≤50
after expand/collapse on large threads.
"""

from __future__ import annotations

import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from app.database import async_session
from app.nostr import sign_event
from app.relay import store_event
from tests.conftest import kind1_tags

ROOT = Path(__file__).resolve().parents[1]
INDEX_JS = (ROOT / "app" / "static" / "index.js").read_text()
PRIV = "b" * 64
N_REPLIES = 55


def _toggle_replies_fn() -> str:
    return INDEX_JS.split("async function toggleReplies", 1)[1].split(
        "\nfunction scrollToNote", 1
    )[0]


def _signed_reply(parent_id: str, i: int, created_at: int | None = None) -> dict:
    # Older than a freshly POST'd parent so default feed limit=50 still includes parent
    # (replies are filtered client-side as non-top-level, but still consume the page).
    ts = created_at if created_at is not None else int(time.time()) - 10_000 - i
    return sign_event(
        PRIV,
        {
            "created_at": ts,
            "kind": 1,
            "tags": kind1_tags(PRIV, [["e", parent_id, "", "reply"]]),
            "content": f"p17.3-reply-{i}",
        },
    )


async def _seed_replies_async(parent_id: str, n: int = N_REPLIES) -> None:
    """Bulk-store replies via store_event (bypasses RATE_POST)."""
    async with async_session() as db:
        for i in range(n):
            await store_event(db, _signed_reply(parent_id, i), sats_clank=21, origin="clankfeed")


def _seed_replies_sqlite(db_path: Path, parent_id: str, n: int = N_REPLIES) -> None:
    """Insert replies into a live-server sqlite file (WAL-safe enough for tests)."""
    conn = sqlite3.connect(str(db_path))
    try:
        for i in range(n):
            ev = _signed_reply(parent_id, i)
            conn.execute(
                "INSERT INTO nostr_events "
                "(id, pubkey, created_at, kind, tags, content, sig, "
                " sats_clank, value_usd, sats_ext, origin) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ev["id"],
                    ev["pubkey"],
                    ev["created_at"],
                    ev["kind"],
                    json.dumps(ev["tags"]),
                    ev["content"],
                    ev["sig"],
                    21,
                    "0",
                    0,
                    "clankfeed",
                ),
            )
        conn.commit()
    finally:
        conn.close()


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
    db_path = tmp_path / "p17_cap.db"
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


class TestReplyCountCapSource:
    """Static contracts: expand must never lower an existing cache entry."""

    def test_toggle_replies_never_lowers_cache_with_page_count(self):
        """Must Math.max (or equivalent) existing cache vs expand response count."""
        fn = _toggle_replies_fn()
        assert "Math.max" in fn, (
            "toggleReplies must Math.max(existing cache, expand count) so a "
            "prior reply-counts total is not clobbered by capped data.count"
        )
        assert "data.count" in fn or "replies.length" in fn

    def test_toggle_replies_does_not_blind_assign_cnt(self):
        """Adversarial: bare replyCountCache[eventId] = cnt (no max) is forbidden."""
        fn = _toggle_replies_fn()
        blind = re.search(
            r"replyCountCache\[eventId\]\s*=\s*cnt\b",
            fn,
        )
        assert blind is None, (
            "unguarded replyCountCache[eventId] = cnt overwrites accurate batch "
            "counts with capped GET /replies page size"
        )


@pytest.mark.asyncio
async def test_get_replies_count_is_true_total_not_page_len(client):
    """API: count must be full reply total even when replies list is limit-capped."""
    parent = (await client.post("/api/v1/post", json={"content": "p17.3-parent"})).json()[
        "event"
    ]
    pid = parent["id"]
    await _seed_replies_async(pid, N_REPLIES)

    resp = await client.get(f"/api/v1/events/{pid}/replies?sort=newest&limit=50")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["replies"]) == 50, "page must still be capped at limit"
    assert body["count"] == N_REPLIES, (
        f"count must be true total {N_REPLIES}, not len(replies)={len(body['replies'])}"
    )

    counts = await client.post(
        "/api/v1/events/reply-counts",
        json={"event_ids": [pid]},
    )
    assert counts.status_code == 200
    assert counts.json()["counts"][pid] == N_REPLIES


async def _poll_btn_count_ge(page, btn_id: str, min_n: int, timeout_ms: int = 20000) -> str:
    deadline = time.time() + timeout_ms / 1000.0
    loc = page.locator(f"#{btn_id}")
    while time.time() < deadline:
        if await loc.count():
            txt = await loc.text_content()
            if txt and "replies" in txt:
                m = re.search(r"(\d+)\s*replies", txt)
                if m and int(m.group(1)) >= min_n:
                    return txt
        await page.wait_for_timeout(100)
    raise AssertionError(f"#{btn_id} never showed count >= {min_n}")


@pytest.mark.asyncio
async def test_17_3_expand_keeps_true_count_over_fifty(live_server):
    """Live: >50 replies — expand/collapse must keep true count on the control (not 50)."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    db_path = live_server["db"]
    with httpx.Client(
        base_url=base, timeout=30.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        parent = c.post(
            "/api/v1/post",
            json={"content": "p17.3-live-parent", "display_name": "CapParent"},
        ).json()["event"]
        pid = parent["id"]

    _seed_replies_sqlite(db_path, pid, N_REPLIES)

    with httpx.Client(
        base_url=base, timeout=30.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        counts = c.post(
            "/api/v1/events/reply-counts", json={"event_ids": [pid]}
        ).json()["counts"]
        assert counts[pid] == N_REPLIES
        capped = c.get(f"/api/v1/events/{pid}/replies?limit=50").json()
        assert len(capped["replies"]) == 50
        # Pre-fix: buggy API returns count==50; keep this assert soft until API fixed —
        # the UI acceptance below is the primary live guard.

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{pid}", timeout=15_000)

        btn_id = f"expand-replies-{pid}"
        before = await _poll_btn_count_ge(page, btn_id, N_REPLIES)
        assert str(N_REPLIES) in before

        await page.locator(f"#{btn_id}").click()
        await page.wait_for_selector(f"#replies-{pid}:not(.hidden)", timeout=10_000)
        after_expand = await page.locator(f"#{btn_id}").text_content()
        assert after_expand is not None
        m = re.search(r"(\d+)\s*replies", after_expand)
        assert m, f"no count in expand btn: {after_expand!r}"
        shown = int(m.group(1))
        assert shown == N_REPLIES, (
            f"expand clobbered count to {shown} (want {N_REPLIES}, not ≤50)"
        )

        await page.locator(f"#{btn_id}").click()
        # .hidden is display:none — wait for attached+class, not visible
        deadline = time.time() + 10
        while time.time() < deadline:
            cls = await page.locator(f"#replies-{pid}").get_attribute("class") or ""
            if "hidden" in cls.split():
                break
            await page.wait_for_timeout(50)
        else:
            raise AssertionError("replies container did not collapse")
        after_collapse = await page.locator(f"#{btn_id}").text_content()
        assert after_collapse is not None
        m2 = re.search(r"(\d+)\s*replies", after_collapse)
        assert m2 and int(m2.group(1)) == N_REPLIES, (
            f"collapse shows {after_collapse!r}, want {N_REPLIES} replies"
        )

        cached = await page.evaluate(f"() => replyCountCache[{pid!r}]")
        assert cached == N_REPLIES, f"replyCountCache clobbered to {cached}"

        await browser.close()
