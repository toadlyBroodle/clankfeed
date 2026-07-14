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


async def _seed_one_local(base: str) -> str:
    """One origin=clankfeed note via relay-signed post (test-mode)."""
    with httpx.Client(base_url=base, timeout=10.0) as c:
        local = c.post("/api/v1/post", json={"content": "local-ui37-nonempty"}).json()
        local_id = local["event"]["id"]
        clank = c.get("/api/v1/events?kinds=1&origin=clankfeed").json()["events"]
        assert local_id in {e["id"] for e in clank}
    return local_id


async def _seed_zero_and_valued_external(base: str, db_path: Path) -> dict:
    """FEED-1a/1b: one zero-sats external + ≥2 valued externals (+ local)."""
    with httpx.Client(base_url=base, timeout=10.0) as c:
        local = c.post("/api/v1/post", json={"content": "local-feed1a"}).json()
        local_id = local["event"]["id"]

    zero = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 30,
            "kind": 1,
            "tags": [],
            "content": "ext-zero-feed1a",
        },
    )
    valued_high = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 20,
            "kind": 1,
            "tags": [],
            "content": "ext-valued-high-feed1a",
        },
    )
    valued_low = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 10,
            "kind": 1,
            "tags": [],
            "content": "ext-valued-low-feed1a",
        },
    )

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        for note, sats_ext in (
            (zero, 0),
            (valued_high, 500),
            (valued_low, 77),
        ):
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

    def _ext_payload(note: dict, sats_ext: int) -> dict:
        return {
            "id": note["id"],
            "pubkey": note["pubkey"],
            "created_at": note["created_at"],
            "kind": 1,
            "tags": [],
            "content": note["content"],
            "sig": note["sig"],
            "origin": "external",
            "sats_ext": sats_ext,
            "sats_clank": 0,
        }

    valued_events = [
        _ext_payload(valued_high, 500),
        _ext_payload(valued_low, 77),
    ]
    return {
        "local_id": local_id,
        "zero_id": zero["id"],
        "valued_ids": [valued_high["id"], valued_low["id"]],
        "valued_id": valued_high["id"],  # back-compat alias (first valued)
        "zero_event": _ext_payload(zero, 0),
        "valued_events": valued_events,
        "valued_event": valued_events[0],
    }


async def _seed_zero_only_external(base: str, db_path: Path) -> dict:
    """FEED-1b: local + ≥1 zero-sats external, no valued externals."""
    with httpx.Client(base_url=base, timeout=10.0) as c:
        local = c.post("/api/v1/post", json={"content": "local-feed1b-zero-only"}).json()
        local_id = local["event"]["id"]

    zero_a = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 20,
            "kind": 1,
            "tags": [],
            "content": "ext-zero-only-a",
        },
    )
    zero_b = sign_event(
        AUTHOR_SK,
        {
            "created_at": int(time.time()) - 10,
            "kind": 1,
            "tags": [],
            "content": "ext-zero-only-b",
        },
    )

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        for note in (zero_a, zero_b):
            await conn.execute(
                text(
                    "INSERT INTO nostr_events "
                    "(id, pubkey, created_at, kind, tags, content, sig, "
                    "sats_clank, value_usd, sats_ext, origin) "
                    "VALUES (:id, :pubkey, :created_at, :kind, :tags, :content, :sig, "
                    "0, '0', 0, 'external')"
                ),
                {
                    "id": note["id"],
                    "pubkey": note["pubkey"],
                    "created_at": note["created_at"],
                    "kind": note["kind"],
                    "tags": "[]",
                    "content": note["content"],
                    "sig": note["sig"],
                },
            )
    await engine.dispose()

    return {
        "local_id": local_id,
        "zero_ids": [zero_a["id"], zero_b["id"]],
        "valued_ids": [],
    }


@pytest.mark.asyncio
async def test_feed1a_external_tab_omits_zero_shows_valued(live_server):
    """FEED-1a/FEED-1b: #feed-external omits zero; shows ≥2 valued (cardinality).

    Single-valued seed left a many/none gap: a filter that only keeps the first
    valued (or hides all when any zero is present) stayed green. Seed ≥2 valued
    + one zero; assert every valued id is in the DOM and zero is absent.
    Avoid page.wait_for_function — CSP script-src lacks unsafe-eval.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    ids = await _seed_zero_and_valued_external(live_server["base"], live_server["db"])
    base = live_server["base"]
    valued_ids = ids["valued_ids"]
    assert len(valued_ids) >= 2, "seed must provide ≥2 valued externals"

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#feed-clankfeed", timeout=10_000)
        await page.wait_for_selector(f"#note-{ids['local_id']}", timeout=15_000)

        # Clankfeed tab: local only (externals never belong here)
        assert await page.locator(f"#note-{ids['local_id']}").count() == 1
        assert await page.locator(f"#note-{ids['zero_id']}").count() == 0
        for vid in valued_ids:
            assert await page.locator(f"#note-{vid}").count() == 0

        await page.click("#feed-external")
        await page.wait_for_selector(f"#note-{valued_ids[0]}", timeout=15_000)

        for vid in valued_ids:
            assert await page.locator(f"#note-{vid}").count() == 1, (
                f"valued external {vid} missing from #feed-external"
            )
        assert await page.locator(f"#note-{ids['local_id']}").count() == 1
        # Critical FEED-1a assertion: zero-sats external must not appear
        assert await page.locator(f"#note-{ids['zero_id']}").count() == 0

        await browser.close()


@pytest.mark.asyncio
async def test_feed1a_external_tab_zero_only_hides_all_externals(live_server):
    """FEED-1b: zero-only externals (no valued) must not appear on #feed-external.

    Many-valued coverage alone misses the none-valued edge: a bug that shows
    zeros when the valued list is empty would stay green under the ≥2 seed.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    ids = await _seed_zero_only_external(live_server["base"], live_server["db"])
    base = live_server["base"]
    assert len(ids["zero_ids"]) >= 1
    assert not ids.get("valued_ids"), "zero-only seed must not include valued"

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#feed-clankfeed", timeout=10_000)
        await page.wait_for_selector(f"#note-{ids['local_id']}", timeout=15_000)

        assert await page.locator(f"#note-{ids['local_id']}").count() == 1
        for zid in ids["zero_ids"]:
            assert await page.locator(f"#note-{zid}").count() == 0

        await page.click("#feed-external")
        await page.wait_for_selector(f"#note-{ids['local_id']}", timeout=15_000)

        assert await page.locator(f"#note-{ids['local_id']}").count() == 1
        for zid in ids["zero_ids"]:
            assert await page.locator(f"#note-{zid}").count() == 0, (
                f"zero-only external {zid} leaked onto #feed-external"
            )

        await browser.close()


@pytest.mark.asyncio
async def test_feed1a_addNote_inject_skips_zero_keeps_valued(live_server):
    """FEED-1a adversarial: live addNote must skip zero external, keep valued.

    REST seeding alone cannot catch inverted client skip/keep logic — API already
    filters zeros. Inject synthetic events into page-global addNote while on
    #feed-external.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    ids = await _seed_zero_and_valued_external(live_server["base"], live_server["db"])
    base = live_server["base"]
    valued_ids = ids["valued_ids"]

    # Fresh synthetic ids so inject is not deduped against seeded cards
    inject_zero = {
        **ids["zero_event"],
        "id": "0" * 64,
        "content": "inject-zero-feed1a",
        "origin": "external",
        "sats_ext": 0,
        "sats_clank": 0,
    }
    inject_valued = {
        **ids["valued_events"][0],
        "id": "1" * 64,
        "content": "inject-valued-feed1a",
        "origin": "external",
        "sats_ext": 21,
        "sats_clank": 0,
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#feed-clankfeed", timeout=10_000)
        await page.click("#feed-external")
        await page.wait_for_selector(f"#note-{valued_ids[0]}", timeout=15_000)

        # CDP evaluate bypasses page CSP (unlike wait_for_function polling)
        added = await page.evaluate(
            """([zeroEv, valuedEv]) => {
              if (typeof addNote !== 'function') return 'no-addNote';
              addNote(zeroEv);
              addNote(valuedEv);
              return 'ok';
            }""",
            [inject_zero, inject_valued],
        )
        assert added == "ok", f"addNote not callable in page: {added}"

        for _ in range(50):
            if await page.locator(f"#note-{inject_valued['id']}").count() == 1:
                break
            await page.wait_for_timeout(50)
        assert await page.locator(f"#note-{inject_valued['id']}").count() == 1
        assert await page.locator(f"#note-{inject_zero['id']}").count() == 0

        await browser.close()


@pytest.mark.asyncio
async def test_ui37_nonempty_clankfeed_hides_empty_state(live_server):
    """UI3.7: nonempty clankfeed must hide #empty-feed (add('hidden') branch).

    UI3.6 only covered empty + external reclaim. A broken else-branch that never
    calls add('hidden') stays green under that smoke. Seed one local note.
    Avoid page.wait_for_function — CSP script-src lacks unsafe-eval.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    local_id = await _seed_one_local(live_server["base"])
    base = live_server["base"]

    async def _empty_hidden_with_card() -> bool:
        if await page.locator(f"#note-{local_id}").count() != 1:
            return False
        if await page.locator("#notes-feed .note-card").count() < 1:
            return False
        empty = page.locator("#empty-feed")
        if await empty.count() != 1:
            return False
        return await empty.is_hidden()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#feed-clankfeed", timeout=10_000)

        for _ in range(100):
            if await _empty_hidden_with_card():
                break
            await page.wait_for_timeout(100)
        else:
            empty = page.locator("#empty-feed")
            raise AssertionError(
                "nonempty clankfeed must hide #empty-feed with ≥1 .note-card; "
                f"empty visible={await empty.is_visible() if await empty.count() else 'missing'}, "
                f"cards={await page.locator('#notes-feed .note-card').count()}, "
                f"local={await page.locator(f'#note-{local_id}').count()}"
            )

        assert await page.locator("#empty-feed").is_hidden()
        assert await page.locator("#notes-feed .note-card").count() >= 1
        assert await page.locator(f"#note-{local_id}").count() == 1

        # Adversarial: visit external then return — empty-feed stays hidden
        await page.click("#feed-external")
        await page.wait_for_selector(f"#note-{local_id}", timeout=15_000)
        await page.click("#feed-clankfeed")
        for _ in range(100):
            if await _empty_hidden_with_card():
                break
            await page.wait_for_timeout(100)
        else:
            raise AssertionError(
                "#empty-feed reappeared after return to nonempty clankfeed"
            )
        assert await page.locator("#empty-feed").is_hidden()
        assert await page.locator(f"#note-{local_id}").count() == 1

        await browser.close()
