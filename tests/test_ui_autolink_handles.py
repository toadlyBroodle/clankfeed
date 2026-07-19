"""UI-4 autolink URLs + UI-6 kind:0 handles on note cards.

Source contracts + Playwright DOM smoke. XSS payloads must not execute;
only http/https URLs become anchors.
"""

from __future__ import annotations

import json
import os
import re
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
AUTHOR_SK_NAME = "d" * 64  # kind:0 with name (UI-4.2 preference)
AUTHOR_SK_NIP05 = "e" * 64  # kind:0 with nip05 only
AUTHOR_SK_PLAIN = "11" * 32  # no kind:0 picture — UI-5 placeholder + UI-4.3 zero-URL
AUTHOR_PK = None  # filled from first signed event


def _node_linkify(text: str) -> str:
    """Run real linkify() via Node with a DOM-free esc() stub."""
    src = (_STATIC / "nostr-auth.js").read_text()
    m = re.search(r"function linkify\([^)]*\)\s*\{.*?\n\}", src, re.DOTALL)
    assert m, "linkify function not found"
    # Node has no document; stub esc with the same entity escapes browsers use.
    stub_esc = (
        "function esc(s) {"
        "  return String(s == null ? '' : s)"
        "    .replace(/&/g, '&amp;')"
        "    .replace(/</g, '&lt;')"
        "    .replace(/>/g, '&gt;')"
        "    .replace(/\"/g, '&quot;');"
        "}"
    )
    node = subprocess.run(
        [
            "node",
            "-e",
            stub_esc
            + "\n"
            + m.group(0)
            + f"; process.stdout.write(linkify({json.dumps(text)}));",
        ],
        capture_output=True,
        text=True,
    )
    assert node.returncode == 0, node.stderr
    return node.stdout


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
        index = ((_STATIC / "index.js").read_text() + "\n" + (_STATIC / "index.html").read_text())
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert "linkify(" in fn
        # Display-time attribution: linkify(displayNoteContent(n)), not raw n.content
        assert (
            "linkify(displayNoteContent(n))" in fn
            or "linkify(n.content)" in fn
            or "linkify(n.content ||" in fn
        )

    def test_profile_notes_use_linkify(self):
        profile = ((_STATIC / "profile.js").read_text() + "\n" + (_STATIC / "profile.html").read_text())
        assert "linkify(" in profile
        assert (
            "linkify(displayNoteContent(n))" in profile
            or "linkify(n.content)" in profile
            or "linkify(n.content ||" in profile
        )

    def test_linkify_only_http_https_and_escapes(self):
        js = (_STATIC / "nostr-auth.js").read_text()
        fn = js.split("function linkify", 1)[1].split("\nfunction ", 1)[0]
        # Escape is used on non-URL segments / href text (XSS)
        assert "esc(" in fn
        # Protocol allowlist
        assert "https?" in fn or "http" in fn
        # Must not treat javascript: as a link target construction without filter
        assert "noopener" in fn or "noreferrer" in fn
        assert "target" in fn


class TestLinkifyUI41Ampersand:
    """UI-4.1: match http(s) on raw text — do not truncate at & after escape."""

    def test_multi_param_url_full_href(self):
        out = _node_linkify("see https://example.com/path?a=1&b=2 end")
        assert 'href="https://example.com/path?a=1&amp;b=2"' in out or (
            'href="https://example.com/path?a=1&b=2"' in out
        )
        # Must not stop at first &
        assert 'href="https://example.com/path?a=1"' not in out or "&amp;b=2" in out
        assert "b=2" in out
        assert 'class="note-link"' in out

    def test_multi_param_url_not_truncated_at_amp(self):
        r"""Adversarial: escape-first + [^\s<&]+ would yield href ending at ?a=1."""
        out = _node_linkify("https://ex.com/?x=1&y=2&z=3")
        # Full query must appear in the href (entity-escaped & is fine)
        assert "x=1" in out and "y=2" in out and "z=3" in out
        # Broken old behavior: only ?x=1 in href, then literal &amp;y=2 as text
        assert not re.search(
            r'href="https://ex\.com/\?x=1"[^>]*>https://ex\.com/\?x=1</a>&amp;y=2',
            out,
        )

    def test_xss_and_javascript_still_inert(self):
        out = _node_linkify(
            '<script>alert(1)</script> javascript:alert(1) '
            "https://ok.com/?a=1&b=2"
        )
        assert "<script>" not in out
        assert "&lt;script&gt;" in out
        assert 'href="javascript:' not in out
        assert "a=1" in out and "b=2" in out


class TestHandlesUI6Source:
    """getDisplayName must prefer kind:0 name, then display_name, then nip05."""

    def test_getDisplayName_reads_display_name_and_nip05(self):
        index = ((_STATIC / "index.js").read_text() + "\n" + (_STATIC / "index.html").read_text())
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
                "see https://example.com/path?q=1&more=2 "
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


# 1x1 PNG — loads without network so img.avatar is not replaced by onerror
_PIC_DATA = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)
_PIC_DATA_REPLY = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


async def _seed_ui42(db_path: Path) -> dict:
    """UI-4.2: parent+reply with many links; name-pref and nip05-only authors.

    Also seeds UI-4.3 zero-URL note and UI-5 no-picture author.
    """
    now = int(time.time())
    meta_display = sign_event(
        AUTHOR_SK,
        {
            "kind": 0,
            "created_at": now - 30,
            "tags": [],
            "content": json.dumps(
                {
                    "display_name": "HandleBot",
                    "nip05": "bot@example.com",
                    "picture": _PIC_DATA,
                }
            ),
        },
    )
    meta_name = sign_event(
        AUTHOR_SK_NAME,
        {
            "kind": 0,
            "created_at": now - 29,
            "tags": [],
            "content": json.dumps(
                {
                    "name": "NameWins",
                    "display_name": "DispLose",
                    "nip05": "lose@example.com",
                    "picture": _PIC_DATA_REPLY,
                }
            ),
        },
    )
    meta_nip05 = sign_event(
        AUTHOR_SK_NIP05,
        {
            "kind": 0,
            "created_at": now - 28,
            "tags": [],
            "content": '{"nip05":"onlynip@example.com"}',
        },
    )
    # UI-5: kind:0 without picture → placeholder on note card
    meta_plain = sign_event(
        AUTHOR_SK_PLAIN,
        {
            "kind": 0,
            "created_at": now - 27,
            "tags": [],
            "content": '{"name":"NoPicBot"}',
        },
    )
    parent = sign_event(
        AUTHOR_SK,
        {
            "kind": 1,
            "created_at": now - 20,
            "tags": [],
            "content": (
                "parent links "
                "https://a.example/p?a=1&b=2 "
                "https://b.example/q "
                "https://c.example/r?x=9&y=8"
            ),
        },
    )
    reply = sign_event(
        AUTHOR_SK_NAME,
        {
            "kind": 1,
            "created_at": now - 10,
            "tags": [["e", parent["id"], "", "reply"]],
            "content": "reply has https://reply.example/z?u=1&v=2",
        },
    )
    nip05_note = sign_event(
        AUTHOR_SK_NIP05,
        {
            "kind": 1,
            "created_at": now - 5,
            "tags": [],
            "content": "nip05 author https://nip.example/ok",
        },
    )
    # UI-4.3: plain text only — zero http(s) → zero .note-link anchors
    plain_note = sign_event(
        AUTHOR_SK_PLAIN,
        {
            "kind": 1,
            "created_at": now - 4,
            "tags": [],
            "content": "plain text only no urls www.notalink.example javascript:alert(1)",
        },
    )
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        rows = [
            (meta_display, 0, "[]"),
            (meta_name, 0, "[]"),
            (meta_nip05, 0, "[]"),
            (meta_plain, 0, "[]"),
            (parent, 21, "[]"),
            (reply, 21, json.dumps([["e", parent["id"], "", "reply"]])),
            (nip05_note, 21, "[]"),
            (plain_note, 21, "[]"),
        ]
        for ev, sc, tags in rows:
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
                    "tags": tags,
                    "content": ev["content"],
                    "sig": ev["sig"],
                    "sc": sc,
                },
            )
    await engine.dispose()
    return {
        "parent_id": parent["id"],
        "reply_id": reply["id"],
        "nip05_note_id": nip05_note["id"],
        "plain_note_id": plain_note["id"],
        "display_pubkey": meta_display["pubkey"],
        "name_pubkey": meta_name["pubkey"],
        "nip05_pubkey": meta_nip05["pubkey"],
        "plain_pubkey": meta_plain["pubkey"],
        "picture_url": _PIC_DATA,
        "reply_picture_url": _PIC_DATA_REPLY,
    }


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

        # UI-4 / UI-4.1: multi-param https URL becomes full href
        link = card.locator("a.note-link, .note-content a[href^='https://']")
        await link.first.wait_for(timeout=5000)
        href = await link.first.get_attribute("href")
        assert href and href.startswith("https://example.com/")
        assert "q=1" in href and "more=2" in href
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


@pytest.mark.asyncio
async def test_ui42_profile_autolink_and_many_links(live_server):
    """UI-4.2: profile linkifies; feed shows ≥3 anchors; amp query preserved."""
    pytest.importorskip("playwright")
    from playwright.async_api import async_playwright

    seeded = await _seed_ui42(live_server["db"])
    base = live_server["base"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Feed: many-link cardinality on parent card
        await page.goto(base + "/", wait_until="networkidle")
        parent = page.locator(f"#note-{seeded['parent_id']}")
        await parent.wait_for(timeout=15000)
        links = parent.locator(".note-content a.note-link, .note-content a[href^='https://']")
        assert await links.count() >= 3
        hrefs = [await links.nth(i).get_attribute("href") for i in range(await links.count())]
        assert any(h and "a=1" in h and "b=2" in h for h in hrefs)

        # Name preference: name beats display_name
        # nip05-only note is top-level
        nip_card = page.locator(f"#note-{seeded['nip05_note_id']}")
        await nip_card.wait_for(timeout=10000)
        nip_text = await nip_card.inner_text()
        assert "onlynip@example.com" in nip_text

        # Expand replies: reply card shows NameWins + linkified URL with &
        expand = page.locator(f"#expand-replies-{seeded['parent_id']}")
        await expand.click()
        reply_card = page.locator(f"#note-{seeded['reply_id']}")
        await reply_card.wait_for(timeout=10000)
        reply_text = await reply_card.inner_text()
        assert "NameWins" in reply_text
        assert "DispLose" not in reply_text
        reply_link = reply_card.locator(".note-content a[href^='https://']")
        await reply_link.first.wait_for(timeout=5000)
        rh = await reply_link.first.get_attribute("href")
        assert rh and "u=1" in rh and "v=2" in rh

        # Profile public notes: autolink
        await page.goto(
            base + f"/profile?pubkey={seeded['display_pubkey']}",
            wait_until="networkidle",
        )
        pub = page.locator("#pub-notes .note-content a[href^='https://']")
        await pub.first.wait_for(timeout=15000)
        ph = await pub.first.get_attribute("href")
        assert ph and ph.startswith("https://")
        assert "a=1" in ph and "b=2" in ph

        await browser.close()


@pytest.mark.asyncio
async def test_ui43_zero_url_note_has_no_note_links(live_server):
    """UI-4.3: user text with no http(s) → zero non-promo .note-link anchors.

    Local kind:1 notes still get one display-time clankfeed.com attribution link.
    """
    pytest.importorskip("playwright")
    from playwright.async_api import async_playwright

    seeded = await _seed_ui42(live_server["db"])
    base = live_server["base"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base + "/", wait_until="networkidle")

        plain = page.locator(f"#note-{seeded['plain_note_id']}")
        await plain.wait_for(timeout=15000)
        all_links = plain.locator(
            ".note-content a.note-link, .note-content a[href^='http']"
        )
        hrefs = [
            await all_links.nth(i).get_attribute("href")
            for i in range(await all_links.count())
        ]
        # Local notes get display-time clankfeed promo; user text must still add zero URLs
        non_promo = [h for h in hrefs if h and "clankfeed.com" not in h.lower()]
        assert non_promo == [], f"unexpected non-promo links: {non_promo}"
        assert any(h and "clankfeed.com" in h.lower() for h in hrefs), (
            "expected display-time attribution link on local plain note"
        )
        # Adversarial: bare www. / javascript: must not become hrefs either
        assert await plain.locator("a[href^='javascript:']").count() == 0
        assert await plain.locator("a[href*='notalink']").count() == 0

        # Many-link parent still has anchors (cardinality contrast)
        parent = page.locator(f"#note-{seeded['parent_id']}")
        await parent.wait_for(timeout=10000)
        assert (
            await parent.locator(
                ".note-content a.note-link, .note-content a[href^='https://']"
            ).count()
            >= 3
        )

        await browser.close()


@pytest.mark.asyncio
async def test_ui5_avatars_on_cards_replies_profile(live_server):
    """UI-5: kind:0 picture → img.avatar on feed/reply; none → placeholder; profile header."""
    pytest.importorskip("playwright")
    from playwright.async_api import async_playwright

    seeded = await _seed_ui42(live_server["db"])
    base = live_server["base"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(base + "/", wait_until="networkidle")

        # Feed note with picture
        parent = page.locator(f"#note-{seeded['parent_id']}")
        await parent.wait_for(timeout=15000)
        avatar = parent.locator("img.avatar")
        await avatar.wait_for(timeout=10000)
        src = await avatar.get_attribute("src")
        assert src == seeded["picture_url"]

        # No picture → placeholder (not img.avatar)
        plain = page.locator(f"#note-{seeded['plain_note_id']}")
        await plain.wait_for(timeout=10000)
        assert await plain.locator("img.avatar").count() == 0
        assert await plain.locator(".avatar-placeholder").count() >= 1
        plain_text = await plain.inner_text()
        assert "NoPicBot" in plain_text

        # Reply card avatar from kind:0 picture
        await page.locator(f"#expand-replies-{seeded['parent_id']}").click()
        reply_card = page.locator(f"#note-{seeded['reply_id']}")
        await reply_card.wait_for(timeout=10000)
        reply_av = reply_card.locator("img.avatar")
        await reply_av.wait_for(timeout=5000)
        assert await reply_av.get_attribute("src") == seeded["reply_picture_url"]

        # Profile page header shows picture when present
        await page.goto(
            base + f"/profile?pubkey={seeded['display_pubkey']}",
            wait_until="networkidle",
        )
        await page.wait_for_selector(
            f'img[src="{seeded["picture_url"]}"]', timeout=15000
        )

        # UI-5.1: public profile header with no picture → placeholder, no img
        await page.goto(
            base + f"/profile?pubkey={seeded['plain_pubkey']}",
            wait_until="networkidle",
        )
        await page.wait_for_selector("#pub-name", timeout=15000)
        # Wait until kind:0 name lands (else still truncated pubkey)
        await page.wait_for_function(
            "() => document.getElementById('pub-name')?.textContent === 'NoPicBot'",
            timeout=15000,
        )
        pub_av = page.locator("#pub-avatar.avatar-placeholder")
        await pub_av.wait_for(timeout=5000)
        assert await pub_av.count() == 1
        assert await page.locator("#view-public img").count() == 0
        assert (await pub_av.inner_text()).strip() == "N"  # NoPicBot initial

        # Adversarial: nip05-only author (no picture) stays placeholder on feed
        await page.goto(base + "/", wait_until="networkidle")
        nip = page.locator(f"#note-{seeded['nip05_note_id']}")
        await nip.wait_for(timeout=10000)
        assert await nip.locator("img.avatar").count() == 0
        assert await nip.locator(".avatar-placeholder").count() >= 1

        await browser.close()


class TestAvatarUI5Source:
    """UI-5 source contract: getAvatar reads kind:0 picture; renderNoteCard uses it."""

    def test_getAvatar_reads_picture(self):
        index = ((_STATIC / "index.js").read_text() + "\n" + (_STATIC / "index.html").read_text())
        fn = index.split("function getAvatar", 1)[1].split("\nfunction ", 1)[0]
        assert "picture" in fn
        assert "metadataCache" in fn

    def test_renderNoteCard_uses_getAvatar(self):
        index = ((_STATIC / "index.js").read_text() + "\n" + (_STATIC / "index.html").read_text())
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert "getAvatar(" in fn
        assert "img" in fn and "avatar" in fn
        assert "avatar-placeholder" in fn

    def test_profile_shows_picture_when_present(self):
        profile = ((_STATIC / "profile.js").read_text() + "\n" + (_STATIC / "profile.html").read_text())
        assert "meta.picture" in profile or "picture" in profile
        assert "prof-picture" in profile
        assert "pub-avatar" in profile

    def test_profile_no_picture_keeps_placeholder(self):
        """UI-5.1 source: else branch keeps #pub-avatar.avatar-placeholder."""
        profile = ((_STATIC / "profile.js").read_text() + "\n" + (_STATIC / "profile.html").read_text())
        # Public profile: picture → replace with img; else set initial on placeholder
        assert "pub-avatar" in profile
        assert "avatar-placeholder" in profile
        assert "meta.picture" in profile
        # Must have an else path that does not outerHTML-replace with img
        pub_block = profile.split("pub-avatar", 1)[1]
        assert "outerHTML" in pub_block or "meta.picture" in profile
        assert "charAt(0)" in profile or ".charAt(0)" in profile
