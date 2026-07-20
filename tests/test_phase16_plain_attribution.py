"""16.21: plain-URL clankfeed attribution before sign; strip on clankfeed.com UI.

Decision 2026-07-20:
  (1) Append promo before sign (client-signed + server-signed).
  (2) On clankfeed.com note cards, strip/omit the footer when rendering.
  (3) Plain-URL footer only: '\\n\\nvia https://clankfeed.com/' (not markdown).
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

import app.attribution as attribution_mod
from app.attribution import (
    CLANKFEED_ATTRIBUTION,
    CLANKFEED_SITE_URL,
    has_clankfeed_attribution,
    with_clankfeed_attribution,
)
from tests.conftest import attributed

STATIC = Path(__file__).resolve().parents[1] / "app" / "static"
OLD_MARKDOWN_FOOTER = (
    "\n\n[clankfeed — zap-signal ranked L402 nostr agent relay]"
    f"({CLANKFEED_SITE_URL})"
)


def _strip(content):
    """Resolve strip helper — must exist for 16.21."""
    fn = getattr(attribution_mod, "strip_clankfeed_attribution", None)
    assert fn is not None, "strip_clankfeed_attribution missing from app.attribution"
    return fn(content)


def test_attribution_is_plain_url_not_markdown():
    """Footer must be bare 'via https://clankfeed.com/' — Amethyst-hostile markdown gone."""
    assert CLANKFEED_SITE_URL == "https://clankfeed.com/"
    assert "via " in CLANKFEED_ATTRIBUTION
    assert CLANKFEED_SITE_URL in CLANKFEED_ATTRIBUTION
    assert "[" not in CLANKFEED_ATTRIBUTION
    assert "](" not in CLANKFEED_ATTRIBUTION
    assert CLANKFEED_ATTRIBUTION.strip() == f"via {CLANKFEED_SITE_URL}"


def test_with_attribution_appends_plain_via():
    out = with_clankfeed_attribution("Hello agents")
    assert out.startswith("Hello agents")
    assert out.endswith(f"via {CLANKFEED_SITE_URL}") or out.endswith(
        f"\n\nvia {CLANKFEED_SITE_URL}"
    )
    assert "[" not in out
    assert out == attributed("Hello agents")


def test_with_attribution_idempotent_for_plain_and_legacy_markdown():
    once = with_clankfeed_attribution("Hello")
    assert with_clankfeed_attribution(once) == once
    legacy = "Hello" + OLD_MARKDOWN_FOOTER
    assert with_clankfeed_attribution(legacy) == legacy  # already has clankfeed.com


def test_strip_removes_plain_and_legacy_markdown():
    plain = with_clankfeed_attribution("Note body")
    assert _strip(plain) == "Note body"
    legacy = "Note body" + OLD_MARKDOWN_FOOTER
    assert _strip(legacy) == "Note body"
    # Adversarial: user mention of clankfeed mid-body must not be nuked wholesale
    mid = "I love https://clankfeed.com/ but wrote more"
    assert "wrote more" in _strip(mid)


def test_strip_idempotent_and_empty_safe():
    assert _strip("") == ""
    assert _strip(None) == ""
    body = "plain note"
    assert _strip(_strip(body)) == body


@pytest.mark.asyncio
async def test_relay_post_bakes_plain_via(client):
    resp = await client.post("/api/v1/post", json={"content": "plain-via-seed"})
    assert resp.status_code == 200, resp.text
    content = resp.json()["event"]["content"]
    assert "plain-via-seed" in content
    assert f"via {CLANKFEED_SITE_URL}" in content or content.endswith(
        CLANKFEED_SITE_URL
    )
    assert "[clankfeed" not in content


def test_ui_display_strips_attribution():
    """displayNoteContent must strip promo (plain + legacy), never append."""
    auth = (STATIC / "nostr-auth.js").read_text()
    assert "function displayNoteContent" in auth
    assert "function stripClankfeedAttribution" in auth or "stripClankfeedAttribution" in auth
    fn = auth.split("function displayNoteContent", 1)[1].split("\nfunction ", 1)[0]
    # Must strip — not withClankfeedAttribution append path
    assert "stripClankfeedAttribution" in fn or "strip" in fn.lower()
    assert "withClankfeedAttribution" not in fn

    # Constant is plain via form
    assert re.search(r"via\s+https://clankfeed\.com/", auth)
    assert "[clankfeed — zap-signal" not in auth


def test_client_signed_post_appends_before_sign():
    """submitClientSignedPost must bake attribution into event.content before signNostrEvent."""
    index = (STATIC / "index.js").read_text()
    fn = index.split("async function submitClientSignedPost", 1)[1].split(
        "\nasync function ", 1
    )[0]
    assert "withClankfeedAttribution" in fn or "CLANKFEED_ATTRIBUTION" in fn
    # Attribution applied before sign
    before_sign = fn.split("signNostrEvent", 1)[0]
    assert (
        "withClankfeedAttribution" in before_sign
        or "CLANKFEED_ATTRIBUTION" in before_sign
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server_attr(tmp_path):
    db_path = tmp_path / "p1621.db"
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
        cwd=str(STATIC.parent.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=1) as r:
                if r.status == 200:
                    break
        except Exception:
            time.sleep(0.15)
    else:
        proc.kill()
        raise RuntimeError("server not healthy")
    try:
        yield {"base": base, "db": db_path}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.asyncio
async def test_headed_note_content_has_zero_promo_footer(live_server_attr):
    """Headed: local kind:1 with baked plain via → .note-content shows body only, no via footer."""
    pytest.importorskip("playwright")
    from playwright.async_api import async_playwright

    base = live_server_attr["base"]
    req = urllib.request.Request(
        f"{base}/api/v1/post",
        data=json.dumps({"content": "zero-promo-body-1621"}).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        event = json.loads(r.read())["event"]
    assert "via " in event["content"] or "clankfeed.com" in event["content"]
    eid = event["id"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=not bool(os.environ.get("DISPLAY"))
        )
        page = await browser.new_page()
        await page.goto(base + "/", wait_until="networkidle")
        note = page.locator(f"#note-{eid} .note-content")
        await note.wait_for(timeout=15000)
        text = await note.inner_text()
        assert "zero-promo-body-1621" in text
        assert "via https://clankfeed.com" not in text.lower()
        assert "zap-signal ranked" not in text.lower()
        hrefs = await page.locator(
            f"#note-{eid} .note-content a[href*='clankfeed.com']"
        ).count()
        assert hrefs == 0
        await browser.close()
