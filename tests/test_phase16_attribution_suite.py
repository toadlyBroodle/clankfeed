"""16.4: suite contract for relay-signed attribution footer.

Relay-signed posts bake the clankfeed promo into signed content. Client-signed
posts also bake before sign (16.21); UI strips at display time. Equality
assertions must use `attributed()`, not bare body text.
"""

from __future__ import annotations

import pytest

from app.attribution import CLANKFEED_SITE_URL, with_clankfeed_attribution
from tests.conftest import attributed


@pytest.mark.asyncio
async def test_relay_post_content_equals_attributed_helper(client):
    """Adversarial: bare body equality must fail; attributed() is the contract."""
    body = "suite-16-4-seed"
    resp = await client.post("/api/v1/post", json={"content": body})
    assert resp.status_code == 200, resp.text
    content = resp.json()["event"]["content"]
    assert content != body  # promo appended
    assert content == attributed(body)
    assert content == with_clankfeed_attribution(body)
    assert CLANKFEED_SITE_URL in content


@pytest.mark.asyncio
async def test_xss_payload_survives_attribution_prefix(client):
    """XSS bytes stay in stored content; attribution does not strip or escape them."""
    xss = '<script>alert("xss")</script>'
    resp = await client.post("/api/v1/post", json={"content": xss})
    assert resp.status_code == 200
    content = resp.json()["event"]["content"]
    assert content.startswith(xss)
    assert content == attributed(xss)
    assert CLANKFEED_SITE_URL in content


def test_ui_source_uses_displayNoteContent_not_raw_n_content():
    """renderNoteCard must linkify(displayNoteContent(n)), not linkify(n.content)."""
    from pathlib import Path

    static = Path(__file__).resolve().parents[1] / "app" / "static"
    index = (static / "index.js").read_text()
    fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
    assert "linkify(displayNoteContent(n))" in fn
    assert "note-content" in fn
    # Must not regress to raw n.content in the content paragraph
    assert "linkify(n.content)" not in fn
    assert "${esc(n.content)}" not in fn

    profile = (static / "profile.js").read_text()
    assert "linkify(displayNoteContent(n))" in profile
