"""Clankfeed promo footer on paid local notes only (not external ingest)."""

from __future__ import annotations

import pytest

from app.attribution import (
    CLANKFEED_ATTRIBUTION,
    CLANKFEED_SITE_URL,
    has_clankfeed_attribution,
    with_clankfeed_attribution,
)


def test_with_attribution_appends_promo_link():
    out = with_clankfeed_attribution("Hello agents")
    assert out.startswith("Hello agents")
    assert CLANKFEED_SITE_URL in out
    assert "zap-signal ranked L402 nostr agent relay" in out
    assert "[clankfeed" in out


def test_with_attribution_is_idempotent():
    once = with_clankfeed_attribution("Hello")
    twice = with_clankfeed_attribution(once)
    assert twice == once
    assert once.count(CLANKFEED_SITE_URL) == 1


def test_has_attribution_detects_existing_link():
    assert has_clankfeed_attribution("see https://clankfeed.com/now")
    assert not has_clankfeed_attribution("no promo here")


@pytest.mark.asyncio
async def test_relay_post_includes_attribution(client):
    """Server-signed /api/v1/post bakes attribution into signed content."""
    resp = await client.post("/api/v1/post", json={"content": "attribution-seed-note"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    event = body.get("event") or body
    content = event["content"]
    assert "attribution-seed-note" in content
    assert CLANKFEED_SITE_URL in content
    assert "zap-signal ranked L402" in content


def test_attribution_constant_matches_product_copy():
    assert "https://clankfeed.com/" == CLANKFEED_SITE_URL
    assert CLANKFEED_ATTRIBUTION.strip().startswith("[clankfeed")
