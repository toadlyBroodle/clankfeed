"""Tests for the HTTP API and basic relay functionality."""

import time
import pytest

from app.nostr import sign_event

TEST_SK = "a" * 64


def _make_event(content="test"):
    return sign_event(TEST_SK, {
        "created_at": int(time.time()),
        "kind": 1,
        "tags": [],
        "content": content,
    })


@pytest.mark.asyncio
async def test_nip11_relay_info(client):
    """NIP-11: GET / with Accept: application/nostr+json returns relay metadata."""
    resp = await client.get("/", headers={"Accept": "application/nostr+json"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "clankfeed"
    assert 1 in data["supported_nips"]
    assert 11 in data["supported_nips"]
    assert data["limitation"]["payment_required"] is True


@pytest.mark.asyncio
async def test_root_serves_html(client):
    """GET / without nostr accept header serves the web client."""
    resp = await client.get("/")
    assert resp.status_code == 200
    # Should be HTML (the static file or fallback JSON)
    content_type = resp.headers.get("content-type", "")
    assert "html" in content_type or "json" in content_type


@pytest.mark.asyncio
async def test_health_endpoint(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_api_post_test_mode(client):
    """In test mode (AUTH_ROOT_KEY=test-mode), /api/post stores immediately."""
    resp = await client.post("/api/post", json={"content": "Hello from test!"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["paid"] is True
    assert data["event"]["content"] == "Hello from test!"
    assert len(data["event"]["id"]) == 64
    assert len(data["event"]["sig"]) == 128


@pytest.mark.asyncio
async def test_api_post_empty_content(client):
    resp = await client.post("/api/post", json={"content": ""})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_api_post_with_display_name(client):
    resp = await client.post("/api/post", json={
        "content": "Named note",
        "display_name": "TestBot",
    })
    assert resp.status_code == 200
    data = resp.json()
    tags = data["event"]["tags"]
    assert any(t[0] == "display_name" and t[1] == "TestBot" for t in tags)
