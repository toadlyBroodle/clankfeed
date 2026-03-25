"""Tests for Phase 9: variable amounts, sort/filter, replies, voting."""

import json
import time
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.limiter import limiter
from app.nostr import sign_event


TEST_SK = "b" * 64


@pytest.fixture(autouse=True)
def _reset():
    limiter.reset()
    yield
    limiter.reset()


def _make_event(content="test", kind=1, tags=None):
    return sign_event(TEST_SK, {
        "created_at": int(time.time()),
        "kind": kind,
        "tags": tags or [],
        "content": content,
    })


# ---------------------------------------------------------------------------
# 9a: Variable payment amounts
# ---------------------------------------------------------------------------

class TestVariableAmounts:
    @pytest.mark.asyncio
    async def test_custom_amount_stored(self, client):
        """Post with custom amount stores value_sats."""
        resp = await client.post("/api/v1/post", json={
            "content": "expensive note", "amount_sats": 100,
        })
        assert resp.status_code == 200
        assert resp.json()["value_sats"] == 100

    @pytest.mark.asyncio
    async def test_default_amount(self, client):
        """Post without amount uses minimum (21 sats)."""
        resp = await client.post("/api/v1/post", json={"content": "cheap note"})
        assert resp.status_code == 200
        assert resp.json()["value_sats"] == 21

    @pytest.mark.asyncio
    async def test_below_minimum_uses_minimum(self, client):
        """Amount below minimum gets bumped to minimum."""
        resp = await client.post("/api/v1/post", json={
            "content": "too cheap", "amount_sats": 5,
        })
        assert resp.status_code == 200
        assert resp.json()["value_sats"] == 21

    @pytest.mark.asyncio
    async def test_value_in_read_response(self, client):
        """GET /events returns value_sats on each event."""
        await client.post("/api/v1/post", json={
            "content": "valued note", "amount_sats": 500,
        })
        resp = await client.get("/api/v1/events?kinds=1&limit=1")
        events = resp.json()["events"]
        assert len(events) >= 1
        assert events[0]["value_sats"] == 500

    @pytest.mark.asyncio
    async def test_agent_event_custom_amount(self, client):
        """Agent-signed event with custom amount."""
        event = _make_event("agent expensive")
        resp = await client.post("/api/v1/events", json={
            "event": event, "amount_sats": 200,
        })
        assert resp.status_code == 200
        assert resp.json()["value_sats"] == 200


# ---------------------------------------------------------------------------
# 9d: Sort and filter
# ---------------------------------------------------------------------------

class TestSortAndFilter:
    @pytest.mark.asyncio
    async def test_sort_by_value(self, client):
        """sort=value returns highest value first."""
        await client.post("/api/v1/post", json={"content": "low", "amount_sats": 21})
        await client.post("/api/v1/post", json={"content": "high", "amount_sats": 1000})
        await client.post("/api/v1/post", json={"content": "mid", "amount_sats": 100})

        resp = await client.get("/api/v1/events?sort=value&kinds=1")
        events = resp.json()["events"]
        assert events[0]["value_sats"] >= events[-1]["value_sats"]
        assert events[0]["content"] == "high"

    @pytest.mark.asyncio
    async def test_sort_by_newest(self, client):
        """sort=newest (default) returns newest first."""
        await client.post("/api/v1/post", json={"content": "first"})
        await client.post("/api/v1/post", json={"content": "second"})

        resp = await client.get("/api/v1/events?sort=newest&kinds=1")
        events = resp.json()["events"]
        assert events[0]["created_at"] >= events[-1]["created_at"]

    @pytest.mark.asyncio
    async def test_min_value_filter(self, client):
        """min_value filters out low-value notes."""
        await client.post("/api/v1/post", json={"content": "cheap", "amount_sats": 21})
        await client.post("/api/v1/post", json={"content": "pricey", "amount_sats": 500})

        resp = await client.get("/api/v1/events?min_value=100&kinds=1")
        events = resp.json()["events"]
        assert all(e["value_sats"] >= 100 for e in events)
        assert any(e["content"] == "pricey" for e in events)

    @pytest.mark.asyncio
    async def test_max_value_filter(self, client):
        """max_value filters out high-value notes."""
        await client.post("/api/v1/post", json={"content": "cheap", "amount_sats": 21})
        await client.post("/api/v1/post", json={"content": "pricey", "amount_sats": 500})

        resp = await client.get("/api/v1/events?max_value=100&kinds=1")
        events = resp.json()["events"]
        assert all(e["value_sats"] <= 100 for e in events)

    @pytest.mark.asyncio
    async def test_combined_filters(self, client):
        """Combine sort + value range + time."""
        await client.post("/api/v1/post", json={"content": "a", "amount_sats": 50})
        await client.post("/api/v1/post", json={"content": "b", "amount_sats": 200})
        await client.post("/api/v1/post", json={"content": "c", "amount_sats": 500})

        resp = await client.get("/api/v1/events?sort=value&min_value=100&max_value=300&kinds=1")
        events = resp.json()["events"]
        assert len(events) == 1
        assert events[0]["content"] == "b"

    @pytest.mark.asyncio
    async def test_invalid_sort_defaults_to_newest(self, client):
        resp = await client.get("/api/v1/events?sort=invalid")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 9b: Replies
# ---------------------------------------------------------------------------

class TestReplies:
    @pytest.mark.asyncio
    async def test_relay_post_reply(self, client):
        """reply_to adds e tag to the event."""
        resp = await client.post("/api/v1/post", json={"content": "parent note"})
        parent_id = resp.json()["event"]["id"]

        resp = await client.post("/api/v1/post", json={
            "content": "reply to parent", "reply_to": parent_id,
        })
        assert resp.status_code == 200
        tags = resp.json()["event"]["tags"]
        e_tags = [t for t in tags if t[0] == "e"]
        assert len(e_tags) == 1
        assert e_tags[0][1] == parent_id
        assert e_tags[0][3] == "reply"

    @pytest.mark.asyncio
    async def test_get_replies(self, client):
        """GET /events/{id}/replies returns replies."""
        resp = await client.post("/api/v1/post", json={"content": "parent"})
        parent_id = resp.json()["event"]["id"]

        await client.post("/api/v1/post", json={"content": "reply 1", "reply_to": parent_id})
        await client.post("/api/v1/post", json={"content": "reply 2", "reply_to": parent_id})

        resp = await client.get(f"/api/v1/events/{parent_id}/replies")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    @pytest.mark.asyncio
    async def test_reply_to_filter(self, client):
        """GET /events?reply_to= filters replies."""
        resp = await client.post("/api/v1/post", json={"content": "parent"})
        parent_id = resp.json()["event"]["id"]

        await client.post("/api/v1/post", json={"content": "reply", "reply_to": parent_id})
        await client.post("/api/v1/post", json={"content": "unrelated"})

        resp = await client.get(f"/api/v1/events?reply_to={parent_id}&kinds=1")
        assert resp.json()["count"] == 1
        assert resp.json()["events"][0]["content"] == "reply"

    @pytest.mark.asyncio
    async def test_replies_to_nonexistent(self, client):
        resp = await client.get("/api/v1/events/0" * 32 + "/replies")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 9c: Voting (test mode / no payment)
# ---------------------------------------------------------------------------

class TestVoting:
    @pytest.mark.asyncio
    async def test_upvote(self, client):
        """Upvote increases note value."""
        resp = await client.post("/api/v1/post", json={"content": "vote me"})
        event_id = resp.json()["event"]["id"]
        initial_value = resp.json()["value_sats"]

        resp = await client.post(f"/api/v1/events/{event_id}/vote", json={
            "direction": 1, "amount_sats": 50,
        })
        assert resp.status_code == 200
        assert resp.json()["voted"] is True
        assert resp.json()["new_value_sats"] == initial_value + 50

    @pytest.mark.asyncio
    async def test_downvote(self, client):
        """Downvote decreases note value."""
        resp = await client.post("/api/v1/post", json={
            "content": "downvote me", "amount_sats": 100,
        })
        event_id = resp.json()["event"]["id"]

        resp = await client.post(f"/api/v1/events/{event_id}/vote", json={
            "direction": -1, "amount_sats": 30,
        })
        assert resp.status_code == 200
        assert resp.json()["new_value_sats"] == 70  # 100 - 30

    @pytest.mark.asyncio
    async def test_vote_invalid_direction(self, client):
        resp = await client.post("/api/v1/post", json={"content": "test"})
        eid = resp.json()["event"]["id"]
        resp = await client.post(f"/api/v1/events/{eid}/vote", json={"direction": 0})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_vote_nonexistent_event(self, client):
        resp = await client.post(f"/api/v1/events/{'0' * 64}/vote", json={"direction": 1})
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_multiple_votes_accumulate(self, client):
        """Multiple votes accumulate on the note value."""
        resp = await client.post("/api/v1/post", json={"content": "popular"})
        eid = resp.json()["event"]["id"]

        await client.post(f"/api/v1/events/{eid}/vote", json={"direction": 1, "amount_sats": 50})
        await client.post(f"/api/v1/events/{eid}/vote", json={"direction": 1, "amount_sats": 100})
        resp = await client.post(f"/api/v1/events/{eid}/vote", json={"direction": -1, "amount_sats": 25})

        # 21 (initial) + 50 + 100 - 25 = 146
        assert resp.json()["new_value_sats"] == 146
