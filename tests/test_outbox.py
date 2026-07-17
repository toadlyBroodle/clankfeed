"""Phase 15: outbox fan-out after paid store + config / discovery surfaces."""

import ast
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Base, engine, async_session
from app.nostr import sign_event
from app.relay import store_event
from tests.conftest import kind1_tags

ROOT = Path(__file__).resolve().parents[1]
BOTFEED_DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.snort.social",
    "wss://relay.primal.net",
    "wss://nostr.wine",
]


def _signed_note(priv: str = "b" * 64, content: str = "outbox note") -> dict:
    return sign_event(
        priv,
        {
            "created_at": 1_700_000_000,
            "kind": 1,
            "tags": kind1_tags(priv),
            "content": content,
        },
    )


# ---------------------------------------------------------------------------
# 15.3 Config defaults
# ---------------------------------------------------------------------------


class TestOutboxConfig:
    def test_outbox_disabled_in_conftest(self):
        """Unit tests must not open real outbox WebSockets."""
        from app.config import settings

        assert settings.OUTBOX_ENABLED is False

    def test_outbox_relays_default_matches_botfeed_discovery(self, monkeypatch):
        monkeypatch.delenv("OUTBOX_RELAYS", raising=False)
        # Re-read via parsing defaults on Settings class source / fresh getenv path
        from app import config as cfg

        raw = cfg.Settings.OUTBOX_RELAYS
        # Class attr may already be bound at import; check DEFAULT constant or env default
        from app.config import DEFAULT_OUTBOX_RELAYS

        urls = [u.strip() for u in DEFAULT_OUTBOX_RELAYS.split(",") if u.strip()]
        assert urls == BOTFEED_DEFAULT_RELAYS
        assert "wss://relay.snort.social" in raw or "snort" in DEFAULT_OUTBOX_RELAYS

    def test_env_example_documents_outbox(self):
        text = (ROOT / ".env.example").read_text()
        assert "OUTBOX_ENABLED" in text
        assert "OUTBOX_RELAYS" in text


# ---------------------------------------------------------------------------
# 15.2 / 15.4 Outbox publisher behavior
# ---------------------------------------------------------------------------


class TestOutboxPublisher:
    @pytest.mark.asyncio
    async def test_outbox_event_sends_nip01_event_to_each_relay(self, monkeypatch):
        monkeypatch.setattr("app.outbox.settings.OUTBOX_ENABLED", True)
        monkeypatch.setattr(
            "app.outbox.settings.OUTBOX_RELAYS",
            "wss://relay.one,wss://relay.two",
        )
        event = _signed_note()
        sent: list[tuple[str, str]] = []

        class FakeWS:
            def __init__(self, url):
                self.url = url

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def send(self, raw):
                sent.append((self.url, raw))

            async def recv(self):
                msg = json.loads(sent[-1][1])
                eid = msg[1]["id"]
                return json.dumps(["OK", eid, True, ""])

        def fake_connect(url, **kwargs):
            return FakeWS(url)

        with patch("app.outbox.websockets.connect", side_effect=fake_connect):
            from app.outbox import outbox_event

            await outbox_event(event)

        assert len(sent) == 2
        urls = {u for u, _ in sent}
        assert urls == {"wss://relay.one", "wss://relay.two"}
        for _, raw in sent:
            msg = json.loads(raw)
            assert msg[0] == "EVENT"
            assert msg[1]["id"] == event["id"]
            assert msg[1]["sig"] == event["sig"]

    @pytest.mark.asyncio
    async def test_outbox_disabled_makes_no_network(self, monkeypatch):
        monkeypatch.setattr("app.outbox.settings.OUTBOX_ENABLED", False)
        monkeypatch.setattr(
            "app.outbox.settings.OUTBOX_RELAYS",
            "wss://should.not.connect",
        )
        connect = AsyncMock()
        with patch("app.outbox.websockets.connect", connect):
            from app.outbox import outbox_event

            await outbox_event(_signed_note())
        connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_one_relay_fail_others_still_attempted(self, monkeypatch):
        monkeypatch.setattr("app.outbox.settings.OUTBOX_ENABLED", True)
        monkeypatch.setattr(
            "app.outbox.settings.OUTBOX_RELAYS",
            "wss://bad.relay,wss://good.relay",
        )
        event = _signed_note()
        attempted: list[str] = []

        class BadWS:
            async def __aenter__(self):
                attempted.append("bad")
                raise ConnectionError("boom")

            async def __aexit__(self, *args):
                return None

        class GoodWS:
            async def __aenter__(self):
                attempted.append("good")
                return self

            async def __aexit__(self, *args):
                return None

            async def send(self, raw):
                self._raw = raw

            async def recv(self):
                eid = json.loads(self._raw)[1]["id"]
                return json.dumps(["OK", eid, True, ""])

        def fake_connect(url, **kwargs):
            if "bad" in url:
                return BadWS()
            return GoodWS()

        with patch("app.outbox.websockets.connect", side_effect=fake_connect):
            from app.outbox import outbox_event

            await outbox_event(event)  # must not raise

        assert "bad" in attempted and "good" in attempted


class TestStoreEventSchedulesOutbox:
    @pytest_asyncio.fixture
    async def db(self):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with async_session() as session:
            yield session
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @pytest.mark.asyncio
    async def test_clankfeed_store_schedules_outbox_when_enabled(
        self, db: AsyncSession, monkeypatch
    ):
        monkeypatch.setattr("app.outbox.settings.OUTBOX_ENABLED", True)
        scheduled: list[dict] = []

        def fake_schedule(event):
            scheduled.append(event)

        event = _signed_note(content="paid local")
        with patch("app.outbox.schedule_outbox", side_effect=fake_schedule):
            # import path used by relay
            with patch("app.relay.schedule_outbox", side_effect=fake_schedule):
                await store_event(db, event, sats_clank=21, origin="clankfeed")

        assert len(scheduled) == 1
        assert scheduled[0]["id"] == event["id"]

    @pytest.mark.asyncio
    async def test_external_origin_does_not_outbox(
        self, db: AsyncSession, monkeypatch
    ):
        monkeypatch.setattr("app.outbox.settings.OUTBOX_ENABLED", True)
        scheduled: list = []

        def fake_schedule(event):
            scheduled.append(event)

        event = _signed_note(content="ingested")
        with patch("app.relay.schedule_outbox", side_effect=fake_schedule):
            await store_event(db, event, sats_clank=0, origin="external")

        assert scheduled == []

    @pytest.mark.asyncio
    async def test_outbox_disabled_store_does_not_schedule(
        self, db: AsyncSession, monkeypatch
    ):
        monkeypatch.setattr("app.outbox.settings.OUTBOX_ENABLED", False)
        monkeypatch.setattr("app.relay.settings.OUTBOX_ENABLED", False)
        scheduled: list = []

        def fake_schedule(event):
            scheduled.append(event)

        event = _signed_note(content="no net")
        with patch("app.relay.schedule_outbox", side_effect=fake_schedule):
            await store_event(db, event, sats_clank=21, origin="clankfeed")

        assert scheduled == []

    @pytest.mark.asyncio
    async def test_nwc_info_kind_does_not_outbox(
        self, db: AsyncSession, monkeypatch
    ):
        """Free NWC accepts (13194) must not fan-out to public relays."""
        monkeypatch.setattr("app.relay.settings.OUTBOX_ENABLED", True)
        scheduled: list = []

        def fake_schedule(event):
            scheduled.append(event)

        priv = "c" * 64
        event = sign_event(
            priv,
            {
                "created_at": 1_700_000_100,
                "kind": 13194,
                "tags": [],
                "content": "{}",
            },
        )
        with patch("app.relay.schedule_outbox", side_effect=fake_schedule):
            await store_event(db, event, sats_clank=0, origin="clankfeed")

        assert scheduled == []


# ---------------------------------------------------------------------------
# 15.6 NIP-11 / discovery outbox policy
# ---------------------------------------------------------------------------


class TestOutboxDiscovery:
    @pytest.mark.asyncio
    async def test_nip11_mentions_outbox_policy(self, client, monkeypatch):
        monkeypatch.setattr("app.main.settings.OUTBOX_ENABLED", True)
        monkeypatch.setattr(
            "app.main.settings.OUTBOX_RELAYS",
            ",".join(BOTFEED_DEFAULT_RELAYS),
        )
        resp = await client.get("/", headers={"Accept": "application/nostr+json"})
        assert resp.status_code == 200
        doc = resp.json()
        blob = json.dumps(doc).lower()
        assert "outbox" in blob or "republish" in blob
        # relays list present when enabled
        relays = doc.get("outbox_relays") or (doc.get("outbox") or {}).get("relays")
        assert relays
        assert "wss://relay.damus.io" in relays

    @pytest.mark.asyncio
    async def test_well_known_l402_mentions_outbox(self, client):
        resp = await client.get("/.well-known/l402")
        assert resp.status_code == 200
        data = resp.json()
        blob = json.dumps(data).lower()
        assert "outbox" in blob or "republish" in blob
