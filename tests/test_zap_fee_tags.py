"""13.2 + 13.3: NIP-57 zap fee-split tags on kind:1 create + reject."""

import time

import pytest
from coincurve import PrivateKey

from app import config
from app.nostr import sign_event
from app.zaps import (
    build_zap_split_tags,
    relay_pubkey_hex,
    validate_kind1_zap_fee_tags,
)


def _pubkey(sk_hex: str) -> str:
    sk = PrivateKey(bytes.fromhex(sk_hex))
    return sk.public_key.format(compressed=True)[1:].hex()


RELAY_SK = "a" * 64  # matches conftest RELAY_PRIVATE_KEY
AUTHOR_SK = "c" * 64
AUTHOR_PK = _pubkey(AUTHOR_SK)
RELAY_PK = _pubkey(RELAY_SK)


class TestBuildZapSplitTags132:
    """Unit: zap tag shape matches NIP-57 Appendix G + Phase 13 weights."""

    def test_build_zap_split_tags_author_and_relay(self):
        tags = build_zap_split_tags(AUTHOR_PK)
        assert len(tags) == 2
        author_tag, relay_tag = tags
        assert author_tag[0] == "zap"
        assert author_tag[1] == AUTHOR_PK
        assert author_tag[2] == config.settings.BASE_URL
        assert author_tag[3] == str(config.settings.ZAP_AUTHOR_WEIGHT)
        assert relay_tag[0] == "zap"
        assert relay_tag[1] == RELAY_PK
        assert relay_tag[2] == config.settings.BASE_URL
        assert relay_tag[3] == str(config.settings.ZAP_RELAY_WEIGHT)

    def test_relay_pubkey_matches_configured_private_key(self):
        assert relay_pubkey_hex() == RELAY_PK

    def test_adversarial_weights_are_stringified_ints(self):
        """NIP-57 weights are strings; clients parse as numbers — never float JSON."""
        tags = build_zap_split_tags(AUTHOR_PK)
        for tag in tags:
            assert isinstance(tag[3], str)
            assert tag[3].isdigit()
            assert int(tag[3]) > 0


class TestValidateKind1ZapFeeTags133:
    """Unit: client-signed kind:1 must carry author + relay fee zap tags."""

    def test_valid_tags_pass(self):
        event = {
            "kind": 1,
            "pubkey": AUTHOR_PK,
            "tags": build_zap_split_tags(AUTHOR_PK),
        }
        ok, err = validate_kind1_zap_fee_tags(event)
        assert ok is True
        assert err == ""

    def test_missing_relay_fee_tag_fails(self):
        event = {
            "kind": 1,
            "pubkey": AUTHOR_PK,
            "tags": [
                [
                    "zap",
                    AUTHOR_PK,
                    config.settings.BASE_URL,
                    str(config.settings.ZAP_AUTHOR_WEIGHT),
                ]
            ],
        }
        ok, err = validate_kind1_zap_fee_tags(event)
        assert ok is False
        assert "zap" in err.lower()

    def test_wrong_relay_weight_fails(self):
        event = {
            "kind": 1,
            "pubkey": AUTHOR_PK,
            "tags": [
                [
                    "zap",
                    AUTHOR_PK,
                    config.settings.BASE_URL,
                    str(config.settings.ZAP_AUTHOR_WEIGHT),
                ],
                ["zap", RELAY_PK, config.settings.BASE_URL, "99"],
            ],
        }
        ok, err = validate_kind1_zap_fee_tags(event)
        assert ok is False
        assert "zap" in err.lower() or "weight" in err.lower()

    def test_kind0_skips_zap_requirement(self):
        event = {"kind": 0, "pubkey": AUTHOR_PK, "tags": []}
        ok, err = validate_kind1_zap_fee_tags(event)
        assert ok is True
        assert err == ""

    def test_adversarial_dilution_extra_zap_weight_fails(self):
        """Extra high-weight zap recipient would dilute the 90/10 fee — reject."""
        other = "d" * 64
        tags = build_zap_split_tags(AUTHOR_PK) + [
            ["zap", other, config.settings.BASE_URL, "100"],
        ]
        event = {"kind": 1, "pubkey": AUTHOR_PK, "tags": tags}
        ok, err = validate_kind1_zap_fee_tags(event)
        assert ok is False


@pytest.mark.asyncio
class TestRelaySignedInject132:
    """Integration: /api/v1/post and legacy /api/post inject zap tags before sign."""

    async def test_v1_post_injects_zap_tags(self, client):
        resp = await client.post("/api/v1/post", json={"content": "zap-tag inject"})
        assert resp.status_code == 200
        event = resp.json()["event"]
        assert event["kind"] == 1
        zap_tags = [t for t in event["tags"] if t and t[0] == "zap"]
        assert len(zap_tags) == 2
        # Anon relay-signed: author_pk == relay_pk — both tags share pubkey, weights 9 and 1
        assert event["pubkey"] == RELAY_PK
        weights = {t[3] for t in zap_tags}
        assert weights == {
            str(config.settings.ZAP_AUTHOR_WEIGHT),
            str(config.settings.ZAP_RELAY_WEIGHT),
        }
        assert all(t[1] == RELAY_PK for t in zap_tags)
        # Signature must cover the injected tags (id matches)
        from app.nostr import validate_event

        valid, err = validate_event(event)
        assert valid, err

    async def test_legacy_api_post_injects_zap_tags(self, client):
        resp = await client.post("/api/post", json={"content": "legacy zap inject"})
        assert resp.status_code == 200
        event = resp.json()["event"]
        zap_tags = [t for t in event["tags"] if t and t[0] == "zap"]
        assert len(zap_tags) == 2
        assert any(t[1] == RELAY_PK and t[3] == "1" for t in zap_tags)


@pytest.mark.asyncio
class TestRejectClientSigned133:
    """Integration: POST /api/v1/events + WS EVENT reject kind:1 without fee tags."""

    async def test_events_api_rejects_missing_zap_tags(self, client):
        event = sign_event(
            AUTHOR_SK,
            {
                "created_at": int(time.time()),
                "kind": 1,
                "tags": [],
                "content": "no zap tags",
            },
        )
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 400
        detail = resp.json().get("detail", "").lower()
        assert "zap" in detail

    async def test_events_api_accepts_valid_zap_tags(self, client):
        tags = build_zap_split_tags(AUTHOR_PK)
        event = sign_event(
            AUTHOR_SK,
            {
                "created_at": int(time.time()),
                "kind": 1,
                "tags": tags,
                "content": "with zap tags",
            },
        )
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 200
        assert resp.json()["paid"] is True

    async def test_ws_event_rejects_missing_zap_tags(self, client):
        """WebSocket EVENT path must enforce the same fee-tag gate as REST."""
        from starlette.testclient import TestClient
        from app.main import app

        event = sign_event(
            AUTHOR_SK,
            {
                "created_at": int(time.time()),
                "kind": 1,
                "tags": [],
                "content": "ws no zap",
            },
        )
        with TestClient(app) as tc:
            with tc.websocket_connect("/") as ws:
                # Drain AUTH challenge
                ws.receive_json()
                ws.send_json(["EVENT", event])
                msg = ws.receive_json()
                assert msg[0] == "OK"
                assert msg[1] == event["id"]
                assert msg[2] is False
                assert "zap" in msg[3].lower()
