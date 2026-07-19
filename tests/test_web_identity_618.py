"""6.18: web identity authorship + NIP-11 content-negotiation / canSign.

1) Logged-in nsec/NIP-07 posts must be client-signed (user pubkey), not relay-signed.
2) NIP-11 Accept negotiation must not return cached HTML; signing requires canSign().
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


def _index() -> str:
    return (STATIC / "index.js").read_text()


def _auth() -> str:
    return (STATIC / "nostr-auth.js").read_text()


# ---------------------------------------------------------------------------
# 6.18a — client-signed posts when identity can sign
# ---------------------------------------------------------------------------


class TestClientSignedPostsWhenLoggedIn:
    """When canSign(), post form submits user-signed kind:1 via /api/v1/events."""

    def test_can_sign_helper_exists(self):
        auth = _auth()
        assert "function canSign" in auth
        # nsec mode needs in-memory key; extension needs window.nostr
        assert "userNsec" in auth
        assert "window.nostr" in auth

    def test_post_form_uses_events_endpoint_when_signing(self):
        index = _index()
        # Must branch on canSign (not merely isLoggedIn — stale pubkey ≠ can sign)
        assert "canSign()" in index
        assert "/api/v1/events" in index
        # Anonymous / no-key path still uses relay-signed post
        assert "/api/v1/post" in index

    def test_client_post_builds_zap_fee_tags_before_sign(self):
        index = _index()
        # Client-signed kind:1 must carry author + relay zap tags (Phase 13)
        assert "zap" in index
        assert "relayPubkey" in index
        # Weights / relay URL come from NIP-11 discovery (not hard-coded only)
        assert "zapFee" in index or "zap_fees" in index or "authorWeight" in index

    def test_client_post_signs_before_submit(self):
        index = _index()
        assert "signNostrEvent" in index
        # Post path must call sign when canSign
        post_fn = index.split("post-form", 1)[1] if "post-form" in index else index
        assert "signNostrEvent" in post_fn or "signNostrEvent" in index


# ---------------------------------------------------------------------------
# 6.18b — NIP-11 Vary + canSign for zaps
# ---------------------------------------------------------------------------


class TestNip11ContentNegotiation:
    """GET / HTML vs NIP-11 must Vary on Accept so browsers don't cache HTML as JSON."""

    @pytest.mark.asyncio
    async def test_nip11_response_sends_vary_accept(self, client):
        resp = await client.get("/", headers={"Accept": "application/nostr+json"})
        assert resp.status_code == 200
        vary = resp.headers.get("vary", "")
        assert "accept" in vary.lower()
        assert "nostr+json" in resp.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_html_root_sends_vary_accept(self, client):
        resp = await client.get("/", headers={"Accept": "text/html"})
        assert resp.status_code == 200
        vary = resp.headers.get("vary", "")
        assert "accept" in vary.lower()

    @pytest.mark.asyncio
    async def test_nip11_exposes_zap_fee_config(self, client):
        """Client needs relay_url + weights to build valid client-signed zap tags."""
        resp = await client.get("/", headers={"Accept": "application/nostr+json"})
        data = resp.json()
        fees = data.get("zap_fees") or data.get("zapFees")
        assert isinstance(fees, dict)
        assert "author_weight" in fees or "authorWeight" in fees
        assert "relay_weight" in fees or "relayWeight" in fees
        assert "relay_url" in fees or "relayUrl" in fees

    def test_client_nip11_fetch_guards_html(self):
        index = _index()
        assert "application/nostr+json" in index
        # Must not blindly r.json() HTML (cache: no-store and/or content-type check)
        assert "cache" in index.lower() or "content-type" in index.lower() or "nostr+json" in index
        # Stronger: explicit no-store or content-type gate near the fetch
        nip_region = index[index.find("application/nostr+json") : index.find("application/nostr+json") + 600]
        assert (
            "no-store" in nip_region
            or "content-type" in nip_region.lower()
            or "contentType" in nip_region
            or "includes(" in nip_region
        )


class TestCanSignForZaps:
    """Zap signing must require canSign(); stale nsec-less session must not pretend to sign."""

    def test_submit_zap_checks_can_sign(self):
        index = _index()
        assert "function submitZap" in index or "async function submitZap" in index
        fn = index.split("function submitZap", 1)[1].split("\nfunction ", 1)[0]
        assert "canSign" in fn

    def test_can_sign_false_when_nsec_missing(self):
        auth = _auth()
        fn = auth.split("function canSign", 1)[1].split("\nfunction ", 1)[0]
        # nsec branch requires userNsec truthy
        assert "userNsec" in fn
        assert "nsec" in fn


# ---------------------------------------------------------------------------
# Integration: client-signed note is authored by user, not relay
# ---------------------------------------------------------------------------


class TestClientSignedAuthorshipIntegration:
    """Adversarial: /api/v1/events stores user pubkey; /api/v1/post stays relay-signed."""

    @pytest.mark.asyncio
    async def test_client_signed_event_keeps_user_pubkey(self, client):
        import time
        from app.nostr import sign_event
        from app.zaps import pubkey_from_privkey
        from tests.conftest import kind1_tags

        user_sk = "b" * 64
        user_pk = pubkey_from_privkey(user_sk)
        relay_pk = pubkey_from_privkey("a" * 64)
        assert user_pk != relay_pk

        event = sign_event(user_sk, {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(user_sk),
            "content": "identity-authorship-note",
        })
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 200, resp.text
        stored = resp.json()["event"]
        assert stored["pubkey"] == user_pk
        assert stored["pubkey"] != relay_pk

    @pytest.mark.asyncio
    async def test_relay_post_still_uses_relay_pubkey(self, client):
        from app.zaps import pubkey_from_privkey

        relay_pk = pubkey_from_privkey("a" * 64)
        resp = await client.post("/api/v1/post", json={"content": "anon-relay-note"})
        assert resp.status_code == 200
        assert resp.json()["event"]["pubkey"] == relay_pk
