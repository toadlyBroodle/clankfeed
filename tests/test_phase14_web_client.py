"""Phase 14.6: Web client non-custodial — L402 post/downvote; NIP-57 zap tip."""

from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


def _index_src() -> str:
    return (STATIC / "index.js").read_text() + "\n" + (STATIC / "index.html").read_text()


def _auth_src() -> str:
    return (STATIC / "nostr-auth.js").read_text()


def _widget_src() -> str:
    return (STATIC / "payment-widget.js").read_text()


class TestL402ClientHelpers:
    """Client must parse L402 challenges and retry with Authorization: L402."""

    def test_parse_l402_challenge_helper_exists(self):
        src = _auth_src()
        assert "function parseL402Challenge" in src
        assert "macaroon" in src
        assert "invoice" in src

    def test_pay_l402_and_retry_helper_exists(self):
        src = _auth_src()
        assert "function payL402AndRetry" in src or "async function payL402AndRetry" in src
        assert "Authorization" in src
        assert "L402 " in src or "L402 ${" in src or "L402 `" in src or "'L402 " in src

    def test_webln_or_bc_captures_preimage(self):
        """L402 needs the payment preimage — WebLN/BC must surface it."""
        combined = _auth_src() + "\n" + _widget_src()
        assert "preimage" in combined
        assert "webln" in combined.lower() or "__bc" in combined


class TestPostFlowL402:
    """Post: 402 → WebLN/BC pay → retry with Authorization: L402 …"""

    def test_post_submit_uses_l402_retry(self):
        index = _index_src()
        assert "parseL402Challenge" in index or "payL402AndRetry" in index
        # Primary settle path must attach L402 credential (not credits)
        assert "L402" in index
        assert "credits used" not in index.lower() or "credit" not in index.split("post-form")[1][:800].lower()

    def test_post_does_not_rely_on_credit_short_circuit_copy(self):
        index = _index_src()
        assert "Post Note" in index
        assert "credits used" not in index

    def test_post_l402_primary_over_confirm_only(self):
        """Primary Lightning settle is L402 retry; confirm may remain Tempo fallback only."""
        index = _index_src()
        auth = _auth_src()
        combined = index + "\n" + auth
        assert "payL402AndRetry" in combined or (
            "parseL402Challenge" in combined and "Authorization" in combined and "L402" in combined
        )


class TestTipIsNip57Zap:
    """Tip button is NIP-57 Zap only — no custodial upvote invoice / credit boost."""

    def test_note_card_has_zap_action_not_upvote_tip(self):
        index = _index_src()
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert 'data-action="zap"' in fn
        assert 'data-action="upvote"' not in fn
        assert "Zap" in fn or "zap" in fn.lower()

    def test_no_credit_boost_ui(self):
        index = _index_src()
        lower = index.lower()
        assert "credit boost" not in lower
        assert "boost (credits)" not in lower
        assert "deposit credits" not in lower

    def test_zap_handler_exists(self):
        index = _index_src()
        assert "function startZap" in index or "async function startZap" in index
        assert 'action === "zap"' in index or "action === 'zap'" in index

    def test_zap_uses_fee_split_tags(self):
        """Zap UX must read NIP-57 zap tags (90/10) from the note."""
        index = _index_src() + "\n" + _auth_src()
        assert "zap" in index
        # Must reference tag weight / split (author + relay legs)
        assert "ZAP_AUTHOR" in index or "weight" in index.lower() or 't[0] === "zap"' in index or "t[0]==='zap'" in index or '== "zap"' in index

    def test_upvote_vote_api_not_used_for_tips(self):
        """Tip must not POST direction:1 to the custodial vote invoice path."""
        index = _index_src()
        # startVote(..., 1) from tip path must be gone
        assert "startVote(id, 1)" not in index
        assert "startVote(id, -1)" in index  # downvote stays


class TestDownvoteL402:
    """Downvote remains L402-to-relay (anti-signal)."""

    def test_downvote_action_present(self):
        index = _index_src()
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert 'data-action="downvote"' in fn

    def test_downvote_uses_l402_or_vote_path(self):
        index = _index_src() + "\n" + _auth_src()
        assert "downvote" in index
        assert "/vote" in index
        assert "L402" in index or "payL402AndRetry" in index


class TestNip11RelayLud16:
    """Client needs relay lud16 for the fee leg of NIP-57 zaps."""

    @pytest.mark.asyncio
    async def test_nip11_includes_lud16_when_configured(self, client, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "RELAY_LUD16", "relay@example.com")
        resp = await client.get("/", headers={"Accept": "application/nostr+json"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("lud16") == "relay@example.com"

    @pytest.mark.asyncio
    async def test_nip11_omits_empty_lud16(self, client, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "RELAY_LUD16", "")
        resp = await client.get("/", headers={"Accept": "application/nostr+json"})
        assert resp.status_code == 200
        data = resp.json()
        assert "lud16" not in data or data.get("lud16") in (None, "")


class TestZapInvoiceHelper:
    """Browser CSP blocks third-party LNURL; server resolves invoice (no custody)."""

    @pytest.mark.asyncio
    async def test_zap_invoice_endpoint_exists(self, client):
        resp = await client.post(
            "/api/v1/zap/invoice",
            json={"lud16": "a@b.com", "amount_msat": 1000},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        # Not 404 — endpoint must exist (may 400/502 on bad lud16)
        assert resp.status_code != 404, "zap invoice helper missing"

    @pytest.mark.asyncio
    async def test_zap_invoice_rejects_bad_lud16(self, client):
        resp = await client.post(
            "/api/v1/zap/invoice",
            json={"lud16": "not-an-address", "amount_msat": 1000},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code in (400, 422)
        detail = (resp.json().get("detail") or "").lower()
        assert "lud16" in detail or "lightning" in detail or "address" in detail

    @pytest.mark.asyncio
    async def test_zap_invoice_rejects_ssrf_lud16(self, client):
        """Adversarial: loopback lud16 must not be resolved."""
        resp = await client.post(
            "/api/v1/zap/invoice",
            json={"lud16": "alice@127.0.0.1", "amount_msat": 21000},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code in (400, 403, 502)
        assert resp.status_code != 200


class TestParseL402AdversarialSource:
    """Malformed challenge must not invent credentials (source contract)."""

    def test_parse_handles_missing_fields(self):
        src = _auth_src()
        # Helper must return null/undefined on bad input — not throw blindly
        assert "parseL402Challenge" in src
        assert "return null" in src or "return undefined" in src or "!macaroon" in src
