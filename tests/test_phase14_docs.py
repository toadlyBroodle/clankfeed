"""Phase 14.8–14.9: transparent L402/NIP-57 docs + discovery / custody invariants.

Docs (README, API.md) must teach L402 challenge/credential flow, NIP-57 fee split,
and state non-custodial (no accounts / credits / custody). Tests assert those surfaces
and that tip paths never pay authors from a server balance.
"""

from pathlib import Path

import pytest
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


def _readme() -> str:
    return (ROOT / "README.md").read_text()


def _api_md() -> str:
    return (ROOT / "docs" / "API.md").read_text()


def _lower(s: str) -> str:
    return s.lower()


# ---------------------------------------------------------------------------
# 14.8 Transparent docs — README
# ---------------------------------------------------------------------------


class TestReadmeL402HowTo:
    def test_readme_documents_l402_challenge_header(self):
        readme = _readme()
        assert "WWW-Authenticate: L402" in readme
        assert "macaroon=" in readme
        assert "invoice=" in readme

    def test_readme_documents_l402_credential_shape(self):
        readme = _readme()
        assert "Authorization: L402" in readme
        assert "<macaroon>" in readme
        assert "preimage" in _lower(readme)

    def test_readme_has_l402_worked_example(self):
        readme = _readme()
        assert "402" in readme
        assert "L402" in readme
        assert "preimage" in _lower(readme)
        assert "retry" in _lower(readme)
        assert "/.well-known/l402" in readme

    def test_readme_primary_payment_is_l402_not_mpp_only(self):
        readme = _readme()
        assert "L402" in readme
        assert "All payment negotiation uses" not in readme


class TestReadmeNip57AndNonCustodial:
    def test_readme_documents_nip57_fee_split(self):
        readme = _readme()
        text = _lower(readme)
        assert "nip-57" in text or "nip 57" in text
        assert "90" in readme and "10" in readme
        assert "zap" in text
        assert "author" in text and ("relay" in text or "fee" in text)

    def test_readme_explicit_no_accounts_credits_custody(self):
        text = _lower(_readme())
        assert "no accounts" in text or "no account" in text
        assert "no credits" in text or "no credit" in text
        assert "no custody" in text or "non-custodial" in text or "noncustodial" in text

    def test_readme_does_not_advertise_live_account_apis(self):
        """Removed custodial surfaces must not be presented as live features."""
        readme = _readme()
        forbidden = [
            "POST /api/v1/account/create",
            "POST /api/v1/account/deposit",
            "GET  /api/v1/account/balance",
            "GET /api/v1/account/balance",
        ]
        for line in forbidden:
            assert line not in readme, f"README still advertises live account API: {line}"

    def test_readme_has_no_account_system_section(self):
        assert "## Account system" not in _readme()


# ---------------------------------------------------------------------------
# 14.8 Transparent docs — API.md
# ---------------------------------------------------------------------------


class TestApiMdL402HowTo:
    def test_api_md_documents_l402_www_authenticate(self):
        api = _api_md()
        assert "WWW-Authenticate: L402" in api
        assert "macaroon=" in api
        assert "invoice=" in api

    def test_api_md_documents_l402_credential(self):
        api = _api_md()
        assert "Authorization: L402" in api
        assert "macaroon" in _lower(api)
        assert "preimage" in _lower(api)

    def test_api_md_has_l402_worked_example(self):
        api = _api_md()
        assert "L402" in api
        assert "/.well-known/l402" in api
        assert "httpx" in api or "curl" in _lower(api) or "import httpx" in api

    def test_api_md_how_to_pay_primary_l402(self):
        text = _lower(_api_md())
        assert "how_to_pay" in text or "primary" in text
        assert "l402" in text


class TestApiMdNip57AndNonCustodial:
    def test_api_md_documents_nip57_fee_split(self):
        api = _api_md()
        text = _lower(api)
        assert "nip-57" in text or "zap" in text
        assert "90" in api and "10" in api
        assert "lud16" in text or "lightning address" in text or "lnurl" in text

    def test_api_md_explicit_no_accounts_credits_custody(self):
        text = _lower(_api_md())
        assert "no accounts" in text or "no account" in text or "accounts and credits removed" in text
        assert "credit" in text  # mentioned as removed
        assert "custod" in text or "non-custodial" in text or "no custody" in text

    def test_api_md_does_not_require_mpp_as_sole_auth(self):
        """Auth section must not claim MPP is the only credential path."""
        api = _api_md()
        idx = api.find("## Authentication")
        assert idx >= 0
        chunk = api[idx : idx + 900]
        assert "L402" in chunk


# ---------------------------------------------------------------------------
# 14.9 Zap UI / docs discovery
# ---------------------------------------------------------------------------


class TestZapDocsAndUiDiscovery:
    def test_readme_points_at_zap_fee_weights(self):
        readme = _readme()
        assert "ZAP_AUTHOR_WEIGHT" in readme or "90%" in readme or "90/10" in readme
        assert "RELAY_LUD16" in readme or "lud16" in _lower(readme)

    def test_api_md_mentions_zap_or_nip57_tip_path(self):
        text = _lower(_api_md())
        assert "zap" in text
        assert "tip" in text or "nip-57" in text or "fee split" in text or "90" in _api_md()

    def test_index_js_exposes_zap_action_for_docs_parity(self):
        """UI discovery: tip is NIP-57 zap (docs claim must match shipped UI)."""
        index = (STATIC / "index.js").read_text()
        assert 'data-action="zap"' in index or "action === 'zap'" in index
        assert "90/10" in index or "splitZapAmounts" in index


# ---------------------------------------------------------------------------
# 14.9 Credit APIs gone + no author payout from server balance
# ---------------------------------------------------------------------------


class TestCreditApisGoneOpenapi:
    @pytest.mark.asyncio
    async def test_openapi_has_no_account_key_scheme(self, client):
        from app.main import app

        app.openapi_schema = None
        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        schemes = resp.json().get("components", {}).get("securitySchemes", {})
        assert "AccountKey" not in schemes
        # L402 scheme present for discovery
        assert "L402" in schemes

    @pytest.mark.asyncio
    async def test_account_create_still_410(self, client):
        resp = await client.post("/api/v1/account/create", json={})
        assert resp.status_code == 410


class TestNoAuthorPayoutFromServerBalance:
    """Invariant: server never remits tip/author value from deposited/custodial funds."""

    def test_zaps_module_does_not_import_accounts_or_spend_credits(self):
        zaps = (ROOT / "app" / "zaps.py").read_text()
        assert "from app.accounts" not in zaps
        assert "import app.accounts" not in zaps
        assert "spend_credits" not in zaps
        assert "deposit_credits" not in zaps

    def test_api_v1_try_spend_credits_is_hard_disabled(self):
        src = (ROOT / "app" / "api_v1.py").read_text()
        assert "async def _try_spend_credits" in src
        # Body must always return False (no live credit short-circuit)
        start = src.index("async def _try_spend_credits")
        chunk = src[start : start + 400]
        assert "return False" in chunk or 'return (False' in chunk

    @pytest.mark.asyncio
    async def test_no_withdraw_or_payout_routes(self, client):
        for path in (
            "/api/v1/account/withdraw",
            "/api/v1/payout",
            "/api/v1/tips/payout",
            "/api/v1/author/pay",
        ):
            resp = await client.post(path, json={})
            assert resp.status_code in (404, 405, 410), f"{path}: {resp.status_code}"

    @pytest.mark.asyncio
    async def test_paid_post_does_not_create_account_balance_row(self, client):
        from app.database import async_session
        from app.models import Account

        resp = await client.post("/api/v1/post", json={"content": "docs-cycle"})
        assert resp.status_code in (200, 402)
        async with async_session() as db:
            rows = (await db.execute(select(Account))).scalars().all()
        assert rows == []
