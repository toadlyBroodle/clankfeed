"""Phase 14.6: Web client non-custodial — L402 post/downvote; NIP-57 zap tip."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


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


# ---------------------------------------------------------------------------
# 14.16: content-bearing unauthenticated POST must return pending/token JSON
# ---------------------------------------------------------------------------

MOCK_POST_INVOICE = {
    "payment_hash": "cd" * 32,
    "payment_request": "lnbc210n1phase1416post",
}


class TestRelayPostContent402Json:
    """14.16: unpaid content POST → pending token + l402 + lightning (not probe-only)."""

    @pytest.mark.asyncio
    async def test_unauthenticated_content_post_returns_token_l402_lightning(
        self, monkeypatch,
    ):
        """Content-bearing POST without Authorization must get Tempo/QR-capable 402 JSON."""
        from unittest.mock import AsyncMock, patch

        from httpx import ASGITransport, AsyncClient

        from app.database import Base, engine
        from app.limiter import limiter
        from app.main import app

        root_key = "phase14-16-root-key"
        monkeypatch.setenv("AUTH_ROOT_KEY", root_key)
        from app import config

        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", root_key)
        monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")
        monkeypatch.setattr(config.settings, "POST_PRICE_SATS", 21)
        limiter.reset()

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                headers={"X-Requested-With": "XMLHttpRequest"},
            ) as client:
                with patch(
                    "app.api_v1.create_invoice",
                    new_callable=AsyncMock,
                    return_value=MOCK_POST_INVOICE,
                ), patch(
                    "app.l402.create_invoice",
                    new_callable=AsyncMock,
                    return_value=MOCK_POST_INVOICE,
                ):
                    resp = await client.post(
                        "/api/v1/post",
                        json={"content": "web client unpaid note"},
                    )
            assert resp.status_code == 402, resp.text
            body = resp.json()
            assert body.get("token"), f"missing pending token: {body}"
            assert "l402" in body, f"missing l402 JSON: {body.keys()}"
            assert body["l402"].get("macaroon") and body["l402"].get("invoice")
            assert "lightning" in body, f"missing lightning: {body.keys()}"
            assert body["lightning"].get("bolt11") == MOCK_POST_INVOICE["payment_request"]
            assert body["lightning"].get("payment_hash") == MOCK_POST_INVOICE["payment_hash"]
            # Adversarial: must not be the probe-only problem+detail shape without pay fields
            assert body.get("status") == "payment_required" or body.get("token")
            assert "bolt11" in body or body.get("lightning", {}).get("bolt11")
        finally:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            limiter.reset()

    @pytest.mark.asyncio
    async def test_empty_discovery_probe_still_402_without_pending(self, monkeypatch):
        """Empty/discovery POST (no content) may early-probe without storing pending."""
        from unittest.mock import AsyncMock, patch

        from httpx import ASGITransport, AsyncClient

        from app.database import Base, engine
        from app.limiter import limiter
        from app.main import app

        root_key = "phase14-16-probe-key"
        monkeypatch.setenv("AUTH_ROOT_KEY", root_key)
        from app import config

        monkeypatch.setattr(config.settings, "AUTH_ROOT_KEY", root_key)
        monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "")
        limiter.reset()

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                headers={"X-Requested-With": "XMLHttpRequest"},
            ) as client:
                with patch(
                    "app.api_v1.create_invoice",
                    new_callable=AsyncMock,
                    return_value=MOCK_POST_INVOICE,
                ), patch(
                    "app.l402.create_invoice",
                    new_callable=AsyncMock,
                    return_value=MOCK_POST_INVOICE,
                ):
                    resp = await client.post("/api/v1/post", json={})
            assert resp.status_code == 402, resp.text
            body = resp.json()
            # Discovery probe: no pending token required
            assert "payment-required" in body.get("type", "") or "how_to_pay" in body
            assert not body.get("token"), f"empty probe must not create pending: {body}"
        finally:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            limiter.reset()


# ---------------------------------------------------------------------------
# 14.17: Playwright — zap prompt + identity hint + L402 post widget
# ---------------------------------------------------------------------------


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_health(base: str, timeout: float = 20.0) -> None:
    import time

    import httpx

    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base}/health", timeout=1.0)
            if r.status_code == 200:
                return
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(0.15)
    raise RuntimeError(f"server did not become healthy: {last_err}")


@pytest.fixture
def live_server_free(tmp_path):
    """Uvicorn with AUTH_ROOT_KEY=test-mode (free posts for zap UI)."""
    import os
    import subprocess
    import sys
    import time

    db_path = tmp_path / "p14_zap.db"
    port = _free_port()
    env = os.environ.copy()
    env.update(
        {
            "AUTH_ROOT_KEY": "test-mode",
            "EXTERNAL_INGEST": "false",
            "DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "RELAY_PRIVATE_KEY": "a" * 64,
            "TEMPO_RECIPIENT": "",
            "BASE_URL": f"ws://127.0.0.1:{port}",
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
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_health(base)
        yield {"base": base, "db": db_path, "port": port}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


@pytest.fixture
def live_server_paid(tmp_path):
    """Uvicorn with payments enabled + stub LNBits for real /api/v1/post 402 JSON."""
    import json
    import os
    import subprocess
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    db_path = tmp_path / "p14_paid.db"
    ln_port = _free_port()
    app_port = _free_port()

    class _LnBitsHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: ARG002
            return

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps(
                {
                    "payment_hash": "ef" * 32,
                    "payment_request": "lnbc210n1phase1417playwright",
                }
            ).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            body = b'{"paid": false}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    ln_httpd = HTTPServer(("127.0.0.1", ln_port), _LnBitsHandler)
    ln_thread = threading.Thread(target=ln_httpd.serve_forever, daemon=True)
    ln_thread.start()

    env = os.environ.copy()
    env.update(
        {
            "AUTH_ROOT_KEY": "phase14-17-live-key",
            "EXTERNAL_INGEST": "false",
            "DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "RELAY_PRIVATE_KEY": "a" * 64,
            "TEMPO_RECIPIENT": "",
            "PAYMENT_URL": f"http://127.0.0.1:{ln_port}",
            "PAYMENT_KEY": "test-lnbits-key",
            "BASE_URL": f"ws://127.0.0.1:{app_port}",
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
            str(app_port),
        ],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{app_port}"
    try:
        _wait_health(base)
        yield {"base": base, "db": db_path, "port": app_port}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        ln_httpd.shutdown()


@pytest.mark.asyncio
async def test_playwright_zap_prompt_and_identity_hint(live_server_free):
    """14.17: zap opens prompt with NIP-57 title; submit without identity shows hint."""
    import httpx

    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server_free["base"]
    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        note = c.post("/api/v1/post", json={"content": "p14-zap-seed"}).json()["event"]["id"]

    headless = not bool(__import__("os").environ.get("DISPLAY"))
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{note}", timeout=15_000)

        await page.click(f'#note-{note} button[data-action="zap"]')
        await page.wait_for_selector(f"#vote-prompt-{note}.active", timeout=5_000)
        status = await page.locator(f"#vote-status-{note}").text_content()
        assert status is not None and "Zap" in status and "NIP-57" in status

        await page.click(f'#note-{note} button[data-action="submit-vote"]')
        await page.wait_for_function(
            f"() => (document.getElementById('vote-status-{note}')?.textContent || '')"
            f".includes('identity')",
            timeout=5_000,
        )
        hint = await page.locator(f"#vote-status-{note}").text_content()
        assert hint and "identity" in hint.lower() and "/profile" in hint

        await browser.close()


@pytest.mark.asyncio
async def test_playwright_l402_pay_to_post_widget(live_server_paid):
    """14.17: unpaid submit shows L402 'Pay to post' widget from real 402 JSON."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server_paid["base"]
    headless = not bool(__import__("os").environ.get("DISPLAY"))
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        page = await browser.new_page()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#post-form", timeout=10_000)

        await page.fill("#post-content", "p14-l402-unpaid-widget")
        await page.click("#post-btn")

        await page.wait_for_selector("#pw-widget:not(.hidden)", timeout=15_000)
        title = await page.locator("#pw-title").text_content()
        assert title and "Pay to post" in title and "L402" in title
        bolt11 = await page.locator("#pw-bolt11").text_content()
        assert bolt11 and "lnbc" in bolt11

        await browser.close()
