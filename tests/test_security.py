"""Security tests: input validation, injection attempts, malformed payloads."""

import base64
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from httpx import AsyncClient, ASGITransport

from app.database import engine, Base
from app.limiter import limiter
from app.nostr import sign_event
from tests.conftest import kind1_tags


TEST_SK = "b" * 64


def _nip98(url: str, method: str) -> dict:
    event = {"kind": 27235, "created_at": int(time.time()), "tags": [["u", url], ["method", method.upper()]], "content": ""}
    signed = sign_event(TEST_SK, event)
    token = base64.b64encode(json.dumps(signed).encode()).decode()
    return {"Authorization": f"Nostr {token}", "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


def _make_event(content="test", kind=1):
    return sign_event(TEST_SK, {
        "created_at": int(time.time()),
        "kind": kind,
        "tags": kind1_tags(TEST_SK) if kind == 1 else [],
        "content": content,
    })


@pytest_asyncio.fixture
async def sec_client(monkeypatch):
    """Client with Tempo enabled for testing payment input validation."""
    from app import config
    monkeypatch.setenv("ENABLE_TEMPO", "1")
    monkeypatch.setattr(config.settings, "TEMPO_RECIPIENT", "0xRecipient")
    monkeypatch.setattr(config.settings, "TEMPO_CURRENCY", "0xToken")
    monkeypatch.setattr(config.settings, "TEMPO_PRICE_USD", "0.01")
    monkeypatch.setattr(config.settings, "TEMPO_TESTNET", True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from app.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as c:
        yield c

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# SQL injection attempts
# ---------------------------------------------------------------------------

class TestSQLInjection:
    """Verify SQL injection via query params and JSON body is blocked."""

    @pytest.mark.asyncio
    async def test_event_id_injection(self, client):
        """SQL injection via event_id path param."""
        resp = await client.get("/api/v1/events/'; DROP TABLE nostr_events; --")
        assert resp.status_code == 400  # L3 format reject, not 500

    @pytest.mark.asyncio
    async def test_authors_filter_injection(self, client):
        """SQL injection via authors query param."""
        resp = await client.get("/api/v1/events?authors=' OR 1=1 --")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0  # no match, no crash

    @pytest.mark.asyncio
    async def test_ids_filter_injection(self, client):
        resp = await client.get("/api/v1/events?ids=' UNION SELECT * FROM consumed_payments --")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    @pytest.mark.asyncio
    async def test_kinds_filter_injection(self, client):
        """Non-integer kinds should not crash."""
        resp = await client.get("/api/v1/events?kinds=abc")
        # Should either return 422 (FastAPI validation) or handle gracefully
        assert resp.status_code in (200, 400, 422)


# ---------------------------------------------------------------------------
# XSS attempts
# ---------------------------------------------------------------------------

class TestXSS:
    """Verify XSS payloads are stored safely and not executed."""

    @pytest.mark.asyncio
    async def test_xss_in_content(self, client):
        """Script tags in content should be stored as-is (escaped on render)."""
        xss = '<script>alert("xss")</script>'
        resp = await client.post("/api/v1/post", json={"content": xss})
        assert resp.status_code == 200
        # Content stored verbatim (escaping is client-side)
        assert resp.json()["event"]["content"] == xss

    @pytest.mark.asyncio
    async def test_xss_in_display_name(self, client):
        xss = '<img src=x onerror=alert(1)>'
        resp = await client.post("/api/v1/post", json={
            "content": "test", "display_name": xss,
        })
        assert resp.status_code == 200
        tags = resp.json()["event"]["tags"]
        assert any(t[1] == xss for t in tags)  # stored verbatim


# ---------------------------------------------------------------------------
# Client DOM XSS (S-H1 / S-M7 / S-L4) — static source + jsStr contract
# ---------------------------------------------------------------------------

_STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


class TestDOMXSSClient:
    """Frontend XSS cluster: payment widget (H1), API-key display (M7), onclick (L4)."""

    def test_h1_payment_widget_binds_server_data_via_textcontent(self):
        """S-H1: bolt11 / tempo recipient / currency must not be interpolated into innerHTML."""
        src = (_STATIC / "payment-widget.js").read_text()
        # Static shell may use innerHTML once; dynamic fields must use textContent.
        assert "getElementById('pw-tempo-recipient').textContent" in src
        assert "getElementById('pw-tempo-amount').textContent" in src
        assert "getElementById('pw-tempo-token').textContent" in src
        assert "getElementById('pw-title').textContent" in src or "title.textContent" in src
        # No template-literal injection of server fields into innerHTML
        for needle in ("innerHTML = `", "innerHTML=`", '.innerHTML = "'):
            if needle in src:
                # Only the static _ensureWidgetDOM shell is allowed; it must not
                # reference data./bolt11/token/recipient inside that assignment.
                start = src.index(needle)
                chunk = src[start:start + 1200]
                assert "data." not in chunk
                assert "${" not in chunk or all(
                    dyn not in chunk
                    for dyn in ("${data", "${bolt11", "${token", "${recipient")
                )
        index = (_STATIC / "index.js").read_text()
        # showVotePayment must delegate to the safe widget, not build its own HTML
        assert "function showVotePayment" in index
        vote_fn = index.split("function showVotePayment", 1)[1].split("\nfunction ", 1)[0]
        assert "showPaymentWidget" in vote_fn
        assert "innerHTML" not in vote_fn

    def test_m7_no_showApiKey_innerhtml_path(self):
        """S-M7: showApiKey must not exist; API keys must not be assigned via innerHTML."""
        for path in list(_STATIC.glob("*.html")) + list(_STATIC.glob("*.js")):
            text = path.read_text()
            assert "function showApiKey" not in text, f"showApiKey still in {path.name}"
            assert "showApiKey(" not in text, f"showApiKey call in {path.name}"
            # No legacy API-key → innerHTML wiring
            lowered = text.lower()
            if "clankfeed_api_key" in lowered or "api_key" in lowered:
                for line in text.splitlines():
                    if "innerHTML" in line and ("api_key" in line.lower() or "apiKey" in line):
                        raise AssertionError(f"API key via innerHTML in {path.name}: {line}")

    def test_l4_onclick_handlers_use_jsstr_not_single_quote_interp(self):
        """S-L4 under M4: no dynamic onclick; data-action + esc() attrs (no quote interp)."""
        index = (_STATIC / "index.js").read_text()
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        # Legacy vulnerable onclick patterns must stay gone
        assert "onclick=\"startReply('${n.id}', '${esc(displayName || pk)}')\"" not in index
        assert "onclick=\"startVote('${n.id}', 1)\"" not in index
        assert "onclick='" not in fn and 'onclick="' not in fn
        # M4: delegated data-action handlers with HTML-escaped attrs
        assert 'data-action="reply"' in fn
        assert "data-name=" in fn
        assert "esc(" in fn

    def test_l4_jsstr_helper_uses_json_stringify_and_html_attr_escape(self):
        """jsStr must JSON.stringify AND neutralize raw apostrophes for HTML attrs."""
        src = (_STATIC / "nostr-auth.js").read_text()
        assert "function jsStr(" in src
        body = src.split("function jsStr(", 1)[1].split("\n}", 1)[0]
        assert "JSON.stringify" in body
        # Must rewrite apostrophe for single-quoted HTML onclick attrs (\\u0027 or equiv)
        assert "\\u0027" in body or "u0027" in body or ".replace(/'/g" in body

    def test_l4_html_attr_preserves_apostrophe_name(self):
        """HTML-parse startReply onclick: getAttribute must retain full O'Brien name."""
        import html.parser
        import re
        import subprocess

        src = (_STATIC / "nostr-auth.js").read_text()
        m = re.search(r"function jsStr\([^)]*\)\s*\{.*?\n\}", src, re.DOTALL)
        assert m, "jsStr function not found"
        js_fn = m.group(0)
        # Run real jsStr via Node (source of truth), embed in single-quoted onclick, HTML-parse.
        name = "O'Brien"
        note_id = "a" * 64
        node = subprocess.run(
            [
                "node",
                "-e",
                js_fn
                + f"; process.stdout.write(jsStr({json.dumps(note_id)}) + '\\n' + jsStr({json.dumps(name)}));",
            ],
            capture_output=True,
            text=True,
        )
        assert node.returncode == 0, node.stderr
        lit_id, lit_name = node.stdout.split("\n", 1)
        fragment = (
            f"<button onclick='startReply({lit_id}, {lit_name})'>reply</button>"
        )

        class _Attr(html.parser.HTMLParser):
            def __init__(self):
                super().__init__()
                self.onclick = None

            def handle_starttag(self, tag, attrs):
                for k, v in attrs:
                    if k == "onclick":
                        self.onclick = v

        p = _Attr()
        p.feed(fragment)
        assert p.onclick is not None, "onclick attribute missing after HTML parse"
        # Truncation bug: attr ends at the apostrophe → "startReply(..., \"O"
        assert "Brien" in p.onclick, (
            f"apostrophe truncated HTML attr; got {p.onclick!r}"
        )
        # Round-trip: Node must recover the original display name from the attr JS
        assert p.onclick.startswith("startReply(")
        args_js = p.onclick[len("startReply(") :]
        if args_js.endswith(")"):
            args_js = args_js[:-1]
        rt = subprocess.run(
            [
                "node",
                "-e",
                f"const [a,b]=[{args_js}]; "
                f"if (a !== {json.dumps(note_id)} || b !== {json.dumps(name)}) process.exit(1);",
            ],
            capture_output=True,
            text=True,
        )
        assert rt.returncode == 0, (
            f"onclick JS did not round-trip name {name!r}; attr={p.onclick!r} stderr={rt.stderr}"
        )

    def test_l4_jsstr_adversarial_quote_breakout(self):
        """Adversarial names must survive HTML attr parse + JS eval (no quote breakout)."""
        import html.parser
        import re
        import subprocess

        src = (_STATIC / "nostr-auth.js").read_text()
        m = re.search(r"function jsStr\([^)]*\)\s*\{.*?\n\}", src, re.DOTALL)
        assert m, "jsStr function not found"
        js_fn = m.group(0)
        payloads = [
            "');alert(1);//",
            '"onload=alert(1)',
            "O'Brien",
            "</script><script>alert(1)</script>",
            "a\nb",
        ]
        for p in payloads:
            node = subprocess.run(
                [
                    "node",
                    "-e",
                    js_fn + f"; process.stdout.write(jsStr({json.dumps(p)}));",
                ],
                capture_output=True,
                text=True,
            )
            assert node.returncode == 0, node.stderr
            lit = node.stdout
            # Raw apostrophe must not appear — breaks single-quoted HTML attrs
            assert "'" not in lit, (
                f"jsStr({p!r}) still contains raw apostrophe for HTML attr: {lit!r}"
            )
            fragment = f"<button onclick='startReply({lit}, {lit})'>x</button>"

            class _Attr(html.parser.HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.onclick = None

                def handle_starttag(self, tag, attrs):
                    for k, v in attrs:
                        if k == "onclick":
                            self.onclick = v

            parser = _Attr()
            parser.feed(fragment)
            assert parser.onclick is not None
            assert parser.onclick.startswith("startReply(")
            args_js = parser.onclick[len("startReply(") :]
            if args_js.endswith(")"):
                args_js = args_js[:-1]
            rt = subprocess.run(
                [
                    "node",
                    "-e",
                    f"const [a,b]=[{args_js}]; "
                    f"if (a !== {json.dumps(p)} || b !== {json.dumps(p)}) process.exit(1);",
                ],
                capture_output=True,
                text=True,
            )
            assert rt.returncode == 0, f"payload={p!r} attr={parser.onclick!r} err={rt.stderr}"


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

class TestMalformedInput:
    """Test handling of unexpected/malformed payloads."""

    @pytest.mark.asyncio
    async def test_non_json_body(self, client):
        resp = await client.post(
            "/api/v1/events",
            content="not json at all",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_nested_event_object(self, client):
        """Deeply nested JSON should not crash."""
        resp = await client.post("/api/v1/events", json={
            "event": {"event": {"event": "deep"}},
        })
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_event_with_wrong_types(self, client):
        """Event fields with wrong types rejected."""
        resp = await client.post("/api/v1/events", json={
            "event": {
                "id": 12345,  # should be string
                "pubkey": "abc",
                "created_at": "not a number",
                "kind": "text",
                "tags": "not an array",
                "content": 999,
                "sig": True,
            },
        })
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_oversized_content(self, client):
        resp = await client.post("/api/v1/post", json={
            "content": "x" * 10000,
        })
        assert resp.status_code == 400
        assert "too long" in resp.json()["detail"].lower() or "exceeds" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_empty_body(self, client):
        resp = await client.post(
            "/api/v1/events",
            content="",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_null_event(self, client):
        resp = await client.post("/api/v1/events", json={"event": None})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Payment input validation
# ---------------------------------------------------------------------------

class TestPaymentInputValidation:
    """Strict validation of payment-related inputs."""

    @pytest.mark.asyncio
    async def test_invalid_tx_hash_format(self, sec_client):
        """tx_hash must be 0x + 64 hex chars."""
        event = _make_event("tx test")
        resp = await sec_client.post("/api/v1/events", json={"event": event}, headers=_nip98("http://test/api/v1/events", "POST"))
        token = resp.json()["token"]

        # Too short
        resp = await sec_client.post("/api/v1/events/confirm", json={
            "token": token, "method": "tempo", "tx_hash": "0xabc",
        })
        assert resp.status_code == 400
        assert "64 hex" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_tx_hash_non_hex(self, sec_client):
        """tx_hash with non-hex characters rejected."""
        event = _make_event("hex test")
        resp = await sec_client.post("/api/v1/events", json={"event": event}, headers=_nip98("http://test/api/v1/events", "POST"))
        token = resp.json()["token"]

        resp = await sec_client.post("/api/v1/events/confirm", json={
            "token": token, "method": "tempo",
            "tx_hash": "0x" + "g" * 64,
        })
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_payment_hash_non_hex(self, sec_client):
        """payment_hash with non-hex characters rejected."""
        event = _make_event("ln hex test")
        resp = await sec_client.post("/api/v1/events", json={"event": event}, headers=_nip98("http://test/api/v1/events", "POST"))
        token = resp.json()["token"]

        resp = await sec_client.post("/api/v1/events/confirm", json={
            "token": token, "method": "lightning",
            "payment_hash": "not-valid-hex!@#$",
        })
        assert resp.status_code == 400
        assert "hex" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_token_not_hex(self, sec_client):
        """Non-existent token returns 404 (not crash)."""
        resp = await sec_client.post("/api/v1/events/confirm", json={
            "token": "'; DROP TABLE pending_events; --",
            "method": "tempo",
            "tx_hash": "0x" + "a" * 64,
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_method_injection(self, sec_client):
        """Unknown payment method handled gracefully."""
        event = _make_event("method test")
        resp = await sec_client.post("/api/v1/events", json={"event": event}, headers=_nip98("http://test/api/v1/events", "POST"))
        token = resp.json()["token"]

        resp = await sec_client.post("/api/v1/events/confirm", json={
            "token": token, "method": "'; DROP TABLE --",
            "payment_hash": "abc123",
        })
        # Should be 400 (bad hex) or handle gracefully
        assert resp.status_code in (400, 402, 404)


# ---------------------------------------------------------------------------
# Event validation edge cases
# ---------------------------------------------------------------------------

class TestEventEdgeCases:
    """Edge cases in Nostr event validation."""

    @pytest.mark.asyncio
    async def test_future_event_rejected(self, client):
        """Events too far in the future are rejected."""
        event = _make_event("future")
        event["created_at"] = int(time.time()) + 600
        # Re-sign with future timestamp
        event = sign_event(TEST_SK, {
            "created_at": event["created_at"],
            "kind": 1, "tags": kind1_tags(TEST_SK), "content": "future",
        })
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 400
        assert "future" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_too_many_tags(self, client):
        """Events with >100 tags rejected."""
        event = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(TEST_SK, [["t", str(i)] for i in range(101)]),
            "content": "too many tags",
        })
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 400
        assert "tag" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_duplicate_event_idempotent(self, client):
        """Posting the same event twice doesn't error."""
        event = _make_event("duplicate")
        resp1 = await client.post("/api/v1/events", json={"event": event})
        assert resp1.status_code == 200
        resp2 = await client.post("/api/v1/events", json={"event": event})
        assert resp2.status_code == 200


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestInputLimits:
    """Test server-side input length limits."""

    @pytest.mark.asyncio
    async def test_display_name_truncated(self, client):
        """Display names over 100 chars are silently truncated."""
        long_name = "A" * 200
        resp = await client.post("/api/v1/post", json={
            "content": "test",
            "display_name": long_name,
        })
        assert resp.status_code == 200
        tags = resp.json()["event"]["tags"]
        name_tag = [t for t in tags if t[0] == "display_name"]
        assert len(name_tag[0][1]) == 100

    @pytest.mark.asyncio
    async def test_tag_value_too_long(self, client):
        """Tag values over 1024 chars are rejected."""
        event = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(TEST_SK, [["t", "x" * 2000]]),
            "content": "tag test",
        })
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 400
        assert "tag value" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_tag_value_within_limit(self, client):
        """Tag values at 1024 chars are accepted."""
        event = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(TEST_SK, [["t", "x" * 1024]]),
            "content": "ok tag",
        })
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_non_string_tag_values_rejected(self, client):
        """Tag values that aren't strings are rejected."""
        event = sign_event(TEST_SK, {
            "created_at": int(time.time()),
            "kind": 1,
            "tags": kind1_tags(TEST_SK, [["t", 12345]]),
            "content": "bad tag type",
        })
        resp = await client.post("/api/v1/events", json={"event": event})
        assert resp.status_code == 400


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_post_rate_limit(self, client):
        """Exceeding rate limit returns 429."""
        for i in range(11):
            resp = await client.post("/api/v1/post", json={"content": f"rate {i}"})
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# S-H2: auth secrets out of localStorage; httpOnly session cookie
# ---------------------------------------------------------------------------

class TestSessionCookieH2:
    """H2: no nsec/API-key in localStorage; session login removed (14.5)."""

    def test_h2_no_auth_secrets_persisted_to_localstorage(self):
        """Client must not write nsec or API keys into localStorage."""
        src = (_STATIC / "nostr-auth.js").read_text()
        assert "localStorage.setItem('cf_nsec'" not in src
        assert 'localStorage.setItem("cf_nsec"' not in src
        assert "localStorage.setItem('clankfeed_api_key'" not in src
        assert 'localStorage.setItem("clankfeed_api_key"' not in src
        assert "function setAuthState" in src
        body = src.split("function setAuthState", 1)[1].split("\nfunction ", 1)[0]
        assert "userNsec" in body
        assert "localStorage.setItem('cf_nsec'" not in body
        assert 'localStorage.setItem("cf_nsec"' not in body

    def test_h2_auth_fetch_sends_credentials(self):
        """authFetch keeps credentials include for legacy cookie clear on logout."""
        src = (_STATIC / "nostr-auth.js").read_text()
        assert "credentials" in src
        assert "'include'" in src or '"include"' in src

    @pytest.mark.asyncio
    async def test_h2_login_removed(self, client):
        """POST /api/v1/auth/login is gone (410); no cf_session minted."""
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        resp = await client.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code == 410
        set_cookie = resp.headers.get("set-cookie", "")
        assert "cf_session=" not in set_cookie.lower()

    @pytest.mark.asyncio
    async def test_h2_session_cookie_does_not_authenticate(self, client):
        """Legacy cf_session alone must not authenticate /auth/me."""
        from app.session_auth import mint_session_token
        from app.zaps import pubkey_from_privkey

        token = mint_session_token(pubkey_from_privkey("b" * 64))
        client.cookies.set("cf_session", token)
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_h2_logout_still_clears_cookie(self, client):
        """POST /api/v1/auth/logout still clears legacy cookies."""
        from app.session_auth import mint_session_token
        from app.zaps import pubkey_from_privkey

        client.cookies.set("cf_session", mint_session_token(pubkey_from_privkey("b" * 64)))
        logout = await client.post("/api/v1/auth/logout")
        assert logout.status_code == 200
        set_cookie = logout.headers.get("set-cookie", "")
        assert "cf_session" in set_cookie.lower()

    @pytest.mark.asyncio
    async def test_h2_me_requires_nip98(self, client):
        """GET /api/v1/auth/me returns pubkey only with valid NIP-98."""
        from app.zaps import pubkey_from_privkey

        headers = _nip98("http://test/api/v1/auth/me", "GET")
        me = await client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["pubkey"] == pubkey_from_privkey("b" * 64)
        assert me.json()["auth_method"] == "nip98"


# ---------------------------------------------------------------------------
# S-H2a: Secure flag from request HTTPS (X-Forwarded-Proto / scheme)
# ---------------------------------------------------------------------------

class TestSessionSecureH2a:
    """H2a: set_session_cookie Secure follows request HTTPS (logout still uses it)."""

    @pytest.mark.asyncio
    async def test_h2a_secure_when_x_forwarded_proto_https(self, client, monkeypatch):
        from app import config
        from app.session_auth import set_session_cookie
        from starlette.responses import Response
        from unittest.mock import MagicMock
        from fastapi import Request

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        req = MagicMock(spec=Request)
        req.url.scheme = "http"
        req.headers = {"x-forwarded-proto": "https"}
        r = Response()
        set_session_cookie(r, "a" * 64, req)
        set_cookie = r.headers.get("set-cookie", "")
        assert "cf_session=" in set_cookie.lower()
        assert "secure" in set_cookie.lower()

    @pytest.mark.asyncio
    async def test_h2a_insecure_on_plain_http_without_forwarded(self, client, monkeypatch):
        from app import config
        from app.session_auth import set_session_cookie
        from starlette.responses import Response
        from unittest.mock import MagicMock
        from fastapi import Request

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        req = MagicMock(spec=Request)
        req.url.scheme = "http"
        req.headers = {}
        r = Response()
        set_session_cookie(r, "a" * 64, req)
        set_cookie = r.headers.get("set-cookie", "")
        assert "cf_session=" in set_cookie.lower()
        assert "secure" not in set_cookie.lower()

    @pytest.mark.asyncio
    async def test_h2a_adversarial_forwarded_http_not_secure(self, client, monkeypatch):
        from app import config
        from app.session_auth import set_session_cookie
        from starlette.responses import Response
        from unittest.mock import MagicMock
        from fastapi import Request

        monkeypatch.setattr(config.settings, "BASE_URL", "wss://clankfeed.com")
        req = MagicMock(spec=Request)
        req.url.scheme = "http"
        req.headers = {"x-forwarded-proto": "http"}
        r = Response()
        set_session_cookie(r, "a" * 64, req)
        set_cookie = r.headers.get("set-cookie", "")
        assert "cf_session=" in set_cookie.lower()
        assert "secure" not in set_cookie.lower()

    @pytest.mark.asyncio
    async def test_h2a_logout_secure_matches_forwarded_https(self, client, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        logout = await client.post(
            "/api/v1/auth/logout",
            headers={"X-Forwarded-Proto": "https"},
        )
        assert logout.status_code == 200
        set_cookie = logout.headers.get("set-cookie", "")
        assert "cf_session" in set_cookie.lower()
        assert "secure" in set_cookie.lower()


# ---------------------------------------------------------------------------
# S-H4: CORS allow_origins restricted (no wildcard)
# ---------------------------------------------------------------------------

class TestCORSH4:
    """H4: CORS must not reflect arbitrary origins; allow clankfeed + localhost."""

    def test_h4_cors_origins_not_wildcard(self):
        """main.py must not use allow_origins=['*']."""
        main_src = (Path(__file__).resolve().parents[1] / "app" / "main.py").read_text()
        assert 'allow_origins=["*"]' not in main_src
        assert "allow_origins=['*']" not in main_src
        # Must call a helper or list explicit origins
        assert "cors_allow_origins" in main_src or "CORS_ALLOW" in main_src or "clankfeed.com" in main_src

    @pytest.mark.asyncio
    async def test_h4_allowed_origin_gets_acao(self, client, monkeypatch):
        """https://clankfeed.com preflight/GET receives Access-Control-Allow-Origin."""
        from app import config
        monkeypatch.setattr(config.settings, "BASE_URL", "wss://clankfeed.com")
        # Re-import would be heavy; exercise OPTIONS against live middleware via app
        from app.main import cors_allow_origins
        allowed = cors_allow_origins()
        assert "https://clankfeed.com" in allowed
        assert "*" not in allowed

        resp = await client.options(
            "/api/v1/events",
            headers={
                "Origin": "https://clankfeed.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Starlette CORS answers 200 on preflight when origin allowed
        assert resp.status_code in (200, 204)
        assert resp.headers.get("access-control-allow-origin") == "https://clankfeed.com"

    @pytest.mark.asyncio
    async def test_h4_evil_origin_not_reflected(self, client):
        """evil.com must not receive a reflecting ACAO header."""
        resp = await client.get(
            "/api/v1/events",
            headers={"Origin": "https://evil.example"},
        )
        acao = resp.headers.get("access-control-allow-origin")
        assert acao != "https://evil.example"
        assert acao != "*"

    @pytest.mark.asyncio
    async def test_h4_origincheck_allows_127_when_base_is_localhost(self, client, monkeypatch):
        """OriginCheck must share cors_allow_origins(): 127.0.0.1 allowed when BASE_URL is localhost."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        headers = {
            "Origin": "http://127.0.0.1:8089",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }
        resp = await client.post(
            "/api/v1/post",
            json={"content": "h4 origin ok"},
            headers=headers,
        )
        assert resp.status_code != 403, (
            "127.0.0.1:8089 is in cors_allow_origins() and must pass OriginCheck "
            f"when BASE_URL is localhost; got {resp.status_code}: {resp.text}"
        )
        assert resp.status_code in (200, 402)

    @pytest.mark.asyncio
    async def test_h4_origincheck_rejects_evil_origin(self, client, monkeypatch):
        """OriginCheck still blocks origins outside cors_allow_origins()."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        headers = {
            "Origin": "https://evil.example",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }
        resp = await client.post(
            "/api/v1/post",
            json={"content": "evil"},
            headers=headers,
        )
        assert resp.status_code == 403
        assert "cross-origin" in resp.text.lower() or "cross-origin" in str(resp.json()).lower()


# ---------------------------------------------------------------------------
# S-H5: Require X-Requested-With when Origin absent (CSRF gap after H4)
# ---------------------------------------------------------------------------

class TestOriginCheckH5:
    """H5: mutating requests without Origin need X-Requested-With or Authorization."""

    @pytest.mark.asyncio
    async def test_h5_no_origin_no_headers_rejected(self, client):
        """POST without Origin, X-Requested-With, or Authorization → 403."""
        # Bypass fixture default XRW if present: use a bare ASGI call
        from app.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as bare:
            resp = await bare.post("/api/v1/post", json={"content": "csrf?"})
        assert resp.status_code == 403
        detail = resp.text.lower()
        assert "origin" in detail or "requested" in detail or "csrf" in detail or "header" in detail

    @pytest.mark.asyncio
    async def test_h5_no_origin_with_xrw_allowed(self, client):
        """POST without Origin but with X-Requested-With → not blocked by H5."""
        resp = await client.post(
            "/api/v1/post",
            json={"content": "h5 ok"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code != 403
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_h5_no_origin_with_authorization_allowed(self, client):
        """Agents without Origin may authenticate via Authorization (no XRW needed)."""
        headers = _nip98("http://test/api/v1/post", "POST")
        headers.pop("X-Requested-With", None)
        from app.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as bare:
            resp = await bare.post(
                "/api/v1/post",
                json={"content": "h5 auth ok"},
                headers={**headers, "Content-Type": "application/json"},
            )
        assert resp.status_code != 403
        assert resp.status_code in (200, 402)

    @pytest.mark.asyncio
    async def test_h5_valid_origin_without_xrw_allowed(self, client, monkeypatch):
        """Valid Origin alone still passes (H4 path); XRW not required when Origin ok."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        from app.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as bare:
            resp = await bare.post(
                "/api/v1/post",
                json={"content": "origin ok"},
                headers={"Origin": "http://127.0.0.1:8089"},
            )
        assert resp.status_code != 403
        assert resp.status_code == 200

    def test_h5_frontend_sends_xrw(self):
        """Browser fetch helpers must set X-Requested-With for CSRF defense."""
        auth_src = (Path(__file__).resolve().parents[1] / "app" / "static" / "nostr-auth.js").read_text()
        assert "X-Requested-With" in auth_src
        assert "function apiFetch" in auth_src
        _st = Path(__file__).resolve().parents[1] / "app" / "static"
        index_src = (_st / "index.js").read_text() + "\n" + (_st / "index.html").read_text()
        # Mutating POSTs that skip authFetch must use apiFetch (sets XRW)
        assert "apiFetch" in index_src
        # 11c/14.6: L402 primary; MPP Payment fallthrough (no /api/post/confirm)
        assert (
            "payL402AndRetry" in index_src
            or "parseL402Challenge" in index_src
        )
        assert "buildLightningPaymentAuth" in index_src or "buildLightningPaymentAuth" in auth_src
        assert "apiFetch('/api/v1/post'" in index_src or 'apiFetch("/api/v1/post"' in index_src
        assert "apiFetch(`/api/v1/events/${eventId}/vote`" in index_src or "apiFetch(`/api/v1/events/${eventId}/vote`" in auth_src
        # Profile paid-path POSTs use XRW wrappers; deposit APIs removed (14.5)
        profile_src = (_st / "profile.js").read_text() + "\n" + (_st / "profile.html").read_text()
        assert "authFetch" in profile_src or "apiFetch" in profile_src
        assert "/api/v1/account/deposit" not in profile_src
        assert "section-deposit" not in profile_src
        # 11c: confirm gone — no bare fetch confirm path
        assert "fetch('/api/post/confirm'" not in profile_src
        assert 'fetch("/api/post/confirm"' not in profile_src
        assert "/api/post/confirm" not in profile_src

    def test_h5_cors_allows_xrw_header(self):
        """CORS must allow X-Requested-With so browsers can send it cross-origin to our allowlist."""
        main_src = (Path(__file__).resolve().parents[1] / "app" / "main.py").read_text()
        assert "X-Requested-With" in main_src


# ---------------------------------------------------------------------------
# S-M3: reply_to must be 64 hex before LIKE query
# ---------------------------------------------------------------------------

class TestReplyToM3:
    """M3: reply_to wildcards must not reach the tags.contains LIKE path."""

    @pytest.mark.asyncio
    async def test_m3_reply_to_wildcard_rejected(self, client):
        resp = await client.get("/api/v1/events?reply_to=%25&kinds=1")
        assert resp.status_code == 400
        assert "reply_to" in resp.json().get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_m3_reply_to_underscore_rejected(self, client):
        bad = "a" * 63 + "_"  # 64 chars but not hex
        resp = await client.get(f"/api/v1/events?reply_to={bad}&kinds=1")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_m3_reply_to_valid_hex_ok(self, client):
        parent = "ab" * 32
        resp = await client.get(f"/api/v1/events?reply_to={parent}&kinds=1")
        assert resp.status_code == 200
        assert "events" in resp.json()


# ---------------------------------------------------------------------------
# S-L3: event_id path params must be 64 hex
# ---------------------------------------------------------------------------

class TestEventIdPathL3:
    """L3: reject non-hex / wrong-length event_id path params with 400."""

    @pytest.mark.asyncio
    async def test_l3_get_event_rejects_short_id(self, client):
        resp = await client.get("/api/v1/events/notanid")
        assert resp.status_code == 400
        assert "event" in resp.json().get("detail", "").lower() or "id" in resp.json().get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_l3_get_event_rejects_injection_shape(self, client):
        resp = await client.get("/api/v1/events/'; DROP TABLE nostr_events; --")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_l3_replies_rejects_bad_id(self, client):
        resp = await client.get("/api/v1/events/zzzz/replies")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_l3_vote_rejects_bad_id(self, client):
        resp = await client.post(
            "/api/v1/events/nothex/vote",
            json={"direction": -1, "amount_sats": 21},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# S-L5: WebSocket subscription id max 256 chars
# ---------------------------------------------------------------------------

class TestSubIdLengthL5:
    """L5: REQ with subscription_id longer than 256 chars is rejected."""

    def test_l5_long_sub_id_closed(self, client):
        from starlette.testclient import TestClient
        from app.main import app

        long_id = "s" * 257
        with TestClient(app) as tc:
            with tc.websocket_connect("/") as ws:
                ws.receive_json()  # AUTH challenge
                ws.send_json(["REQ", long_id, {"kinds": [1], "limit": 1}])
                msg = ws.receive_json()
                assert msg[0] == "CLOSED"
                assert msg[1] == long_id
                assert "subscription" in msg[2].lower() or "length" in msg[2].lower() or "too long" in msg[2].lower()

    def test_l5_sub_id_256_ok(self, client):
        from starlette.testclient import TestClient
        from app.main import app

        ok_id = "s" * 256
        with TestClient(app) as tc:
            with tc.websocket_connect("/") as ws:
                ws.receive_json()
                ws.send_json(["REQ", ok_id, {"kinds": [1], "limit": 1}])
                # May get EVENT(s) then EOSE, or just EOSE
                while True:
                    msg = ws.receive_json()
                    if msg[0] == "EOSE":
                        assert msg[1] == ok_id
                        break
                    if msg[0] == "CLOSED":
                        pytest.fail(f"256-char sub_id should be accepted, got CLOSED: {msg}")
                    if msg[0] == "EVENT":
                        continue
                    # ignore NOTICE etc.
                    if msg[0] not in ("EVENT", "EOSE"):
                        # unexpected but keep draining briefly
                        if msg[0] == "NOTICE":
                            continue
                        break


# ---------------------------------------------------------------------------
# S-M1: Floor sats_clank / sats_ext at 0 on downvotes
# ---------------------------------------------------------------------------

class TestVoteFloorM1:
    """M1: downvotes must not drive sats_clank / sats_ext negative."""

    @pytest.mark.asyncio
    async def test_m1_downvote_overshoot_returns_zero_not_negative(self, client):
        resp = await client.post("/api/v1/post", json={
            "content": "m1 overshoot", "amount_sats": 21,
        })
        eid = resp.json()["event"]["id"]
        resp = await client.post(
            f"/api/v1/events/{eid}/vote",
            json={"direction": -1, "amount_sats": 500},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["new_sats_clank"] == 0
        assert data["new_sats_ext"] == 0
        assert data["new_sats_clank"] >= 0
        assert data["new_sats_ext"] >= 0

    @pytest.mark.asyncio
    async def test_m1a_confirm_vote_overshoot_floors_at_zero(self, client):
        """S-M1a: paid POST .../vote/confirm must floor overshoot downvote at 0.

        Free + credits paths are covered elsewhere; this hits confirm_vote so a
        re-inline of unfloored math on the paid path cannot ship undetected.
        """
        from datetime import datetime, timedelta, timezone

        from app.database import async_session
        from app.models import NostrEvent, PendingEvent

        resp = await client.post("/api/v1/post", json={
            "content": "m1a confirm overshoot", "amount_sats": 21,
        })
        assert resp.status_code == 200
        eid = resp.json()["event"]["id"]

        payment_hash = "ab" * 32
        token = "cd" * 32
        vote_data = {
            "vote_event_id": eid,
            "direction": -1,
            "amount_sats": 500,
            "amount_usd": "0.01",
        }

        async with async_session() as db:
            row = await db.get(NostrEvent, eid)
            row.sats_ext = 10
            db.add(PendingEvent(
                token=token,
                event_json=json.dumps(vote_data),
                payment_hash=payment_hash,
                amount_sats=500,
                amount_usd="0.01",
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            ))
            await db.commit()

        with (
            patch("app.api_v1.check_payment_status", new_callable=AsyncMock, return_value=True),
            patch("app.api_v1.check_and_consume_payment", new_callable=AsyncMock, return_value=True),
        ):
            resp = await client.post(
                f"/api/v1/events/{eid}/vote/confirm",
                json={
                    "token": token,
                    "method": "lightning",
                    "payment_hash": payment_hash,
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["voted"] is True
        assert data["direction"] == -1
        assert data["new_sats_clank"] == 0  # 21 - 500 floored (not -479)
        assert data["new_sats_ext"] == 0    # 10 - 500 floored (not -490)
        assert data["new_sats_clank"] >= 0
        assert data["new_sats_ext"] >= 0

        async with async_session() as db:
            row = await db.get(NostrEvent, eid)
            assert row.sats_clank == 0
            assert (row.sats_ext or 0) == 0


# ---------------------------------------------------------------------------
# S-M2: reply-counts must be one batched query (not N+1)
# ---------------------------------------------------------------------------

class TestReplyCountsM2:
    """M2: POST /events/reply-counts must not issue one SQL query per event_id."""

    @pytest.mark.asyncio
    async def test_m2_counts_match_replies(self, client):
        """Functional: batch counts equal per-parent reply totals; zeros omitted."""
        parents = []
        for i in range(3):
            resp = await client.post("/api/v1/post", json={"content": f"m2 parent {i}"})
            assert resp.status_code == 200
            parents.append(resp.json()["event"]["id"])

        for i in range(2):
            r = await client.post("/api/v1/post", json={
                "content": f"reply to p0 #{i}", "reply_to": parents[0],
            })
            assert r.status_code == 200
        r = await client.post("/api/v1/post", json={
            "content": "reply to p1 #0", "reply_to": parents[1],
        })
        assert r.status_code == 200
        # parents[2] has zero replies

        orphan = "aa" * 32  # valid hex, no replies
        resp = await client.post(
            "/api/v1/events/reply-counts",
            json={"event_ids": parents + [orphan]},
        )
        assert resp.status_code == 200
        counts = resp.json()["counts"]
        assert counts[parents[0]] == 2
        assert counts[parents[1]] == 1
        assert parents[2] not in counts
        assert orphan not in counts

    @pytest.mark.asyncio
    async def test_m2_single_sql_execute(self, client):
        """Adversarial DoS guard: N event_ids must not yield N SQL executes."""
        from sqlalchemy.ext.asyncio import AsyncSession

        parents = []
        for i in range(5):
            resp = await client.post("/api/v1/post", json={"content": f"m2 q parent {i}"})
            assert resp.status_code == 200
            pid = resp.json()["event"]["id"]
            parents.append(pid)
            await client.post("/api/v1/post", json={
                "content": f"reply {i}", "reply_to": pid,
            })

        execute_calls = {"n": 0}
        orig_execute = AsyncSession.execute

        async def counting_execute(self, *args, **kwargs):
            execute_calls["n"] += 1
            return await orig_execute(self, *args, **kwargs)

        with patch.object(AsyncSession, "execute", counting_execute):
            resp = await client.post(
                "/api/v1/events/reply-counts",
                json={"event_ids": parents},
            )

        assert resp.status_code == 200
        assert resp.json()["counts"][parents[0]] == 1
        # Pre-fix: 5 queries (N+1). Post-fix: exactly one SELECT.
        assert execute_calls["n"] == 1, (
            f"expected 1 SQL execute for batch reply-counts, got {execute_calls['n']}"
        )

    @pytest.mark.asyncio
    async def test_m2_rejects_over_200(self, client):
        ids = [f"{i:064x}" for i in range(201)]
        resp = await client.post(
            "/api/v1/events/reply-counts",
            json={"event_ids": ids},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_m2_rejects_non_list(self, client):
        resp = await client.post(
            "/api/v1/events/reply-counts",
            json={"event_ids": "not-a-list"},
        )
        assert resp.status_code == 400

    def test_m2_source_uses_group_by_or_single_select(self):
        """Source must batch (GROUP BY / single select), not per-id execute loop."""
        src = (Path(__file__).resolve().parents[1] / "app" / "api_v1.py").read_text()
        # Locate reply_counts handler body (until next route decorator)
        start = src.index("async def reply_counts")
        end = src.index("@router.", start + 1)
        body = src[start:end]
        assert "for eid in event_ids:" not in body or "db.execute" not in body.split("for eid in event_ids:")[1].split("\n    return")[0]
        # Prefer explicit batch markers
        assert (
            "group_by" in body.lower()
            or "GROUP BY" in body
            or "or_(" in body
            or "func.sum" in body
        )


# ---------------------------------------------------------------------------
# S-M2a: reply-counts event_ids must be 64 hex before LIKE
# ---------------------------------------------------------------------------

class TestReplyCountsM2a:
    """M2a: wildcards in event_ids must not reach tags.contains LIKE (same class as M3)."""

    @pytest.mark.asyncio
    async def test_m2a_percent_wildcard_rejected(self, client):
        resp = await client.post(
            "/api/v1/events/reply-counts",
            json={"event_ids": ["%"]},
        )
        assert resp.status_code == 400
        detail = resp.json().get("detail", "").lower()
        assert "event" in detail or "hex" in detail or "id" in detail

    @pytest.mark.asyncio
    async def test_m2a_underscore_wildcard_rejected(self, client):
        bad = "a" * 63 + "_"  # 64 chars but not hex
        resp = await client.post(
            "/api/v1/events/reply-counts",
            json={"event_ids": [bad]},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_m2a_mixed_valid_and_wildcard_rejected_no_sql(self, client):
        """Any invalid id → 400 before SQL; LIKE must not see %/_."""
        from sqlalchemy.ext.asyncio import AsyncSession

        good = "ab" * 32
        execute_calls = {"n": 0, "sql": []}
        orig_execute = AsyncSession.execute

        async def counting_execute(self, *args, **kwargs):
            execute_calls["n"] += 1
            execute_calls["sql"].append(str(args[0]) if args else "")
            return await orig_execute(self, *args, **kwargs)

        with patch.object(AsyncSession, "execute", counting_execute):
            resp = await client.post(
                "/api/v1/events/reply-counts",
                json={"event_ids": [good, "%", "aa" * 32]},
            )

        assert resp.status_code == 400
        assert execute_calls["n"] == 0, (
            f"invalid event_ids must not reach SQL (got {execute_calls['n']} executes)"
        )

    @pytest.mark.asyncio
    async def test_m2a_valid_hex_still_ok(self, client):
        parent_resp = await client.post("/api/v1/post", json={"content": "m2a parent"})
        assert parent_resp.status_code == 200
        parent = parent_resp.json()["event"]["id"]
        await client.post("/api/v1/post", json={"content": "m2a reply", "reply_to": parent})

        resp = await client.post(
            "/api/v1/events/reply-counts",
            json={"event_ids": [parent]},
        )
        assert resp.status_code == 200
        assert resp.json()["counts"][parent] == 1

    def test_m2a_source_gates_with_event_id_re(self):
        src = (Path(__file__).resolve().parents[1] / "app" / "api_v1.py").read_text()
        start = src.index("async def reply_counts")
        end = src.index("@router.", start + 1)
        body = src[start:end]
        assert "_EVENT_ID_RE.fullmatch" in body
        assert "tags.contains" in body
        # Gate must appear before any tags.contains construction
        gate_pos = body.index("_EVENT_ID_RE.fullmatch")
        contains_pos = body.index("tags.contains")
        assert gate_pos < contains_pos


# ---------------------------------------------------------------------------
# S-M5: Per-connection WebSocket message rate limiting
# ---------------------------------------------------------------------------

class TestWsMsgRateLimitM5:
    """M5: a single WS connection may not flood messages; abusers are disconnected."""

    def test_m5_connection_allows_under_limit(self, monkeypatch):
        from app import config
        from app.relay import Connection

        monkeypatch.setattr(config, "WS_MSG_RATE_LIMIT", 5)
        monkeypatch.setattr(config, "WS_MSG_RATE_WINDOW", 1.0)
        conn = Connection(ws=None)
        t0 = 1000.0
        for i in range(5):
            assert conn.allow_message(now=t0 + i * 0.01) is True

    def test_m5_connection_rejects_over_limit(self, monkeypatch):
        from app import config
        from app.relay import Connection

        monkeypatch.setattr(config, "WS_MSG_RATE_LIMIT", 5)
        monkeypatch.setattr(config, "WS_MSG_RATE_WINDOW", 1.0)
        conn = Connection(ws=None)
        t0 = 1000.0
        for i in range(5):
            assert conn.allow_message(now=t0 + i * 0.01) is True
        assert conn.allow_message(now=t0 + 0.05) is False

    def test_m5_window_expiry_resets_budget(self, monkeypatch):
        from app import config
        from app.relay import Connection

        monkeypatch.setattr(config, "WS_MSG_RATE_LIMIT", 3)
        monkeypatch.setattr(config, "WS_MSG_RATE_WINDOW", 1.0)
        conn = Connection(ws=None)
        t0 = 1000.0
        for i in range(3):
            assert conn.allow_message(now=t0) is True
        assert conn.allow_message(now=t0 + 0.5) is False
        # After window elapses, budget recovers
        assert conn.allow_message(now=t0 + 1.01) is True

    def test_m5_flood_disconnects_websocket(self, client, monkeypatch):
        """Exceeding the per-connection limit closes the socket (policy violation)."""
        from starlette.testclient import TestClient
        from starlette.websockets import WebSocketDisconnect
        from app import config
        from app.main import app

        monkeypatch.setattr(config, "WS_MSG_RATE_LIMIT", 5)
        monkeypatch.setattr(config, "WS_MSG_RATE_WINDOW", 1.0)

        with TestClient(app) as tc:
            with tc.websocket_connect("/") as ws:
                ws.receive_json()  # AUTH challenge
                disconnected = False
                close_code = None
                for i in range(20):
                    try:
                        ws.send_json(["REQ", f"m5-{i}", {"kinds": [1], "limit": 1}])
                        # Drain until EOSE (or CLOSED); do not block forever after EOSE
                        while True:
                            msg = ws.receive_json()
                            if msg[0] in ("EOSE", "CLOSED"):
                                break
                    except WebSocketDisconnect as e:
                        disconnected = True
                        close_code = getattr(e, "code", None)
                        break
                assert disconnected, "abusive connection must be disconnected"
                assert i >= 5, f"should disconnect after limit, got i={i}"
                if close_code is not None:
                    assert close_code == 1008

    def test_m5_source_checks_rate_in_ws_loop(self):
        """websocket_relay must call allow_message (or equivalent) before handle_message."""
        src = (Path(__file__).resolve().parents[1] / "app" / "main.py").read_text()
        start = src.index("async def websocket_relay")
        end = src.index("\n@", start + 1) if "\n@" in src[start:] else len(src)
        # Find end of function more reliably
        body = src[start:start + 800]
        assert "allow_message" in body
        assert "handle_message" in body
        assert body.index("allow_message") < body.index("handle_message")


# ---------------------------------------------------------------------------
# S-M4: CSP script-src without unsafe-inline
# ---------------------------------------------------------------------------

class TestCspM4:
    """M4: remove script-src 'unsafe-inline'; externalize page JS; no inline handlers."""

    @pytest.mark.asyncio
    async def test_m4_csp_script_src_has_no_unsafe_inline(self, client):
        """CSP on HTML responses must not allow 'unsafe-inline' in script-src."""
        resp = await client.get("/")
        assert resp.status_code == 200
        csp = resp.headers.get("content-security-policy", "")
        assert "script-src" in csp
        # Isolate script-src directive (CSP directives are ';'-separated)
        script_src = ""
        for part in csp.split(";"):
            part = part.strip()
            if part.startswith("script-src"):
                script_src = part
                break
        assert script_src, f"no script-src in CSP: {csp!r}"
        assert "'unsafe-inline'" not in script_src, (
            f"script-src still allows unsafe-inline: {script_src!r}"
        )
        # 'self' + known CDNs remain
        assert "'self'" in script_src
        assert "cdn.tailwindcss.com" in script_src
        assert "cdn.jsdelivr.net" in script_src
        assert "esm.sh" in script_src

    @pytest.mark.asyncio
    async def test_m4_csp_still_on_api_and_profile(self, client):
        """CSP applies site-wide; profile + health also lack script-src unsafe-inline."""
        for path in ("/health", "/profile"):
            resp = await client.get(path)
            assert resp.status_code == 200
            csp = resp.headers.get("content-security-policy", "")
            script_src = next(
                (p.strip() for p in csp.split(";") if p.strip().startswith("script-src")),
                "",
            )
            assert script_src and "'unsafe-inline'" not in script_src, path

    def test_m4_html_has_no_inline_script_bodies(self):
        """index/profile HTML may only load scripts via src= (no inline bodies)."""
        import re

        for name in ("index.html", "profile.html"):
            html = (_STATIC / name).read_text()
            # Strip comments
            html_nc = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
            for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html_nc, re.DOTALL | re.I):
                attrs, body = m.group(1), m.group(2)
                assert body.strip() == "", (
                    f"{name}: inline script body not allowed under CSP without "
                    f"unsafe-inline; attrs={attrs!r} body_preview={body.strip()[:80]!r}"
                )
                assert re.search(r"\bsrc\s*=", attrs, re.I), (
                    f"{name}: script tag missing src= : {attrs!r}"
                )

    def test_m4_page_js_externalized(self):
        """Page logic lives in external /static/*.js files referenced by HTML."""
        for page, js_name in (("index.html", "index.js"), ("profile.html", "profile.js")):
            html = (_STATIC / page).read_text()
            assert (_STATIC / js_name).is_file(), f"missing {js_name}"
            assert f"/static/{js_name}" in html, f"{page} must load /static/{js_name}"
        # Shared bitcoin-connect / noble crypto module
        assert (_STATIC / "bc-crypto.js").is_file()
        for page in ("index.html", "profile.html"):
            html = (_STATIC / page).read_text()
            assert "/static/bc-crypto.js" in html

    def test_m4_no_inline_event_handlers_in_templates(self):
        """onclick/onerror/etc. are blocked without unsafe-inline — use data-action."""
        import re

        handler_re = re.compile(
            # HTML attrs / template attrs — not JS property assigns like el.onclick =
            r"(?<![\w.])on(?:click|error|load|submit|change|input|keyup|keydown)\s*=",
            re.I,
        )
        paths = list(_STATIC.glob("*.html")) + list(_STATIC.glob("*.js"))
        assert paths, "no static html/js to scan"
        hits = []
        for path in paths:
            text = path.read_text()
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("<!--"):
                    continue
                if handler_re.search(line):
                    hits.append(f"{path.name}:{i}: {stripped[:100]}")
        assert not hits, "inline event handlers forbidden under M4:\n" + "\n".join(hits[:20])

    def test_m4_note_cards_use_data_action_not_onclick(self):
        """Dynamic note UI must wire actions via data-* + delegation, not onclick."""
        index_js = (_STATIC / "index.js").read_text()
        assert "function renderNoteCard" in index_js
        fn = index_js.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert "onclick=" not in fn
        assert "onerror=" not in fn
        assert "data-action=" in fn or "data-action =" in fn
        # Reply needs a name that may contain apostrophes — attr-escaped, not jsStr/onclick
        assert "data-name=" in fn or "data-name =" in fn
        assert "esc(" in fn  # HTML-escape attribute values

    def test_m4_data_name_preserves_apostrophe_via_html_attr(self):
        """Adversarial: O'Brien in data-name survives HTML parse (L4 goal under M4)."""
        import html.parser

        name = "O'Brien"
        # Mimic esc() for text nodes / attrs (entities)
        from html import escape as html_escape

        escaped = html_escape(name, quote=True)
        fragment = f'<button data-action="reply" data-name="{escaped}">reply</button>'

        class _Attr(html.parser.HTMLParser):
            def __init__(self):
                super().__init__()
                self.name = None

            def handle_starttag(self, tag, attrs):
                d = dict(attrs)
                if "data-name" in d:
                    self.name = d["data-name"]

        p = _Attr()
        p.feed(fragment)
        assert p.name == name, f"apostrophe lost in data-name: {p.name!r}"


# ---------------------------------------------------------------------------
# S-L2: Sanitize error details (no internals in 4xx/5xx bodies)
# ---------------------------------------------------------------------------

class TestErrorSanitizeL2:
    """L2: 5xx (and unhandled) responses must not echo exception/SQL/path internals."""

    _LEAK = (
        "SQLAlchemy OperationalError: /home/rob/Dev/clankfeed/db/relay.db locked"
    )

    @pytest.mark.asyncio
    async def test_l2_http_500_leaky_detail_sanitized(self, client):
        """HTTPException(500, detail=<internals>) must not return the leaky detail."""
        from fastapi import HTTPException
        from fastapi.routing import APIRoute

        from app.main import app

        async def leaky_health():
            raise HTTPException(status_code=500, detail=self._LEAK)

        route = next(
            r for r in app.routes
            if isinstance(r, APIRoute) and r.path == "/health"
        )
        orig_ep, orig_call = route.endpoint, route.dependant.call
        route.endpoint = leaky_health
        route.dependant.call = leaky_health
        try:
            resp = await client.get("/health")
            assert resp.status_code == 500
            body = resp.text
            assert self._LEAK not in body
            assert "/home/rob" not in body
            assert "SQLAlchemy" not in body
            assert "relay.db" not in body
            data = resp.json()
            assert data.get("detail") == "Internal server error"
        finally:
            route.endpoint = orig_ep
            route.dependant.call = orig_call

    @pytest.mark.asyncio
    async def test_l2_starlette_http_500_leaky_detail_sanitized(self, client):
        """Starlette HTTPException(500) must also be sanitized (not only FastAPI subclass).

        Registering the L2 handler only on fastapi.HTTPException leaves
        starlette.exceptions.HTTPException on the default handler, which echoes
        detail verbatim — adversarial path for 6.19.
        """
        from fastapi.routing import APIRoute
        from starlette.exceptions import HTTPException as StarletteHTTPException

        from app.main import app

        async def leaky_health():
            raise StarletteHTTPException(status_code=500, detail=self._LEAK)

        route = next(
            r for r in app.routes
            if isinstance(r, APIRoute) and r.path == "/health"
        )
        orig_ep, orig_call = route.endpoint, route.dependant.call
        route.endpoint = leaky_health
        route.dependant.call = leaky_health
        try:
            resp = await client.get("/health")
            assert resp.status_code == 500
            body = resp.text
            assert self._LEAK not in body
            assert "/home/rob" not in body
            assert "SQLAlchemy" not in body
            assert "relay.db" not in body
            data = resp.json()
            assert data.get("detail") == "Internal server error"
        finally:
            route.endpoint = orig_ep
            route.dependant.call = orig_call

    @pytest.mark.asyncio
    async def test_l2_unhandled_exception_no_internals(self, client):
        """Unhandled Exception → 500 JSON without exception message / paths."""
        from fastapi.routing import APIRoute
        from httpx import ASGITransport, AsyncClient

        from app.main import app

        async def boom_health():
            raise RuntimeError("LEAKED_INTERNAL_/home/rob/secret.db traceback")

        route = next(
            r for r in app.routes
            if isinstance(r, APIRoute) and r.path == "/health"
        )
        orig_ep, orig_call = route.endpoint, route.dependant.call
        route.endpoint = boom_health
        route.dependant.call = boom_health
        try:
            # Unhandled exceptions re-raise under default ASGITransport; disable that.
            transport = ASGITransport(app=app, raise_app_exceptions=False)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                headers={"X-Requested-With": "XMLHttpRequest"},
            ) as c:
                resp = await c.get("/health")
            assert resp.status_code == 500
            body = resp.text
            assert "LEAKED_INTERNAL_" not in body
            assert "/home/rob" not in body
            assert "traceback" not in body.lower()
            data = resp.json()
            assert data.get("detail") == "Internal server error"
        finally:
            route.endpoint = orig_ep
            route.dependant.call = orig_call

    @pytest.mark.asyncio
    async def test_l2_4xx_intentional_detail_preserved(self, client):
        """Adversarial: intentional 4xx client messages must still reach the client."""
        resp = await client.post(
            "/api/v1/post",
            json={},  # missing content
        )
        assert resp.status_code == 400
        assert resp.json().get("detail") == "Content is required"

    def test_l2_client_safe_detail_unit(self):
        """Unit: 5xx strips internals; allowlisted 502 kept; 4xx passthrough."""
        from app.main import client_safe_detail

        assert client_safe_detail(500, self._LEAK) == "Internal server error"
        assert client_safe_detail(502, "Payment service unavailable") == (
            "Payment service unavailable"
        )
        assert client_safe_detail(400, "Content is required") == "Content is required"
        assert client_safe_detail(500, None) == "Internal server error"


# ---------------------------------------------------------------------------
# S-L1: Replace deprecated datetime.utcnow() with datetime.now(timezone.utc)
# ---------------------------------------------------------------------------

class TestUtcnowL1:
    """L1: app code must not call datetime.utcnow(); use timezone-aware UTC."""

    _APP_FILES = (
        "app/relay.py",
        "app/payment.py",
        "app/api_v1.py",
        "app/models.py",
        "app/main.py",
    )

    def test_l1_no_utcnow_in_app_sources(self):
        """Adversarial source scan: utcnow must be absent from production modules."""
        root = Path(__file__).resolve().parents[1]
        offenders = []
        for rel in self._APP_FILES:
            text = (root / rel).read_text(encoding="utf-8")
            if "utcnow" in text:
                offenders.append(rel)
        assert offenders == [], f"utcnow still present in: {offenders}"

    def test_l1_model_defaults_use_aware_now(self):
        """Model DateTime defaults must call datetime.now(timezone.utc), not utcnow."""
        import re
        from datetime import datetime, timezone

        text = (Path(__file__).resolve().parents[1] / "app/models.py").read_text(
            encoding="utf-8"
        )
        assert "utcnow" not in text
        defaults = re.findall(
            r"default=lambda:\s*datetime\.now\(timezone\.utc\)",
            text,
        )
        assert len(defaults) >= 5, (
            f"expected ≥5 aware DateTime defaults in models.py, found {len(defaults)}"
        )
        # Callable itself must return aware UTC (pre-persist; SQLite may strip on store)
        value = datetime.now(timezone.utc)
        assert value.tzinfo is not None
        assert value.utcoffset().total_seconds() == 0

    @pytest.mark.asyncio
    async def test_l1_store_pending_no_utcnow_and_defaults_fire(self, client):
        """store_pending_event + model inserts must not emit utcnow DeprecationWarning."""
        import warnings

        from app.database import async_session
        from app.models import Account, ConsumedPayment, NostrEvent, PendingEvent, Vote
        from app.relay import store_pending_event

        event = _make_event("l1-defaults")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            async with async_session() as db:
                token = await store_pending_event(db, event, amount_sats=1)
                pending = await db.get(PendingEvent, token)
                assert pending is not None
                assert pending.created_at is not None
                assert pending.expires_at is not None

                acct = Account(id="k" * 64, balance_sats=0)
                vote = Vote(
                    id="v" * 64,
                    event_id="e" * 64,
                    pubkey="p" * 64,
                    direction=1,
                    payment_id="pay1",
                )
                consumed = ConsumedPayment(payment_hash="h" * 64)
                note = NostrEvent(
                    id=event["id"],
                    pubkey=event["pubkey"],
                    created_at=event["created_at"],
                    kind=event["kind"],
                    tags="[]",
                    content=event["content"],
                    sig=event["sig"],
                )
                db.add_all([acct, vote, consumed, note])
                await db.commit()
                await db.refresh(acct)
                await db.refresh(vote)
                await db.refresh(consumed)
                await db.refresh(note)
                assert acct.created_at is not None
                assert vote.created_at is not None
                assert consumed.consumed_at is not None
                assert note.stored_at is not None

            utcnow_warns = [
                w for w in caught
                if issubclass(w.category, DeprecationWarning)
                and "utcnow" in str(w.message).lower()
            ]
            assert utcnow_warns == [], f"utcnow DeprecationWarning: {utcnow_warns}"

    @pytest.mark.asyncio
    async def test_l1_pending_expiry_compare_works_with_aware_now(self, client):
        """Expired pending token must 404; live token must not — no naive/aware crash."""
        import warnings
        from datetime import datetime, timedelta, timezone

        from app.database import async_session
        from app.models import PendingEvent
        from app.relay import store_pending_event

        event = _make_event("l1-expiry")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            async with async_session() as db:
                token = await store_pending_event(db, event, amount_sats=21)
            utcnow_warns = [
                w for w in caught
                if issubclass(w.category, DeprecationWarning)
                and "utcnow" in str(w.message).lower()
            ]
            assert utcnow_warns == [], f"utcnow DeprecationWarning: {utcnow_warns}"

        # Still-valid pending: GET /pay may 402 or return challenge, not 404-expired
        resp = await client.get(f"/pay?token={token}")
        assert resp.status_code != 404

        # Force expiry and assert 404 without TypeError on aware/naive compare
        async with async_session() as db:
            pending = await db.get(PendingEvent, token)
            pending.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await db.commit()

        resp = await client.get(f"/pay?token={token}")
        assert resp.status_code == 404
        assert "expired" in resp.json().get("detail", "").lower() or "not found" in (
            resp.json().get("detail", "").lower()
        )
