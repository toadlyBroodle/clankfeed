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
        index = (_STATIC / "index.html").read_text()
        # showVotePayment must delegate to the safe widget, not build its own HTML
        assert "function showVotePayment" in index
        vote_fn = index.split("function showVotePayment", 1)[1].split("\nfunction ", 1)[0]
        assert "showPaymentWidget" in vote_fn
        assert "innerHTML" not in vote_fn

    def test_m7_no_showApiKey_innerhtml_path(self):
        """S-M7: showApiKey must not exist; API keys must not be assigned via innerHTML."""
        for path in _STATIC.glob("*.{html,js}"):
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
        """S-L4: dynamic onclick args must use jsStr/JSON.stringify, not '${...}'."""
        index = (_STATIC / "index.html").read_text()
        # Vulnerable patterns (single-quoted JS string interp inside double-quoted attr)
        assert "onclick=\"startReply('${n.id}', '${esc(displayName || pk)}')\"" not in index
        assert "onclick=\"startVote('${n.id}', 1)\"" not in index
        assert "onclick=\"startVote('${n.id}', -1)\"" not in index
        assert "onclick=\"toggleReplies('${n.id}')\"" not in index
        assert "onclick=\"submitVote('${n.id}')\"" not in index
        assert "onclick=\"cancelVote('${n.id}')\"" not in index
        assert "onclick=\"scrollToNote('${parentId}')\"" not in index
        # Handlers must go through jsStr(...) — do not lock a single-quoted attr form
        # that truncates on apostrophes (see test_l4_html_attr_preserves_apostrophe_name).
        assert "jsStr(n.id)" in index
        assert "jsStr(displayName || pk)" in index
        assert "jsStr(parentId)" in index
        assert "startReply(${jsStr(" in index
        assert "startVote(${jsStr(" in index
        assert "toggleReplies(${jsStr(" in index

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
    """H2: no nsec/API-key in localStorage; NIP-98 login mints httpOnly session."""

    def test_h2_no_auth_secrets_persisted_to_localstorage(self):
        """Client must not write nsec or API keys into localStorage."""
        src = (_STATIC / "nostr-auth.js").read_text()
        # Forbidden persistence of signing secrets / legacy API keys
        assert "localStorage.setItem('cf_nsec'" not in src
        assert 'localStorage.setItem("cf_nsec"' not in src
        assert "localStorage.setItem('clankfeed_api_key'" not in src
        assert 'localStorage.setItem("clankfeed_api_key"' not in src
        # setAuthState must keep nsec in memory only (assign userNsec, no setItem for it)
        assert "function setAuthState" in src
        body = src.split("function setAuthState", 1)[1].split("\nfunction ", 1)[0]
        assert "userNsec" in body
        assert "localStorage.setItem('cf_nsec'" not in body
        assert 'localStorage.setItem("cf_nsec"' not in body

    def test_h2_auth_fetch_sends_credentials(self):
        """authFetch must include cookies so the httpOnly session is sent."""
        src = (_STATIC / "nostr-auth.js").read_text()
        assert "credentials" in src
        assert "'include'" in src or '"include"' in src

    @pytest.mark.asyncio
    async def test_h2_login_sets_httponly_session_cookie(self, client):
        """POST /api/v1/auth/login with NIP-98 sets httpOnly cf_session cookie."""
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        resp = await client.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["pubkey"]  # hex pubkey
        # httpx stores cookies; Set-Cookie must be HttpOnly
        set_cookie = resp.headers.get("set-cookie", "")
        assert "cf_session=" in set_cookie.lower() or "cf_session" in client.cookies
        assert "httponly" in set_cookie.lower()
        assert "cf_session" in client.cookies

    @pytest.mark.asyncio
    async def test_h2_session_cookie_authenticates_without_nip98(self, client):
        """After login, balance endpoint accepts cookie alone (no Authorization)."""
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        login = await client.post("/api/v1/auth/login", headers=headers)
        assert login.status_code == 200
        pubkey = login.json()["pubkey"]

        resp = await client.get("/api/v1/account/balance")  # cookie from client jar
        assert resp.status_code == 200
        body = resp.json()
        assert "balance_sats" in body
        # Session identity is the login pubkey (account.pubkey), not server nostr_pubkey
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["pubkey"] == pubkey
        assert me.json()["auth_method"] == "session"
    @pytest.mark.asyncio
    async def test_h2_logout_clears_session(self, client):
        """POST /api/v1/auth/logout clears cookie; subsequent authed call is 401."""
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        await client.post("/api/v1/auth/login", headers=headers)
        logout = await client.post("/api/v1/auth/logout")
        assert logout.status_code == 200
        set_cookie = logout.headers.get("set-cookie", "")
        # Cleared cookie: Max-Age=0 or empty value
        assert "cf_session" in set_cookie.lower() or "cf_session" not in client.cookies or client.cookies.get("cf_session") in ("", None)

        resp = await client.get("/api/v1/account/balance")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_h2_tampered_session_cookie_rejected(self, client):
        """Adversarial: forged/tampered cf_session must not authenticate."""
        client.cookies.set("cf_session", "deadbeef.9999999999.forgedsignature")
        resp = await client.get("/api/v1/account/balance")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_h2_me_returns_session_pubkey(self, client):
        """GET /api/v1/auth/me returns pubkey when session cookie is valid."""
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        login = await client.post("/api/v1/auth/login", headers=headers)
        pubkey = login.json()["pubkey"]
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["pubkey"] == pubkey


# ---------------------------------------------------------------------------
# S-H2a: Secure flag from request HTTPS (X-Forwarded-Proto / scheme)
# ---------------------------------------------------------------------------

class TestSessionSecureH2a:
    """H2a: cf_session Secure follows request HTTPS, not only BASE_URL wss://."""

    @pytest.mark.asyncio
    async def test_h2a_secure_when_x_forwarded_proto_https(self, client, monkeypatch):
        """Prod-like: BASE_URL is ws://localhost but nginx sends X-Forwarded-Proto: https."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        headers["X-Forwarded-Proto"] = "https"
        resp = await client.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie", "")
        assert "cf_session=" in set_cookie.lower()
        assert "secure" in set_cookie.lower(), (
            "Secure must be set when X-Forwarded-Proto is https even if BASE_URL is ws://; "
            f"got Set-Cookie: {set_cookie!r}"
        )

    @pytest.mark.asyncio
    async def test_h2a_insecure_on_plain_http_without_forwarded(self, client, monkeypatch):
        """Local http://test: no Secure when neither scheme nor X-Forwarded-Proto is https."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        resp = await client.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie", "")
        assert "cf_session=" in set_cookie.lower()
        assert "secure" not in set_cookie.lower(), (
            f"Secure must be absent on plain HTTP; got Set-Cookie: {set_cookie!r}"
        )

    @pytest.mark.asyncio
    async def test_h2a_adversarial_forwarded_http_not_secure(self, client, monkeypatch):
        """Adversarial: X-Forwarded-Proto: http must not mint a Secure cookie."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "wss://clankfeed.com")
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        headers["X-Forwarded-Proto"] = "http"
        resp = await client.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie", "")
        assert "cf_session=" in set_cookie.lower()
        # Request says http — Secure follows the request, not BASE_URL alone
        assert "secure" not in set_cookie.lower(), (
            "X-Forwarded-Proto: http must win over BASE_URL=wss://; "
            f"got Set-Cookie: {set_cookie!r}"
        )

    @pytest.mark.asyncio
    async def test_h2a_logout_secure_matches_forwarded_https(self, client, monkeypatch):
        """Logout delete_cookie must use Secure when clearing over HTTPS (browser match)."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        headers["X-Forwarded-Proto"] = "https"
        await client.post("/api/v1/auth/login", headers=headers)
        logout = await client.post(
            "/api/v1/auth/logout",
            headers={"X-Forwarded-Proto": "https"},
        )
        assert logout.status_code == 200
        set_cookie = logout.headers.get("set-cookie", "")
        assert "cf_session" in set_cookie.lower()
        assert "secure" in set_cookie.lower(), (
            f"logout Clear-Cookie over HTTPS needs Secure; got {set_cookie!r}"
        )


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
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        headers["Origin"] = "http://127.0.0.1:8089"
        resp = await client.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code != 403, (
            "127.0.0.1:8089 is in cors_allow_origins() and must pass OriginCheck "
            f"when BASE_URL is localhost; got {resp.status_code}: {resp.text}"
        )
        assert resp.status_code == 200
        assert "cf_session" in client.cookies or "cf_session" in resp.headers.get("set-cookie", "").lower()

    @pytest.mark.asyncio
    async def test_h4_origincheck_rejects_evil_origin(self, client, monkeypatch):
        """OriginCheck still blocks origins outside cors_allow_origins()."""
        from app import config

        monkeypatch.setattr(config.settings, "BASE_URL", "ws://localhost:8089")
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        headers["Origin"] = "https://evil.example"
        resp = await client.post("/api/v1/auth/login", headers=headers)
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
        headers = _nip98("http://test/api/v1/auth/login", "POST")
        # Ensure no X-Requested-With sneaks in from a default
        headers.pop("X-Requested-With", None)
        from app.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as bare:
            resp = await bare.post("/api/v1/auth/login", headers=headers)
        assert resp.status_code != 403
        assert resp.status_code == 200

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
        index_src = (Path(__file__).resolve().parents[1] / "app" / "static" / "index.html").read_text()
        # Mutating POSTs that skip authFetch must use apiFetch (sets XRW)
        assert "apiFetch" in index_src
        assert "apiFetch('/api/post/confirm'" in index_src or 'apiFetch("/api/post/confirm"' in index_src
        assert "apiFetch(`/api/v1/events/${eventId}/vote/confirm`" in index_src
        # Profile paid-path POSTs (confirm + deposit) must use XRW wrappers (6.6)
        profile_src = (Path(__file__).resolve().parents[1] / "app" / "static" / "profile.html").read_text()
        assert "apiFetch('/api/post/confirm'" in profile_src or 'apiFetch("/api/post/confirm"' in profile_src
        assert "authFetch('/api/v1/account/deposit'" in profile_src or 'authFetch("/api/v1/account/deposit"' in profile_src
        assert (
            "authFetch('/api/v1/account/deposit/confirm'" in profile_src
            or 'authFetch("/api/v1/account/deposit/confirm"' in profile_src
        )
        # Adversarial: bare fetch() on those paths would omit XRW
        assert "fetch('/api/post/confirm'" not in profile_src
        assert 'fetch("/api/post/confirm"' not in profile_src
        assert "fetch('/api/v1/account/deposit'" not in profile_src
        assert "fetch('/api/v1/account/deposit/confirm'" not in profile_src

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
            json={"direction": 1, "amount_sats": 21},
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
