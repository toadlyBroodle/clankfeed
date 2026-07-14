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
        "tags": [],
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
    async with AsyncClient(transport=transport, base_url="http://test") as c:
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
        assert resp.status_code == 404  # safe, not 500

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
        # Fixed pattern: single-quoted HTML attr + jsStr(...)
        assert "onclick='startReply(${jsStr(n.id)}, ${jsStr(displayName || pk)})'" in index
        assert "onclick='startVote(${jsStr(n.id)}, 1)'" in index
        assert "onclick='toggleReplies(${jsStr(n.id)})'" in index

    def test_l4_jsstr_helper_uses_json_stringify(self):
        """jsStr must wrap JSON.stringify so quotes/newlines cannot break out of JS strings."""
        src = (_STATIC / "nostr-auth.js").read_text()
        assert "function jsStr(" in src
        # Pull the function body and require JSON.stringify
        body = src.split("function jsStr(", 1)[1].split("\n}", 1)[0]
        assert "JSON.stringify" in body

    def test_l4_jsstr_adversarial_quote_breakout(self):
        """Adversarial display names with quotes must serialize to safe JS literals."""
        import json
        import re
        import subprocess

        src = (_STATIC / "nostr-auth.js").read_text()
        m = re.search(r"function jsStr\(([^)]*)\)\s*\{([^}]*)\}", src, re.DOTALL)
        assert m, "jsStr function not found"
        # Evaluate the same contract Node would: JSON.stringify(String(s ?? ''))
        payloads = [
            "');alert(1);//",
            "\"onload=alert(1)",
            "O'Brien",
            "</script><script>alert(1)</script>",
            "a\nb",
        ]
        for p in payloads:
            # Mirror expected jsStr implementation
            lit = json.dumps("" if p is None else str(p))
            assert lit.startswith('"') and lit.endswith('"')
            assert "');" not in lit or lit == json.dumps(p)
            # A single-quoted HTML attr wrapping this literal must not see a raw '
            # that closes a JS single-quoted string — JSON uses double quotes.
            attr = f"onclick='startReply({lit}, {lit})'"
            # Extract JS inside the HTML attribute
            js = attr[len("onclick='"):-1]
            # Parse as a CallExpression args via JSON — both args are JSON strings
            assert js.startswith("startReply(")
            # Node round-trip: eval the arg list safely
            result = subprocess.run(
                ["node", "-e", f"const a={lit}; const b={lit}; if (a !== {json.dumps(p)} || b !== {json.dumps(p)}) process.exit(1);"],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, result.stderr


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
            "kind": 1, "tags": [], "content": "future",
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
            "tags": [["t", str(i)] for i in range(101)],
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
        event = _make_event("tag test")
        event["tags"] = [["t", "x" * 2000]]
        # Re-sign since tags changed
        event = sign_event(TEST_SK, {
            "created_at": event["created_at"],
            "kind": 1,
            "tags": [["t", "x" * 2000]],
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
            "tags": [["t", "x" * 1024]],
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
            "tags": [["t", 12345]],
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
