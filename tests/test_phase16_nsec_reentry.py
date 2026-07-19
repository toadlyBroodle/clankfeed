"""Phase 16.9 + 16.6: profile nsec paste/copy/bech32 + post-form re-entry when !canSign.

16.9 — /profile login must accept nsec1 bech32 (not only 64-hex), paste into #login-nsec
must work, and [copy] on privkeys must succeed even when navigator.clipboard is denied
(secure-context / permission fallback).

16.6 — When authMode==='nsec' but userNsec was scrubbed (e.g. /profile→/ nav), the post
form must prompt re-entry and must NOT fall through to relay-signed /api/v1/post with a
logged-in display_name façade. True anon remains relay-signed.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


def _auth() -> str:
    return (STATIC / "nostr-auth.js").read_text()


def _profile_js() -> str:
    return (STATIC / "profile.js").read_text()


def _profile_html() -> str:
    return (STATIC / "profile.html").read_text()


def _profile() -> str:
    return _profile_js() + "\n" + _profile_html()


def _index() -> str:
    return (STATIC / "index.js").read_text()


def _bc() -> str:
    return (STATIC / "bc-crypto.js").read_text()


# ---------------------------------------------------------------------------
# 16.9 — nsec bech32 login + clipboard paste/copy
# ---------------------------------------------------------------------------


class TestNsecBech32Login169:
    """Login must normalize nsec1… → 64-hex before derivePubkey / setAuthState."""

    def test_normalize_nsec_helper_exists(self):
        auth = _auth()
        assert "function normalizeNsec" in auth or "function nsecToHex" in auth
        # Must mention bech32 / nsec1 decoding path
        assert "nsec1" in auth.lower() or "bech32" in auth.lower()

    def test_login_with_nsec_uses_normalizer(self):
        profile = _profile_js()
        assert "loginWithNsec" in profile
        fn = profile.split("function loginWithNsec", 1)[1].split("\nasync function ", 1)[0]
        # Must not only regex-check 64-hex — must call normalizer
        assert "normalizeNsec" in fn or "nsecToHex" in fn
        # Hex-only gate alone is the bug
        assert "/^[0-9a-f]{64}$/i.test(input)" not in fn or "normalizeNsec" in fn or "nsecToHex" in fn

    def test_login_rejects_garbage_not_hex_only_message(self):
        """Error copy must not claim 'must be 64-char hex' exclusively (bech32 is valid)."""
        profile = _profile_js()
        fn = profile.split("function loginWithNsec", 1)[1].split("\nasync function ", 1)[0]
        assert "must be 64-char hex" not in fn

    def test_bc_crypto_exposes_bech32_or_nip19(self):
        """Decode must come from a real bech32 lib (producer), not a hand-rolled stub."""
        bc = _bc()
        assert "bech32" in bc.lower() or "nip19" in bc.lower() or "@scure/base" in bc


class TestClipboardCopyFallback169:
    """[copy] must work when navigator.clipboard.writeText rejects / is missing."""

    def test_copy_to_clipboard_helper_exists(self):
        auth = _auth()
        assert "function copyToClipboard" in auth
        # Fallback path required
        assert "execCommand" in auth
        assert "clipboard" in auth.lower()

    def test_profile_copy_buttons_use_helper(self):
        profile = _profile_js()
        # Account key copy + new-identity copy must not bare-call navigator.clipboard alone
        assert "copyToClipboard" in profile
        # Bare writeText without helper is the no-op bug on insecure contexts
        copy_region = profile
        # Every writeText should go through copyToClipboard (helper may still reference clipboard)
        bare = [
            line
            for line in copy_region.splitlines()
            if "navigator.clipboard.writeText" in line and "copyToClipboard" not in line
        ]
        assert bare == [], f"bare clipboard.writeText still present: {bare}"

    def test_login_input_paste_friendly(self):
        """#login-nsec must accept paste (text or password with autocomplete off, no paste block)."""
        html = _profile_html()
        js = _profile_js()
        assert 'id="login-nsec"' in html
        # Must not preventDefault on paste
        assert "preventDefault" not in js or "paste" not in js.lower()
        login_block = html[html.find("login-nsec") - 200 : html.find("login-nsec") + 200]
        # Placeholder / label should mention nsec or bech32-friendly paste
        assert "nsec" in login_block.lower() or "private key" in login_block.lower()
        # autocomplete off helps paste on some browsers; type=text preferred for paste UX
        assert (
            'autocomplete="off"' in login_block
            or 'type="text"' in login_block
            or "paste" in js.lower()
        )


# ---------------------------------------------------------------------------
# 16.6 — stale nsec session must not silent-relay-sign
# ---------------------------------------------------------------------------


class TestStaleNsecPostReentry166:
    """isLoggedIn && !canSign (nsec scrubbed) → prompt re-entry, no submitRelaySignedPost."""

    def test_post_form_checks_stale_nsec_before_relay(self):
        index = _index()
        # Extract post-form submit handler region
        assert "post-form" in index
        region = index.split("post-form", 1)[1][:1200]
        assert "canSign()" in region
        # Stale nsec gate (mirror submitZap)
        assert "authMode" in region or "userNsec" in region
        assert "userNsec" in region
        # Must mention re-enter / profile prompt
        assert "/profile" in region or "Re-enter" in region or "re-enter" in region

    def test_stale_nsec_does_not_call_relay_signed(self):
        """When authMode==='nsec' && !userNsec, must return before submitRelaySignedPost."""
        index = _index()
        # Find the submit listener body between canSign branch and submitRelaySignedPost
        assert "submitRelaySignedPost" in index
        # The gate must sit BETWEEN canSign false and relay call
        form_handler = index.split("addEventListener('submit'", 1)[1].split(
            "async function submitClientSignedPost", 1
        )[0]
        assert "userNsec" in form_handler
        # Pattern: if stale → message + return; else relay
        assert "return" in form_handler
        # Must not go straight from !canSign() to submitRelaySignedPost without nsec check
        after_cansign = form_handler.split("canSign()", 1)[1]
        # Before submitRelaySignedPost there must be an authMode/userNsec stale check
        before_relay = after_cansign.split("submitRelaySignedPost", 1)[0]
        assert "userNsec" in before_relay
        assert "nsec" in before_relay

    def test_true_anon_still_uses_relay_post(self):
        """Unauthenticated users (no authMode) still call submitRelaySignedPost."""
        index = _index()
        assert "submitRelaySignedPost" in index
        assert "/api/v1/post" in index

    def test_submit_zap_reentry_message_still_present(self):
        """Invariant: zap path re-entry prompt unchanged."""
        index = _index()
        fn = index.split("function submitZap", 1)[1].split("\nasync function ", 1)[0]
        assert "canSign" in fn
        assert "Re-enter" in fn or "re-enter" in fn or "/profile" in fn


# ---------------------------------------------------------------------------
# Adversarial: known nsec1 vector decodes to expected hex (browser eval)
# ---------------------------------------------------------------------------


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(base: str, timeout: float = 15.0) -> None:
    import time
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.15)
    raise RuntimeError(f"server not healthy: {base}")


@pytest.fixture
def live_server(tmp_path):
    import os
    import subprocess
    import sys

    db_path = tmp_path / "p16.db"
    port = _free_port()
    env = os.environ.copy()
    env.update(
        {
            "AUTH_ROOT_KEY": "test-mode",
            "EXTERNAL_INGEST": "false",
            "OUTBOX_ENABLED": "false",
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
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _encode_nsec(priv: bytes) -> str:
    """Minimal bech32 encode for HRP 'nsec' (NIP-19). Test helper only."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def _polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                chk ^= gen[i] if ((b >> i) & 1) else 0
        return chk

    def _hrp_expand(hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def _convertbits(data, frombits, tobits, pad=True):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for value in data:
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)
        return ret

    hrp = "nsec"
    data = _convertbits(priv, 8, 5)
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(charset[d] for d in data + checksum)


class TestNsecDecodeLive169:
    """Exercise normalizeNsec against a known NIP-19 vector in Chromium."""

    @pytest.mark.asyncio
    async def test_normalize_nsec_decodes_bech32_in_browser(self, live_server):
        """Producer shape: @scure/base bech32 → 32-byte hex privkey.

        Avoid page.wait_for_function — CSP script-src lacks unsafe-eval.
        """
        from playwright.async_api import async_playwright

        priv_hex = "11" * 32
        nsec = _encode_nsec(bytes.fromhex(priv_hex))
        base = live_server
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(f"{base}/profile", wait_until="domcontentloaded", timeout=30_000)
            await page.wait_for_selector("#login-nsec", timeout=10_000)
            ready = False
            for _ in range(100):
                ready = await page.evaluate(
                    "() => !!(window.__nostrCrypto && typeof normalizeNsec === 'function')"
                )
                if ready:
                    break
                import asyncio

                await asyncio.sleep(0.1)
            assert ready, "normalizeNsec / __nostrCrypto not ready"
            result = await page.evaluate(
                """([nsec, hex]) => {
                  return { a: normalizeNsec(nsec), b: normalizeNsec(hex) };
                }""",
                [nsec, priv_hex],
            )
            await browser.close()
        assert result["a"].lower() == priv_hex
        assert result["b"].lower() == priv_hex
