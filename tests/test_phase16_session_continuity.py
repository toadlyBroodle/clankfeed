"""Phase 16.17–16.19: nsec session continuity + profile 402 status + zap null-guard.

16.17 — userNsec was memory-only (H2); localStorage keeps mode+pubkey. Live:
  /profile login → navigate / ⇒ isLoggedIn() && !canSign(); reload /profile shows
  empty #key-priv account façade. Fix: tab-scoped sessionStorage for nsec
  (never localStorage); clear on logout. Acceptance: profile login → home →
  canSign()===true → Post hits POST /api/v1/events with user pubkey; reload
  /profile shows privkey (not empty-key façade).

16.18 — saveProfile leaves #prof-status "Saving..." after 402 opens #pw-widget.
  Set payment-needed / clear status when the widget opens.

16.19 — submitZap does parseInt(amountInput.value) without null-guard → TypeError
  when #vote-amount-${id} is missing.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"

_NSEC_SK = "b" * 64  # distinct from relay a*64


def _auth() -> str:
    return (STATIC / "nostr-auth.js").read_text()


def _profile_js() -> str:
    return (STATIC / "profile.js").read_text()


def _index() -> str:
    return (STATIC / "index.js").read_text()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(base: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.15)
    raise RuntimeError(f"server not healthy: {base}")


def _headed() -> bool:
    return bool(os.environ.get("DISPLAY"))


@pytest.fixture
def live_server(tmp_path):
    db_path = tmp_path / "p1617.db"
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


async def _wait_auth_ready(page, timeout_s: float = 10.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        ready = await page.evaluate(
            "() => !!(window.__nostrCrypto && typeof canSign === 'function'"
            " && typeof setAuthState === 'function')"
        )
        if ready:
            return
        await asyncio.sleep(0.1)
    raise RuntimeError("auth/crypto helpers not ready")


async def _wait_relay_pubkey(page, timeout_s: float = 10.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        if await page.evaluate(
            "() => !!(relayPubkey && relayPubkey.length === 64)"
        ):
            return
        await asyncio.sleep(0.1)
    raise RuntimeError("relayPubkey not loaded from NIP-11")


# ---------------------------------------------------------------------------
# 16.17 — source contracts (sessionStorage, never localStorage)
# ---------------------------------------------------------------------------


class TestNsecSessionStorageSource1617:
    def test_set_auth_state_writes_session_storage_not_local(self):
        auth = _auth()
        body = auth.split("function setAuthState", 1)[1].split("\nfunction ", 1)[0]
        assert "sessionStorage" in body, "setAuthState must persist nsec in sessionStorage"
        assert "localStorage.setItem('cf_nsec'" not in body
        assert 'localStorage.setItem("cf_nsec"' not in body
        # Must actually set a session key for the secret
        assert "sessionStorage.setItem" in body

    def test_init_restores_nsec_from_session_storage(self):
        auth = _auth()
        # Top-level restore (before or near userNsec init)
        assert "sessionStorage.getItem" in auth
        # Restore must not read nsec from localStorage
        assert "localStorage.getItem('cf_nsec')" not in auth
        assert 'localStorage.getItem("cf_nsec")' not in auth

    def test_clear_auth_removes_session_nsec(self):
        auth = _auth()
        body = auth.split("async function clearAuthState", 1)[1].split(
            "\n// ----", 1
        )[0]
        assert "sessionStorage.removeItem" in body

    def test_h2_still_forbids_localstorage_nsec(self):
        """H2 amendment: tab-scoped sessionStorage OK; localStorage still banned."""
        auth = _auth()
        assert "localStorage.setItem('cf_nsec'" not in auth
        assert 'localStorage.setItem("cf_nsec"' not in auth


# ---------------------------------------------------------------------------
# 16.18 — saveProfile status on payment widget
# ---------------------------------------------------------------------------


class TestSaveProfileStatusSource1618:
    def test_save_profile_clears_saving_when_payment_widget_opens(self):
        js = _profile_js()
        fn = js.split("async function saveProfile", 1)[1].split(
            "\nasync function ", 1
        )[0]
        assert "showPaymentWidget" in fn
        assert "else if (data.token)" in fn or "data.token" in fn
        # Only the payment-required branch body (between data.token and showPaymentWidget)
        token_branch = fn.split("data.token", 1)[1].split("showPaymentWidget", 1)[0]
        # Must set #prof-status in THIS branch (not rely on leftover 'Saving...')
        assert "status.textContent" in token_branch, (
            "saveProfile token/402 branch must set #prof-status before showPaymentWidget"
        )
        assert "Saving..." not in token_branch
        # Reject the Saved! line leaking from the prior branch — require pay/invoice/clear
        assigns = [
            line.strip()
            for line in token_branch.splitlines()
            if "status.textContent" in line
        ]
        assert assigns, "expected status.textContent assignment in token branch"
        joined = " ".join(assigns).lower()
        assert "saved!" not in joined
        assert (
            "pay" in joined
            or "invoice" in joined
            or "payment" in joined
            or "=''" in joined.replace(" ", "")
            or '=""' in joined.replace(" ", "")
        ), f"token branch status assigns must be payment-needed/clear; got {assigns}"


# ---------------------------------------------------------------------------
# 16.19 — submitZap null-guard
# ---------------------------------------------------------------------------


class TestSubmitZapNullGuardSource1619:
    def test_submit_zap_null_guards_amount_input(self):
        js = _index()
        fn = js.split("async function submitZap", 1)[1].split(
            "\nasync function ", 1
        )[0]
        # Must not bare-deref .value before a null check
        head = fn.split("canSign", 1)[0] if "canSign" in fn else fn[:400]
        assert "amountInput" in head or "vote-amount" in head
        # Guard pattern: if (!amountInput) or amountInput?. or amountInput &&
        assert (
            "if (!amountInput)" in fn
            or "if (!amountInput)" in head
            or "amountInput?" in fn
            or "amountInput &&" in fn
            or "amountInput == null" in fn
            or "amountInput === null" in fn
        ), "submitZap must null-guard amountInput before .value"


# ---------------------------------------------------------------------------
# 16.17 — live: profile login → home keeps canSign → client-signed post
# ---------------------------------------------------------------------------


class TestNsecSessionContinuityLive1617:
    @pytest.mark.asyncio
    async def test_profile_login_navigate_home_can_sign_and_posts_events(
        self, live_server
    ):
        """Acceptance: /profile nsec login → / → canSign → POST /api/v1/events
        with user pubkey (not relay).
        """
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        user_pk = pubkey_from_privkey(_NSEC_SK)
        relay_pk = pubkey_from_privkey("a" * 64)
        base = live_server
        events_bodies: list[dict] = []
        post_hits: list[str] = []
        alerts: list[str] = []
        content = "p16-17-session-continuity-post"

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            context = await browser.new_context()
            page = await context.new_page()

            async def on_dialog(dialog):
                alerts.append(dialog.message)
                await dialog.accept()

            page.on("dialog", on_dialog)

            async def on_route(route):
                req = route.request
                if "/api/v1/post" in req.url and req.method == "POST":
                    post_hits.append(req.url)
                if "/api/v1/events" in req.url and req.method == "POST":
                    try:
                        events_bodies.append(req.post_data_json or {})
                    except Exception:
                        events_bodies.append({})
                await route.continue_()

            await page.route("**/api/v1/**", on_route)

            await page.goto(
                f"{base}/profile", wait_until="domcontentloaded", timeout=30_000
            )
            await _wait_auth_ready(page)
            await page.fill("#login-nsec", _NSEC_SK)
            await page.click("#btn-login-nsec")
            for _ in range(50):
                if await page.evaluate("() => isLoggedIn() && canSign()"):
                    break
                await asyncio.sleep(0.1)
            assert await page.evaluate("() => canSign()") is True

            # Cross-page navigation must KEEP signing ability (sessionStorage)
            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)
            await _wait_relay_pubkey(page)
            assert await page.evaluate("() => canSign() && authMode === 'nsec'") is True
            # Must not be in localStorage
            assert await page.evaluate(
                "() => localStorage.getItem('cf_nsec') === null"
            ) is True
            assert await page.evaluate(
                "() => !!(sessionStorage.getItem('cf_nsec') || "
                "sessionStorage.getItem('cf_session_nsec'))"
            ) is True

            await page.fill("#post-content", content)
            await page.evaluate(
                "() => document.getElementById('post-form').requestSubmit()"
            )
            for _ in range(80):
                if events_bodies or alerts:
                    break
                await asyncio.sleep(0.1)
            await browser.close()

        assert alerts == [], f"unexpected alerts (should canSign): {alerts}"
        assert post_hits == [], f"must not use relay /api/v1/post: {post_hits}"
        assert events_bodies, "expected POST /api/v1/events"
        req_pk = (events_bodies[0].get("event") or {}).get("pubkey")
        assert req_pk == user_pk, f"expected user pubkey {user_pk}, got {req_pk}"
        assert req_pk != relay_pk

    @pytest.mark.asyncio
    async def test_profile_reload_keeps_privkey_not_empty_facade(self, live_server):
        """Reload /profile after nsec login must show #key-priv filled (not empty)."""
        from playwright.async_api import async_playwright

        base = live_server

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            context = await browser.new_context()
            page = await context.new_page()

            await page.goto(
                f"{base}/profile", wait_until="domcontentloaded", timeout=30_000
            )
            await _wait_auth_ready(page)
            await page.fill("#login-nsec", _NSEC_SK)
            await page.click("#btn-login-nsec")
            for _ in range(50):
                if await page.evaluate("() => canSign()"):
                    break
                await asyncio.sleep(0.1)

            await page.reload(wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)
            for _ in range(50):
                if await page.evaluate("() => canSign()"):
                    break
                await asyncio.sleep(0.1)

            can = await page.evaluate("() => canSign()")
            priv = await page.evaluate(
                "() => (document.getElementById('key-priv') || {}).value || ''"
            )
            account_visible = await page.evaluate(
                "() => !document.getElementById('view-account').classList.contains('hidden')"
            )
            await browser.close()

        assert can is True
        assert account_visible is True
        assert priv == _NSEC_SK, f"expected filled #key-priv, got {priv!r}"

    @pytest.mark.asyncio
    async def test_logout_clears_session_nsec_adversarial(self, live_server):
        """Logout must scrub sessionStorage nsec so a later page cannot canSign."""
        from playwright.async_api import async_playwright

        base = live_server

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            context = await browser.new_context()
            page = await context.new_page()

            await page.goto(
                f"{base}/profile", wait_until="domcontentloaded", timeout=30_000
            )
            await _wait_auth_ready(page)
            await page.fill("#login-nsec", _NSEC_SK)
            await page.click("#btn-login-nsec")
            for _ in range(50):
                if await page.evaluate("() => canSign()"):
                    break
                await asyncio.sleep(0.1)

            await page.click("#btn-logout")
            for _ in range(40):
                if await page.evaluate("() => !isLoggedIn()"):
                    break
                await asyncio.sleep(0.1)

            sess = await page.evaluate(
                """() => ({
                  cf_nsec: sessionStorage.getItem('cf_nsec'),
                  cf_session_nsec: sessionStorage.getItem('cf_session_nsec'),
                  local: localStorage.getItem('cf_nsec'),
                  can: typeof canSign === 'function' ? canSign() : null,
                })"""
            )
            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)
            can_home = await page.evaluate("() => canSign()")
            await browser.close()

        assert sess["local"] is None
        assert sess["cf_nsec"] is None and sess["cf_session_nsec"] is None
        assert sess["can"] is False
        assert can_home is False


# ---------------------------------------------------------------------------
# 16.18 — live: 402 opens widget and clears Saving...
# ---------------------------------------------------------------------------


class TestSaveProfileStatusLive1618:
    @pytest.mark.asyncio
    async def test_save_profile_402_sets_payment_status_not_saving(self, live_server):
        """When Save gets payment_required / token, #prof-status must leave Saving..."""
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        user_pk = pubkey_from_privkey(_NSEC_SK)
        base = live_server

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()

            await page.goto(
                f"{base}/profile", wait_until="domcontentloaded", timeout=30_000
            )
            await _wait_auth_ready(page)
            await page.evaluate(
                """([sk, pk]) => {
                  try { delete window.nostr; } catch (e) { window.nostr = undefined; }
                  setAuthState('nsec', pk, sk);
                }""",
                [_NSEC_SK, user_pk],
            )
            await page.evaluate("() => showOwnAccount()")
            await page.fill("#prof-name", "PayNeededBot")

            # Intercept POST /api/v1/events → 402 with token (producer shape from payment stack)
            _pay_hash = "ab" * 32
            _body_402 = (
                '{"status":"payment_required","token":"tok-test",'
                f'"bolt11":"lnbc1test","payment_hash":"{_pay_hash}",'
                '"amount_sats":21,"lightning":{"invoice":"lnbc1test"}}'
            )

            async def _fulfill_402(route):
                if route.request.method == "POST":
                    await route.fulfill(
                        status=402,
                        content_type="application/json",
                        body=_body_402,
                    )
                else:
                    await route.continue_()

            await page.route("**/api/v1/events", _fulfill_402)

            await page.click("#btn-save-profile")
            for _ in range(50):
                status = await page.evaluate(
                    "() => (document.getElementById('prof-status') || {}).textContent || ''"
                )
                widget = await page.evaluate(
                    "() => !!document.getElementById('pw-widget')"
                )
                if widget or (status and status != "Saving..."):
                    break
                await asyncio.sleep(0.1)

            status = await page.evaluate(
                "() => (document.getElementById('prof-status') || {}).textContent || ''"
            )
            widget = await page.evaluate(
                "() => !!document.getElementById('pw-widget')"
            )
            await browser.close()

        assert widget is True, "expected #pw-widget after 402"
        assert status != "Saving...", f"status stuck on Saving...: {status!r}"
        assert status == "" or "pay" in status.lower() or "invoice" in status.lower() or "payment" in status.lower()


# ---------------------------------------------------------------------------
# 16.19 — live: missing amount input does not throw
# ---------------------------------------------------------------------------


class TestSubmitZapNullGuardLive1619:
    @pytest.mark.asyncio
    async def test_submit_zap_missing_amount_no_typeerror(self, live_server):
        import httpx
        from app.zaps import pubkey_from_privkey
        from playwright.async_api import async_playwright

        user_pk = pubkey_from_privkey(_NSEC_SK)
        base = live_server

        with httpx.Client(
            base_url=base,
            timeout=10.0,
            headers={"X-Requested-With": "XMLHttpRequest"},
        ) as c:
            r = c.post("/api/v1/post", json={"content": "p16-19-zap-null-guard"})
            assert r.status_code in (200, 201, 402) or r.status_code == 200
            # test-mode stores directly
            ev = c.get("/api/v1/events?kinds=1&limit=5").json()
            events = ev.get("events") or []
            assert events, "need a note to zap"
            note_id = events[0]["id"]

        page_errors: list[str] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not _headed())
            page = await browser.new_page()
            page.on(
                "pageerror",
                lambda exc: page_errors.append(str(exc)),
            )

            await page.goto(f"{base}/", wait_until="domcontentloaded", timeout=30_000)
            await _wait_auth_ready(page)
            await page.evaluate(
                """([sk, pk]) => {
                  setAuthState('nsec', pk, sk);
                }""",
                [_NSEC_SK, user_pk],
            )
            # Remove amount input (adversarial missing DOM)
            await page.evaluate(
                """(id) => {
                  const el = document.getElementById('vote-amount-' + id);
                  if (el) el.remove();
                }""",
                note_id,
            )
            # Call submitZap directly
            await page.evaluate("(id) => submitZap(id)", note_id)
            await asyncio.sleep(0.3)
            status = await page.evaluate(
                f"() => (document.getElementById('vote-status-{note_id}') || {{}}).textContent || ''"
            )
            await browser.close()

        type_errs = [e for e in page_errors if "TypeError" in e or "null" in e.lower()]
        assert not type_errs, f"submitZap threw on missing amount: {type_errs}"
        # Optional status message — must not crash; status may warn about amount
        assert "TypeError" not in status
