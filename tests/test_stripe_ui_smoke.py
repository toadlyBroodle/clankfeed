"""7a.11: Playwright e2e for Stripe Card tab / Elements / SPT settle / downvote fallthrough.

TestStripeWebClientWidget in test_stripe.py is source-string only. These drive a real
browser against live CSP + route-mocked 402 producer shapes (from _build_payment_options).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]

# Minimal mock Stripe.js — Elements.mount writes a marker; createPaymentMethod returns pm_
_MOCK_STRIPE_JS = """
window.Stripe = function (pk) {
  return {
    elements: function () {
      return {
        create: function () {
          return {
            mount: function (sel) {
              var el = typeof sel === 'string' ? document.querySelector(sel) : sel;
              if (el) {
                el.innerHTML = '<div data-mock-stripe-element="card" data-pk="' +
                  String(pk || '') + '">mock-card</div>';
              }
            },
            destroy: function () {},
          };
        },
      };
    },
    createPaymentMethod: async function () {
      return { paymentMethod: { id: 'pm_mock_card_visa' } };
    },
  };
};
"""

# Producer-shaped stripe.challenge echo (fields buildStripePaymentAuth requires)
_STRIPE_CHALLENGE = {
    "id": "chal_test_stripe_7a11",
    "realm": "clankfeed",
    "method": "stripe",
    "intent": "charge",
    "request": "eyJhbW91bnQiOiI1MCIsImN1cnJlbmN5IjoidXNkIiwiZGVjaW1hbHMiOjJ9",
    "expires": "2099-01-01T00:00:00Z",
}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_health(base: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base}/health", timeout=1.0)
            if r.status_code == 200:
                return
        except Exception as e:  # noqa: BLE001 — poll until up
            last_err = e
        time.sleep(0.15)
    raise RuntimeError(f"server did not become healthy: {last_err}")


def _is_csp_script_src_violation(text: str) -> bool:
    t = text.lower()
    if "content security policy" not in t and "csp" not in t:
        if "refused to" not in t:
            return False
    scriptish = (
        "script-src" in t
        or "inline script" in t
        or "eval" in t
        or "unsafe-inline" in t
        or "unsafe-eval" in t
    )
    return scriptish or ("refused to execute" in t and "script" in t)


def _stripe_402_body(
    *,
    token: str = "tok-7a11",
    include_l402: bool = False,
    include_stripe: bool = True,
    include_lightning: bool = True,
) -> str:
    """Mimic api_v1 _build_payment_options 402 JSON (producer shape)."""
    methods: list[str] = []
    body: dict = {
        "status": "payment_required",
        "token": token,
    }
    if include_lightning:
        methods.append("lightning")
        bolt11 = "lnbc210n17a11playwright"
        pay_hash = "ab" * 32
        body["bolt11"] = bolt11
        body["payment_hash"] = pay_hash
        body["lightning"] = {
            "bolt11": bolt11,
            "payment_hash": pay_hash,
            "amount_sats": 21,
            "expires_in": 600,
        }
    if include_stripe:
        methods.append("stripe")
        body["stripe"] = {
            "network_id": "profile_test_7a11",
            "amount_usd": "0.50",
            "currency": "usd",
            "publishable_key": "pk_test_7a11_mock",
            "payment_method_types": ["card", "link"],
            "challenge": dict(_STRIPE_CHALLENGE),
        }
    body["methods"] = methods
    if include_l402 and include_lightning:
        body["l402"] = {
            "macaroon": "mac_test_7a11",
            "invoice": body["bolt11"],
        }
    return json.dumps(body)


@pytest.fixture
def live_server(tmp_path):
    """Uvicorn with AUTH_ROOT_KEY=test-mode (free seed posts; 402s via route-mock)."""
    db_path = tmp_path / "stripe_ui.db"
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


@pytest.mark.asyncio
async def test_playwright_stripe_card_tab_elements_mount_under_csp(live_server):
    """7a.11: unpaid post 402 with stripe → #pw-tab-stripe visible; Elements mount; CSP clean."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    csp_violations: list[str] = []
    headless = not bool(os.environ.get("DISPLAY"))

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        page = await browser.new_page()

        def _on_console(msg):
            if _is_csp_script_src_violation(msg.text):
                csp_violations.append(msg.text)

        page.on("console", _on_console)

        stripe_js_loaded = {"ok": False}

        async def _route(route):
            req = route.request
            url = req.url
            if "js.stripe.com" in url:
                stripe_js_loaded["ok"] = True
                await route.fulfill(
                    status=200,
                    content_type="application/javascript",
                    body=_MOCK_STRIPE_JS,
                )
                return
            if (
                req.method == "POST"
                and "/api/v1/post" in url
                and "/confirm" not in url
                and not req.headers.get("authorization")
            ):
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body=_stripe_402_body(include_l402=False),
                )
                return
            await route.continue_()

        await page.route("**/*", _route)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#post-form", timeout=10_000)
        await page.wait_for_timeout(400)

        assert not csp_violations, f"CSP before post: {csp_violations}"

        await page.fill("#post-content", "7a11-stripe-card-tab")
        await page.click("#post-btn")

        await page.wait_for_selector("#pw-widget:not(.hidden)", timeout=15_000)
        assert await page.locator("#pw-tab-stripe:not(.hidden)").count() == 1
        amount = await page.locator("#pw-stripe-amount").text_content()
        # Amount fills when stripe present (may be on hidden panel until tab click)
        assert amount is not None and "0.50" in amount

        await page.click("#pw-tab-stripe")
        await page.wait_for_selector("#pw-stripe:not(.hidden)", timeout=5_000)
        await page.wait_for_selector(
            '#pw-stripe-card [data-mock-stripe-element="card"]',
            timeout=10_000,
        )
        assert stripe_js_loaded["ok"], "expected js.stripe.com load under CSP"

        assert not csp_violations, (
            f"CSP script-src violations during Stripe Elements mount: {csp_violations}"
        )

        await browser.close()


@pytest.mark.asyncio
async def test_playwright_stripe_spt_paste_authorization_payment_settle(live_server):
    """7a.11: paste SPT → settle POST carries Authorization: Payment …"""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    settle_auths: list[str] = []
    headless = not bool(os.environ.get("DISPLAY"))

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        page = await browser.new_page()

        async def _route(route):
            req = route.request
            url = req.url
            if "js.stripe.com" in url:
                await route.fulfill(
                    status=200,
                    content_type="application/javascript",
                    body=_MOCK_STRIPE_JS,
                )
                return
            if req.method == "POST" and "/api/v1/post" in url and "/confirm" not in url:
                auth = req.headers.get("authorization") or ""
                if auth.startswith("Payment "):
                    settle_auths.append(auth)
                    await route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps(
                            {
                                "paid": True,
                                "event": {
                                    "id": "e" * 64,
                                    "pubkey": "f" * 64,
                                    "created_at": 1,
                                    "kind": 1,
                                    "tags": [],
                                    "content": "7a11-paid",
                                    "sig": "a" * 128,
                                },
                            }
                        ),
                    )
                    return
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body=_stripe_402_body(include_l402=False),
                )
                return
            await route.continue_()

        await page.route("**/*", _route)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#post-form", timeout=10_000)

        await page.fill("#post-content", "7a11-spt-paste-settle")
        await page.click("#post-btn")
        await page.wait_for_selector("#pw-widget:not(.hidden)", timeout=15_000)
        await page.click("#pw-tab-stripe")
        await page.wait_for_selector("#pw-stripe:not(.hidden)", timeout=5_000)

        await page.fill("#pw-stripe-spt", "spt_test_7a11_paste")
        await page.click("#pw-stripe-spt-btn")

        for _ in range(80):
            if settle_auths:
                break
            await page.wait_for_timeout(100)

        assert settle_auths, "expected POST /api/v1/post with Authorization: Payment"
        assert settle_auths[-1].startswith("Payment "), settle_auths[-1]
        # Credential is base64url JSON with challenge + spt payload
        assert len(settle_auths[-1]) > len("Payment ")

        await page.wait_for_selector("#pw-widget.hidden", state="attached", timeout=10_000)

        await browser.close()


@pytest.mark.asyncio
async def test_playwright_stripe_downvote_l402_fail_fallthrough_shows_card_tab(
    live_server,
):
    """7a.11 / 7a.10: L402 fail on downvote co-challenged with stripe → Card tab."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    headless = not bool(os.environ.get("DISPLAY"))

    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        note_id = c.post(
            "/api/v1/post", json={"content": "7a11-downvote-fallthrough-seed"}
        ).json()["event"]["id"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        page = await browser.new_page()

        async def _route(route):
            req = route.request
            url = req.url
            if "js.stripe.com" in url:
                await route.fulfill(
                    status=200,
                    content_type="application/javascript",
                    body=_MOCK_STRIPE_JS,
                )
                return
            if (
                req.method == "POST"
                and f"/api/v1/events/{note_id}/vote" in url
                and "/confirm" not in url
            ):
                # Co-challenge: L402 + stripe (no wallet → L402 throws → fallthrough)
                body = json.loads(
                    _stripe_402_body(
                        token="vote-tok-7a11",
                        include_l402=True,
                        include_stripe=True,
                        include_lightning=True,
                    )
                )
                body["event_id"] = note_id
                body["direction"] = -1
                body["amount_sats"] = 21
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body=json.dumps(body),
                )
                return
            await route.continue_()

        await page.route("**/*", _route)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{note_id}", timeout=15_000)

        # Ensure no WebLN / BC — L402 must fail so fallthrough runs
        await page.evaluate(
            """() => {
              try { delete window.webln; } catch (e) { window.webln = undefined; }
              window.__bcLaunchPaymentModal = undefined;
              window.__bcConnected = false;
            }"""
        )

        await page.click(f'#note-{note_id} button[data-action="downvote"]')
        await page.wait_for_selector(f"#vote-prompt-{note_id}.active", timeout=5_000)
        await page.click(f'#note-{note_id} button[data-action="submit-vote"]')

        await page.wait_for_selector("#pw-widget:not(.hidden)", timeout=15_000)
        assert await page.locator("#pw-tab-stripe:not(.hidden)").count() == 1

        await page.click("#pw-tab-stripe")
        await page.wait_for_selector("#pw-stripe:not(.hidden)", timeout=5_000)
        await page.wait_for_selector(
            '#pw-stripe-card [data-mock-stripe-element="card"]',
            timeout=10_000,
        )

        await browser.close()


@pytest.mark.asyncio
async def test_playwright_adversarial_stripe_tab_hidden_without_stripe(live_server):
    """Adversarial: 402 without stripe in methods → #pw-tab-stripe stays hidden."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    headless = not bool(os.environ.get("DISPLAY"))

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        page = await browser.new_page()

        async def _route(route):
            req = route.request
            if (
                req.method == "POST"
                and "/api/v1/post" in req.url
                and "/confirm" not in req.url
            ):
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body=_stripe_402_body(
                        include_stripe=False,
                        include_lightning=True,
                        include_l402=False,
                    ),
                )
                return
            await route.continue_()

        await page.route("**/*", _route)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#post-form", timeout=10_000)

        await page.fill("#post-content", "7a11-no-stripe-adversarial")
        await page.click("#post-btn")
        await page.wait_for_selector("#pw-widget:not(.hidden)", timeout=15_000)

        # Tab may exist in DOM but must remain .hidden
        visible = await page.locator("#pw-tab-stripe:not(.hidden)").count()
        assert visible == 0
        hidden = await page.locator("#pw-tab-stripe.hidden").count()
        assert hidden == 1

        await browser.close()
