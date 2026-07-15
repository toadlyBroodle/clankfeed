"""6.13 / 6.14: Playwright runtime coverage for CSP M4 (no script-src unsafe-inline).

TestCspM4 in test_security.py is ASGI/source-only. These drive a real browser under
the live CSP header and assert:
- 6.13: zero CSP script-src console violations on / + /profile; data-action click fires
- 6.14: organic post→402→showPaymentWidget (Lightning/Tempo tabs + cancel) under CSP
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]


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
    """Chromium console wording for script-src CSP blocks."""
    t = text.lower()
    if "content security policy" not in t and "csp" not in t:
        # Chromium: "Refused to execute inline script because it violates..."
        if "refused to" not in t:
            return False
    scriptish = (
        "script-src" in t
        or "inline script" in t
        or "eval" in t
        or "unsafe-inline" in t
        or "unsafe-eval" in t
    )
    return scriptish or (
        "refused to execute" in t and "script" in t
    )


@pytest.fixture
def live_server(tmp_path):
    """Uvicorn subprocess with file SQLite (AUTH_ROOT_KEY=test-mode)."""
    db_path = tmp_path / "csp_m4.db"
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
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.asyncio
async def test_m4_csp_zero_script_src_violations_and_data_action(live_server):
    """6.13: / + /profile load clean under CSP; note-card data-action still works."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]

    # Seed a note so data-action controls exist on the feed
    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        note = c.post("/api/v1/post", json={"content": "csp-m4-data-action-target"}).json()
        note_id = note["event"]["id"]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        csp_violations: list[str] = []

        def _on_console(msg):
            text = msg.text
            if _is_csp_script_src_violation(text):
                csp_violations.append(text)

        page.on("console", _on_console)

        # --- index: clean load + data-action click ---
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{note_id}", timeout=15_000)
        # Let deferred scripts settle
        await page.wait_for_timeout(800)

        clean_index = list(csp_violations)
        assert not clean_index, (
            f"CSP script-src violations on / before click: {clean_index}"
        )

        # data-action="reply" must fire (delegation, not inline onclick)
        await page.click(f'#note-{note_id} button[data-action="reply"]')
        await page.wait_for_selector("#reply-context:not(.hidden)", timeout=5_000)
        ctx_name = await page.locator("#reply-context-name").text_content()
        assert ctx_name is not None and ctx_name.strip() != ""

        after_click = [v for v in csp_violations if v not in clean_index]
        assert not after_click, (
            f"CSP script-src violations after data-action click: {after_click}"
        )

        # --- profile: clean load under same CSP ---
        csp_violations.clear()
        await page.goto(f"{base}/profile", wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#view-login", timeout=15_000)
        await page.wait_for_timeout(800)
        assert not csp_violations, (
            f"CSP script-src violations on /profile: {csp_violations}"
        )

        # Adversarial: inline <script> must be blocked (proves collector sees script-src)
        csp_violations.clear()
        await page.evaluate(
            """() => {
              const s = document.createElement('script');
              s.textContent = 'window.__cspM4Probe = 1';
              document.body.appendChild(s);
            }"""
        )
        await page.wait_for_timeout(400)
        probe = await page.evaluate("() => window.__cspM4Probe")
        assert probe is None, "inline script executed despite CSP (unsafe-inline leak?)"
        assert csp_violations, (
            "expected CSP console violation after adversarial inline script inject; "
            "collector may be broken"
        )

        await browser.close()


@pytest.mark.asyncio
async def test_m4_organic_post_shows_payment_widget_under_csp(live_server):
    """6.14: route-mock unpaid post→402 with bolt11 opens payment widget under CSP."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    pay_hash = "ab" * 32
    fake_token = "post-" + ("cd" * 16)
    csp_violations: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        def _on_console(msg):
            text = msg.text
            if _is_csp_script_src_violation(text):
                csp_violations.append(text)

        page.on("console", _on_console)

        async def _route_handler(route):
            req = route.request
            url = req.url
            if (
                req.method == "POST"
                and "/api/v1/post" in url
                and "/confirm" not in url
            ):
                # Mimic payments-enabled 402 body (producer shape from api_v1 / payment)
                tempo_recipient = "0x" + ("ab" * 20)
                tempo_currency = "0x" + ("cd" * 20)
                body = (
                    '{"status":"payment_required","token":"%s",'
                    '"methods":["lightning","tempo"],'
                    '"bolt11":"lnbc1m4posttestinvoice","payment_hash":"%s",'
                    '"lightning":{"bolt11":"lnbc1m4posttestinvoice",'
                    '"payment_hash":"%s","amount_sats":21,"expires_in":600},'
                    '"tempo":{"amount_usd":"0.02","recipient":"%s",'
                    '"currency":"%s","testnet":true}}'
                ) % (fake_token, pay_hash, pay_hash, tempo_recipient, tempo_currency)
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body=body,
                )
                return
            await route.continue_()

        await page.route("**/*", _route_handler)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#post-form", timeout=10_000)
        await page.wait_for_timeout(500)

        assert not csp_violations, (
            f"CSP script-src violations before post: {csp_violations}"
        )

        await page.fill("#post-content", "csp-m4-organic-unpaid-post")
        await page.click("#post-btn")

        # Widget must appear with Lightning + Tempo tabs
        await page.wait_for_selector("#pw-widget:not(.hidden)", timeout=10_000)
        assert await page.locator("#pw-tab-ln:not(.hidden)").count() == 1
        assert await page.locator("#pw-tab-tempo:not(.hidden)").count() == 1
        title = await page.locator("#pw-title").text_content()
        assert title and "Pay to post" in title

        # Switch Tempo tab (addEventListener path — no inline onclick)
        await page.click("#pw-tab-tempo")
        await page.wait_for_selector("#pw-tempo:not(.hidden)", timeout=5_000)
        assert await page.locator("#pw-lightning.hidden").count() == 1

        # Cancel restores Post Note button
        await page.click("#pw-cancel-btn")
        await page.wait_for_selector("#pw-widget.hidden", state="attached", timeout=5_000)
        btn_text = await page.locator("#post-btn").text_content()
        assert btn_text and "Post Note" in btn_text
        disabled = await page.locator("#post-btn").is_disabled()
        assert not disabled

        assert not csp_violations, (
            f"CSP script-src violations during payment-widget path: {csp_violations}"
        )

        # Adversarial: 402 without bolt11/tempo must NOT open the widget
        await page.unroute("**/*")

        async def _empty_402(route):
            req = route.request
            if (
                req.method == "POST"
                and "/api/v1/post" in req.url
                and "/confirm" not in req.url
            ):
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body='{"status":"payment_required","token":"x","methods":[]}',
                )
                return
            await route.continue_()

        await page.route("**/*", _empty_402)
        await page.fill("#post-content", "csp-m4-no-bolt11")
        await page.click("#post-btn")
        await page.wait_for_timeout(800)
        # Widget stays hidden (organic path requires bolt11 || tempo)
        hidden = await page.locator("#pw-widget.hidden").count()
        # Widget may not exist yet, or exist and be hidden
        visible = await page.locator("#pw-widget:not(.hidden)").count()
        assert visible == 0, "widget opened without bolt11/tempo (empty 402)"
        assert hidden in (0, 1)  # 0 if never created, 1 if hidden

        await browser.close()
