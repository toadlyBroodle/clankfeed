"""6.13–6.17: Playwright runtime coverage for CSP M4 (no script-src unsafe-inline).

TestCspM4 in test_security.py is ASGI/source-only. These drive a real browser under
the live CSP header and assert:
- 6.13: zero CSP script-src console violations on / + /profile; data-action click fires
- 6.14: organic post→402→showPaymentWidget (Lightning/Tempo tabs + cancel) under CSP
- 6.15: upvote/downvote/cancel-vote/toggle-replies + multi-note cardinality under CSP
- 6.16: profile deposit→402→showPaymentWidget under live CSP
- 6.17: empty-feed zero-row (#empty-feed visible, zero .note-card) under live CSP
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
    """6.13+6.15: / + /profile clean under CSP; all note-card data-actions fire.

    6.15: seed ≥2 notes (one with a child), exercise upvote/downvote/cancel-vote/
    toggle-replies + reply, assert multi-note cardinality and zero new script-src
    violations after each action.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]

    # Seed ≥2 notes; note_a gets a child for toggle-replies
    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        note_a = c.post(
            "/api/v1/post", json={"content": "csp-m4-parent-a"}
        ).json()["event"]["id"]
        note_b = c.post(
            "/api/v1/post", json={"content": "csp-m4-sibling-b"}
        ).json()["event"]["id"]
        reply = c.post(
            "/api/v1/post",
            json={"content": "csp-m4-child-of-a", "reply_to": note_a},
        ).json()["event"]["id"]
        assert note_a != note_b
        assert reply != note_a

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        csp_violations: list[str] = []

        def _on_console(msg):
            text = msg.text
            if _is_csp_script_src_violation(text):
                csp_violations.append(text)

        page.on("console", _on_console)

        def _new_csp_since(baseline: list[str]) -> list[str]:
            return [v for v in csp_violations if v not in baseline]

        # --- index: clean load + multi-note cardinality ---
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{note_a}", timeout=15_000)
        await page.wait_for_selector(f"#note-{note_b}", timeout=15_000)
        # Let deferred scripts + reply-count fetch settle
        await page.wait_for_timeout(1200)

        clean_index = list(csp_violations)
        assert not clean_index, (
            f"CSP script-src violations on / before click: {clean_index}"
        )

        # Both top-level notes must expose the full data-action set
        for nid in (note_a, note_b):
            for action in ("upvote", "downvote", "reply", "toggle-replies"):
                assert (
                    await page.locator(
                        f'#note-{nid} button[data-action="{action}"]'
                    ).count()
                    == 1
                ), f"missing data-action={action} on note {nid[:8]}"

        # --- upvote → vote-prompt.active + status ---
        await page.click(f'#note-{note_a} button[data-action="upvote"]')
        await page.wait_for_selector(
            f"#vote-prompt-{note_a}.active", timeout=5_000
        )
        status = await page.locator(f"#vote-status-{note_a}").text_content()
        assert status is not None and "Upvote" in status
        assert not _new_csp_since(clean_index), (
            f"CSP after upvote: {_new_csp_since(clean_index)}"
        )

        # --- cancel-vote → prompt inactive ---
        await page.click(f'#note-{note_a} button[data-action="cancel-vote"]')
        await page.wait_for_function(
            f"() => !document.getElementById('vote-prompt-{note_a}')"
            f".classList.contains('active')",
            timeout=5_000,
        )
        assert not _new_csp_since(clean_index), (
            f"CSP after cancel-vote: {_new_csp_since(clean_index)}"
        )

        # --- downvote on sibling note (multi-note cardinality) ---
        await page.click(f'#note-{note_b} button[data-action="downvote"]')
        await page.wait_for_selector(
            f"#vote-prompt-{note_b}.active", timeout=5_000
        )
        status_b = await page.locator(f"#vote-status-{note_b}").text_content()
        assert status_b is not None and "Downvote" in status_b
        # note_a prompt must still be inactive (per-note state)
        assert (
            await page.locator(f"#vote-prompt-{note_a}.active").count() == 0
        )
        assert not _new_csp_since(clean_index), (
            f"CSP after downvote: {_new_csp_since(clean_index)}"
        )
        await page.click(f'#note-{note_b} button[data-action="cancel-vote"]')

        # --- toggle-replies on parent (child must appear) ---
        await page.click(f'#note-{note_a} button[data-action="toggle-replies"]')
        await page.wait_for_selector(
            f"#replies-{note_a}:not(.hidden)", timeout=10_000
        )
        await page.wait_for_selector(
            f"#replies-{note_a} #note-{reply}", timeout=10_000
        )
        assert not _new_csp_since(clean_index), (
            f"CSP after toggle-replies: {_new_csp_since(clean_index)}"
        )

        # --- reply (6.13 baseline) still works ---
        await page.click(f'#note-{note_b} button[data-action="reply"]')
        await page.wait_for_selector("#reply-context:not(.hidden)", timeout=5_000)
        ctx_name = await page.locator("#reply-context-name").text_content()
        assert ctx_name is not None and ctx_name.strip() != ""
        assert not _new_csp_since(clean_index), (
            f"CSP after reply: {_new_csp_since(clean_index)}"
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
async def test_m4_empty_feed_zero_row_under_csp(live_server):
    """6.17: empty DB → #empty-feed visible, zero .note-card, clean CSP console.

    6.15 only covers the multi-note (≥2) end under live CSP. UI3.6 covers empty
    DOM without CSP script-src collection. This closes the zero-row CSP path.
    Avoid page.wait_for_function — CSP script-src lacks unsafe-eval.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    # Confirm DB is empty (no seed) — adversarial if prior test pollution
    with httpx.Client(base_url=base, timeout=10.0) as c:
        events = c.get("/api/v1/events?kinds=1&origin=clankfeed").json()["events"]
        assert events == [], f"expected empty DB, got {len(events)} events"

    csp_violations: list[str] = []

    async def _empty_visible(page) -> bool:
        loc = page.locator("#empty-feed")
        if await loc.count() != 1:
            return False
        return await loc.is_visible()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        def _on_console(msg):
            text = msg.text
            if _is_csp_script_src_violation(text):
                csp_violations.append(text)

        page.on("console", _on_console)

        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#feed-clankfeed", timeout=10_000)

        for _ in range(100):
            if (
                await _empty_visible(page)
                and await page.locator("#notes-feed .note-card").count() == 0
            ):
                break
            await page.wait_for_timeout(100)
        else:
            raise AssertionError(
                "#empty-feed not visible after empty clankfeed load under CSP "
                f"(count={await page.locator('#empty-feed').count()}, "
                f"cards={await page.locator('#notes-feed .note-card').count()})"
            )

        # Let deferred scripts settle, then assert clean CSP
        await page.wait_for_timeout(1200)
        assert not csp_violations, (
            f"CSP script-src violations on empty /: {csp_violations}"
        )

        empty = page.locator("#empty-feed")
        assert await empty.count() == 1
        assert await empty.is_visible()
        text = (await empty.inner_text()).strip()
        assert "No notes yet" in text or "first to post" in text.lower()
        assert await page.locator(".note-card").count() == 0
        assert await page.locator("#notes-feed .note-card").count() == 0

        # Adversarial: seed one local note + reload → empty-feed hides, ≥1 card,
        # still zero new script-src violations (nonempty end under same CSP path)
        with httpx.Client(
            base_url=base,
            timeout=10.0,
            headers={"X-Requested-With": "XMLHttpRequest"},
        ) as c:
            note_id = c.post(
                "/api/v1/post", json={"content": "csp-m4-empty-then-one"}
            ).json()["event"]["id"]

        csp_violations.clear()
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{note_id}", timeout=15_000)
        await page.wait_for_timeout(800)

        assert await page.locator("#empty-feed").is_hidden(), (
            "nonempty feed must hide #empty-feed under CSP"
        )
        assert await page.locator(".note-card").count() >= 1
        assert not csp_violations, (
            f"CSP script-src violations on nonempty reload: {csp_violations}"
        )

        # Adversarial: inline script still blocked (collector live on this page)
        csp_violations.clear()
        await page.evaluate(
            """() => {
              const s = document.createElement('script');
              s.textContent = 'window.__cspM4EmptyProbe = 1';
              document.body.appendChild(s);
            }"""
        )
        await page.wait_for_timeout(400)
        probe = await page.evaluate("() => window.__cspM4EmptyProbe")
        assert probe is None, "inline script executed despite CSP"
        assert csp_violations, (
            "expected CSP console violation after adversarial inline script inject"
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


@pytest.mark.asyncio
async def test_m4_profile_deposit_shows_payment_widget_under_csp(live_server):
    """6.16: route-mock profile deposit→402→showPaymentWidget under live CSP.

    6.14 covers feed post only; startDeposit must open #pw-widget with
    Lightning/Tempo tabs + cancel without script-src violations. Adversarial
    empty-402 (token only, no bolt11/tempo methods) must not leave a usable
    multi-method widget (tabs stay hidden / cancel still works).
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    pay_hash = "ef" * 32
    fake_token = "dep-" + ("ab" * 16)
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
                and "/api/v1/account/deposit" in url
                and "/confirm" not in url
            ):
                tempo_recipient = "0x" + ("ab" * 20)
                tempo_currency = "0x" + ("cd" * 20)
                body = (
                    '{"status":"payment_required","token":"%s",'
                    '"deposit_amount_sats":5000,"methods":["lightning","tempo"],'
                    '"bolt11":"lnbc1m4deptestinvoice","payment_hash":"%s",'
                    '"lightning":{"bolt11":"lnbc1m4deptestinvoice",'
                    '"payment_hash":"%s","amount_sats":5000,"expires_in":600},'
                    '"tempo":{"amount_usd":"0.05","recipient":"%s",'
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
        await page.goto(f"{base}/profile", wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_function(
            "() => !!(window.__nostrCrypto && window.__nostrCrypto.getPublicKey)",
            timeout=60_000,
        )
        await page.wait_for_selector("#view-login", timeout=10_000)
        await page.click("text=Generate New Identity")
        await page.wait_for_selector("#section-deposit", state="visible", timeout=15_000)
        await page.wait_for_timeout(500)

        assert not csp_violations, (
            f"CSP script-src violations before deposit: {csp_violations}"
        )

        await page.fill("#deposit-amount", "5000")
        await page.locator("#btn-deposit").click()

        await page.wait_for_selector("#pw-widget:not(.hidden)", timeout=10_000)
        assert await page.locator("#pw-tab-ln:not(.hidden)").count() == 1
        assert await page.locator("#pw-tab-tempo:not(.hidden)").count() == 1
        title = await page.locator("#pw-title").text_content()
        assert title and "Deposit" in title

        await page.click("#pw-tab-tempo")
        await page.wait_for_selector("#pw-tempo:not(.hidden)", timeout=5_000)
        assert await page.locator("#pw-lightning.hidden").count() == 1

        await page.click("#pw-cancel-btn")
        await page.wait_for_selector("#pw-widget.hidden", state="attached", timeout=5_000)

        assert not csp_violations, (
            f"CSP script-src violations during deposit widget path: {csp_violations}"
        )

        # Adversarial: token-only 402 without lightning/tempo methods → no usable tabs
        await page.unroute("**/*")

        async def _empty_402(route):
            req = route.request
            if (
                req.method == "POST"
                and "/api/v1/account/deposit" in req.url
                and "/confirm" not in req.url
            ):
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body=(
                        '{"status":"payment_required","token":"x",'
                        '"deposit_amount_sats":100,"methods":[]}'
                    ),
                )
                return
            await route.continue_()

        await page.route("**/*", _empty_402)
        await page.fill("#deposit-amount", "100")
        await page.locator("#btn-deposit").click()
        await page.wait_for_timeout(800)
        # startDeposit opens widget whenever token is present, but tabs must stay hidden
        ln_visible = await page.locator("#pw-tab-ln:not(.hidden)").count()
        tempo_visible = await page.locator("#pw-tab-tempo:not(.hidden)").count()
        assert ln_visible == 0 and tempo_visible == 0, (
            "payment-method tabs visible without lightning/tempo methods"
        )

        await browser.close()
