"""6.7: Playwright/network assert that authFetch/apiFetch POSTs send X-Requested-With.

Source greps (6.6) cannot catch a runtime regression where wrappers drop XRW.
Under AUTH_ROOT_KEY=test-mode, confirm never fires naturally — route-mock forces
payment_required, then WebLN mock triggers the confirm callback so we observe
the confirm POST headers too.
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


@pytest.fixture
def live_server(tmp_path):
    """Uvicorn subprocess with file SQLite (AUTH_ROOT_KEY=test-mode)."""
    db_path = tmp_path / "h5xrw.db"
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


def _xrw(headers: dict) -> str | None:
    for k, v in headers.items():
        if k.lower() == "x-requested-with":
            return v
    return None


@pytest.mark.asyncio
async def test_h5_post_and_vote_pos_send_xrw(live_server):
    """UI post + vote under test-mode: authFetch POSTs must carry X-Requested-With."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    captured: list[tuple[str, str, dict]] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        def _on_request(req):
            if req.method == "POST":
                captured.append((req.method, req.url, dict(req.headers)))

        page.on("request", _on_request)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#post-form", timeout=10_000)

        await page.fill("#post-content", "h5-xrw-post-note")
        await page.click("#post-btn")

        # Wait for post POST to appear
        for _ in range(50):
            if any("/api/v1/post" in u and "/confirm" not in u for _, u, _ in captured):
                break
            await page.wait_for_timeout(100)

        post_hdrs = [
            h
            for _, u, h in captured
            if "/api/v1/post" in u and "/confirm" not in u
        ]
        assert post_hdrs, f"expected POST /api/v1/post; saw: {[u for _, u, _ in captured]}"
        assert _xrw(post_hdrs[-1]) == "XMLHttpRequest", (
            f"authFetch post missing XRW; headers={post_hdrs[-1]}"
        )

        # Seeded note appears after paid post; vote on it
        note_id = None
        with httpx.Client(
            base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
        ) as c:
            events = c.get("/api/v1/events?kinds=1&limit=5").json()["events"]
            for e in events:
                if e.get("content") == "h5-xrw-post-note":
                    note_id = e["id"]
                    break
        assert note_id, "posted note not found via API"

        # Reload so feed has the note with vote buttons
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{note_id}", timeout=15_000)
        captured.clear()

        await page.click(f'#note-{note_id} button[title="Downvote"]')
        await page.wait_for_selector(f"#vote-submit-{note_id}", timeout=5_000)
        await page.click(f"#vote-submit-{note_id}")

        for _ in range(50):
            if any(f"/api/v1/events/{note_id}/vote" in u and "/confirm" not in u for _, u, _ in captured):
                break
            await page.wait_for_timeout(100)

        vote_hdrs = [
            h
            for _, u, h in captured
            if f"/api/v1/events/{note_id}/vote" in u and "/confirm" not in u
        ]
        assert vote_hdrs, f"expected POST vote; saw: {[u for _, u, _ in captured]}"
        assert _xrw(vote_hdrs[-1]) == "XMLHttpRequest", (
            f"apiFetch vote missing XRW; headers={vote_hdrs[-1]}"
        )

        await browser.close()


@pytest.mark.asyncio
async def test_h5_confirm_path_sends_xrw_via_route_mock(live_server):
    """Route-mock payment_required → WebLN pay → Payment-auth retry must carry XRW.

    Phase 11c: settle is Authorization: Payment on the original POST (not /confirm).
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    pay_hash = "ab" * 32
    fake_token = "tok-" + ("cd" * 16)
    # Minimal challenge echo the client needs for buildLightningPaymentAuth
    challenge = {
        "id": "challenge-id-h5",
        "realm": "clankfeed.com",
        "method": "lightning",
        "intent": "charge",
        "request": "dGVzdA",
        "expires": "2099-01-01T00:00:00Z",
    }
    import json as _json
    challenge_json = _json.dumps(challenge)

    with httpx.Client(
        base_url=base, timeout=10.0, headers={"X-Requested-With": "XMLHttpRequest"}
    ) as c:
        note = c.post("/api/v1/post", json={"content": "h5-xrw-confirm-target"}).json()
        note_id = note["event"]["id"]

    captured: list[tuple[str, str, dict]] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        async def _route_handler(route):
            req = route.request
            url = req.url
            if req.method == "POST" and f"/api/v1/events/{note_id}/vote" in url:
                auth = (req.headers.get("authorization") or "")
                if auth.startswith("Payment ") or auth.startswith("L402 "):
                    await route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=(
                            '{"voted":true,"new_sats_clank":42,"new_sats_ext":0,'
                            '"direction":-1,"amount_sats":21}'
                        ),
                    )
                    return
                body = (
                    '{"status":"payment_required","token":"%s","event_id":"%s",'
                    '"direction":-1,"methods":["lightning"],'
                    '"bolt11":"lnbc1h5xrwtestinvoice","payment_hash":"%s",'
                    '"lightning":{"bolt11":"lnbc1h5xrwtestinvoice",'
                    '"payment_hash":"%s","amount_sats":21,"expires_in":600,'
                    '"challenge":%s}}'
                    % (fake_token, note_id, pay_hash, pay_hash, challenge_json)
                )
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    body=body,
                )
                return
            await route.continue_()

        await page.route("**/*", _route_handler)

        def _on_request(req):
            if req.method == "POST":
                captured.append((req.method, req.url, dict(req.headers)))

        page.on("request", _on_request)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector(f"#note-{note_id}", timeout=15_000)

        # Valid 64-hex preimage for buildLightningPaymentAuth
        await page.evaluate(
            """() => {
              window.__bcConnected = true;
              window.webln = {
                sendPayment: async () => ({ preimage: '%s' })
              };
            }""" % ("11" * 32)
        )

        await page.click(f'#note-{note_id} button[title="Downvote"]')
        await page.wait_for_selector(f"#vote-submit-{note_id}", timeout=5_000)
        await page.click(f"#vote-submit-{note_id}")

        for _ in range(80):
            if any(
                f"/api/v1/events/{note_id}/vote" in u
                and (h.get("authorization") or "").startswith("Payment ")
                for _, u, h in captured
            ):
                break
            await page.wait_for_timeout(100)

        settle_hdrs = [
            h for _, u, h in captured
            if f"/api/v1/events/{note_id}/vote" in u
            and (h.get("authorization") or "").startswith("Payment ")
        ]
        assert settle_hdrs, (
            f"expected Payment-auth vote settle; saw: "
            f"{[(u, (h.get('authorization') or '')[:40]) for _, u, h in captured]}"
        )
        assert _xrw(settle_hdrs[-1]) == "XMLHttpRequest", (
            f"Payment settle missing XRW; headers={settle_hdrs[-1]}"
        )

        # Also exercise apiFetch POST directly (same XRW wrapper)
        captured.clear()
        await page.evaluate(
            """async () => {
              await apiFetch('/api/v1/post', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content: 'h5-xrw-direct'}),
              });
            }"""
        )
        for _ in range(40):
            if any("/api/v1/post" in u for _, u, _ in captured):
                break
            await page.wait_for_timeout(100)
        post_hdrs = [h for _, u, h in captured if "/api/v1/post" in u]
        assert post_hdrs, f"expected apiFetch /api/v1/post; saw: {[u for _, u, _ in captured]}"
        assert _xrw(post_hdrs[-1]) == "XMLHttpRequest"

        # Adversarial: bare fetch must NOT invent XRW
        captured.clear()
        await page.evaluate(
            """async () => {
              await fetch('/api/v1/post', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content: 'h5-xrw-bare'}),
              });
            }"""
        )
        for _ in range(40):
            if any("/api/v1/post" in u for _, u, _ in captured):
                break
            await page.wait_for_timeout(100)
        bare = [h for _, u, h in captured if "/api/v1/post" in u]
        assert bare, "expected bare fetch /api/v1/post"
        assert _xrw(bare[-1]) is None, (
            f"adversarial bare fetch unexpectedly had XRW; headers={bare[-1]}"
        )

        await browser.close()


@pytest.mark.asyncio
async def test_h5_post_form_l402_fail_payment_auth_settle(live_server):
    """11c.9: post-form L402 wallet fail → Authorization: Payment retry carries XRW.

    Mirrors vote Payment-auth settle for #post-form: route-mock 402 with L402 +
    lightning challenge; WebLN throws once (L402 fail) then returns preimage for
    MPP fallthrough; assert Payment Authorization + XRW on /api/v1/post.
    """
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright
    import json as _json

    base = live_server["base"]
    pay_hash = "ab" * 32
    fake_token = "tok-" + ("ef" * 16)
    challenge = {
        "id": "challenge-id-h5-post",
        "realm": "clankfeed.com",
        "method": "lightning",
        "intent": "charge",
        "request": "dGVzdA",
        "expires": "2099-01-01T00:00:00Z",
    }
    challenge_json = _json.dumps(challenge)
    preimage = "11" * 32
    event_id = "aa" * 32

    captured: list[tuple[str, str, dict]] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        async def _route_handler(route):
            req = route.request
            url = req.url
            if req.method == "POST" and "/api/v1/post" in url and "/confirm" not in url:
                auth = (req.headers.get("authorization") or "")
                if auth.startswith("Payment ") or auth.startswith("L402 "):
                    await route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=_json.dumps(
                            {"paid": True, "event": {"id": event_id, "content": "ok"}}
                        ),
                    )
                    return
                body = {
                    "status": "payment_required",
                    "token": fake_token,
                    "methods": ["lightning"],
                    "bolt11": "lnbc1h5posttestinvoice",
                    "payment_hash": pay_hash,
                    "l402": {
                        "macaroon": "mac_h5_post",
                        "invoice": "lnbc1h5posttestinvoice",
                    },
                    "lightning": {
                        "bolt11": "lnbc1h5posttestinvoice",
                        "payment_hash": pay_hash,
                        "amount_sats": 21,
                        "expires_in": 600,
                        "challenge": challenge,
                    },
                }
                await route.fulfill(
                    status=402,
                    content_type="application/json",
                    headers={
                        "WWW-Authenticate": (
                            'L402 macaroon="mac_h5_post", '
                            'invoice="lnbc1h5posttestinvoice"'
                        ),
                    },
                    body=_json.dumps(body),
                )
                return
            await route.continue_()

        await page.route("**/*", _route_handler)

        def _on_request(req):
            if req.method == "POST":
                captured.append((req.method, req.url, dict(req.headers)))

        page.on("request", _on_request)
        await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("#post-form", timeout=10_000)

        # First WebLN call fails (L402 path); subsequent succeed (Payment fallthrough)
        await page.evaluate(
            """() => {
              let calls = 0;
              window.__bcConnected = true;
              window.webln = {
                sendPayment: async () => {
                  calls += 1;
                  if (calls === 1) throw new Error('wallet cancelled');
                  return { preimage: '%s' };
                }
              };
            }""" % preimage
        )

        await page.fill("#post-content", "h5-post-payment-auth-settle")
        await page.click("#post-btn")

        for _ in range(100):
            if any(
                "/api/v1/post" in u
                and "/confirm" not in u
                and (h.get("authorization") or "").startswith("Payment ")
                for _, u, h in captured
            ):
                break
            await page.wait_for_timeout(100)

        settle_hdrs = [
            h for _, u, h in captured
            if "/api/v1/post" in u
            and "/confirm" not in u
            and (h.get("authorization") or "").startswith("Payment ")
        ]
        assert settle_hdrs, (
            f"expected Payment-auth post settle; saw: "
            f"{[(u, (h.get('authorization') or '')[:40]) for _, u, h in captured]}"
        )
        assert _xrw(settle_hdrs[-1]) == "XMLHttpRequest", (
            f"Payment post settle missing XRW; headers={settle_hdrs[-1]}"
        )

        await browser.close()


@pytest.mark.asyncio
async def test_h5_profile_no_deposit_path_under_live(live_server):
    """14.5: deposit chrome gone; profile identity + save still use XRW helpers."""
    playwright = pytest.importorskip("playwright.async_api")
    async_playwright = playwright.async_playwright

    base = live_server["base"]
    from pathlib import Path

    profile_js = (Path(__file__).resolve().parents[1] / "app" / "static" / "profile.js").read_text()
    assert "/api/v1/account/deposit" not in profile_js
    assert "authFetch('/api/v1/events'" in profile_js or 'authFetch("/api/v1/events"' in profile_js

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(f"{base}/profile", wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_function(
            "() => !!(window.__nostrCrypto && window.__nostrCrypto.getPublicKey)",
            timeout=60_000,
        )
        await page.wait_for_selector("#view-login", timeout=10_000)
        assert await page.locator("#section-deposit").count() == 0
        await page.click("text=Generate New Identity")
        await page.wait_for_selector("#view-account:not(.hidden)", timeout=15_000)
        assert await page.locator("#btn-deposit").count() == 0
        await browser.close()
