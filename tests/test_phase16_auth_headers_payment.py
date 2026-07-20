"""16.24: authHeaders must not clobber L402/Payment Authorization with NIP-98.

Live bug (2026-07-20): profile Save settled via authFetch; authHeaders always
overwrote Authorization: Payment/L402 with Nostr NIP-98, so settle minted a
fresh 402 invoice after the user had already paid.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH_JS = (ROOT / "app" / "static" / "nostr-auth.js").read_text()
PROFILE_JS = (ROOT / "app" / "static" / "profile.js").read_text()


def test_auth_headers_preserves_payment_authorization():
    fn = AUTH_JS.split("async function authHeaders", 1)[1].split(
        "\nasync function authFetch", 1
    )[0]
    assert "L402" in fn and "Payment" in fn
    assert "makeNip98Auth" in fn
    # Guard must return early before NIP-98 overwrite
    assert "return headers" in fn
    assert "/^(L402|LSAT|Payment)" in fn or r"/^(L402|LSAT|Payment)" in fn


def test_save_profile_uses_l402_retry_and_api_fetch_settle():
    """Profile save must settle like home post: payL402AndRetry + apiFetch fallback."""
    assert "payL402AndRetry" in PROFILE_JS
    assert "parseL402Challenge" in PROFILE_JS
    settle = PROFILE_JS.split("async function saveProfile", 1)[1].split(
        "\n// ---- Public Profile", 1
    )[0]
    assert "apiFetch('/api/v1/events'" in settle or 'apiFetch("/api/v1/events"' in settle
    # After payment_required, settle must not call authFetch( (NIP-98 clobber).
    after_402 = settle.split("payment_required", 1)[-1]
    assert "authFetch(" not in after_402


def test_save_profile_confirms_before_payment():
    """User must confirm sats cost before payL402AndRetry / payment widget."""
    settle = PROFILE_JS.split("async function saveProfile", 1)[1].split(
        "\n// ---- Public Profile", 1
    )[0]
    after_402 = settle.split("payment_required", 1)[-1]
    assert "confirm(" in after_402 or "window.confirm(" in after_402
    # Confirm must run before auto-pay
    conf_i = after_402.find("confirm(")
    pay_i = after_402.find("payL402AndRetry")
    assert conf_i >= 0 and pay_i > conf_i
    assert "Save cancelled" in after_402
