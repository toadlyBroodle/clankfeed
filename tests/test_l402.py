"""L402 core: macaroon mint/verify, require_l402, amount binding, replay (Phase 14.1)."""

import hashlib
from unittest.mock import patch, AsyncMock

import pytest

from app.l402 import mint_macaroon, verify_l402, require_l402


def _detail_text(detail) -> str:
    """Normalize HTTPException.detail (str or structured 402 dict) to a message string."""
    if isinstance(detail, dict):
        return str(detail.get("detail", detail))
    return str(detail)


# --- mint / verify round-trip ---

class TestMintAndVerify:
    def test_mint_returns_base64_string(self):
        mac_b64 = mint_macaroon("abc123")
        assert isinstance(mac_b64, str)
        assert len(mac_b64) > 10

    def test_roundtrip_with_valid_preimage(self):
        preimage = b"secret-preimage-bytes"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        mac_b64 = mint_macaroon(payment_hash)
        assert verify_l402(mac_b64, preimage_hex) is True

    def test_wrong_preimage_fails(self):
        preimage = b"correct-preimage"
        payment_hash = hashlib.sha256(preimage).hexdigest()
        mac_b64 = mint_macaroon(payment_hash)

        wrong_preimage = b"wrong-preimage-value"
        assert verify_l402(mac_b64, wrong_preimage.hex()) is False

    def test_garbage_macaroon_fails(self):
        assert verify_l402("not-a-macaroon", "aabbccdd") is False

    def test_tampered_macaroon_fails(self):
        preimage = b"my-preimage"
        payment_hash = hashlib.sha256(preimage).hexdigest()
        mac_b64 = mint_macaroon(payment_hash)

        corrupted = mac_b64[:-2] + ("A" if mac_b64[-2] != "A" else "B") + mac_b64[-1]
        assert verify_l402(corrupted, preimage.hex()) is False

    def test_uppercase_payment_hash_roundtrip(self):
        """Lightning wallet may return payment_hash in uppercase; verification must still pass."""
        preimage = b"uppercase-hash-preimage"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest().upper()

        mac_b64 = mint_macaroon(payment_hash)
        assert verify_l402(mac_b64, preimage_hex) is True

    def test_mixed_case_payment_hash_roundtrip(self):
        preimage = b"mixed-case-preimage"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()
        mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(payment_hash))

        mac_b64 = mint_macaroon(mixed)
        assert verify_l402(mac_b64, preimage_hex) is True

    def test_invalid_preimage_hex_returns_false(self):
        """Invalid hex preimage should return False, not raise an exception."""
        mac_b64 = mint_macaroon("a" * 64)
        assert verify_l402(mac_b64, "not-valid-hex!") is False


# --- require_l402 dependency ---

class TestRequireL402:
    @pytest.mark.asyncio
    async def test_test_mode_passes_through(self):
        with patch("app.l402.payments_enabled", return_value=False):
            result = await require_l402(request=None)
            assert result is None

    @pytest.mark.asyncio
    async def test_no_request_outside_test_mode_raises_500(self):
        from fastapi import HTTPException
        with patch("app.l402.payments_enabled", return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=None)
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_no_auth_header_returns_402(self):
        from fastapi import HTTPException
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [],
        }
        request = Request(scope)

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_invoice:
            mock_settings.AUTH_ROOT_KEY = "real-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_invoice.return_value = {
                "payment_hash": "abcd1234" * 8,
                "payment_request": "lnbc21n1fake",
            }

            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=request)

            assert exc_info.value.status_code == 402
            assert "WWW-Authenticate" in exc_info.value.headers
            www_auth = exc_info.value.headers["WWW-Authenticate"]
            assert "L402" in www_auth
            assert "macaroon=" in www_auth
            assert "invoice=" in www_auth

    @pytest.mark.asyncio
    async def test_valid_l402_token_passes(self):
        from starlette.requests import Request

        preimage = b"valid-preimage-for-test"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        root_key = "test-root-key-for-verify"

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status:
            mock_settings.AUTH_ROOT_KEY = root_key
            mock_settings.POST_PRICE_SATS = 21
            mock_status.return_value = (True, 21)

            mac_b64 = mint_macaroon(payment_hash)

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", f"L402 {mac_b64}:{preimage_hex}".encode()),
                ],
            }
            request = Request(scope)
            result = await require_l402(request=request)
            assert result is None

    @pytest.mark.asyncio
    async def test_invalid_l402_token_raises_402_with_fresh_challenge(self):
        from fastapi import HTTPException
        from starlette.requests import Request

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_invoice:
            mock_settings.AUTH_ROOT_KEY = "real-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_invoice.return_value = {
                "payment_hash": "abcd1234" * 8,
                "payment_request": "lnbc21n1fake",
            }

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", b"L402 badmac:badpreimage"),
                ],
            }
            request = Request(scope)

            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=request)
            assert exc_info.value.status_code == 402
            assert "Invalid L402 credentials" in _detail_text(exc_info.value.detail)
            assert "WWW-Authenticate" in exc_info.value.headers

    @pytest.mark.asyncio
    async def test_missing_colon_in_token_raises_401(self):
        from fastapi import HTTPException
        from starlette.requests import Request

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings:
            mock_settings.AUTH_ROOT_KEY = "real-key"

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", b"L402 no-colon-here"),
                ],
            }
            request = Request(scope)

            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=request)
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_lsat_prefix_also_accepted(self):
        preimage = b"lsat-preimage"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        root_key = "lsat-root-key"

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status:
            mock_settings.AUTH_ROOT_KEY = root_key
            mock_settings.POST_PRICE_SATS = 21
            mock_status.return_value = (True, 21)

            mac_b64 = mint_macaroon(payment_hash)

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", f"LSAT {mac_b64}:{preimage_hex}".encode()),
                ],
            }
            from starlette.requests import Request
            request = Request(scope)
            result = await require_l402(request=request)
            assert result is None


class TestL402AmountCheck:
    """Prevent cross-endpoint payment reuse via amount-bound LNBits status."""

    @pytest.mark.asyncio
    async def test_underpaid_l402_rejected_with_402(self):
        from fastapi import HTTPException
        from starlette.requests import Request

        preimage = b"cheap-invoice-preimage"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_invoice:
            mock_settings.AUTH_ROOT_KEY = "cross-endpoint-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_status.return_value = (True, 10)
            mock_invoice.return_value = {
                "payment_hash": "aa" * 32,
                "payment_request": "lnbc1000n1fresh",
            }

            mac_b64 = mint_macaroon(payment_hash)
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", f"L402 {mac_b64}:{preimage_hex}".encode()),
                ],
            }
            request = Request(scope)

            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=request, amount_sats=1000)

            assert exc_info.value.status_code == 402
            assert "amount mismatch" in _detail_text(exc_info.value.detail).lower()
            assert "WWW-Authenticate" in exc_info.value.headers

    @pytest.mark.asyncio
    async def test_overpaid_l402_accepted(self):
        """Overpayment is fine; only underpayment is rejected."""
        from starlette.requests import Request

        preimage = b"overpaid-invoice-preimage"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status:
            mock_settings.AUTH_ROOT_KEY = "overpay-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_status.return_value = (True, 5000)

            mac_b64 = mint_macaroon(payment_hash)
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", f"L402 {mac_b64}:{preimage_hex}".encode()),
                ],
            }
            request = Request(scope)
            result = await require_l402(request=request, amount_sats=21)
            assert result is None

    @pytest.mark.asyncio
    async def test_unpaid_l402_rejected(self):
        from fastapi import HTTPException
        from starlette.requests import Request

        preimage = b"unpaid-preimage"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_invoice:
            mock_settings.AUTH_ROOT_KEY = "unpaid-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_status.return_value = (False, 0)
            mock_invoice.return_value = {
                "payment_hash": "bb" * 32,
                "payment_request": "lnbc21n1fresh2",
            }

            mac_b64 = mint_macaroon(payment_hash)
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", f"L402 {mac_b64}:{preimage_hex}".encode()),
                ],
            }
            request = Request(scope)
            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=request, amount_sats=21)
            assert exc_info.value.status_code == 402


class TestL402Replay:
    """ConsumedPayment replay protection on require_l402 when db is provided."""

    @pytest.mark.asyncio
    async def test_replay_blocked_with_fresh_402(self):
        from fastapi import HTTPException
        from starlette.requests import Request

        preimage = b"replay-preimage-bytes"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.l402.check_and_consume_payment", new_callable=AsyncMock) as mock_consume, \
             patch("app.l402.create_invoice", new_callable=AsyncMock) as mock_invoice:
            mock_settings.AUTH_ROOT_KEY = "replay-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_status.return_value = (True, 21)
            mock_consume.return_value = False  # already consumed
            mock_invoice.return_value = {
                "payment_hash": "cc" * 32,
                "payment_request": "lnbc21n1replay",
            }

            mac_b64 = mint_macaroon(payment_hash)
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", f"L402 {mac_b64}:{preimage_hex}".encode()),
                ],
            }
            request = Request(scope)
            fake_db = object()

            with pytest.raises(HTTPException) as exc_info:
                await require_l402(request=request, db=fake_db, amount_sats=21)

            assert exc_info.value.status_code == 402
            assert "already consumed" in _detail_text(exc_info.value.detail).lower()
            assert "WWW-Authenticate" in exc_info.value.headers
            mock_consume.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_first_use_consumes_and_passes(self):
        from starlette.requests import Request

        preimage = b"first-use-preimage"
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        with patch("app.l402.payments_enabled", return_value=True), \
             patch("app.l402.settings") as mock_settings, \
             patch("app.l402.check_payment_status", new_callable=AsyncMock) as mock_status, \
             patch("app.l402.check_and_consume_payment", new_callable=AsyncMock) as mock_consume:
            mock_settings.AUTH_ROOT_KEY = "first-use-key"
            mock_settings.POST_PRICE_SATS = 21
            mock_status.return_value = (True, 21)
            mock_consume.return_value = True

            mac_b64 = mint_macaroon(payment_hash)
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/test",
                "headers": [
                    (b"authorization", f"L402 {mac_b64}:{preimage_hex}".encode()),
                ],
            }
            request = Request(scope)
            result = await require_l402(request=request, db=object(), amount_sats=21)
            assert result is None
            mock_consume.assert_awaited_once()
