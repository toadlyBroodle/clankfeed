"""Stripe SPT payment handler for MPP (method=stripe).

Implements the MPP Stripe charge intent:
  https://mpp.dev/payment-methods/stripe/charge

Challenge flow:
  1. Server returns 402 with WWW-Authenticate: Payment method="stripe" containing
     amount (minor units), currency, decimals, and methodDetails
     (networkId + paymentMethodTypes). No PaymentIntent is created yet.
  2. Client creates a Shared Payment Token (SPT) scoped to networkId / amount.
  3. Client retries with Authorization: Payment … payload.spt = "spt_…".
  4. Server creates+confirms a Stripe PaymentIntent using the SPT and checks
     status=succeeded and amount >= challenge amount.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from app.config import settings
from app.mpp import (
    _b64url_encode,
    _b64url_decode,
    _compute_challenge_id,
    _verify_challenge_id,
    _format_expires,
    _MPP_REALM,
)

# Preview API version required for Shared Payment Token endpoints
_STRIPE_SPT_API_VERSION = "2026-04-22.preview"
_SPT_TTL_SECONDS = 600

logger = logging.getLogger("clankfeed.stripe")

_DEFAULT_PAYMENT_METHOD_TYPES = ["card", "link"]


def usd_to_cents(amount_usd: str) -> int:
    """Convert a decimal USD string to integer cents (round half up via round())."""
    return int(round(float(amount_usd) * 100))


def build_stripe_challenge(amount_usd: str | None = None, description: str = "") -> str:
    """Build WWW-Authenticate: Payment header for Stripe SPT (MPP stripe.charge)."""
    usd = amount_usd or settings.STRIPE_PRICE_USD
    amount_cents = usd_to_cents(usd)
    expires = _format_expires()
    method = "stripe"
    intent = "charge"

    request_obj = {
        "amount": str(amount_cents),
        "currency": "usd",
        "decimals": 2,
        "methodDetails": {
            "networkId": settings.STRIPE_PROFILE_ID,
            "paymentMethodTypes": list(_DEFAULT_PAYMENT_METHOD_TYPES),
        },
    }
    if description:
        request_obj["description"] = description
    request_b64 = _b64url_encode(json.dumps(request_obj, separators=(",", ":")).encode())

    challenge_id = _compute_challenge_id(
        _MPP_REALM, method, intent, request_b64, expires,
    )

    parts = [
        f'id="{challenge_id}"',
        f'realm="{_MPP_REALM}"',
        f'method="{method}"',
        f'intent="{intent}"',
        f'request="{request_b64}"',
        f'expires="{expires}"',
    ]
    if description:
        safe_desc = description.replace('"', '\\"')
        parts.append(f'description="{safe_desc}"')

    return "Payment " + ", ".join(parts)


def parse_stripe_challenge_header(header: str) -> dict[str, str]:
    """Parse `Payment id="…", realm="…", …` into a dict of param values."""
    params: dict[str, str] = {}
    body = header[len("Payment "):] if header.startswith("Payment ") else header
    for part in body.split(", "):
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        params[key.strip()] = val.strip().strip('"')
    return params


def stripe_challenge_echo(
    amount_usd: str | None = None,
    description: str = "",
) -> dict[str, str]:
    """Challenge fields for JSON 402 bodies (browser multi-WWW-Authenticate is flaky)."""
    header = build_stripe_challenge(amount_usd, description)
    params = parse_stripe_challenge_header(header)
    return {
        "id": params.get("id", ""),
        "realm": params.get("realm", ""),
        "method": params.get("method", "stripe"),
        "intent": params.get("intent", "charge"),
        "request": params.get("request", ""),
        "expires": params.get("expires", ""),
    }


async def create_spt_from_payment_method(
    payment_method: str,
    *,
    amount_cents: int | None = None,
) -> str:
    """Mint an SPT for a Stripe PaymentMethod (MPP createToken proxy).

    Amount/currency/expiry are ALWAYS server-derived — never trust client values.
    Test keys use test_helpers/shared_payment/granted_tokens; live keys use
    shared_payment/issued_tokens scoped to STRIPE_PROFILE_ID.
    """
    if not payment_method or not str(payment_method).startswith("pm_"):
        raise ValueError("payment_method must be a Stripe pm_… id")

    cents = amount_cents if amount_cents is not None else usd_to_cents(settings.STRIPE_PRICE_USD)
    if cents < 50:
        # Stripe card SPT floor
        cents = 50
    expires_at = int(time.time()) + _SPT_TTL_SECONDS
    secret = settings.STRIPE_SECRET_KEY or ""
    network_id = settings.STRIPE_PROFILE_ID or ""

    def _create() -> str:
        import stripe

        stripe.api_key = secret
        params: dict[str, Any] = {
            "payment_method": payment_method,
            "usage_limits": {
                "currency": "usd",
                "max_amount": cents,
                "expires_at": expires_at,
            },
        }
        if secret.startswith("sk_test"):
            path = "/v1/test_helpers/shared_payment/granted_tokens"
        else:
            path = "/v1/shared_payment/issued_tokens"
            params["seller_details"] = {"network_business_profile": network_id}

        resp = stripe.raw_request(
            "post",
            path,
            params=params,
            headers={"Stripe-Version": _STRIPE_SPT_API_VERSION},
        )
        # raw_request returns StripeResponse or similar with .data / parsed body
        body = resp
        if hasattr(resp, "data"):
            body = resp.data
        if isinstance(body, (bytes, bytearray)):
            body = json.loads(body.decode())
        elif isinstance(body, str):
            body = json.loads(body)
        elif not isinstance(body, dict):
            # StripeObject
            body = dict(body) if hasattr(body, "keys") else {"id": getattr(body, "id", "")}

        spt_id = (body or {}).get("id") or ""
        if not spt_id or not str(spt_id).startswith("spt_"):
            raise RuntimeError(f"Stripe SPT mint returned unexpected body: {body!r}")
        return str(spt_id)

    return await asyncio.to_thread(_create)


def extract_stripe_spt(credential: dict) -> str:
    """Extract the SPT id from a Stripe MPP credential payload."""
    try:
        return credential.get("payload", {}).get("spt", "") or ""
    except Exception as e:
        logger.warning("Failed to extract Stripe SPT: %s", e)
        return ""


def extract_stripe_payment_id(credential: dict) -> str | None:
    """Replay-protection id: PaymentIntent id (set during verify) or SPT fallback."""
    try:
        payload = credential.get("payload", {}) or {}
        pi = payload.get("payment_intent_id") or ""
        if pi:
            return pi
        spt = payload.get("spt") or ""
        return spt or None
    except Exception as e:
        logger.warning("Failed to extract Stripe payment id: %s", e)
        return None


async def _create_payment_intent_from_spt(
    *,
    spt: str,
    amount_cents: int,
    currency: str = "usd",
) -> Any:
    """Create+confirm a PaymentIntent consuming an SPT. Runs Stripe SDK off-loop."""

    def _create() -> Any:
        import stripe

        stripe.api_key = settings.STRIPE_SECRET_KEY
        return stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            confirm=True,
            payment_method_data={
                "shared_payment_granted_token": spt,
            },
        )

    return await asyncio.to_thread(_create)


async def verify_stripe_credential(credential: dict) -> bool:
    """Verify a Stripe SPT MPP credential.

    1. HMAC challenge binding + expiry.
    2. method == stripe; payload.spt present.
    3. Create+confirm PaymentIntent from SPT; require succeeded + amount.
    On success, sets payload.payment_intent_id for replay protection.
    """
    try:
        challenge = credential.get("challenge", {})
        payload = credential.setdefault("payload", {})

        challenge_id = challenge.get("id", "")
        realm = challenge.get("realm", "")
        method = challenge.get("method", "")
        intent = challenge.get("intent", "")
        request_b64 = challenge.get("request", "")
        expires = challenge.get("expires", "")
        spt = payload.get("spt", "") or ""

        if not _verify_challenge_id(challenge_id, realm, method, intent, request_b64, expires):
            return False

        if method != "stripe":
            return False

        if not spt or not str(spt).startswith("spt_"):
            return False

        request_json = json.loads(_b64url_decode(request_b64))
        expected_cents = int(request_json.get("amount", "0"))
        currency = (request_json.get("currency") or "usd").lower()

        pi = await _create_payment_intent_from_spt(
            spt=spt,
            amount_cents=expected_cents,
            currency=currency,
        )
        if pi is None:
            return False

        status = getattr(pi, "status", None) or (pi.get("status") if isinstance(pi, dict) else None)
        amount = getattr(pi, "amount", None)
        if amount is None and isinstance(pi, dict):
            amount = pi.get("amount")
        pi_id = getattr(pi, "id", None) or (pi.get("id") if isinstance(pi, dict) else None)
        pi_currency = getattr(pi, "currency", None) or (
            pi.get("currency") if isinstance(pi, dict) else None
        )

        if status != "succeeded":
            logger.warning("Stripe PI not succeeded: %s status=%s", pi_id, status)
            return False

        if int(amount or 0) < expected_cents:
            logger.warning(
                "Stripe underpay: pi=%s got %s expected %s", pi_id, amount, expected_cents,
            )
            return False

        if pi_currency and str(pi_currency).lower() != currency:
            logger.warning("Stripe currency mismatch: %s vs %s", pi_currency, currency)
            return False

        if pi_id:
            payload["payment_intent_id"] = pi_id
        logger.info("Stripe payment verified: %s (%s cents)", pi_id, amount)
        return True

    except Exception as e:
        logger.error("Stripe credential verification failed: %s", e)
        return False
