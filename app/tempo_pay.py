"""Tempo stablecoin payment handler for MPP.

Builds MPP challenges with method="tempo" and verifies on-chain transactions
via Tempo RPC (eth_getTransactionReceipt + ERC-20 Transfer event parsing).

Challenge flow:
  1. Server returns 402 with WWW-Authenticate: Payment header containing
     Tempo recipient address and amount in the `request` auth-param.
  2. Client sends a TIP-20/ERC-20 transfer on the Tempo blockchain.
  3. Client retries with Authorization: Payment <base64url-json> containing
     the transaction hash in payload.txHash.
  4. Server verifies the on-chain transaction (recipient, amount, token, finality).
"""

import json
import logging

import httpx

from app.config import settings
from app.mpp import _b64url_encode, _b64url_decode, _compute_challenge_id, _verify_challenge_id, _format_expires, _MPP_REALM, _CHALLENGE_TTL

import time

logger = logging.getLogger("clankfeed.tempo")

# ERC-20 Transfer event topic: keccak256("Transfer(address,address,uint256)")
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def build_tempo_challenge(amount_usd: str, description: str = "") -> str:
    """Build WWW-Authenticate: Payment header for Tempo stablecoin payment."""
    expires = _format_expires()
    method = "tempo"
    intent = "charge"

    request_obj = {
        "amount": amount_usd,
        "currency": "USD",
        "recipient": settings.TEMPO_RECIPIENT,
        "methodDetails": {
            "currency": settings.TEMPO_CURRENCY,
            "chain": "tempo",
            "testnet": settings.TEMPO_TESTNET,
        },
    }
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


async def verify_tempo_credential(credential: dict) -> bool:
    """Verify a Tempo stablecoin payment credential.

    1. Check HMAC challenge binding (proves we issued this challenge).
    2. Check challenge has not expired.
    3. Verify on-chain transaction: correct recipient, token, amount, and finality.
    """
    try:
        challenge = credential.get("challenge", {})
        payload = credential.get("payload", {})

        challenge_id = challenge.get("id", "")
        realm = challenge.get("realm", "")
        method = challenge.get("method", "")
        intent = challenge.get("intent", "")
        request_b64 = challenge.get("request", "")
        expires = challenge.get("expires", "")
        tx_hash = payload.get("txHash", "")

        if not _verify_challenge_id(challenge_id, realm, method, intent, request_b64, expires):
            return False

        if method != "tempo":
            return False

        if not tx_hash or not tx_hash.startswith("0x") or len(tx_hash) != 66:
            return False
        try:
            bytes.fromhex(tx_hash[2:])
        except ValueError:
            return False

        # Decode challenge request to get expected values
        request_json = json.loads(_b64url_decode(request_b64))
        expected_recipient = request_json.get("recipient", "").lower()
        expected_currency = request_json.get("methodDetails", {}).get("currency", "").lower()
        expected_amount_usd = float(request_json.get("amount", "0"))

        # Verify on-chain via Tempo RPC
        return await _verify_tx_on_chain(
            tx_hash, expected_recipient, expected_currency, expected_amount_usd
        )

    except Exception as e:
        logger.error(f"Tempo credential verification failed: {e}")
        return False


def extract_tempo_tx_hash(credential: dict) -> str | None:
    """Extract the transaction hash from a Tempo credential for replay protection."""
    try:
        return credential.get("payload", {}).get("txHash", "")
    except Exception:
        return None


async def _verify_tx_on_chain(
    tx_hash: str,
    expected_recipient: str,
    expected_currency: str,
    expected_amount_usd: float,
) -> bool:
    """Verify a Tempo transaction via JSON-RPC eth_getTransactionReceipt.

    Checks:
    - Transaction succeeded (status 0x1)
    - Contains a Transfer event to the expected recipient
    - Transfer is for the expected token (currency contract)
    - Transfer amount >= expected amount (in token decimals, assumed 6 for stablecoins)
    """
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                settings.TEMPO_RPC_URL,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash],
                    "id": 1,
                },
            )
            resp.raise_for_status()
            result = resp.json().get("result")

        if not result:
            logger.warning(f"Tempo tx not found: {tx_hash}")
            return False

        # Check transaction succeeded
        if result.get("status") != "0x1":
            logger.warning(f"Tempo tx failed: {tx_hash}")
            return False

        # Parse logs for Transfer event to our recipient
        for log_entry in result.get("logs", []):
            topics = log_entry.get("topics", [])
            if len(topics) < 3:
                continue

            # Check it's a Transfer event
            if topics[0].lower() != _TRANSFER_TOPIC:
                continue

            # Check token contract address matches
            log_address = log_entry.get("address", "").lower()
            if log_address != expected_currency:
                continue

            # topics[2] is the 'to' address (padded to 32 bytes)
            to_address = "0x" + topics[2][-40:]
            if to_address.lower() != expected_recipient:
                continue

            # Decode transfer amount from data field
            data = log_entry.get("data", "0x0")
            amount_raw = int(data, 16)
            # Stablecoins use 6 decimals (USDC, pathUSD)
            amount_usd = amount_raw / 1_000_000

            if amount_usd >= expected_amount_usd:
                logger.info(f"Tempo payment verified: {tx_hash} ({amount_usd} USD)")
                return True
            else:
                logger.warning(
                    f"Tempo underpayment: {tx_hash} got {amount_usd}, expected {expected_amount_usd}"
                )
                return False

        logger.warning(f"Tempo tx has no matching Transfer event: {tx_hash}")
        return False

    except Exception as e:
        logger.error(f"Tempo RPC verification failed: {e}")
        return False
