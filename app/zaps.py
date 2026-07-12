"""NIP-57 zap receipt (kind 9735) verification.

Zap receipts are accepted without payment. A verified receipt credits the
zapped note's sats_ext with the full zap amount — the fair combined ranking
shared with clankfeed votes. sats_clank (money paid to clankfeed) is
untouched by zaps.

Verification enforced here: receipt signature (upstream via validate_event),
embedded kind-9734 zap request id + signature, bolt11 amount == zap request
amount tag, and a valid target event id. Full NIP-57 validation would also
check the receipt pubkey against the recipient's LNURL server nostrPubkey;
that requires an HTTP fetch of the recipient's lud16 metadata and is skipped
to keep ingestion free of network round-trips.
"""

import json
import re

from app.nostr import validate_event

# BOLT11 human-readable part: ln + network + optional amount + multiplier,
# followed by the bech32 "1" separator.
_BOLT11_RE = re.compile(r"^ln(?:bcrt|tbs|bc|tb)(\d+)([munp]?)1", re.IGNORECASE)

# msat per unit digit for each BOLT11 multiplier (amounts are in BTC).
# 1 BTC = 100_000_000_000 msat. "p" is 0.1 msat per digit, so the digit
# count must make the total a whole msat.
_MULT_MSAT = {"": 100_000_000_000, "m": 100_000_000, "u": 100_000, "n": 100}


def bolt11_amount_msat(invoice: str) -> int | None:
    """Extract the amount in millisatoshis from a BOLT11 invoice string.

    Returns None for amountless or unparseable invoices.
    """
    if not isinstance(invoice, str):
        return None
    m = _BOLT11_RE.match(invoice.strip())
    if not m:
        return None
    digits, mult = m.group(1), m.group(2).lower()
    if mult == "p":
        # pico-BTC: 10 p = 1 msat
        val = int(digits)
        if val % 10 != 0:
            return None
        return val // 10
    return int(digits) * _MULT_MSAT[mult]


def _first_tag(tags: list, name: str) -> str | None:
    for tag in tags:
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == name:
            return tag[1]
    return None


def verify_zap_receipt(event: dict) -> tuple[str, dict]:
    """Verify a kind-9735 zap receipt (already NIP-01 validated).

    Returns (error, info). On success error is "" and info contains
    target_event_id, sender_pubkey, and amount_sats.
    """
    description = _first_tag(event["tags"], "description")
    if not description:
        return "missing description tag", {}

    try:
        zap_request = json.loads(description)
    except (json.JSONDecodeError, ValueError):
        return "description is not valid JSON", {}
    if not isinstance(zap_request, dict):
        return "description is not a zap request", {}
    if zap_request.get("kind") != 9734:
        return "description is not a kind 9734 zap request", {}

    valid, err = validate_event(zap_request)
    if not valid:
        return f"zap request: {err}", {}

    bolt11 = _first_tag(event["tags"], "bolt11")
    if not bolt11:
        return "missing bolt11 tag", {}
    msat = bolt11_amount_msat(bolt11)
    if not msat or msat < 1000:
        return "bolt11 has no parseable amount of at least 1 sat", {}

    requested = _first_tag(zap_request["tags"], "amount")
    if not requested or not requested.isdigit():
        return "zap request missing amount tag", {}
    if int(requested) != msat:
        return "bolt11 amount does not match zap request amount", {}

    target_event_id = _first_tag(zap_request["tags"], "e")
    if not target_event_id or not re.fullmatch(r"[0-9a-f]{64}", target_event_id):
        return "zap request has no valid e tag", {}

    return "", {
        "target_event_id": target_event_id,
        "sender_pubkey": zap_request["pubkey"],
        "amount_sats": msat // 1000,
    }
