"""NIP-57 zap receipt (kind 9735) verification.

Zap receipts are accepted without payment. A verified receipt credits the
zapped note's sats_ext with the full zap amount — the fair combined ranking
shared with clankfeed votes. sats_clank (money paid to clankfeed) is
untouched by zaps.

Verification: receipt signature (upstream via validate_event), embedded
kind-9734 zap request id + signature, bolt11 amount == zap request amount
tag, valid target event id, and (async) receipt pubkey == the recipient's
LNURL-pay `nostrPubkey` (fetched from their lud16 metadata and cached).
"""

import ipaddress
import json
import logging
import re
import socket
import time

import httpx
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NostrEvent
from app.nostr import validate_event

logger = logging.getLogger("clankfeed.zaps")

# lud16 -> (fetched_at, nostrPubkey or None for negative cache)
_lnurl_cache: dict[str, tuple[float, str | None]] = {}
_LNURL_CACHE_TTL = 3600  # 1 hour — successful pubkey lookups
_LNURL_NEGATIVE_CACHE_TTL = 60  # errors / missing nostrPubkey

# Hostnames that must never be fetched even if DNS is unexpected.
_BLOCKED_LNURL_HOSTS = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata",
})

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


def lud16_to_lnurlp_url(lud16: str) -> str | None:
    """Convert a lightning address (user@domain) to an LNURL-pay HTTPS URL."""
    if not isinstance(lud16, str) or "@" not in lud16:
        return None
    user, _, domain = lud16.strip().partition("@")
    if not user or not domain or "@" in domain or "/" in domain:
        return None
    return f"https://{domain.lower()}/.well-known/lnurlp/{user}"


def _is_non_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ip must not be fetched (loopback/private/link-local/etc.)."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip.is_reserved)
    )


def lnurl_host_is_safe(host: str) -> bool:
    """Resolve host and reject loopback/private/link-local/metadata targets.

    Used before any server-side HTTP GET of lud16 LNURL-pay metadata (SSRF).
    """
    if not isinstance(host, str) or not host:
        return False
    host = host.strip().lower().rstrip(".")
    if not host or host in _BLOCKED_LNURL_HOSTS:
        return False
    # Bracketed IPv6 literals from URL parsing are not expected in lud16 domains,
    # but strip brackets if present.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    try:
        ip = ipaddress.ip_address(host)
        return not _is_non_public_ip(ip)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if _is_non_public_ip(ip):
            return False
    return True


def clear_lnurl_cache() -> None:
    """Clear the in-process LNURL nostrPubkey cache (tests)."""
    _lnurl_cache.clear()


def extract_lud16_from_kind0_content(content: str) -> str | None:
    """Parse kind:0 JSON content for a lud16 lightning address."""
    try:
        meta = json.loads(content)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(meta, dict):
        return None
    lud16 = meta.get("lud16")
    if isinstance(lud16, str) and "@" in lud16:
        return lud16.strip()
    return None


async def get_author_lud16(db: AsyncSession, pubkey: str) -> str | None:
    """Return lud16 from the latest stored kind:0 for pubkey, if any."""
    stmt = select(NostrEvent).where(
        and_(NostrEvent.pubkey == pubkey, NostrEvent.kind == 0)
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if not row:
        return None
    return extract_lud16_from_kind0_content(row.content)


async def fetch_lnurl_nostr_pubkey(lud16: str) -> str | None:
    """Fetch LNURL-pay metadata for lud16; return nostrPubkey if allowsNostr.

    Successful pubkeys cache for _LNURL_CACHE_TTL; misses/errors use the
    shorter _LNURL_NEGATIVE_CACHE_TTL so brief LNURL blips do not block
    sats_ext credits for a full hour.
    """
    now = time.time()
    cached = _lnurl_cache.get(lud16)
    if cached:
        fetched_at, cached_pk = cached
        ttl = _LNURL_CACHE_TTL if cached_pk is not None else _LNURL_NEGATIVE_CACHE_TTL
        if fetched_at > now - ttl:
            return cached_pk

    url = lud16_to_lnurlp_url(lud16)
    if not url:
        _lnurl_cache[lud16] = (now, None)
        return None

    # SSRF: never GET loopback/private/link-local/metadata targets.
    host = url.split("://", 1)[-1].split("/", 1)[0]
    if not lnurl_host_is_safe(host):
        logger.warning("LNURL SSRF blocked for lud16=%s host=%s", lud16, host)
        _lnurl_cache[lud16] = (now, None)
        return None

    pubkey: str | None = None
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if (
                    isinstance(data, dict)
                    and data.get("allowsNostr") is True
                    and isinstance(data.get("nostrPubkey"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", data["nostrPubkey"].lower())
                ):
                    pubkey = data["nostrPubkey"].lower()
    except Exception as e:
        logger.warning("LNURL fetch failed for %s: %s", lud16, e)

    _lnurl_cache[lud16] = (now, pubkey)
    return pubkey


async def verify_zap_receipt_signer(
    event: dict, recipient_pubkey: str, db: AsyncSession
) -> str:
    """NIP-57 Appendix F: receipt.pubkey must equal author's LNURL nostrPubkey.

    Returns an error string on failure, or "" on success. Fail-closed: missing
    lud16 or unreachable LNURL metadata rejects the receipt.
    """
    lud16 = await get_author_lud16(db, recipient_pubkey)
    if not lud16:
        return "author has no lud16 metadata"

    expected = await fetch_lnurl_nostr_pubkey(lud16)
    if not expected:
        return "could not resolve LNURL nostrPubkey"

    if event.get("pubkey", "").lower() != expected:
        return "receipt pubkey does not match LNURL nostrPubkey"

    return ""


def verify_zap_receipt(event: dict) -> tuple[str, dict]:
    """Verify a kind-9735 zap receipt (already NIP-01 validated).

    Returns (error, info). On success error is "" and info contains
    target_event_id, sender_pubkey, recipient_pubkey, and amount_sats.
    Signer/LNURL checks are async — see verify_zap_receipt_signer.
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

    recipient_pubkey = _first_tag(zap_request["tags"], "p")
    if not recipient_pubkey or not re.fullmatch(r"[0-9a-f]{64}", recipient_pubkey):
        return "zap request has no valid p tag", {}

    return "", {
        "target_event_id": target_event_id,
        "sender_pubkey": zap_request["pubkey"],
        "recipient_pubkey": recipient_pubkey,
        "amount_sats": msat // 1000,
    }
