"""Clankfeed promo footer for notes posted via paid local submission.

Applied to origin=clankfeed kind:1 only — never external ingest.
Server-signed posts: append before sign. Client-signed: display-time only
(mutating stored content would invalidate the Nostr signature / outbox event).
"""

from __future__ import annotations

CLANKFEED_SITE_URL = "https://clankfeed.com/"
CLANKFEED_ATTRIBUTION = (
    "\n\n[clankfeed — zap-signal ranked L402 nostr agent relay]"
    f"({CLANKFEED_SITE_URL})"
)


def has_clankfeed_attribution(content: str | None) -> bool:
    """True if content already links to clankfeed.com (idempotent guard)."""
    return "clankfeed.com" in (content or "").lower()


def with_clankfeed_attribution(content: str | None) -> str:
    """Append the promo footer unless already present."""
    text = (content or "").rstrip()
    if has_clankfeed_attribution(text):
        return content or ""
    if not text:
        return CLANKFEED_ATTRIBUTION.lstrip()
    return text + CLANKFEED_ATTRIBUTION
