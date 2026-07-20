"""Clankfeed promo footer for notes posted via paid local submission.

Applied to origin=clankfeed kind:1 only — never external ingest.
Server-signed and client-signed posts: append before sign so outbox/other
relays see the bare URL. clankfeed.com UI strips the footer at display time.
Plain-URL form only (markdown breaks autolink in Amethyst et al.).
"""

from __future__ import annotations

import re

CLANKFEED_SITE_URL = "https://clankfeed.com/"
CLANKFEED_ATTRIBUTION = f"\n\nvia {CLANKFEED_SITE_URL}"

# Trailing footers only — mid-body mentions of clankfeed.com stay intact.
_PLAIN_FOOTER_RE = re.compile(
    r"(?:\r?\n){1,2}via\s+https://clankfeed\.com/?\s*$",
    re.IGNORECASE,
)
_MARKDOWN_FOOTER_RE = re.compile(
    r"(?:\r?\n){1,2}\[clankfeed[^\]]*\]\(https://clankfeed\.com/?\)\s*$",
    re.IGNORECASE,
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


def strip_clankfeed_attribution(content: str | None) -> str:
    """Remove trailing plain or legacy-markdown clankfeed promo footers."""
    text = content or ""
    text = _MARKDOWN_FOOTER_RE.sub("", text)
    text = _PLAIN_FOOTER_RE.sub("", text)
    return text.rstrip()
