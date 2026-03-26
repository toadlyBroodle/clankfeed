# Security Audit: clankfeed

**Date:** 2026-03-26
**Auditor:** Claude Code

## CRITICAL

### C1. Private Keys Stored Plaintext in Database
- **File:** `app/models.py:36`, `app/accounts.py:60`
- **Description:** Account Nostr private keys (`nostr_privkey`) stored as plaintext hex in SQLite. Anyone with DB file access can extract all user keys.
- **Fix:** Encrypt private keys at rest using Fernet/AES-GCM with a separate server-side secret.
- **Status:** [x] Fixed: Fernet encryption via `app/crypto.py` using `FIELD_ENCRYPTION_KEY` env var. `app/accounts.py` encrypts on create, `app/api_v1.py` decrypts on use (signing, export). `app/database.py` auto-migrates plaintext keys on startup. `app/models.py` column widened to `Text` for ciphertext. `cryptography` added to requirements.txt.

### C2. Private Key Exposed via GET Endpoint
- **File:** `app/api_v1.py:1014-1029`
- **Description:** `GET /api/v1/account/key` returns private key in response body. GET responses can leak via browser history, referrer headers, proxy logs. Also vulnerable to CSRF via `<img>` tags.
- **Fix:** Change to POST. Consider whether raw private key export is necessary at all.
- **Status:** [x] Fixed: Changed to `POST /api/v1/account/key` in `app/api_v1.py`. Web client updated to use POST in `app/static/index.html` profile fetch.

### C3. NWC Events Bypass Payment Gate Without Validation
- **File:** `app/relay.py:286-289`
- **Description:** NWC event kinds (13194, 23194, 23195) skip payment, content length, and tag validation. Enables free database flooding.
- **Fix:** Apply content length and tag count limits. Consider relay-only (no persistence) for NWC events.
- **Status:** [x] Fixed: Content length (`MAX_CONTENT_LENGTH`) and tag count (`MAX_EVENT_TAGS`) validation added before store/broadcast in `app/relay.py`.

## HIGH

### H1. DOM XSS in Vote Payment Widget
- **File:** `app/static/index.html:796-828`
- **Description:** `showVotePayment` interpolates server data (`bolt11`, `recipient`, `token`) directly into `innerHTML` without escaping.
- **Fix:** Use `esc()` or DOM APIs instead of string concatenation for dynamic values.
- **Status:** [ ]

### H2. API Key in localStorage Vulnerable to XSS
- **File:** `app/static/index.html:200,1070,1114`
- **Description:** API key grants full account access including private key export. Any XSS exfiltrates it via `localStorage.getItem()`.
- **Fix:** Use httpOnly cookies for session management, or eliminate all XSS vectors first.
- **Status:** [ ]

### H3. No Dedicated Rate Limit on Account Creation
- **File:** `app/api_v1.py:827`
- **Description:** Shares `RATE_POST` (10/min). Attacker can create 10 accounts/min/IP, generating keypairs and DB bloat.
- **Fix:** Add stricter rate limit specific to account creation (e.g., 3/hour per IP).
- **Status:** [ ]

### H4. CORS Allows All Origins
- **File:** `app/main.py:276-281`
- **Description:** `allow_origins=["*"]` lets any site make cross-origin GET requests with `X-Account-Key`, reading balances and exporting private keys.
- **Fix:** Restrict to actual deployment domain(s).
- **Status:** [ ]

### H5. Origin Check Bypassed Without Header
- **File:** `app/main.py:129-144`
- **Description:** CSRF protection only triggers when `Origin` header is present. By design for API clients, but combined with CORS wildcard creates a gap.
- **Fix:** Require custom header (e.g., `X-Requested-With`) for browser endpoints. Tighten CORS first (H4).
- **Status:** [ ]

### H6. Deposit Confirm Doesn't Verify Token Ownership
- **File:** `app/api_v1.py:933-1007`
- **Description:** Does not verify that the pending deposit token belongs to the requesting account. Attacker with valid token could credit deposits to their own account.
- **Fix:** Parse `pending.event_json`, extract `deposit_account`, verify it matches `X-Account-Key`.
- **Status:** [ ]

## MEDIUM

### M1. No Floor on Negative Vote Values
- **File:** `app/api_v1.py:670,688`
- **Description:** `value_sats` can go arbitrarily negative via downvotes.
- **Fix:** Add floor check: `max(0, ...)`.
- **Status:** [ ]

### M2. reply-counts Endpoint N+1 Queries
- **File:** `app/api_v1.py:564-583`
- **Description:** Up to 200 separate SQL queries per request. DoS via resource exhaustion.
- **Fix:** Batch into single SQL statement with GROUP BY.
- **Status:** [ ]

### M3. reply_to Filter Doesn't Escape LIKE Wildcards
- **File:** `app/relay.py:132`
- **Description:** `%` and `_` in `reply_to` input could match unintended rows via `contains()` LIKE query.
- **Fix:** Validate reply_to is exactly 64 hex characters.
- **Status:** [ ]

### M4. unsafe-inline in CSP script-src
- **File:** `app/main.py:108`
- **Description:** Weakens XSS protection. Required by inline JS and Tailwind CDN.
- **Fix:** Move inline JS to external files, use nonces for remaining inline scripts.
- **Status:** [ ]

### M5. No WebSocket Per-Connection Rate Limiting
- **File:** `app/main.py:379-400`
- **Description:** Single connection can flood messages with no throttle.
- **Fix:** Add per-connection message rate limiting (e.g., max 30 msg/sec). Disconnect abusers.
- **Status:** [ ]

### M6. Payment Hash Validation Too Loose
- **File:** `app/api_v1.py:344`
- **Description:** Regex `[0-9a-fA-F]+` accepts any length hex. Lightning hashes are always 64 chars.
- **Fix:** Tighten to `[0-9a-fA-F]{64}`.
- **Status:** [ ]

### M7. API Key Injected into innerHTML Without Escaping
- **File:** `app/static/index.html:1079-1094`
- **Description:** `showApiKey(key)` doesn't escape before HTML interpolation.
- **Fix:** Use `esc(key)` or DOM APIs.
- **Status:** [ ]

## LOW

### L1. datetime.utcnow() Deprecated
- **Files:** `relay.py`, `payment.py`, `api_v1.py`, `models.py`
- **Fix:** Replace with `datetime.now(timezone.utc)`.
- **Status:** [ ]

### L2. Error Messages May Leak Internals
- **File:** `app/main.py:84,258`
- **Fix:** Sanitize error details before returning to clients.
- **Status:** [ ]

### L3. No Format Validation on event_id Path Params
- **File:** `app/api_v1.py:440,590`
- **Fix:** Validate `^[0-9a-f]{64}$` before querying.
- **Status:** [ ]

### L4. Single-Quote Breakout in onclick Handlers
- **File:** `app/static/index.html:326-354`
- **Fix:** Use `JSON.stringify()` for JS string contexts, or attach listeners via JS.
- **Status:** [ ]

### L5. No Subscription ID Length Limit
- **File:** `app/relay.py:329`
- **Fix:** Limit to max 256 characters.
- **Status:** [ ]

## INFO

- **I1.** Dependencies unpinned in `requirements.txt`
- **I2.** SQLite DB file permissions may be too permissive
- **I3.** `CLAUDE.md` gitignored but referenced as checked-in
- **I4.** `docs/` gitignored but `docs/SPEC.md` modified
- **I5.** Test mode (`AUTH_ROOT_KEY=test-mode`) disables all security; no startup warning
