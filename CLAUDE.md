# CLAUDE.md

## Commands

```bash
# Run dev server
uvicorn app.main:app --reload --port 8089

# Run all tests
python -m pytest

# Run single test file
python -m pytest tests/test_nostr.py
```

## Architecture

Lightweight Nostr relay (NIP-01) with MPP Lightning payment gate. FastAPI serves both WebSocket (relay protocol) and HTTP (payment endpoints + web client).

**Route split:**
- WebSocket `/`: Nostr relay protocol (EVENT, REQ, CLOSE)
- HTTP `GET /`: NIP-11 relay info (if Accept: application/nostr+json) or static web client
- HTTP `/pay`: MPP payment endpoints (GET for 402 challenge, POST for credential verification)
- HTTP `/pay/status`: Payment status polling for web client
- HTTP `/api/post`: Web client note posting (server-signed events)

**Payment flow (programmatic/AI agents):**
1. Client sends EVENT via WebSocket
2. Relay validates signature, responds `["OK", id, false, "payment-required:<url>"]`
3. Client hits HTTP payment endpoint, gets 402 with MPP challenge (Lightning invoice)
4. Client pays invoice, submits MPP credential with preimage
5. Relay verifies, stores event, broadcasts to subscribers

**Payment flow (web client):**
1. POST /api/post with note content
2. Server returns Lightning invoice (BOLT11 + payment_hash)
3. Client displays QR, polls /pay/status
4. On payment, server creates relay-signed event, stores, broadcasts

**Test mode:** `AUTH_ROOT_KEY=test-mode` in `.env` bypasses all payment gates.

## Key Files

- `app/config.py`: All settings (env-based), `payments_enabled()` guard
- `app/nostr.py`: NIP-01 event serialization, id computation, BIP-340 Schnorr signature verification
- `app/relay.py`: WebSocket handler, subscription manager, filter matching
- `app/mpp.py`: MPP protocol (adapted from satring): HMAC-bound challenges, credential verification
- `app/lightning.py`: LNBits API (adapted from satring): invoice creation, payment status
- `app/limiter.py`: Shared slowapi rate limiter instance
- `app/payment.py`: HTTP payment endpoints (rate-limited via slowapi)
- `app/models.py`: SQLAlchemy models (NostrEvent, ConsumedPayment, PendingEvent)
- `app/database.py`: Async SQLAlchemy engine + WAL mode

## Database

SQLite via aiosqlite. Default path: `db/relay.db`. WAL mode for concurrent reads.

## Security Patterns

- BIP-340 Schnorr signature verification on all incoming events
- HMAC-SHA256 challenge binding (stateless, no DB for challenges)
- Replay protection via ConsumedPayment table (unique payment_hash constraint)
- `payments_enabled()` guard in config.py

## Conventions

- Dark terminal theme (green-on-black) for web client
- MPP-only payments (no L402 macaroons, no x402)
- Same LNBits wallet as satring
