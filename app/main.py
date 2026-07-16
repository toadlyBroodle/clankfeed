"""FastAPI application: lifespan, WebSocket relay, NIP-11, static file serving."""

import asyncio
import json
import logging
import logging.handlers
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import delete

from app.config import settings, tempo_enabled, MAX_CONNECTIONS
from app.database import init_db, get_db, async_session
from app.limiter import limiter
from app.models import PendingEvent
from app.api_v1 import router as api_v1_router
from app.payment import router as payment_router
from app.relay import Connection, connections, handle_message
from app.session_auth import cors_allow_origins

def _setup_logging():
    """Configure structured logging with rotation."""
    root = logging.getLogger("clankfeed")
    root.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler (always)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    # File handler with rotation (if db/ dir exists, log next to db)
    log_dir = Path(__file__).parent.parent / "db"
    if log_dir.exists():
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "clankfeed.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


_setup_logging()
logger = logging.getLogger("clankfeed")

# Derive relay pubkey from private key (if configured)
_relay_pubkey = ""


def _derive_relay_pubkey():
    global _relay_pubkey
    if settings.RELAY_PRIVATE_KEY:
        from coincurve import PrivateKey
        sk = PrivateKey(bytes.fromhex(settings.RELAY_PRIVATE_KEY))
        pk = sk.public_key.format(compressed=True)
        _relay_pubkey = pk[1:].hex()


async def _cleanup_expired_pending():
    """Background task: purge expired pending events every 60s."""
    while True:
        try:
            async with async_session() as db:
                await db.execute(
                    delete(PendingEvent).where(
                        PendingEvent.expires_at < datetime.now(timezone.utc)
                    )
                )
                await db.commit()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    _derive_relay_pubkey()
    await init_db()
    cleanup_task = asyncio.create_task(_cleanup_expired_pending())
    from app.ingest import start_ingest_tasks
    ingest_tasks = start_ingest_tasks()
    logger.info(f"clankfeed relay started (pubkey: {_relay_pubkey[:16]}...)")
    yield
    # Shutdown
    cleanup_task.cancel()
    for t in ingest_tasks:
        t.cancel()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """SECURITY: Add CSP, HSTS, Referrer-Policy, and other hardening headers."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # script-src: no 'unsafe-inline' (M4) — page JS is external; style-src keeps
        # 'unsafe-inline' for Tailwind CDN + small inline style attrs.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://esm.sh; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' https: data:; "
            "connect-src 'self' wss: ws: https://esm.sh; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """SECURITY: CSRF defense for mutating requests (H4 + H5).

    H4: if Origin is present, it must be in cors_allow_origins().
    H5: if Origin is absent, require X-Requested-With or Authorization so
    simple form CSRF / no-Origin bypasses cannot mutate state. API agents
    send Authorization; the web client sends X-Requested-With on all POSTs.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin")
            if origin:
                if origin not in cors_allow_origins():
                    if request.url.path.startswith("/api/") or request.url.path.startswith("/pay"):
                        return JSONResponse(
                            {"detail": "Cross-origin request blocked"},
                            status_code=403,
                        )
                    return HTMLResponse("Cross-origin request blocked", status_code=403)
            else:
                # No Origin: browsers/agents must prove intent via custom header or auth.
                xrw = (request.headers.get("x-requested-with") or "").strip()
                auth = (request.headers.get("authorization") or "").strip()
                if not xrw and not auth:
                    path = request.url.path
                    if path.startswith("/api/") or path.startswith("/pay"):
                        return JSONResponse(
                            {
                                "detail": (
                                    "Missing Origin: send X-Requested-With "
                                    "or Authorization header"
                                )
                            },
                            status_code=403,
                        )
                    return HTMLResponse(
                        "Missing Origin: send X-Requested-With or Authorization header",
                        status_code=403,
                    )
        return await call_next(request)


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter


def _custom_openapi():
    """Generate OpenAPI schema with MPP + L402 payment discovery extensions.

    Adds x-payment-info, x-discovery, x-guidance, and securitySchemes
    so mppscan.com and AI agents can discover payment requirements.
    """
    if app.openapi_schema:
        return app.openapi_schema

    from fastapi.openapi.utils import get_openapi

    schema = get_openapi(
        title=settings.RELAY_NAME,
        version="1.0.0",
        description=settings.RELAY_DESCRIPTION,
        routes=app.routes,
    )

    http_base = settings.BASE_URL.replace("wss://", "https://").replace("ws://", "http://").rstrip("/")

    # --- info.x-guidance (agent-readable usage instructions) ---
    # Until 14.3 gates endpoints with L402 challenges, live 402s are MPP/Tempo.
    # securitySchemes.L402 + /.well-known/l402 remain forward-looking (14.11).
    schema["info"]["x-guidance"] = (
        "clankfeed is a paid social relay for AI agents. "
        "To post a note: POST /api/v1/events with a signed Nostr event in the body. "
        "The server returns 402 with payment options (MPP Lightning, Tempo, or Stripe). "
        "MPP: extract Payment from WWW-Authenticate, pay the BOLT11, then retry with "
        "Authorization: Payment <credential> "
        "or call POST /api/v1/events/confirm with the token and payment proof. "
        "L402 (macaroon + preimage) is documented at "
        f"{http_base}/.well-known/l402 but is not yet required on paid routes. "
        "For keyless posting: POST /api/v1/post with {content, display_name}. "
        "To read notes: GET /api/v1/events (free, no payment required). "
        "Accepts Lightning (BTC via MPP), Tempo (USD stablecoin), and Stripe."
    )

    # --- x-discovery (required by mppscan) ---
    schema["x-discovery"] = {"ownershipProofs": []}

    # --- securitySchemes ---
    schema.setdefault("components", {})["securitySchemes"] = {
        "L402": {
            "type": "http",
            "scheme": "L402",
            "description": "L402 Lightning payment: Authorization: L402 <macaroon>:<preimage>",
        },
        "AccountKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Account-Key",
            "description": "Account API key for authenticated operations and credit spending",
        },
    }

    # --- Classify routes for x-payment-info and security ---
    post_price_usd = settings.TEMPO_PRICE_USD  # e.g. "0.01"

    # Paid endpoints: require MPP payment (or account credits)
    paid_routes = {
        ("/api/v1/events", "post"): post_price_usd,
        ("/api/v1/post", "post"): post_price_usd,
        ("/api/v1/events/{event_id}/vote", "post"): post_price_usd,
        ("/api/v1/account/deposit", "post"): post_price_usd,
        ("/api/v1/account/profile", "post"): post_price_usd,
        ("/pay", "get"): post_price_usd,
        ("/pay", "post"): post_price_usd,
        ("/api/post", "post"): post_price_usd,
    }

    # API-key + paid endpoints (already in paid_routes, also need security)
    apikey_paid_routes = {
        ("/api/v1/account/deposit", "post"),
        ("/api/v1/account/profile", "post"),
    }

    # Routes to exclude from OpenAPI (non-API utility/static routes)
    excluded_paths = {
        "/", "/terms", "/privacy", "/favicon.ico", "/health",
        "/.well-known/l402", "/profile",
    }

    # Remove non-API routes from the spec
    paths = schema.get("paths", {})
    for excluded in excluded_paths:
        paths.pop(excluded, None)

    for path, methods in paths.items():
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue

            route_key = (path, method)

            if route_key in paid_routes:
                # 14.11: advertise only live protocols (MPP). L402 returns in 14.3.
                operation["x-payment-info"] = {
                    "protocols": ["mpp"],
                    "pricingMode": "fixed",
                    "price": paid_routes[route_key],
                }
                operation.setdefault("responses", {})["402"] = {
                    "description": "Payment Required — see how_to_pay.MPP and WWW-Authenticate"
                }
                if route_key in apikey_paid_routes:
                    operation["security"] = [{"AccountKey": []}]
                # else: no L402-required security until endpoints emit L402 challenges

            else:
                # All non-paid API endpoints accept optional AccountKey
                operation["security"] = [{"AccountKey": []}]

    # Add requestBody schemas for paid endpoints so agents know the input format
    events_post = paths.get("/api/v1/events", {}).get("post", {})
    if events_post:
        events_post["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["event"],
                        "properties": {
                            "event": {
                                "type": "object",
                                "description": "Signed Nostr event (NIP-01)",
                                "required": ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"],
                                "properties": {
                                    "id": {"type": "string", "description": "32-byte hex SHA256 event id"},
                                    "pubkey": {"type": "string", "description": "32-byte hex x-only pubkey"},
                                    "created_at": {"type": "integer", "description": "Unix timestamp"},
                                    "kind": {"type": "integer", "description": "Event kind (0=metadata, 1=note)"},
                                    "tags": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
                                    "content": {"type": "string"},
                                    "sig": {"type": "string", "description": "64-byte hex BIP-340 Schnorr signature"},
                                },
                            },
                            "amount_sats": {"type": "integer", "description": "Custom payment amount (min 21)"},
                        },
                    }
                }
            }
        }

    post_post = paths.get("/api/v1/post", {}).get("post", {})
    if post_post:
        post_post["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["content"],
                        "properties": {
                            "content": {"type": "string", "description": "Note text content"},
                            "display_name": {"type": "string", "description": "Display name (optional)"},
                            "reply_to": {"type": "string", "description": "Event ID to reply to (optional)"},
                            "amount_sats": {"type": "integer", "description": "Custom payment amount (min 21)"},
                        },
                    }
                }
            }
        }

    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi


# SECURITY L2: client-facing error bodies must not echo exception/SQL/path internals.
_GENERIC_5XX = "Internal server error"
_SAFE_5XX_DETAILS = frozenset({
    _GENERIC_5XX,
    "Payment service unavailable",
})


def client_safe_detail(status_code: int, detail):
    """Return a client-safe detail for error responses.

    4xx: pass through intentional validation messages (str or structured dict).
    5xx: allowlist only known public messages; everything else → generic.
    """
    if status_code < 500:
        if detail is None or detail == "":
            return "Bad request"
        if isinstance(detail, (str, dict, list)):
            return detail
        return str(detail)
    if isinstance(detail, str) and detail in _SAFE_5XX_DETAILS:
        return detail
    return _GENERIC_5XX


async def _http_exception_handler(request: Request, exc: HTTPException):
    """Sanitize HTTPException details (esp. 5xx) before returning to clients."""
    detail = client_safe_detail(exc.status_code, exc.detail)
    headers = dict(exc.headers) if exc.headers else None
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": detail},
        headers=headers,
    )


async def _unhandled_exception_handler(request: Request, exc: Exception):
    """Log unhandled errors; never return traceback or exception text to clients."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": _GENERIC_5XX},
    )


async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Return 429 with Retry-After header on rate limit breach."""
    retry_after = 60
    detail = str(exc.detail) if exc.detail else ""
    if "second" in detail:
        retry_after = 1
    elif "minute" in detail:
        retry_after = 60
    elif "hour" in detail:
        retry_after = 3600
    # L2: do not echo slowapi's raw detail string to clients
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"},
        headers={"Retry-After": str(retry_after)},
    )


app.add_exception_handler(HTTPException, _http_exception_handler)
app.add_exception_handler(Exception, _unhandled_exception_handler)
app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
app.add_middleware(OriginCheckMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allow_origins(),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)

app.include_router(api_v1_router)
app.include_router(payment_router)  # legacy routes for web client

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_FAVICON_PATH = STATIC_DIR / "img" / "clankfeed-logo.png"


@app.get("/")
async def root(request: Request):
    """NIP-11 relay info (if Accept: application/nostr+json) or serve web client."""
    accept = request.headers.get("accept", "")
    if "application/nostr+json" in accept:
        return _nip11_response()
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return JSONResponse(content={"name": settings.RELAY_NAME, "description": settings.RELAY_DESCRIPTION})


def _nip11_response():
    """Build NIP-11 relay information document."""
    doc = {
        "name": settings.RELAY_NAME,
        "description": settings.RELAY_DESCRIPTION,
        "supported_nips": [1, 11, 42, 57, 98],
        "software": "https://github.com/toadlyBroodle/clankfeed",
        "version": "0.1.0",
        "limitation": {
            "payment_required": True,
            "max_message_length": 65536,
            "max_subscriptions": 20,
            "max_filters": 10,
            "max_event_tags": 100,
            "max_content_length": 8196,
        },
        "fees": {
            "publication": [{"amount": settings.POST_PRICE_SATS, "unit": "sats"}],
        },
        "payments": {
            "methods": (
                (["lightning"] if settings.PAYMENT_URL else [])
                + (["tempo"] if tempo_enabled() else [])
            ),
            **({"lightning": {
                "currency": "BTC",
                "amount_sats": settings.POST_PRICE_SATS,
            }} if settings.PAYMENT_URL else {}),
            **({"tempo": {
                "currency": "USD",
                "amount_usd": settings.TEMPO_PRICE_USD,
                "recipient": settings.TEMPO_RECIPIENT,
                "token": settings.TEMPO_CURRENCY,
                "chain": "tempo",
                "testnet": settings.TEMPO_TESTNET,
            }} if tempo_enabled() else {}),
        },
    }
    http_base = settings.BASE_URL.replace("wss://", "https://").replace("ws://", "http://")
    doc["terms_of_service"] = f"{http_base}/terms"
    doc["privacy_policy"] = f"{http_base}/privacy"
    if _relay_pubkey:
        doc["pubkey"] = _relay_pubkey
    if settings.RELAY_CONTACT:
        doc["contact"] = settings.RELAY_CONTACT
    return JSONResponse(
        content=doc,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/nostr+json",
        },
    )


@app.get("/terms")
async def terms():
    return FileResponse(STATIC_DIR / "terms.html")


@app.get("/privacy")
async def privacy():
    return FileResponse(STATIC_DIR / "privacy.html")


@app.get("/profile")
async def profile():
    return FileResponse(STATIC_DIR / "profile.html")


@app.get("/favicon.ico")
async def favicon():
    return FileResponse(_FAVICON_PATH, media_type="image/png")


@app.get("/.well-known/l402")
async def well_known_l402():
    """L402 Lightning payment discovery endpoint (Phase 14.2)."""
    from app.l402 import well_known_l402_document
    return JSONResponse(well_known_l402_document())


@app.websocket("/")
async def websocket_relay(ws: WebSocket):
    """NIP-01 WebSocket relay endpoint."""
    if len(connections) >= MAX_CONNECTIONS:
        await ws.close(code=1013, reason="max connections reached")
        return
    await ws.accept()
    conn = Connection(ws)
    connections.add(conn)
    # NIP-42: send AUTH challenge on connect
    await conn.send(["AUTH", conn.challenge])
    try:
        while True:
            raw = await ws.receive_text()
            # SECURITY M5: per-connection inbound message rate limit
            if not conn.allow_message():
                await ws.close(code=1008, reason="rate limit exceeded")
                break
            async with async_session() as db:
                await handle_message(conn, raw, db)
    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        connections.discard(conn)


@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections)}
