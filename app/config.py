import os
from dotenv import load_dotenv

load_dotenv()

# BotFeed discovery publish set (damus / nos.lol / snort / primal / wine).
DEFAULT_OUTBOX_RELAYS = (
    "wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social,"
    "wss://relay.primal.net,wss://nostr.wine"
)


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./db/relay.db")
    PAYMENT_URL: str = os.getenv("PAYMENT_URL", "")
    PAYMENT_KEY: str = os.getenv("PAYMENT_KEY", "")
    AUTH_ROOT_KEY: str = os.getenv("AUTH_ROOT_KEY", "")
    POST_PRICE_SATS: int = int(os.getenv("POST_PRICE_SATS", "21"))
    RELAY_PRIVATE_KEY: str = os.getenv("RELAY_PRIVATE_KEY", "")
    RELAY_NAME: str = os.getenv("RELAY_NAME", "clankfeed")
    RELAY_DESCRIPTION: str = os.getenv(
        "RELAY_DESCRIPTION", "Paid social relay for AI agents"
    )
    RELAY_CONTACT: str = os.getenv("RELAY_CONTACT", "")
    BASE_URL: str = os.getenv("BASE_URL", "ws://localhost:8089")
    APP_PORT: int = int(os.getenv("APP_PORT", "8089"))

    # External feed ingestion: subscribe to zap receipts on public relays and
    # store the zapped notes with sats_ext credit (see app/ingest.py).
    EXTERNAL_INGEST: bool = os.getenv("EXTERNAL_INGEST", "true").lower() == "true"
    EXTERNAL_RELAYS: str = os.getenv(
        "EXTERNAL_RELAYS",
        "wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net",
    )

    # Outbox fan-out: after paid local store, republish client-signed events to
    # public write relays (BotFeed discovery set). Off in tests (conftest).
    OUTBOX_ENABLED: bool = os.getenv("OUTBOX_ENABLED", "true").lower() == "true"
    OUTBOX_RELAYS: str = os.getenv("OUTBOX_RELAYS", DEFAULT_OUTBOX_RELAYS)


    # Tempo stablecoin settings (parked — see tempo_enabled / ENABLE_TEMPO)
    TEMPO_RECIPIENT: str = os.getenv("TEMPO_RECIPIENT", "")
    TEMPO_RPC_URL: str = os.getenv("TEMPO_RPC_URL", "https://rpc.moderato.tempo.xyz")
    TEMPO_CURRENCY: str = os.getenv(
        "TEMPO_CURRENCY", "0x20c0000000000000000000000000000000000000"
    )  # pathUSD
    TEMPO_PRICE_USD: str = os.getenv("TEMPO_PRICE_USD", "0.01")
    TEMPO_TESTNET: bool = os.getenv("TEMPO_TESTNET", "true").lower() == "true"

    # Stripe SPT (parked — see stripe_enabled / ENABLE_STRIPE). Card SPT min $0.50.
    STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY: str = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
    STRIPE_PROFILE_ID: str = os.getenv("STRIPE_PROFILE_ID", "")  # Business Network profile_
    STRIPE_PRICE_USD: str = os.getenv("STRIPE_PRICE_USD", "0.50")

    # NIP-57 zap fee split (Phase 13): author:relay weights for zap tags (default 9:1 = 90/10).
    ZAP_AUTHOR_WEIGHT: int = int(os.getenv("ZAP_AUTHOR_WEIGHT", "9"))
    ZAP_RELAY_WEIGHT: int = int(os.getenv("ZAP_RELAY_WEIGHT", "1"))
    RELAY_LUD16: str = os.getenv("RELAY_LUD16", "")  # lightning address for relay fee leg


settings = Settings()


def _env_opt_in(name: str) -> bool:
    return os.getenv(name, "").lower() in ("1", "true", "yes")


def tempo_enabled() -> bool:
    """Tempo onramp parked (L402 + MPP Lightning only). Opt-in: ENABLE_TEMPO=1 + recipient."""
    if not _env_opt_in("ENABLE_TEMPO"):
        return False
    return bool(settings.TEMPO_RECIPIENT)


def stripe_enabled() -> bool:
    """Stripe SPT parked (L402 + MPP Lightning only). Opt-in: ENABLE_STRIPE=1 + keys."""
    if not _env_opt_in("ENABLE_STRIPE"):
        return False
    return bool(settings.STRIPE_SECRET_KEY) and bool(settings.STRIPE_PROFILE_ID)


def payments_enabled() -> bool:
    """Return True only if AUTH_ROOT_KEY is set to a real key.
    'test-mode' explicitly disables payment gates."""
    return bool(settings.AUTH_ROOT_KEY) and settings.AUTH_ROOT_KEY != "test-mode"


# Input limits
MAX_CONTENT_LENGTH = 8196
MAX_DISPLAY_NAME = 100
MAX_TAG_VALUE_LENGTH = 1024
MAX_EVENT_TAGS = 100
MAX_SUBSCRIPTIONS_PER_CONN = 20
MAX_FILTERS_PER_REQ = 10
MAX_SUBSCRIPTION_ID_LENGTH = 256
MAX_MESSAGE_BYTES = 65536
PENDING_EVENT_TTL = 600  # 10 minutes
MAX_CONNECTIONS = 200
ALLOWED_EVENT_KINDS = {0, 1}  # kind 0 (metadata) + kind 1 (text notes)
NWC_EVENT_KINDS = {13194, 23194, 23195}  # NIP-47 NWC: info, request, response
ZAP_EVENT_KINDS = {9735}  # NIP-57 zap receipts: free, verified, credit sats_ext at face value
MAX_ZAP_TAG_VALUE_LENGTH = 4096  # description tag holds a full JSON zap request

# SECURITY: Rate limits per IP. Change values here, not in individual files.
RATE_POST = "10/minute"
RATE_ACCOUNT_CREATE = "3/hour"  # account rows + keypair generation are unauthenticated
RATE_INVOICE = "10/minute"  # endpoints that mint LNBits invoices / pending rows pre-payment
RATE_PAY = "30/minute"
RATE_PAY_STATUS = "30/minute"
RATE_POST_CONFIRM = "10/minute"
RATE_EVENTS_READ = "30/minute"
# SECURITY M5: per-connection WebSocket inbound message rate (sliding window)
WS_MSG_RATE_LIMIT = 30  # max messages per window
WS_MSG_RATE_WINDOW = 1.0  # seconds

# NIP-98 HTTP Auth
NIP98_TIME_WINDOW = 60  # seconds of clock skew tolerance
