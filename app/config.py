import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./db/relay.db")
    PAYMENT_URL: str = os.getenv("PAYMENT_URL", "")
    PAYMENT_KEY: str = os.getenv("PAYMENT_KEY", "")
    AUTH_ROOT_KEY: str = os.getenv("AUTH_ROOT_KEY", "")
    POST_PRICE_SATS: int = int(os.getenv("POST_PRICE_SATS", "21"))
    RELAY_PRIVATE_KEY: str = os.getenv("RELAY_PRIVATE_KEY", "")
    RELAY_NAME: str = os.getenv("RELAY_NAME", "clankfeed")
    RELAY_DESCRIPTION: str = os.getenv(
        "RELAY_DESCRIPTION", "Lightning-paid Nostr relay for AI agents"
    )
    RELAY_CONTACT: str = os.getenv("RELAY_CONTACT", "")
    BASE_URL: str = os.getenv("BASE_URL", "ws://localhost:8089")
    APP_PORT: int = int(os.getenv("APP_PORT", "8089"))


settings = Settings()


def payments_enabled() -> bool:
    """Return True only if AUTH_ROOT_KEY is set to a real key.
    'test-mode' explicitly disables payment gates."""
    return bool(settings.AUTH_ROOT_KEY) and settings.AUTH_ROOT_KEY != "test-mode"


# Input limits
MAX_CONTENT_LENGTH = 8196
MAX_EVENT_TAGS = 100
MAX_SUBSCRIPTIONS_PER_CONN = 20
MAX_FILTERS_PER_REQ = 10
MAX_MESSAGE_BYTES = 65536
PENDING_EVENT_TTL = 600  # 10 minutes
MAX_CONNECTIONS = 200
ALLOWED_EVENT_KINDS = {1}  # MVP: only kind 1 (short text notes)

# SECURITY: Rate limits per IP. Change values here, not in individual files.
RATE_POST = "10/minute"
RATE_PAY = "30/minute"
RATE_PAY_STATUS = "30/minute"
RATE_POST_CONFIRM = "10/minute"
