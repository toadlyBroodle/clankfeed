"""BTC/USD spot rate for converting USD payments to sats."""

import logging
import time

import httpx

logger = logging.getLogger("clankfeed.rates")

# Cache: (timestamp, rate)
_cache: tuple[float, float] = (0.0, 0.0)
_CACHE_TTL = 300  # 5 minutes


async def get_btc_usd_price() -> float:
    """Fetch current BTC/USD price. Cached for 5 minutes.

    Returns 0.0 on failure (caller should handle).
    """
    global _cache
    now = time.time()
    if _cache[0] > now - _CACHE_TTL and _cache[1] > 0:
        return _cache[1]

    # Try CoinGecko (free, no key)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.coingecko.com/api/v3/simple/price",
                params={"ids": "bitcoin", "vs_currencies": "usd"},
            )
            if resp.status_code == 200:
                price = resp.json().get("bitcoin", {}).get("usd", 0.0)
                if price > 0:
                    _cache = (now, price)
                    logger.info(f"BTC/USD rate: ${price:,.0f}")
                    return price
    except Exception as e:
        logger.warning(f"CoinGecko rate fetch failed: {e}")

    # Fallback: return cached even if stale
    if _cache[1] > 0:
        return _cache[1]

    return 0.0


def usd_to_sats(usd_amount: float, btc_price: float) -> int:
    """Convert USD to satoshis at the given BTC/USD rate.

    Returns 0 if rate is invalid.
    """
    if btc_price <= 0 or usd_amount <= 0:
        return 0
    return int((usd_amount / btc_price) * 100_000_000)
