"""Outbox fan-out: republish paid local events to public Nostr relays.

Best-effort NIP-01 EVENT publish after a successful clankfeed store. Failures
are logged and never fail the local accept. Disabled when OUTBOX_ENABLED=false
(tests / ops). Ingest-sourced (origin=external) rows are never outboxed.
"""

from __future__ import annotations

import asyncio
import json
import logging

import websockets

from app.config import settings

logger = logging.getLogger("clankfeed.outbox")

OUTBOX_CONNECT_TIMEOUT = 10  # seconds
OUTBOX_RECV_TIMEOUT = 15  # seconds waiting for OK
OUTBOX_MAX_CONCURRENT = 5


def outbox_relay_urls() -> list[str]:
    return [u.strip() for u in settings.OUTBOX_RELAYS.split(",") if u.strip()]


async def _publish_one(url: str, event: dict) -> bool:
    """Send ["EVENT", event] to one relay; True on OK true for this event id."""
    eid = event.get("id", "")
    try:
        async with websockets.connect(
            url,
            max_size=65536,
            open_timeout=OUTBOX_CONNECT_TIMEOUT,
            close_timeout=5,
        ) as ws:
            await ws.send(json.dumps(["EVENT", event]))
            deadline = asyncio.get_running_loop().time() + OUTBOX_RECV_TIMEOUT
            while asyncio.get_running_loop().time() < deadline:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue
                if (
                    isinstance(msg, list)
                    and len(msg) >= 3
                    and msg[0] == "OK"
                    and msg[1] == eid
                ):
                    ok = bool(msg[2])
                    if ok:
                        logger.info("Outbox OK: relay=%s event=%s", url, eid[:12])
                    else:
                        reason = msg[3] if len(msg) > 3 else ""
                        logger.warning(
                            "Outbox rejected: relay=%s event=%s reason=%s",
                            url, eid[:12], reason,
                        )
                    return ok
            logger.warning("Outbox timeout waiting OK: relay=%s event=%s", url, eid[:12])
            return False
    except Exception as e:
        logger.warning("Outbox fail: relay=%s event=%s err=%s", url, eid[:12], e)
        return False


async def outbox_event(event: dict) -> None:
    """Fan-out EVENT to each OUTBOX_RELAYS URL. No-op when disabled."""
    if not settings.OUTBOX_ENABLED:
        return
    urls = outbox_relay_urls()
    if not urls:
        return
    eid = (event or {}).get("id", "")[:12]
    logger.info("Outbox fan-out: event=%s relays=%d", eid, len(urls))
    sem = asyncio.Semaphore(OUTBOX_MAX_CONCURRENT)

    async def _guarded(url: str) -> bool:
        async with sem:
            return await _publish_one(url, event)

    results = await asyncio.gather(*[_guarded(u) for u in urls], return_exceptions=True)
    ok_n = sum(1 for r in results if r is True)
    logger.info("Outbox done: event=%s ok=%d/%d", eid, ok_n, len(urls))


def schedule_outbox(event: dict) -> None:
    """Fire-and-forget outbox from a running event loop (never raises)."""
    if not settings.OUTBOX_ENABLED:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug("Outbox skipped: no running event loop")
        return
    loop.create_task(outbox_event(event), name=f"outbox-{event.get('id', '')[:12]}")
