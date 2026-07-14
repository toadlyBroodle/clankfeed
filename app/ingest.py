"""Populate the external feed from public Nostr relays.

One lightweight WebSocket client per relay in EXTERNAL_RELAYS subscribes to
kind-9735 zap receipts. For each verified receipt, the zapped kind-1 note is
fetched (same connection, separate subscription) and stored with sats_ext
credited at face value — the same fair ranking clankfeed votes feed into.
Only zapped notes are stored, never the firehose, so storage stays small.
"""

import asyncio
import json
import logging

import websockets

from app.config import settings, MAX_CONTENT_LENGTH, MAX_EVENT_TAGS
from app.database import async_session
from app.models import NostrEvent
from app.nostr import validate_event
from app.relay import apply_zap_receipt, store_event
from app.zaps import verify_zap_receipt

logger = logging.getLogger("clankfeed.ingest")

BACKFILL_LIMIT = 200  # zap receipts requested on (re)connect
MAX_PENDING_TARGETS = 500  # receipts parked while their note is fetched
RECONNECT_MAX = 300  # seconds


def _acceptable_note(event: dict) -> bool:
    return (
        event.get("kind") == 1
        and len(event.get("content", "")) <= MAX_CONTENT_LENGTH
        and len(event.get("tags", [])) <= MAX_EVENT_TAGS
    )


async def _apply_receipts(target_id: str, receipts: list[tuple[dict, dict]]):
    """Credit parked (event, info) receipts now that their target is stored."""
    async with async_session() as db:
        target = await db.get(NostrEvent, target_id)
        if not target:
            return
        for event, info in receipts:
            if await db.get(NostrEvent, event["id"]):
                continue  # receipt already credited
            await apply_zap_receipt(db, event, info, target)


async def _handle_receipt(ws, event: dict, pending: dict):
    valid, _ = validate_event(event)
    if not valid or event.get("kind") != 9735:
        return
    err, info = verify_zap_receipt(event)
    if err:
        return
    target_id = info["target_event_id"]

    async with async_session() as db:
        if await db.get(NostrEvent, event["id"]):
            return  # duplicate receipt
        target = await db.get(NostrEvent, target_id)
        if target:
            await apply_zap_receipt(db, event, info, target)
            return

    # Target unknown: park the receipt and fetch the note on this connection
    if target_id not in pending and len(pending) >= MAX_PENDING_TARGETS:
        return
    first_request = target_id not in pending
    pending.setdefault(target_id, []).append((event, info))
    if first_request:
        await ws.send(json.dumps(["REQ", f"t-{target_id}", {"ids": [target_id], "limit": 1}]))


async def _handle_target(ws, sub_id: str, event: dict, pending: dict):
    target_id = sub_id[2:]
    receipts = pending.pop(target_id, [])
    await ws.send(json.dumps(["CLOSE", sub_id]))
    if not receipts or event.get("id") != target_id:
        return
    valid, _ = validate_event(event)
    if not valid or not _acceptable_note(event):
        return
    async with async_session() as db:
        await store_event(db, event, sats_clank=0, origin="external")
    await _apply_receipts(target_id, receipts)
    logger.info("Ingested external note %s with %d zap(s)", target_id[:12], len(receipts))


async def _relay_loop(url: str):
    delay = 5
    while True:
        try:
            async with websockets.connect(url, max_size=131072, open_timeout=15) as ws:
                logger.info("Ingest connected: %s", url)
                delay = 5
                pending: dict[str, list] = {}
                await ws.send(json.dumps(["REQ", "zaps", {"kinds": [9735], "limit": BACKFILL_LIMIT}]))
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(msg, list) or len(msg) < 3 or msg[0] != "EVENT":
                        continue
                    sub_id, event = msg[1], msg[2]
                    if not isinstance(event, dict):
                        continue
                    if sub_id == "zaps":
                        await _handle_receipt(ws, event, pending)
                    elif isinstance(sub_id, str) and sub_id.startswith("t-"):
                        await _handle_target(ws, sub_id, event, pending)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Ingest %s: %s (reconnect in %ds)", url, e, delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, RECONNECT_MAX)


def start_ingest_tasks() -> list[asyncio.Task]:
    """Start one ingest task per configured external relay."""
    if not settings.EXTERNAL_INGEST:
        return []
    urls = [u.strip() for u in settings.EXTERNAL_RELAYS.split(",") if u.strip()]
    tasks = [asyncio.create_task(_relay_loop(url)) for url in urls]
    if tasks:
        logger.info("External ingest started for %d relay(s)", len(tasks))
    return tasks
