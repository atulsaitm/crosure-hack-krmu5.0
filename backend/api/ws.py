"""WebSocket endpoint for real-time scan progress."""

import json
import logging
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.models import WSEvent

logger = logging.getLogger("crosure.ws")
logger.setLevel(logging.DEBUG)

router = APIRouter(tags=["websocket"])

# Connected clients
connected_clients: Set[WebSocket] = set()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time scan updates."""
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await websocket.receive_text()
            # Client can send ping/filters
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
    except Exception:
        connected_clients.discard(websocket)


async def broadcast_event(event: WSEvent):
    """Broadcast a scan event to all connected WebSocket clients."""
    logger.debug(f"[WS] Broadcasting: phase={event.phase.value} progress={event.progress:.0%} msg={event.message}")
    if not connected_clients:
        logger.warning("[WS] No connected clients to broadcast to")
        return

    message = event.model_dump()
    message["phase"] = event.phase.value  # Serialize enum

    dead_clients = set()
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception as e:
            logger.warning(f"[WS] Failed to send to client: {e}")
            dead_clients.add(client)

    connected_clients.difference_update(dead_clients)
    logger.debug(f"[WS] Sent to {len(connected_clients) - len(dead_clients)} clients")
