"""
api.ws_manager
==============
Minimal WebSocket connection manager, used to broadcast each scored
authentication event to any connected dashboard clients in real time.

Kept deliberately simple (a plain list of active connections) since this
is a single-process prototype. A multi-instance production deployment
would need a shared broker (Redis pub/sub, etc.) instead of an in-process
list - noted as a limitation in docs/realtime_dashboard.md.
"""

from __future__ import annotations

from typing import List

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """Send a JSON message to every connected client, dropping any dead ones."""
        living: List[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(message)
                living.append(ws)
            except Exception:
                pass  # client disconnected without a clean close - drop it
        self.active = living


manager = ConnectionManager()
