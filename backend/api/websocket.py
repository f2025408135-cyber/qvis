import asyncio
import json
from typing import List, Optional
from fastapi import WebSocket, WebSocketDisconnect
import structlog
from backend.threat_engine.models import SimulationSnapshot
from backend.metrics import (
    websocket_connections_active,
    websocket_messages_sent_total,
    websocket_errors_total,
)

logger = structlog.get_logger()

# WebSocket hardening constants
MAX_CONNECTIONS = 200
MAX_MESSAGE_SIZE = 256 * 1024  # 256 KB
MAX_MESSAGES_PER_MINUTE = 60  # Prevent message flooding


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._per_client_msg_count: dict = {}  # client -> count
        self._per_client_window_start: dict = {}  # client -> timestamp

    def _check_message_rate(self, websocket: WebSocket) -> bool:
        """Check if a client is sending too many messages. Returns True if allowed."""
        import time as _time
        now = _time.monotonic()
        client_id = id(websocket)

        if client_id not in self._per_client_window_start:
            self._per_client_window_start[client_id] = now
            self._per_client_msg_count[client_id] = 1
            return True

        window_start = self._per_client_window_start[client_id]
        if now - window_start > 60.0:
            # Reset window
            self._per_client_window_start[client_id] = now
            self._per_client_msg_count[client_id] = 1
            return True

        self._per_client_msg_count[client_id] = self._per_client_msg_count.get(client_id, 0) + 1
        if self._per_client_msg_count[client_id] > MAX_MESSAGES_PER_MINUTE:
            return False
        return True

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept a WebSocket connection. Returns False if max connections reached."""
        if len(self.active_connections) >= MAX_CONNECTIONS:
            logger.warning("websocket_max_connections_reached", current=len(self.active_connections), max=MAX_CONNECTIONS)
            await websocket.close(code=1013, reason="Maximum connections reached")
            return False

        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("websocket_connected", total_connections=len(self.active_connections))
        websocket_connections_active.set(len(self.active_connections))
        return True

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            client_id = id(websocket)
            self._per_client_msg_count.pop(client_id, None)
            self._per_client_window_start.pop(client_id, None)
            logger.info("websocket_disconnected", total_connections=len(self.active_connections))
            websocket_connections_active.set(len(self.active_connections))

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error("websocket_send_error", error=str(e))
            websocket_errors_total.inc()
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
                websocket_messages_sent_total.inc()
            except Exception as e:
                logger.error("websocket_broadcast_error", error=str(e))
                websocket_errors_total.inc()
                self.disconnect(connection)

    async def broadcast_snapshot(self, snapshot: SimulationSnapshot):
        await self.broadcast(snapshot.model_dump_json())

    def validate_message(self, data: str, websocket: WebSocket) -> bool:
        """Validate an incoming message. Returns False if it should be rejected."""
        # Size check
        if len(data) > MAX_MESSAGE_SIZE:
            logger.warning("websocket_message_too_large", size=len(data), max=MAX_MESSAGE_SIZE)
            return False

        # Rate check
        if not self._check_message_rate(websocket):
            logger.warning("websocket_message_rate_exceeded", client=id(websocket))
            return False

        return True


manager = ConnectionManager()
