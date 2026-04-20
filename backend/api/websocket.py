import asyncio
import json
from typing import List, Optional
from fastapi import WebSocket, WebSocketDisconnect
import structlog
import traceback
from backend.threat_engine.models import SimulationSnapshot
from backend.metrics import (
    websocket_connections_active,
    websocket_messages_sent_total,
    websocket_errors_total,
)
from backend.config import settings

logger = structlog.get_logger()

# WebSocket hardening constants
MAX_CONNECTIONS = 200
MAX_MESSAGE_SIZE = 256 * 1024  # 256 KB
MAX_MESSAGES_PER_MINUTE = 60  # Prevent message flooding

# Redis Pub/Sub for HA WebSockets
redis_client = None
pubsub = None

if settings.redis_url:
    try:
        import redis.asyncio as redis
        redis_client = redis.from_url(settings.redis_url)
        pubsub = redis_client.pubsub()
    except Exception as e:
        logger.error("redis_connection_error", error=str(e))
        redis_client = None
        pubsub = None

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._per_client_msg_count: dict = {}  # client -> count
        self._per_client_window_start: dict = {}  # client -> timestamp
        self._redis_task = None
        
        if redis_client:
            self._redis_task = asyncio.create_task(self._redis_listener())

    async def _redis_listener(self):
        """Listen for broadcast messages from Redis and send to local WebSockets."""
        try:
            await pubsub.subscribe("qvis-websocket-broadcast")
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = message["data"].decode("utf-8")
                    await self._local_broadcast(data)
        except Exception as e:
            logger.error("redis_listener_error", error=str(e))

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

    async def _local_broadcast(self, message: str):
        """Send message to all locally connected websockets."""
        from backend.main import _health_state
        from datetime import datetime, timezone
        
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
                _health_state['last_broadcast_at'] = datetime.now(timezone.utc)
                websocket_messages_sent_total.inc()
            except Exception as e:
                logger.error("websocket_broadcast_error", error=str(e))
                websocket_errors_total.inc()
                self.disconnect(connection)

    async def broadcast(self, message: str):
        if redis_client:
            # Publish to Redis so all instances receive it
            await redis_client.publish("qvis-websocket-broadcast", message)
        else:
            # Fallback to local broadcast
            await self._local_broadcast(message)

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
