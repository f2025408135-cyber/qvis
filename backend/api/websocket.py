import asyncio
import json
from typing import List
from fastapi import WebSocket, WebSocketDisconnect
import structlog
from backend.threat_engine.models import SimulationSnapshot

logger = structlog.get_logger()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("websocket_connected", total_connections=len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("websocket_disconnected", total_connections=len(self.active_connections))

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error("websocket_send_error", error=str(e))
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error("websocket_broadcast_error", error=str(e))
                self.disconnect(connection)

    async def broadcast_snapshot(self, snapshot: SimulationSnapshot):
        await self.broadcast(snapshot.model_dump_json())

manager = ConnectionManager()
