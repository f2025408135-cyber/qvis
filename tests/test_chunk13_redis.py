import pytest
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_redis_broadcast():
    with patch("backend.api.websocket.redis_client", new_callable=AsyncMock) as mock_redis:
        from backend.api.websocket import manager
        
        # Test broadcast calls redis publish if it's set
        await manager.broadcast("test_message")
        mock_redis.publish.assert_called_once_with("qvis-websocket-broadcast", "test_message")
