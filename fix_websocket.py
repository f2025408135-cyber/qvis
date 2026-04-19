import re

with open("backend/api/websocket.py", "r") as f:
    content = f.read()

content = content.replace("await connection.send_text(message)", "await connection.send_text(message)\n                from backend.main import _health_state\n                from datetime import datetime, timezone\n                _health_state['last_broadcast_at'] = datetime.now(timezone.utc)")

with open("backend/api/websocket.py", "w") as f:
    f.write(content)
