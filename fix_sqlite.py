import re
with open("backend/storage/sqlite_db.py", "r") as f:
    content = f.read()

replacement = """    async def health_check(self) -> bool:
        if not self._connection:
            return False
        try:
            await self._ensure_connection()
            await self._connection.execute("SELECT 1")
            return True
        except Exception:
            return False"""

content = content[:content.find("async def health_check(self) -> bool:")] + replacement + content[content.find("    async def close(self) -> None:")-1:]

with open("backend/storage/sqlite_db.py", "w") as f:
    f.write(content)
