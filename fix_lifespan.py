import re
with open("backend/main.py.bak", "r") as f:
    bak_content = f.read()

with open("backend/main.py", "r") as f:
    content = f.read()

bak_lifespan = bak_content[bak_content.find("async def lifespan(app: FastAPI):") : bak_content.find("# ─── FastAPI App")]
content = content[:content.find("async def lifespan(app: FastAPI):")] + bak_lifespan + content[content.find("# ─── FastAPI App"):]

with open("backend/main.py", "w") as f:
    f.write(content)
