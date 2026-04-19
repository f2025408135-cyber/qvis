with open("backend/main.py", "r") as f:
    content = f.read()

import re

# find serve_frontend and replace it with python string manipulation instead of regex sub.
start_idx = content.find('@app.get("/{full_path:path}")\nasync def serve_frontend(full_path: str):')
if start_idx == -1:
    print("Could not find start idx!")

end_str = 'raise HTTPException(status_code=404, detail="Frontend not found")'
end_idx = content.find(end_str, start_idx)
if end_idx == -1:
    print("Could not find end idx!")
end_idx += len(end_str)

replacement = """
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from backend.api.security_headers import generate_nonce, build_csp_header

templates = Jinja2Templates(directory="frontend")

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: starlette.requests.Request):
    nonce = generate_nonce()
    response = templates.TemplateResponse(
        "index.html",
        {"request": request, "csp_nonce": nonce}
    )
    response.headers["Content-Security-Policy"] = build_csp_header(nonce)
    return response

@app.get("/{full_path:path}")
async def serve_frontend(request: starlette.requests.Request, full_path: str):
    \"\"\"Serves the SPA frontend files. Rejects null bytes and reserved paths.\"\"\"
    # Let FastAPI handle its own built-in routes
    if full_path in _RESERVED_PATHS:
        raise HTTPException(status_code=404, detail="Not a frontend route")

    # Block null bytes (all variants)
    if "\\x00" in full_path or "%00" in full_path.lower():
        raise HTTPException(status_code=400, detail="Invalid path")

    # Block path traversal — check both raw and URL-decoded forms
    decoded = unquote(full_path)
    if ".." in full_path or ".." in decoded:
        raise HTTPException(status_code=403, detail="Path traversal blocked")

    from pathlib import Path
    import mimetypes
    frontend_dir = Path(__file__).parent.parent / "frontend"

    if full_path and (frontend_dir / full_path).is_file():
        from starlette.responses import FileResponse
        media_type = mimetypes.guess_type(full_path)[0] or "application/octet-stream"
        return FileResponse(frontend_dir / full_path, media_type=media_type)

    # SPA fallback: serve index.html for any unmatched route
    index_file = frontend_dir / "index.html"
    if index_file.is_file():
        nonce = generate_nonce()
        response = templates.TemplateResponse(
            "index.html",
            {"request": request, "csp_nonce": nonce}
        )
        response.headers["Content-Security-Policy"] = build_csp_header(nonce)
        return response
    raise HTTPException(status_code=404, detail="Frontend not found")
"""

new_content = "import starlette.requests\n" + content[:start_idx] + replacement.strip() + content[end_idx:]

with open("backend/main.py", "w") as f:
    f.write(new_content)
