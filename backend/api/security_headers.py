"""Security headers middleware for all HTTP responses."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every HTTP response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        # CSP: allow Three.js from CDN, Swagger UI (blob: for web workers),
        # and inline scripts/styles needed by Three.js shaders and Swagger
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://unpkg.com https://cdnjs.cloudflare.com "
            "https://cdn.jsdelivr.net 'unsafe-eval' 'unsafe-inline' blob:; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data: blob:; "
            "worker-src 'self' blob:; "
            "font-src 'self' data:"
        )
        return response
