"""Security headers middleware for all HTTP responses."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every HTTP response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # X-XSS-Protection removed — deprecated since Chrome 78 (2019).
        # CSP script-src directive provides equivalent XSS protection.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        # CSP hardened: 'unsafe-eval' removed (no eval() needed by our code).
        # 'unsafe-inline' retained for Three.js inline shaders via <script> tags.
        # blob: is needed for Swagger UI web workers.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://unpkg.com https://cdnjs.cloudflare.com "
            "https://cdn.jsdelivr.net 'unsafe-inline' blob:; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data: blob:; "
            "worker-src 'self' blob:; "
            "font-src 'self' data:; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        # HSTS: enforce HTTPS for 1 year, include subdomains
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        # Cache-Control: no-store for all API responses (real-time threat data)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response
