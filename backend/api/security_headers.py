import secrets
import base64
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


def generate_nonce() -> str:
    """Generate a cryptographically random CSP nonce."""
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def build_csp_header(nonce: str) -> str:
    """
    Build Content-Security-Policy header with nonce.

    The nonce is per-request — never reused.

    Args:
        nonce: Base64-encoded random nonce for this request.

    Returns:
        Complete CSP header value string.
    """
    return (
        f"default-src 'self'; "
        f"script-src 'nonce-{nonce}' 'self' https://unpkg.com "
        f"https://cdnjs.cloudflare.com "
        f"https://cdn.jsdelivr.net blob:; "
        f"style-src 'nonce-{nonce}' 'self' "
        f"https://fonts.googleapis.com; "
        f"font-src 'self' https://fonts.gstatic.com data:; "
        f"connect-src 'self' ws: wss:; "
        f"img-src 'self' data: blob:; "
        f"worker-src 'self' blob:; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self';"
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every HTTP response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        
        # CSP hardened: 'unsafe-eval' removed (no eval() needed by our code).
        # We apply CSP header in the serve_frontend method per request but for API and other requests, we attach a general one here without unsafe-inline.
        # Wait, the instruction says "The index.html route must inject the nonce"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            # Apply strict CSP to API since they don't load HTML
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; form-action 'none';"
            )
            
        return response
