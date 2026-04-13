"""Sliding-window rate limiter middleware."""

import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.config import settings

_rate_windows: dict = defaultdict(dict)


def _parse_rate_limit(rate_string: str) -> tuple:
    """Parse 'requests/seconds' format. Default: 60/60."""
    try:
        parts = rate_string.split("/")
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return 60, 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Weighted sliding-window rate limiter.

    Weights the previous window by how much of it has elapsed,
    preventing burst attacks at window boundaries.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Only rate-limit API routes
        if not path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        max_requests, window_seconds = _parse_rate_limit(settings.rate_limit)

        now = time.time()
        current_window = int(now // window_seconds)
        window_position = (now % window_seconds) / window_seconds  # 0.0 → 1.0

        if client_ip not in _rate_windows:
            _rate_windows[client_ip] = {}

        windows = _rate_windows[client_ip]

        # Prune windows older than previous
        _rate_windows[client_ip] = {
            k: v for k, v in windows.items()
            if abs(int(k) - current_window) <= 1
        }
        windows = _rate_windows[client_ip]

        # Weighted sliding window calculation
        prev_count = windows.get(str(current_window - 1), 0)
        curr_count = windows.get(str(current_window), 0)
        estimated = prev_count * (1.0 - window_position) + curr_count

        if estimated >= max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(window_seconds)},
            )

        # Increment counter for current window
        windows[str(current_window)] = windows.get(str(current_window), 0) + 1

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(int(max_requests - estimated - 1), 0))
        return response
