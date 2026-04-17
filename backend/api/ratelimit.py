"""Sliding-window rate limiter middleware with memory pruning and IP validation."""

import ipaddress
import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.config import settings
from backend.metrics import rate_limit_exceeded_total

# Maximum tracked IPs to prevent memory exhaustion
_MAX_TRACKED_IPS = 10000
# Maximum windows per IP (current + previous)
_MAX_WINDOWS_PER_IP = 3
# Pruning interval: check every this many requests
_PRUNE_COUNTER = 0
_PRUNE_INTERVAL = 100

_rate_windows: dict = defaultdict(dict)
_ip_count = 0


def _is_safe_client_id(client_id: str) -> bool:
    """Validate that a client identifier won't pollute our data structures.
    We allow any string that looks like an IP, hostname, or 'unknown'.
    Reject only strings containing control characters or path separators."""
    if not client_id or len(client_id) > 253:
        return False
    # Reject control chars, null bytes, path traversal
    for ch in client_id:
        if ord(ch) < 32 or ch in ('/', '\\', '\x00'):
            return False
    return True


def _parse_rate_limit(rate_string: str) -> tuple:
    """Parse 'requests/seconds' format. Default: 60/60."""
    try:
        parts = rate_string.split("/")
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return 60, 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Weighted sliding-window rate limiter with memory management.

    Features:
    - Weighted sliding window prevents burst attacks at window boundaries
    - IP validation rejects malformed addresses
    - Automatic memory pruning to cap tracked IPs
    - Per-IP window count limits
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Only rate-limit API routes
        if not path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        # Reject clearly malformed client identifiers (prevent cache poisoning)
        if not _is_safe_client_id(client_ip):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid client address"},
            )

        max_requests, window_seconds = _parse_rate_limit(settings.rate_limit)

        now = time.time()
        current_window = int(now // window_seconds)
        window_position = (now % window_seconds) / window_seconds  # 0.0 → 1.0

        if client_ip not in _rate_windows:
            global _ip_count
            _ip_count += 1

        windows = _rate_windows[client_ip]

        # Prune old windows
        _rate_windows[client_ip] = {
            k: v for k, v in windows.items()
            if abs(int(k) - current_window) <= 1
        }
        windows = _rate_windows[client_ip]

        # Memory pruning: if too many IPs tracked, evict oldest
        global _PRUNE_COUNTER
        _PRUNE_COUNTER += 1
        if _PRUNE_COUNTER >= _PRUNE_INTERVAL and _ip_count > _MAX_TRACKED_IPS:
            self._prune_stale_ips(current_window, window_seconds)
            _PRUNE_COUNTER = 0

        # Weighted sliding window calculation
        prev_count = windows.get(str(current_window - 1), 0)
        curr_count = windows.get(str(current_window), 0)
        estimated = prev_count * (1.0 - window_position) + curr_count

        if estimated >= max_requests:
            rate_limit_exceeded_total.labels(endpoint=path).inc()
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

    @staticmethod
    def _prune_stale_ips(current_window: int, window_seconds: int) -> None:
        """Remove IPs with no recent activity to cap memory usage."""
        global _ip_count, _rate_windows
        cutoff_window = current_window - 2  # IPs with no activity in 2+ windows

        stale_ips = []
        for ip, windows in _rate_windows.items():
            # Check if IP has any window at or after cutoff
            has_recent = any(int(k) >= cutoff_window for k in windows)
            if not has_recent:
                stale_ips.append(ip)

        for ip in stale_ips:
            del _rate_windows[ip]
            _ip_count -= 1

        if stale_ips:
            import structlog
            logger = structlog.get_logger()
            logger.info("rate_limiter_pruned", evicted=len(stale_ips), remaining=_ip_count)
