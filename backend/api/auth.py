"""API key authentication for protected endpoints."""

import hashlib
import secrets
from functools import wraps
from typing import Optional

from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader

from backend.config import settings

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _hash_key(key: str) -> str:
    """Hash an API key with SHA-256."""
    return hashlib.sha256(key.encode()).hexdigest()


def _get_hashed_key() -> Optional[str]:
    """Return the hashed configured API key, or None if not set."""
    if not settings.api_key:
        return None
    return _hash_key(settings.api_key)


async def verify_api_key(request: Request, api_key: Optional[str] = Depends(API_KEY_HEADER)):
    """FastAPI dependency that validates the X-API-Key header.

    Returns None if auth is disabled. Raises 401 if auth is enabled but
    the key is missing or invalid. Uses constant-time comparison to
    prevent timing attacks.
    """
    if not settings.auth_enabled:
        return None

    expected_hash = _get_hashed_key()
    if not expected_hash:
        # Auth enabled but no key configured — deny all
        raise HTTPException(status_code=401, detail="Server not configured for authentication")

    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")

    if not secrets.compare_digest(_hash_key(api_key), expected_hash):
        raise HTTPException(status_code=403, detail="Invalid API key")

    return True
