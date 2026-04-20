"""Enterprise Authentication and RBAC."""

import hashlib
import secrets
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone

from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
import structlog

from backend.config import settings
from backend.metrics import api_auth_failures_total

logger = structlog.get_logger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


class User(BaseModel):
    username: str
    role: str

# Legacy API Key support
def _hash_key(key: str) -> str:
    """Hash an API key with SHA-256."""
    return hashlib.sha256(key.encode()).hexdigest()

def _get_hashed_key() -> Optional[str]:
    """Return the hashed configured API key, or None if not set."""
    secret = settings.api_key.get_secret_value()
    if not secret:
        return None
    return _hash_key(secret)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm)
    return encoded_jwt


async def get_current_user(
    request: Request,
    api_key: Optional[str] = Depends(API_KEY_HEADER),
    token: Optional[str] = Depends(oauth2_scheme)
) -> Optional[User]:
    """
    FastAPI dependency that validates either X-API-Key header OR Bearer token.
    Returns User object with role, or None if auth is disabled.
    """
    if not settings.auth_enabled:
        return None

    # Try Bearer token first
    if token:
        try:
            payload = jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=[settings.jwt_algorithm])
            username: str = payload.get("sub")
            role: str = payload.get("role", "viewer")
            if username is None:
                raise HTTPException(status_code=401, detail="Invalid authentication credentials")
            return User(username=username, role=role)
        except JWTError:
            api_auth_failures_total.inc()
            raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Fallback to API Key
    expected_hash = _get_hashed_key()
    if not expected_hash:
        api_auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Server not configured for authentication")

    if not api_key:
        api_auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Authentication required")

    if not secrets.compare_digest(_hash_key(api_key), expected_hash):
        api_auth_failures_total.inc()
        raise HTTPException(status_code=403, detail="Invalid API key")

    # API key users get admin role by default to preserve backward compatibility
    return User(username="api_key_user", role="admin")

async def verify_api_key(user: Optional[User] = Depends(get_current_user)):
    """Legacy backward-compatibility method."""
    if not settings.auth_enabled:
        return None
    if user is None:
        raise HTTPException(status_code=401, detail="API key required")
    return True

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    async def __call__(self, user: Optional[User] = Depends(get_current_user)):
        if not settings.auth_enabled:
            return None
        
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
            
        if user.role not in self.allowed_roles:
            logger.warning("auth_rbac_denied", username=user.username, role=user.role, required=self.allowed_roles)
            raise HTTPException(status_code=403, detail="Not enough privileges")
        return user

admin_required = RoleChecker(["admin"])
analyst_required = RoleChecker(["admin", "analyst"])
viewer_required = RoleChecker(["admin", "analyst", "viewer"])

