"""Enterprise Authentication and RBAC."""

import hashlib
import secrets
import time
from typing import Optional, Dict, List
from datetime import datetime, timedelta, timezone

from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
import structlog

from backend.config import settings
from backend.metrics import api_auth_failures_total
from backend.security.audit import audit_logger, AuditEvent

logger = structlog.get_logger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Account lockout state
# For in-memory fallback, use an LRU cache so we don't leak memory during an IP spoofing flood
from cachetools import LRUCache
_lockout_tracker: LRUCache = LRUCache(maxsize=10000)
LOCKOUT_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300

class User(BaseModel):
    username: str
    role: str

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

def check_lockout(identifier: str) -> bool:
    """Return True if the user is locked out."""
    state = _lockout_tracker.get(identifier, {"failures": 0, "unlock_time": 0})
    if time.time() < state["unlock_time"]:
        return True
    if time.time() > state["unlock_time"] and state["failures"] >= LOCKOUT_ATTEMPTS:
        # Reset if time expired
        _lockout_tracker[identifier] = {"failures": 0, "unlock_time": 0}
        return False
    return False

def record_failure(identifier: str):
    """Record an authentication failure and lock if needed."""
    state = _lockout_tracker.get(identifier, {"failures": 0, "unlock_time": 0})
    state["failures"] += 1
    if state["failures"] >= LOCKOUT_ATTEMPTS:
        state["unlock_time"] = time.time() + LOCKOUT_DURATION_SECONDS
        logger.warning("account_locked_out", identifier=identifier, duration=LOCKOUT_DURATION_SECONDS)
        
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            user_id=identifier,
            action="LOGIN",
            resource_type="SYSTEM",
            resource_id="auth",
            previous_state=None,
            new_state=None,
            ip_address=identifier,
            user_agent="system",
            status_code=429,
            error_message="LOCKED_OUT"
        )
        audit_logger.log_event(event)

    _lockout_tracker[identifier] = state

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

    client_ip = request.client.host if request.client else "unknown"

    if check_lockout(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    # Try Bearer token first
    if token:
        try:
            payload = jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=[settings.jwt_algorithm])
            username: str = payload.get("sub")
            role: str = payload.get("role", "viewer")
            if username is None:
                record_failure(client_ip)
                raise HTTPException(status_code=401, detail="Invalid authentication credentials")
            return User(username=username, role=role)
        except JWTError:
            api_auth_failures_total.inc()
            record_failure(client_ip)
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
        record_failure(client_ip)
        raise HTTPException(status_code=403, detail="Invalid API key")

    # API key users get admin role by default to preserve backward compatibility
    return User(username="api_key_user", role="admin")

async def verify_api_key(user: Optional[User] = Depends(get_current_user)):
    """Legacy backward-compatibility method."""
    if not settings.auth_enabled:
        return None
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
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
            event = AuditEvent(
                timestamp=datetime.now(timezone.utc),
                user_id=user.username,
                action="AUTHORIZATION",
                resource_type="ENDPOINT",
                resource_id="rbac_denied",
                previous_state=None,
                new_state=None,
                ip_address="unknown",
                user_agent="system",
                status_code=403,
                error_message="DENIED"
            )
            audit_logger.log_event(event)
            raise HTTPException(status_code=403, detail="Not enough privileges")
        return user

admin_required = RoleChecker(["admin"])
analyst_required = RoleChecker(["admin", "analyst"])
viewer_required = RoleChecker(["admin", "analyst", "viewer"])

def verify_ws_token(token: str) -> Optional[User]:
    """Validate JWT token passed to websocket endpoint."""
    if not settings.auth_enabled:
        return User(username="anonymous", role="viewer")
        
    try:
        payload = jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        role: str = payload.get("role", "viewer")
        if username is None:
            return None
        return User(username=username, role=role)
    except JWTError:
        return None
