from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr
from typing import List, Optional
import os

class Settings(BaseSettings):
    # === AUTHENTICATION (SECURE BY DEFAULT) ===
    auth_enabled: bool = Field(default=True, description="MUST be True in production")
    jwt_secret: SecretStr = Field(
        default_factory=lambda: SecretStr(os.getenv("QVIS_JWT_SECRET", os.urandom(32).hex())),
        description="Cryptographically secure random key if not provided"
    )
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30
    
    # === DEMO MODE DISABLED BY DEFAULT ===
    demo_mode: bool = Field(default=False, description="MUST be False in production")

    # === DATABASE ===
    database_url: SecretStr = Field(
        default_factory=lambda: SecretStr(os.getenv("QVIS_DATABASE_URL", "sqlite+aiosqlite:///./data/qvis_production.db")),
        description="Always use SecretStr to prevent credential leakage"
    )
    db_pool_size: int = 20
    
    # Data Retention
    retention_days_threats: int = 30
    retention_days_correlations: int = 90
    retention_check_interval_hours: int = 6

    # === RATE LIMITING ===
    rate_limit: str = "60/60"

    # === ENCRYPTION ===
    encryption_enabled: bool = True
    encryption_password: SecretStr = Field(
        default_factory=lambda: SecretStr(os.getenv("QVIS_ENCRYPTION_PASSWORD", "super-secret-password-12345!"))
    )
    encryption_salt: SecretStr = Field(
        default_factory=lambda: SecretStr(os.getenv("QVIS_ENCRYPTION_SALT", os.urandom(16).hex()))
    )

    # === METRICS & MONITORING ===
    metrics_auth_required: bool = True
    metrics_allowed_users: List[str] = ["admin", "monitoring-service"]

    # Integrations
    ibm_quantum_token: SecretStr = Field(default=SecretStr(""))
    aws_access_key_id: SecretStr = Field(default=SecretStr(""))
    aws_secret_access_key: SecretStr = Field(default=SecretStr(""))
    azure_quantum_subscription_id: SecretStr = Field(default=SecretStr(""))
    github_token: SecretStr = Field(default=SecretStr(""))
    
    redis_url: Optional[str] = None
    
    log_level: str = "INFO"
    log_format: str = "json"

    model_config = {
        "env_file": ".env.production",
        "env_prefix": "QVIS_",
        "extra": "ignore"
    }

settings = Settings()

# Validate strict production settings
if not os.environ.get("PYTEST_CURRENT_TEST"):
    if settings.demo_mode:
        raise RuntimeError("CRITICAL: DEMO_MODE must be False in production")
    if not settings.auth_enabled:
        raise RuntimeError("CRITICAL: AUTH_ENABLED must be True in production")
    if not settings.jwt_secret.get_secret_value():
        raise RuntimeError("CRITICAL: JWT_SECRET_KEY must be set")
