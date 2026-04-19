from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="forbid")

    demo_mode: bool = True
    update_interval_seconds: int = 30

    # ─── Credentials (SecretStr — never logged or exposed via repr/dump) ──
    ibm_quantum_token: SecretStr = SecretStr("")
    aws_access_key_id: SecretStr = SecretStr("")
    aws_secret_access_key: SecretStr = SecretStr("")
    aws_default_region: str = "us-east-1"
    azure_quantum_subscription_id: SecretStr = SecretStr("")

    # Security
    auth_enabled: bool = False
    api_key: SecretStr = SecretStr("")
    rate_limit: str = "60/60"

    # Logging
    log_level: str = Field(default="INFO", description="Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL)")
    log_format: str = Field(default="console", description="Log output format: 'console' or 'json'")

    # Database — controls which backend Alembic and the app use.
    db_pool_size: int = 10
    #   SQLite (default): sqlite+aiosqlite:///data/qvis.db
    #   PostgreSQL:       postgresql+asyncpg://user:pass@host:5432/qvis
    database_url: str = Field(
        default="sqlite+aiosqlite:///data/qvis.db",
        description="SQLAlchemy database URL. Supports SQLite and PostgreSQL.",
    )

    # Data Retention — controls automatic cleanup of old records.
    threat_retention_days: int = Field(
        default=30,
        ge=1,
        le=3650,
        description="Days to retain resolved threat events before purging.",
    )
    retention_check_interval_hours: int = Field(
        default=6,
        ge=1,
        le=720,
        description="Hours between automatic retention cleanup cycles.",
    )

    # GitHub scanner
    github_token: SecretStr = SecretStr("")

    # Alerting
    slack_webhook_url: SecretStr = SecretStr("")
    discord_webhook_url: SecretStr = SecretStr("")
    webhook_url: SecretStr = SecretStr("")

def __repr__(self) -> str:
        """Redacted repr — never exposes secret values."""
        return (
            "Settings(demo_mode={!r}, auth_enabled={!r}, log_level={!r}, "
            "threat_retention_days={!r}, retention_check_interval_hours={!r})"
        ).format(
            self.demo_mode, self.auth_enabled, self.log_level,
            self.threat_retention_days, self.retention_check_interval_hours,
        ).format(
            self.demo_mode, self.auth_enabled, self.log_level,
            self.retention_days_threats, self.retention_days_correlations,
        )


settings = Settings()
