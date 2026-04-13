from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    demo_mode: bool = True
    update_interval_seconds: int = 30
    ibm_quantum_token: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_default_region: str = "us-east-1"
    azure_quantum_subscription_id: str = ""
    anthropic_api_key: str = ""

    # Security
    auth_enabled: bool = False
    api_key: str = ""
    rate_limit: str = "60/60"

    # Logging
    log_level: str = Field(default="INFO", description="Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL)")
    log_format: str = Field(default="console", description="Log output format: 'console' or 'json'")

    # GitHub scanner
    github_token: str = ""

    # Alerting
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    webhook_url: str = ""

settings = Settings()
