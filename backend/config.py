from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    demo_mode: bool = True
    update_interval_seconds: int = 30
    ibm_quantum_token: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_default_region: str = "us-east-1"
    azure_quantum_subscription_id: str = ""
    anthropic_api_key: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
