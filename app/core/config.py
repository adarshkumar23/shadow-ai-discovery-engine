"""
PATENT NOTICE
Module: core/config
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_version: str = "0.1.0"
    app_name: str = "shadow-ai-discovery"
    log_level: str = "INFO"
    database_url: str
    shadow_ai_enabled: bool = True
    shadow_ai_fernet_key: str = ""
    okta_client_id: str = ""
    okta_client_secret: str = ""
    azure_ad_client_id: str = ""
    azure_ad_client_secret: str = ""
    azure_ad_redirect_uri: str = ""
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""
    connector_rate_limit_per_hour: int = 1000
    aws_control_test_access_key_id: str = ""
    aws_control_test_secret_access_key: str = ""
    aws_control_test_region: str = "ap-south-1"

    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False
    )


settings = Settings()
