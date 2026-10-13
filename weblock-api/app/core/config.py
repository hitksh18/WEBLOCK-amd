"""WebLock Phase 0 - single source of truth for configuration.

All secrets come from environment variables. Nothing is hardcoded.
Import via: from app.core.config import settings
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str = "postgresql+psycopg://postgres:CHANGE_ME@localhost:5432/weblock"

    JWT_SECRET_KEY: str = "CHANGE_ME_ACCESS_SECRET"
    JWT_REFRESH_SECRET_KEY: str = "CHANGE_ME_REFRESH_SECRET"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    APP_ENV: str = "development"  # development | test | production
    LOG_LEVEL: str = "INFO"
    APP_VERSION: str = "0.1.0-phase0"

    LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = 10
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300

    CORRELATION_WINDOW_SECONDS: int = 1800
    RISK_LOOKBACK_HOURS: int = 24
    INCIDENT_MIN_RISK: int = 60

    NOTIFICATIONS_ENABLED: bool = False
    WEBLOCK_EMAIL: str = ""
    WEBLOCK_EMAIL_PASSWORD: str = ""

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def is_test(self) -> bool:
        return self.APP_ENV.lower() == "test"

    def validate_secrets(self) -> list[str]:
        """Return list of problems; empty means OK. Called at startup."""
        problems: list[str] = []
        if "CHANGE_ME" in self.JWT_SECRET_KEY:
            problems.append("JWT_SECRET_KEY is still placeholder")
        if "CHANGE_ME" in self.JWT_REFRESH_SECRET_KEY:
            problems.append("JWT_REFRESH_SECRET_KEY is still placeholder")
        if len(self.JWT_SECRET_KEY) < 32:
            problems.append("JWT_SECRET_KEY too short (<32 chars)")
        if "CHANGE_ME" in self.DATABASE_URL:
            problems.append("DATABASE_URL is still placeholder")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
