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

    # Phase 9 AI Security Analyst (disabled unless explicitly enabled with key).
    AI_ENABLED: bool = False
    AI_PROVIDER: str = "openai-compatible"
    AI_MODEL: str = ""
    AI_API_KEY: str = ""
    AI_BASE_URL: str = "https://api.openai.com/v1"
    AI_TIMEOUT_SECONDS: int = 30
    AI_MAX_INPUT_BYTES: int = 12000
    AI_MAX_OUTPUT_BYTES: int = 8000
    AI_MAX_ANALYSES_PER_INCIDENT: int = 20
    AI_MIN_REFRESH_SECONDS: int = 60

    NOTIFICATIONS_ENABLED: bool = False
    WEBLOCK_EMAIL: str = ""
    WEBLOCK_EMAIL_PASSWORD: str = ""

    # Phase 10: browser dashboard origin(s), comma-separated. Empty = no CORS.
    CORS_ORIGINS: str = "http://localhost:5173"

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
