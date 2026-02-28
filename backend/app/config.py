from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    # Application
    APP_NAME: str = "AI-Powered SAST"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://sast_user:dev_password@localhost:5432/sast_db"
    DATABASE_URL_SYNC: str = "postgresql://sast_user:dev_password@localhost:5432/sast_db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Security
    JWT_SECRET: str = "change-this-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_DAYS: int = 7

    # OpenAI
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4-turbo-preview"
    OPENAI_MAX_TOKENS: int = 2000
    OPENAI_FALLBACK_MODEL: str = "gpt-3.5-turbo"

    # GitHub
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:3000/auth/github/callback"

    # Storage
    REPORT_STORAGE_PATH: str = "./reports"
    SCAN_STORAGE_PATH: str = "/tmp/scans"

    # Scanning Limits
    MAX_FILE_SIZE_MB: int = 10
    SCAN_TIMEOUT_MINUTES: int = 30
    MAX_FILES_PER_SCAN: int = 1000
    MAX_LINES_PER_FILE: int = 10000

    # Docker Sandbox
    ENABLE_SANDBOX: bool = False
    SANDBOX_TIMEOUT_MINUTES: int = 5

    @property
    def report_path(self) -> Path:
        p = Path(self.REPORT_STORAGE_PATH)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def scan_path(self) -> Path:
        p = Path(self.SCAN_STORAGE_PATH)
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
