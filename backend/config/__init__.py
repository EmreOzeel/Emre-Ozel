from __future__ import annotations

from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Auth ──────────────────────────────────────────────────────────────────
    JWT_SECRET: str = "pcap-analyzer-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = ""
    DB_PATH: str = "/data/pcap.db"

    UPLOAD_DIR: str = "/data/uploads"
    DEFAULT_USER: str = "admin"
    DEFAULT_PASS: str = "admin123"

    # ── Upload security ───────────────────────────────────────────────────────
    MAX_UPLOAD_MB: int = 100
    ALLOWED_EXTENSIONS: List[str] = [".pcap", ".pcapng", ".cap"]

    # ── Analysis limits ───────────────────────────────────────────────────────
    ANALYSIS_TIMEOUT_SEC: int = 300
    MAX_ANALYSES_PER_USER: int = 0

    # ── CORS ──────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: List[str] = ["*"]

    class Config:
        env_file = ".env"

    @property
    def effective_db_url(self) -> str:
        """Return the resolved SQLAlchemy database URL."""
        return self.DATABASE_URL if self.DATABASE_URL else f"sqlite:///{self.DB_PATH}"


settings = Settings()
