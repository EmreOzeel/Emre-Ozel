from __future__ import annotations
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Auth ──────────────────────────────────────────────────────────────────
    JWT_SECRET: str = "pcap-analyzer-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    # ── Database ──────────────────────────────────────────────────────────────
    # Set DATABASE_URL to use PostgreSQL (or any other SQLAlchemy-supported DB).
    # If empty, falls back to sqlite at DB_PATH.
    # Examples:
    #   postgresql://user:pass@localhost:5432/pcap
    #   sqlite:////data/pcap.db
    DATABASE_URL: str = ""
    DB_PATH: str = "/data/pcap.db"    # used only when DATABASE_URL is empty

    UPLOAD_DIR: str = "/data/uploads"
    DEFAULT_USER: str = "admin"
    DEFAULT_PASS: str = "admin123"

    # ── Upload security ───────────────────────────────────────────────────────
    MAX_UPLOAD_MB: int = 100          # hard cap per file
    ALLOWED_EXTENSIONS: List[str] = [".pcap", ".pcapng", ".cap"]

    # ── Analysis limits ───────────────────────────────────────────────────────
    ANALYSIS_TIMEOUT_SEC: int = 300   # wall-clock limit per analysis job
    MAX_ANALYSES_PER_USER: int = 0    # 0 = unlimited

    # ── CORS ──────────────────────────────────────────────────────────────────
    # Restrict in production: ["https://your-domain.com"]
    ALLOWED_ORIGINS: List[str] = ["*"]

    class Config:
        env_file = ".env"

    @property
    def effective_db_url(self) -> str:
        """Return the resolved SQLAlchemy database URL."""
        return self.DATABASE_URL if self.DATABASE_URL else f"sqlite:///{self.DB_PATH}"


settings = Settings()
