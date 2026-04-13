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

    # ── Live collector ───────────────────────────────────────────────────────
    COLLECTOR_ENABLED: bool = False     # opt-in: set to True to start listener
    SYSLOG_HOST: str = "0.0.0.0"
    SYSLOG_PORT: int = 5514
    COLLECTOR_FLUSH_INTERVAL: float = 1.0   # seconds
    COLLECTOR_BATCH_SIZE: int = 100
    COLLECTOR_SOURCE_ID: str = ""       # override; empty = auto-detect
    COLLECTOR_DEVICE_ROLE: str = "unknown"
    RETENTION_DAYS: int = 7             # live events older than this are purged

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
