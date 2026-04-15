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

    # ── Live collector ───────────────────────────────────────────────────────
    COLLECTOR_ENABLED: bool = False
    SYSLOG_HOST: str = "0.0.0.0"
    SYSLOG_PORT: int = 5514
    COLLECTOR_FLUSH_INTERVAL: float = 1.0
    COLLECTOR_BATCH_SIZE: int = 100
    COLLECTOR_SOURCE_ID: str = ""
    COLLECTOR_DEVICE_ROLE: str = "unknown"
    SYSLOG_MAX_EPS: int = 5000
    SYSLOG_PER_IP_MAX_EPS: int = 500
    NETFLOW_ENABLED: bool = False
    NETFLOW_HOST: str = "0.0.0.0"
    NETFLOW_PORT: int = 2055
    RETENTION_DAYS: int = 7

    # ── CORS ──────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: List[str] = ["*"]

    class Config:
        env_file = ".env"

    @property
    def effective_db_url(self) -> str:
        """Return the resolved SQLAlchemy database URL."""
        return self.DATABASE_URL if self.DATABASE_URL else f"sqlite:///{self.DB_PATH}"


settings = Settings()
