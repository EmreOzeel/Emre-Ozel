from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    JWT_SECRET: str = "pcap-analyzer-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24
    DB_PATH: str = "/data/pcap.db"
    UPLOAD_DIR: str = "/data/uploads"
    DEFAULT_USER: str = "admin"
    DEFAULT_PASS: str = "admin123"

    class Config:
        env_file = ".env"


settings = Settings()
