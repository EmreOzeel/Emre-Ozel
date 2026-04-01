import os
from sqlalchemy import create_engine, Column, Integer, String, BigInteger, Text, DateTime, ForeignKey
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.sql import func
from config import settings

os.makedirs(os.path.dirname(settings.DB_PATH), exist_ok=True)

engine = create_engine(
    f"sqlite:///{settings.DB_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class AnalysisModel(Base):
    __tablename__ = "analyses"
    id = Column(String, primary_key=True)           # UUID string
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=True)
    status = Column(String, default="pending")       # pending / running / completed / failed
    packet_count = Column(Integer, default=0)
    issue_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    result_json = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)


class SuppressionRuleModel(Base):
    """
    Persistent suppression rule — marks matching findings as suppressed.
    Rules are global (team-wide) — any matching finding from any analysis
    is suppressed when results are viewed.
    """
    __tablename__ = "suppression_rules"
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, nullable=True)    # e.g. "SCAN-001" — null = match all
    src_ip = Column(String, nullable=True)     # null = match any src
    dst_ip = Column(String, nullable=True)     # null = match any dst
    reason = Column(String, nullable=False, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(engine)
