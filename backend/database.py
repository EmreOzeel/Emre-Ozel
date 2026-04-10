"""
SQLAlchemy ORM models and engine factory.
Supports SQLite (default) and PostgreSQL (set DATABASE_URL).
"""
import os

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.sql import func

from config import settings

# ── Engine factory ─────────────────────────────────────────────────────────────
_url = settings.effective_db_url
_is_sqlite = _url.startswith("sqlite")

if _is_sqlite:
    # Derive the actual file path from the URL (works for both DATABASE_URL
    # and DB_PATH fallback). sqlite:////abs/path → /abs/path
    _db_file = _url.split("sqlite:///")[-1]
    _db_dir = os.path.dirname(_db_file)
    if _db_dir:
        os.makedirs(_db_dir, exist_ok=True)
    engine = create_engine(_url, connect_args={"check_same_thread": False})
else:
    engine = create_engine(
        _url,
        pool_pre_ping=True,   # detect stale connections
        pool_size=5,
        max_overflow=10,
    )

SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


# ── Models ─────────────────────────────────────────────────────────────────────

class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class AnalysisModel(Base):
    __tablename__ = "analyses"
    id = Column(String, primary_key=True)                   # UUID string
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=True)
    file_hash = Column(String, nullable=True, index=True)   # SHA-256 for dedup / caching
    status = Column(String, default="pending")              # pending/running/completed/failed
    current_stage = Column(String, nullable=True)           # normalize/analyze/profile/…
    progress_pct = Column(Integer, default=0)               # 0–100
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
    Persistent suppression rule.

    scope:
      - "global"   — applies to all users; only admins may create
      - "user"     — applies to creator only (default)
      - "analysis" — applies to a single analysis run; set analysis_id

    Rules with expires_at < now() or is_active=False are ignored at job time.
    """
    __tablename__ = "suppression_rules"
    id = Column(Integer, primary_key=True, index=True)
    scope = Column(String, default="user", nullable=False)      # global | user | analysis
    rule_id = Column(String, nullable=True)                     # e.g. "SCAN-001" — null = any
    src_ip = Column(String, nullable=True)                      # null = any src
    dst_ip = Column(String, nullable=True)                      # null = any dst
    analysis_id = Column(String, ForeignKey("analyses.id"), nullable=True)
    reason = Column(String, nullable=False, default="")
    note = Column(Text, nullable=True)                          # long-form analyst note
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=True)                # null = never expires
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class TelemetryEventModel(Base):
    """
    Non-sensitive usage telemetry.

    Only structural events are recorded — no user data, no PCAP content,
    no IP addresses, no findings content.

    event_type values:
      analysis.started | analysis.completed | analysis.failed |
      suppression.created | triage.updated | report.downloaded | compare.executed
    """
    __tablename__ = "telemetry_events"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    # Structural properties only — JSON string with no sensitive content
    properties_json = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), index=True)


class FindingTriageModel(Base):
    """
    Per-finding analyst triage state.

    finding_key is a stable composite: "{rule_id}|{primary_affected_host}"
    This allows triage state to persist even if the analysis is re-run.

    status values: new | acknowledged | in_progress | resolved | false_positive
    """
    __tablename__ = "finding_triage"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), nullable=False, index=True)
    finding_key = Column(String, nullable=False, index=True)
    status = Column(String, default="new", nullable=False)
    note = Column(Text, nullable=True)
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class PathAnalysisRolePresetModel(Base):
    """
    Saved role-hint profile for CausalPathEngine.

    Each preset belongs to one user (owner_user_id) and stores four optional
    IP/subnet lists as JSON arrays.  List entries are stored in sorted order so
    that two presets with the same IPs in different order compare as identical.
    """
    __tablename__ = "path_analysis_role_presets"
    id                 = Column(Integer, primary_key=True, index=True)
    owner_user_id      = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name               = Column(String, nullable=False)
    firewall_ips       = Column(Text, nullable=False, default="[]")    # JSON array
    load_balancer_vips = Column(Text, nullable=False, default="[]")    # JSON array
    backend_ips        = Column(Text, nullable=False, default="[]")    # JSON array
    backend_subnets    = Column(Text, nullable=False, default="[]")    # JSON array
    created_at         = Column(DateTime, server_default=func.now())
    updated_at         = Column(DateTime, server_default=func.now(), onupdate=func.now())


class PathAnalysisCacheModel(Base):
    """
    Cached result of CausalPathEngine.analyze() for one (analysis, src, dst, port, roles, engine_version) tuple.

    cache_key is a SHA-256 hex digest of the six-component key.  Entries are
    considered valid only when their engine_version matches the constant in
    core.causal_path.  Different roles or a bumped engine version produce a
    different cache_key and therefore a distinct row.
    """
    __tablename__ = "path_analysis_cache"
    id               = Column(Integer, primary_key=True, index=True)
    cache_key        = Column(String, nullable=False, unique=True, index=True)
    analysis_id      = Column(String, ForeignKey("analyses.id"), nullable=False, index=True)
    source_ip        = Column(String, nullable=False)
    destination_ip   = Column(String, nullable=False)
    destination_port = Column(Integer, nullable=True)
    roles_hash       = Column(String, nullable=False)   # SHA-256 of normalised roles JSON
    engine_version   = Column(String, nullable=False)
    result_json      = Column(Text, nullable=False)     # PathAnalysisResult.to_dict() as JSON
    created_at       = Column(DateTime, server_default=func.now())


class PathAnalysisFeedbackModel(Base):
    """
    Analyst verdict on a single CausalPathEngine result.

    Keyed by (analysis_id, source_ip, destination_ip, destination_port, analyst_id)
    so that re-submitting the same query updates the existing record (upsert).

    verdict values: correct | partially_correct | incorrect

    predicted_* fields are sent by the frontend from the live result so we
    capture exactly what the engine said at the moment of judgment — even if
    the PCAP is later deleted and the analysis cannot be re-run.
    """
    __tablename__ = "path_analysis_feedback"
    id               = Column(Integer, primary_key=True, index=True)
    analysis_id      = Column(String, ForeignKey("analyses.id"), nullable=False, index=True)
    source_ip        = Column(String, nullable=False)
    destination_ip   = Column(String, nullable=False)
    destination_port = Column(Integer, nullable=True)
    # Engine prediction captured at submission time
    predicted_outcome    = Column(String, nullable=False)   # success|partial_success|failure|unknown
    predicted_impairment = Column(String, nullable=True)    # primary_impairment token or null
    predicted_confidence = Column(Integer, nullable=False)  # path_confidence_score 0–100
    # Analyst judgment
    verdict           = Column(String, nullable=False)      # correct|partially_correct|incorrect
    analyst_note      = Column(Text, nullable=True)
    actual_root_cause = Column(String, nullable=True)       # free-form or impairment token
    misleading_step   = Column(Text, nullable=True)         # text of the path_step that misled
    # Metadata
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


# ── Session / init helpers ─────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(engine)
