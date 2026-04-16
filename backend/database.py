"""
SQLAlchemy ORM models and engine factory.
Supports SQLite (default) and PostgreSQL (set DATABASE_URL).
"""
import os

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
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

class TeamModel(Base):
    """
    A team groups several users for the purposes of sharing presets, saved
    queries and investigation notes.  A user may belong to at most one team
    (UserModel.team_id).  Items with scope="team" are visible to all members
    of the owner's team.
    """
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True, index=True)
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
    # ── Investigation workflow ────────────────────────────────────────────────
    # Workflow is independent of the engine's processing ``status``:
    #   new | in_progress | needs_review | resolved | dismissed
    workflow_state = Column(
        String, default="new", nullable=False, index=True
    )
    assigned_user_id = Column(
        Integer, ForeignKey("users.id"), nullable=True, index=True
    )
    workflow_updated_at = Column(DateTime, nullable=True)
    workflow_updated_by = Column(
        Integer, ForeignKey("users.id"), nullable=True
    )


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


class PathAnalysisSavedQueryModel(Base):
    """
    A saved path-analysis investigation target.

    A query captures the full set of inputs needed to re-run a path analysis:
    source IP, destination IP, optional port, and role hints.  Role hints may
    be stored either as an explicit reference to a PathAnalysisRolePresetModel
    (role_preset_id) or as inline JSON arrays — or both (the inline values
    override the preset when present).

    List fields are stored in sorted, deduplicated order (same normalisation
    as PathAnalysisRolePresetModel) so that ordering in the original request
    never causes false inequality.
    """
    __tablename__ = "path_analysis_saved_queries"
    id                 = Column(Integer, primary_key=True, index=True)
    owner_user_id      = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name               = Column(String, nullable=False)
    source_ip          = Column(String, nullable=False)
    destination_ip     = Column(String, nullable=False)
    destination_port   = Column(Integer, nullable=True)
    role_preset_id     = Column(Integer, ForeignKey("path_analysis_role_presets.id"),
                                nullable=True)
    firewall_ips       = Column(Text, nullable=False, default="[]")    # JSON array
    load_balancer_vips = Column(Text, nullable=False, default="[]")    # JSON array
    backend_ips        = Column(Text, nullable=False, default="[]")    # JSON array
    backend_subnets    = Column(Text, nullable=False, default="[]")    # JSON array
    note               = Column(Text, nullable=True)
    # ── Sharing scope ─────────────────────────────────────────────────────────
    # scope: "private"  — visible to owner only (default)
    #        "team"     — visible to all members of the owner's team
    #        "global"   — visible to every authenticated user; admin-managed
    scope              = Column(String, nullable=False, default="private", index=True)
    team_id            = Column(Integer, ForeignKey("teams.id"), nullable=True, index=True)
    created_by         = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by         = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at         = Column(DateTime, server_default=func.now())
    updated_at         = Column(DateTime, server_default=func.now(), onupdate=func.now())


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
    # ── Sharing scope (see PathAnalysisSavedQueryModel for semantics) ─────────
    scope              = Column(String, nullable=False, default="private", index=True)
    team_id            = Column(Integer, ForeignKey("teams.id"), nullable=True, index=True)
    created_by         = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by         = Column(Integer, ForeignKey("users.id"), nullable=True)
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
    # Visibility scope — "private" (default) = only the authoring analyst can
    # see this feedback; "team" = every member of the analyst's team can see
    # it (read-only for others).  Values are intentionally a subset of the
    # role-preset/saved-query scope vocabulary.
    scope        = Column(String, nullable=False, default="private", index=True)
    team_id      = Column(Integer, ForeignKey("teams.id"), nullable=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class InvestigationNoteModel(Base):
    """
    Free-form analyst note attached to an investigation target
    (analysis_id + src/dst/port).  Supports private or team-visible scope so
    that several analysts on the same team can collaborate on the same case.

    Editing and deleting are restricted to the author; other team members see
    the note read-only.
    """
    __tablename__ = "investigation_notes"
    id               = Column(Integer, primary_key=True, index=True)
    analysis_id      = Column(String, ForeignKey("analyses.id"), nullable=False, index=True)
    source_ip        = Column(String, nullable=False)
    destination_ip   = Column(String, nullable=False)
    destination_port = Column(Integer, nullable=True)
    body             = Column(Text, nullable=False, default="")
    scope            = Column(String, nullable=False, default="private", index=True)
    team_id          = Column(Integer, ForeignKey("teams.id"), nullable=True, index=True)
    created_by       = Column(Integer, ForeignKey("users.id"), nullable=False)
    updated_by       = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at       = Column(DateTime, server_default=func.now())
    updated_at       = Column(DateTime, server_default=func.now(), onupdate=func.now())


class MonitoredPathModel(Base):
    """
    Scheduled drift monitor for a saved path-analysis query.

    Each row binds a saved query (which captures src/dst/port/role hints) to a
    specific analysis (the PCAP that the periodic re-runs target) and a poll
    interval.  The latest result is snapshotted on every successful run so that
    the next run can detect drift against the prior baseline.

    The model intentionally does NOT include a full scheduler — runs are
    triggered by an in-process tick (see ``run_due_monitors`` in
    ``monitoring.py``) or by an explicit POST /api/path-monitors/{id}/run.
    """
    __tablename__ = "monitored_paths"
    id                   = Column(Integer, primary_key=True, index=True)
    saved_query_id       = Column(
        Integer, ForeignKey("path_analysis_saved_queries.id"),
        nullable=False, index=True,
    )
    analysis_id          = Column(
        String, ForeignKey("analyses.id"), nullable=False, index=True,
    )
    owner_user_id        = Column(
        Integer, ForeignKey("users.id"), nullable=False, index=True,
    )
    schedule_interval_minutes = Column(Integer, nullable=False, default=60)
    enabled              = Column(Boolean, nullable=False, default=True)
    last_run_at          = Column(DateTime, nullable=True)
    last_change_at       = Column(DateTime, nullable=True)
    # JSON-encoded snapshot of the most recent path-analysis result dict
    last_result_json     = Column(Text, nullable=True)
    # JSON-encoded change summary from the most recent drift detection
    last_change_summary  = Column(Text, nullable=True)
    # On the most recent run, did drift detection fire?
    last_drift_severity  = Column(String, nullable=True)   # none|info|warning|critical
    # Last analyst-supplied outcome (denormalised for fast list display).
    last_outcome         = Column(String, nullable=True)
    last_outcome_at      = Column(DateTime, nullable=True)
    # ── Baseline expectations (JSON) ──────────────────────────────────────────
    # Stored as a single JSON blob so the schema doesn't need a migration
    # every time we add a new knob.  Parsed by ``apply_baseline()`` in
    # monitoring.py.  Shape:
    #   {
    #     "accepted_delay_max_ms":      float | null,
    #     "accepted_confidence_min":    int   | null,
    #     "known_noisy_impairments":    ["imp", ...],
    #     "known_visibility_gaps":      ["gap note", ...],
    #   }
    baseline_json        = Column(Text, nullable=True)
    created_at           = Column(DateTime, server_default=func.now())
    updated_at           = Column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class MonitorSuppressionModel(Base):
    """
    Temporary or permanent suppression rule on a monitored path.

    kind values:
      mute           — suppress ALL alerts for the duration
      snooze         — suppress ALL alerts until ``until`` datetime
      impairment     — suppress a specific impairment token
      severity       — suppress drifts at or below a given severity

    ``until`` is required for snooze, optional for the others (null = permanent
    until explicitly deleted).  The runtime checks ``is_active()`` which
    respects both ``enabled`` and ``until``.
    """
    __tablename__ = "monitor_suppressions"
    id                 = Column(Integer, primary_key=True, index=True)
    monitored_path_id  = Column(
        Integer, ForeignKey("monitored_paths.id"),
        nullable=False, index=True,
    )
    kind               = Column(String, nullable=False)         # mute|snooze|impairment|severity
    # For kind=impairment: the specific token to suppress.
    # For kind=severity: the max severity to suppress (e.g. "info").
    value              = Column(String, nullable=True)
    reason             = Column(Text, nullable=True)
    enabled            = Column(Boolean, nullable=False, default=True)
    until              = Column(DateTime, nullable=True)
    created_by         = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at         = Column(DateTime, server_default=func.now())


class MonitorOutcomeModel(Base):
    """
    Analyst-supplied outcome recorded after investigating a monitored path.

    Each row captures one "verdict cycle": the analyst looked at the data,
    decided whether the alert was real, and optionally identified a root
    cause.  ``signal_drivers_json`` snapshots the risk drivers that led to
    the alert so the learning module can build signal → outcome counters
    without re-computing historical risk scores.

    outcome values:
      issue_confirmed   — alert was a real operational issue
      false_positive    — alert noise; path was fine
      transient_issue   — real but self-resolved; brief blip
      root_cause_identified — real; analyst pinned down the cause

    root_cause_type (only when outcome == root_cause_identified):
      network | firewall | app | dns | unknown
    """
    __tablename__ = "monitor_outcomes"
    id                  = Column(Integer, primary_key=True, index=True)
    monitored_path_id   = Column(
        Integer, ForeignKey("monitored_paths.id"),
        nullable=False, index=True,
    )
    outcome             = Column(String, nullable=False, index=True)
    root_cause_type     = Column(String, nullable=True)          # network|firewall|app|dns|unknown
    note                = Column(Text, nullable=True)
    # Snapshot of risk_drivers at the time the outcome was recorded so the
    # learning module can correlate signals → outcomes without lookback.
    signal_drivers_json = Column(Text, nullable=True)            # JSON array of driver strings
    analyst_id          = Column(
        Integer, ForeignKey("users.id"), nullable=True, index=True,
    )
    created_at          = Column(DateTime, server_default=func.now(), index=True)


class MonitoredPathRunModel(Base):
    """
    One historical run record per monitored-path execution.

    Stored on every successful ``_run_monitor`` call (manual or scheduled).
    The full path-analysis result still lives in
    ``MonitoredPathModel.last_result_json`` so the next drift comparison can
    use it; this table keeps a small fixed-shape projection — only the
    fields the trend view actually plots — so we can scan a year of history
    cheaply without parsing JSON.

    ``timing_json`` is the original ``timing_breakdown`` dict (small) so the
    trend module can render any backend-delay-style key without us picking
    a winning column up front.
    """
    __tablename__ = "monitored_path_runs"
    id                    = Column(Integer, primary_key=True, index=True)
    monitored_path_id     = Column(
        Integer, ForeignKey("monitored_paths.id"),
        nullable=False, index=True,
    )
    run_at                = Column(
        DateTime, server_default=func.now(), nullable=False, index=True,
    )
    connection_outcome    = Column(String, nullable=False)   # success|partial_success|failure|unknown
    primary_impairment    = Column(String, nullable=True)
    path_confidence_score = Column(Integer, nullable=False, default=0)
    drift_severity        = Column(String, nullable=False, default="none")  # none|info|warning|critical
    action_required       = Column(Boolean, nullable=False, default=False)
    timing_json           = Column(Text, nullable=True)      # JSON object
    impairments_json      = Column(Text, nullable=True)      # JSON array of impairment tokens


class NotificationModel(Base):
    """
    In-app notification for a single user.

    Notifications are created by server-side triggers on the investigation
    workflow — see ``_notify`` in main.py.  They are intentionally minimal:
    a short human-readable message plus a link target (analysis_id).

    type values:
      assignment        — an analysis was assigned to the recipient
      review_required   — an analysis transitioned to needs_review
      resolved          — an analysis transitioned to resolved
      feedback_alert    — an analyst submitted an "incorrect" verdict
      mention           — recipient was @mentioned in an investigation note
      drift_detected    — a monitored path drifted vs. its previous snapshot
    """
    __tablename__ = "notifications"
    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(
        Integer, ForeignKey("users.id"), nullable=False, index=True
    )
    type           = Column(String, nullable=False, index=True)
    analysis_id    = Column(
        String, ForeignKey("analyses.id"), nullable=True, index=True
    )
    actor_user_id  = Column(Integer, ForeignKey("users.id"), nullable=True)
    message        = Column(Text, nullable=False, default="")
    read_at        = Column(DateTime, nullable=True, index=True)
    created_at     = Column(DateTime, server_default=func.now(), index=True)


class LiveEventModel(Base):
    """
    Normalized live network event ingested from syslog, NetFlow, or webhook.

    Each row represents one firewall/LB/router log entry or flow record,
    normalised to a common schema by the collector's parser pipeline.
    The table is append-heavy and time-indexed; a background retention
    sweep deletes rows older than ``RETENTION_DAYS``.

    Fields are intentionally nullable because not every source populates
    every column — a firewall deny log has no ``bytes_out`` or
    ``response_time_ms``, while a load-balancer health-check log has no
    ``nat_source_ip``.
    """
    __tablename__ = "live_events"
    id                   = Column(Integer, primary_key=True)
    # ── Source identification ─────────────────────────────────────────────────
    source_id            = Column(String, nullable=False, index=True)     # device hostname/IP
    device_type          = Column(String, nullable=False, index=True)     # firewall|load_balancer|router|flow_exporter
    device_role          = Column(String, nullable=True)                  # perimeter|internal|dmz|unknown
    parser_id            = Column(String, nullable=False)                 # paloalto|fortigate|cisco_asa|cef|generic_kv
    # ── Timing ────────────────────────────────────────────────────────────────
    event_time           = Column(DateTime, nullable=False, index=True)   # from the device
    received_at          = Column(DateTime, server_default=func.now(), nullable=False)
    # ── 5-tuple ───────────────────────────────────────────────────────────────
    source_ip            = Column(String, nullable=False, index=True)
    destination_ip       = Column(String, nullable=False, index=True)
    source_port          = Column(Integer, nullable=True)
    destination_port     = Column(Integer, nullable=True)
    protocol             = Column(String, nullable=True)                  # TCP|UDP|ICMP|…
    # ── Verdict ───────────────────────────────────────────────────────────────
    action               = Column(String, nullable=False, index=True)     # allow|deny|drop|reset|nat|forward|health_check
    reason               = Column(String, nullable=True)                  # policy name, reset reason, …
    # ── Volume ────────────────────────────────────────────────────────────────
    bytes_in             = Column(Integer, nullable=True)
    bytes_out            = Column(Integer, nullable=True)
    packets_in           = Column(Integer, nullable=True)
    packets_out          = Column(Integer, nullable=True)
    duration_ms          = Column(Integer, nullable=True)
    # ── NAT ───────────────────────────────────────────────────────────────────
    nat_source_ip        = Column(String, nullable=True)
    nat_destination_ip   = Column(String, nullable=True)
    nat_source_port      = Column(Integer, nullable=True)
    nat_destination_port = Column(Integer, nullable=True)
    # ── Application / service ─────────────────────────────────────────────────
    application          = Column(String, nullable=True)                  # app-id from NGFW
    service              = Column(String, nullable=True)
    # ── Load-balancer specific ────────────────────────────────────────────────
    backend_ip           = Column(String, nullable=True)
    backend_port         = Column(Integer, nullable=True)
    response_time_ms     = Column(Float, nullable=True)
    health_status        = Column(String, nullable=True)                  # up|down|degraded
    # ── Raw ───────────────────────────────────────────────────────────────────
    raw_line             = Column(Text, nullable=True)                    # original log (truncated)
    # ── Suppression ───────────────────────────────────────────────────────────
    suppressed           = Column(Boolean, nullable=True, default=False)


class LiveFlowModel(Base):
    """
    Reconstructed flow/session summary from live events.

    Each row represents one network conversation (5-tuple) observed over
    a window of time.  Flows are assembled in-memory by ``FlowEngine``
    (collector/flows.py) and flushed to DB when they expire or reach a
    terminal state.

    state values:
      active    — still receiving events
      completed — allowed flow that timed out normally
      reset     — at least one RST/reset observed
      denied    — only deny events, no allow
      dropped   — only drop events, no allow
      expired   — timed out without reaching a terminal action
    """
    __tablename__ = "live_flows"
    id                   = Column(Integer, primary_key=True)
    # ── Source identification ─────────────────────────────────────────────────
    source_id            = Column(String, nullable=False, index=True)
    device_type          = Column(String, nullable=False)
    device_role          = Column(String, nullable=True)
    parser_id            = Column(String, nullable=False)
    # ── 5-tuple (flow key) ───────────────────────────────────────────────────
    source_ip            = Column(String, nullable=False, index=True)
    destination_ip       = Column(String, nullable=False, index=True)
    source_port          = Column(Integer, nullable=True)
    destination_port     = Column(Integer, nullable=True)
    protocol             = Column(String, nullable=True, index=True)
    # ── Timing ────────────────────────────────────────────────────────────────
    first_seen           = Column(DateTime, nullable=False, index=True)
    last_seen            = Column(DateTime, nullable=False, index=True)
    duration_ms          = Column(Integer, nullable=True)
    # ── Counters ──────────────────────────────────────────────────────────────
    event_count          = Column(Integer, nullable=False, default=0)
    total_bytes_in       = Column(Integer, nullable=False, default=0)
    total_bytes_out      = Column(Integer, nullable=False, default=0)
    total_packets_in     = Column(Integer, nullable=False, default=0)
    total_packets_out    = Column(Integer, nullable=False, default=0)
    # ── Action counters ───────────────────────────────────────────────────────
    allow_count          = Column(Integer, nullable=False, default=0)
    deny_count           = Column(Integer, nullable=False, default=0)
    drop_count           = Column(Integer, nullable=False, default=0)
    reset_count          = Column(Integer, nullable=False, default=0)
    alert_count          = Column(Integer, nullable=False, default=0)
    # ── Derived summaries ─────────────────────────────────────────────────────
    action_summary       = Column(String, nullable=True)     # mostly_allow|mostly_deny|reset_seen|mixed
    reason_summary       = Column(String, nullable=True)     # most common reason
    # ── NAT ───────────────────────────────────────────────────────────────────
    nat_source_ip        = Column(String, nullable=True)
    nat_destination_ip   = Column(String, nullable=True)
    nat_source_port      = Column(Integer, nullable=True)
    nat_destination_port = Column(Integer, nullable=True)
    # ── Application / service ─────────────────────────────────────────────────
    application          = Column(String, nullable=True)
    service              = Column(String, nullable=True)
    backend_ip           = Column(String, nullable=True)
    backend_port         = Column(Integer, nullable=True)
    # ── State ─────────────────────────────────────────────────────────────────
    state                = Column(String, nullable=False, default="active", index=True)
    raw_event_count      = Column(Integer, nullable=False, default=0)
    # ── Behavioral classification ─────────────────────────────────────────────
    flow_type            = Column(String, nullable=True, index=True)     # normal|unstable|blocked|suspicious|scanning
    reset_ratio          = Column(Float, nullable=True)
    deny_ratio           = Column(Float, nullable=True)
    burst_score          = Column(Float, nullable=True)
    asymmetric_behavior  = Column(Boolean, nullable=True, default=False)
    suspicious_reasons   = Column(Text, nullable=True)                   # JSON array
    # ── Suppression ───────────────────────────────────────────────────────────
    suppressed           = Column(Boolean, nullable=True, default=False)
    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at           = Column(DateTime, server_default=func.now())
    updated_at           = Column(DateTime, server_default=func.now())


class LiveIncidentModel(Base):
    """
    Incident derived from repeated live behavior detections.

    Groups correlated behaviors for the same ``source_ip`` +
    ``behavior_type`` into a single trackable object so the analyst
    doesn't drown in duplicate notifications.

    status values: open | investigating | resolved | dismissed
    severity values: low | medium | high | critical
    """
    __tablename__ = "live_incidents"
    id                = Column(Integer, primary_key=True)
    source_ip         = Column(String, nullable=False, index=True)
    behavior_type     = Column(String, nullable=False, index=True)
    severity          = Column(String, nullable=False, default="low", index=True)
    status            = Column(String, nullable=False, default="open", index=True)
    first_seen        = Column(DateTime, nullable=False)
    last_seen         = Column(DateTime, nullable=False)
    event_count       = Column(Integer, nullable=False, default=1)
    linked_flow_count = Column(Integer, nullable=False, default=0)
    latest_confidence = Column(Float, nullable=True)
    summary           = Column(Text, nullable=True)
    # ── Enrichment ────────────────────────────────────────────────────────────
    top_destination_ips    = Column(Text, nullable=True)     # JSON list, max 5
    top_ports              = Column(Text, nullable=True)     # JSON list, max 5
    total_distinct_destinations = Column(Integer, nullable=True)
    total_distinct_ports   = Column(Integer, nullable=True)
    sample_flows           = Column(Text, nullable=True)     # JSON list of 3 flow summaries
    last_activity_summary  = Column(Text, nullable=True)
    # ── Asset impact ──────────────────────────────────────────────────────────
    impacted_assets_count       = Column(Integer, nullable=True)
    highest_target_criticality  = Column(String, nullable=True)
    target_summary              = Column(Text, nullable=True)
    # ── Priority & aging ──────────────────────────────────────────────────────
    priority_score    = Column(Float, nullable=True)
    last_activity_at  = Column(DateTime, nullable=True)
    decay_factor      = Column(Float, nullable=True)
    # ── PCAP links ────────────────────────────────────────────────────────────
    linked_pcap_analysis_ids = Column(Text, nullable=True, default="[]")   # JSON list of analysis IDs
    pcap_trigger_count       = Column(Integer, nullable=True, default=0)
    created_at        = Column(DateTime, server_default=func.now())
    updated_at        = Column(DateTime, server_default=func.now())


class AttackSessionModel(Base):
    """
    Groups related incidents from the same source IP into a single
    attack session based on temporal proximity and behavior diversity.
    """
    __tablename__ = "attack_sessions"
    id              = Column(Integer, primary_key=True, index=True)
    source_ip       = Column(String, nullable=False, index=True)
    start_time      = Column(DateTime, nullable=False)
    last_activity   = Column(DateTime, nullable=False)
    incident_ids    = Column(Text, nullable=False, default="[]")     # JSON list of ints
    behaviors       = Column(Text, nullable=False, default="[]")     # JSON list of behavior_type strings
    severity        = Column(String, nullable=False, default="low")  # low|medium|high|critical
    priority_score  = Column(Float, nullable=False, default=0)
    status          = Column(String, nullable=False, default="active", index=True)  # active|idle|closed
    total_incidents = Column(Integer, nullable=False, default=0)
    total_destinations = Column(Integer, nullable=False, default=0)
    total_ports     = Column(Integer, nullable=False, default=0)
    # ── Enrichment ────────────────────────────────────────────────────────────
    top_destination_ips       = Column(Text, nullable=True)    # JSON list, max 5
    top_ports                 = Column(Text, nullable=True)    # JSON list, max 5
    target_summary            = Column(Text, nullable=True)
    highest_target_criticality = Column(String, nullable=True) # low|medium|high|critical
    session_summary           = Column(Text, nullable=True)
    recommended_next_step     = Column(Text, nullable=True)
    # ── Intent & timeline ─────────────────────────────────────────────────────
    behavior_timeline         = Column(Text, nullable=True)    # JSON list of {time, behavior}
    behavior_sequence         = Column(String, nullable=True)  # e.g. "scanning → unstable → suspicious"
    attack_intent             = Column(String, nullable=True)
    # ── Confidence & decision ─────────────────────────────────────────────────
    attack_intents            = Column(Text, nullable=True)    # JSON list of {intent, confidence}
    intent_confidence         = Column(Float, nullable=True)   # 0.0–1.0, primary intent confidence
    activity_rate             = Column(Float, nullable=True)   # flows per minute
    burst_flag                = Column(Boolean, nullable=True, default=False)
    recommended_action        = Column(String, nullable=True)  # monitor|investigate|contain|block
    created_at      = Column(DateTime, server_default=func.now())
    updated_at      = Column(DateTime, server_default=func.now())


class IPBaselineModel(Base):
    """
    Learned normal behavior per source IP from historical flows.
    Used to detect deviations from established traffic patterns.
    """
    __tablename__ = "ip_baselines"
    id                      = Column(Integer, primary_key=True, index=True)
    source_ip               = Column(String, nullable=False, unique=True, index=True)
    observation_window_days = Column(Integer, nullable=False, default=7)
    sample_count            = Column(Integer, nullable=False, default=0)
    avg_flows_per_window    = Column(Float, nullable=False, default=0)
    avg_distinct_destinations = Column(Float, nullable=False, default=0)
    avg_distinct_ports      = Column(Float, nullable=False, default=0)
    avg_deny_ratio          = Column(Float, nullable=False, default=0)
    avg_reset_ratio         = Column(Float, nullable=False, default=0)
    avg_bytes_per_flow      = Column(Float, nullable=False, default=0)
    stddev_flows            = Column(Float, nullable=False, default=0)
    stddev_deny_ratio       = Column(Float, nullable=False, default=0)
    stddev_reset_ratio      = Column(Float, nullable=False, default=0)
    last_computed_at        = Column(DateTime, nullable=True)
    created_at              = Column(DateTime, server_default=func.now())
    updated_at              = Column(DateTime, server_default=func.now())


class AssetModel(Base):
    """
    Known network asset for criticality scoring.

    Maps IP addresses to asset metadata so the incident enrichment
    layer can assess target impact.
    """
    __tablename__ = "assets"
    id            = Column(Integer, primary_key=True, index=True)
    ip_address    = Column(String, nullable=False, unique=True, index=True)
    hostname      = Column(String, nullable=True)
    asset_type    = Column(String, nullable=False, default="workstation")  # server|workstation|network|external
    criticality   = Column(String, nullable=False, default="low")          # low|medium|high|critical
    environment   = Column(String, nullable=True)                          # prod|dev|test
    tags          = Column(Text, nullable=True)                            # JSON array
    created_at    = Column(DateTime, server_default=func.now())
    updated_at    = Column(DateTime, server_default=func.now())


class ThreatIndicatorModel(Base):
    """
    Individual Indicator of Compromise (IOC) from a threat intelligence feed.

    indicator_type: ip | cidr | domain | asn
    threat_type:    malware | c2 | scanner | tor_exit | botnet | phishing | unknown
    """
    __tablename__ = "threat_indicators"
    id               = Column(Integer, primary_key=True, index=True)
    indicator_type   = Column(String, nullable=False)                 # ip|cidr|domain|asn
    indicator_value  = Column(String, nullable=False, index=True)
    threat_type      = Column(String, nullable=False, default="unknown")
    confidence       = Column(Float, nullable=False, default=0.5)     # 0.0–1.0
    source_feed      = Column(String, nullable=False)
    first_seen       = Column(DateTime, nullable=False)
    last_seen        = Column(DateTime, nullable=False)
    expiry           = Column(DateTime, nullable=True)                # None = never expires
    tags             = Column(Text, nullable=True)                    # JSON list
    raw_data         = Column(Text, nullable=True)
    created_at       = Column(DateTime, server_default=func.now())
    updated_at       = Column(DateTime, server_default=func.now())


class ThreatFeedModel(Base):
    """
    Threat intelligence feed source registry.

    feed_type: ip_list | cidr_list | domain_list
    format:    plain | csv | json
    """
    __tablename__ = "threat_feeds"
    id                    = Column(Integer, primary_key=True, index=True)
    name                  = Column(String, unique=True, nullable=False)
    feed_type             = Column(String, nullable=False)             # ip_list|cidr_list|domain_list
    url                   = Column(String, nullable=True)
    enabled               = Column(Boolean, nullable=False, default=True)
    last_fetched_at       = Column(DateTime, nullable=True)
    last_indicator_count  = Column(Integer, nullable=False, default=0)
    fetch_interval_hours  = Column(Integer, nullable=False, default=24)
    format                = Column(String, nullable=False, default="plain")  # plain|csv|json
    comment_char          = Column(String, nullable=False, default="#")
    ip_column             = Column(Integer, nullable=False, default=0)       # for CSV feeds
    # Default threat metadata applied to indicators from this feed
    default_threat_type   = Column(String, nullable=False, default="unknown")
    default_confidence    = Column(Float, nullable=False, default=0.5)
    created_at            = Column(DateTime, server_default=func.now())
    updated_at            = Column(DateTime, server_default=func.now())


class CorrelationRuleModel(Base):
    """
    User-defined correlation rule.

    Evaluated periodically against recent LiveFlowModel data to
    automatically create incidents when thresholds are exceeded.

    scope:
      - "global" — visible to all users; only admins may create
      - "user"   — visible only to creator (default)
    """
    __tablename__ = "correlation_rules"
    id                   = Column(Integer, primary_key=True, index=True)
    name                 = Column(String, nullable=False)
    description          = Column(Text, nullable=True)
    enabled              = Column(Boolean, nullable=False, default=True)
    created_by           = Column(Integer, ForeignKey("users.id"), nullable=True)
    scope                = Column(String, nullable=False, default="user")  # global|user

    # ── Condition ─────────────────────────────────────────────────────────────
    condition_field      = Column(String, nullable=False)
    condition_operator   = Column(String, nullable=False)       # eq|neq|gt|lt|gte|lte|in|contains
    condition_value      = Column(String, nullable=False)       # JSON-encoded for lists

    # ── Aggregation ───────────────────────────────────────────────────────────
    aggregation_type     = Column(String, nullable=False)       # count|distinct_count|sum|avg|any
    aggregation_field    = Column(String, nullable=True)        # field to aggregate on
    threshold            = Column(Float, nullable=False)

    # ── Window & grouping ─────────────────────────────────────────────────────
    time_window_minutes  = Column(Integer, nullable=False, default=10)
    target_entity        = Column(String, nullable=False)       # source_ip|destination_ip|src_dst_pair

    # ── Incident creation ─────────────────────────────────────────────────────
    severity             = Column(String, nullable=False, default="medium")
    incident_behavior_type = Column(String, nullable=False)
    cooldown_minutes     = Column(Integer, nullable=False, default=30)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at           = Column(DateTime, server_default=func.now())
    updated_at           = Column(DateTime, server_default=func.now())


class GeoIPCacheModel(Base):
    """
    Cached GeoIP lookup results.

    source: maxmind | ip-api | private
    """
    __tablename__ = "geoip_cache"
    id            = Column(Integer, primary_key=True, index=True)
    ip            = Column(String, nullable=False, unique=True, index=True)
    country_code  = Column(String, nullable=True)
    country_name  = Column(String, nullable=True)
    city          = Column(String, nullable=True)
    latitude      = Column(Float, nullable=True)
    longitude     = Column(Float, nullable=True)
    asn           = Column(Integer, nullable=True)
    asn_org       = Column(String, nullable=True)
    is_private    = Column(Boolean, nullable=False, default=False)
    is_bogon      = Column(Boolean, nullable=False, default=False)
    source        = Column(String, nullable=False)
    looked_up_at  = Column(DateTime, nullable=False)
    created_at    = Column(DateTime, server_default=func.now())


# ── Session / init helpers ─────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(engine)
