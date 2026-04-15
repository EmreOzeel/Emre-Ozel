"""FastAPI application — PCAP Analyzer v3 (async + investigation-grade)."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from auth import create_token, get_current_user, seed_admin, verify_password
from config import settings
from database import (
    AnalysisModel,
    FindingTriageModel,
    InvestigationNoteModel,
    MonitoredPathModel,
    MonitoredPathRunModel,
    MonitorOutcomeModel,
    MonitorSuppressionModel,
    NotificationModel,
    PathAnalysisCacheModel,
    PathAnalysisFeedbackModel,
    PathAnalysisRolePresetModel,
    PathAnalysisSavedQueryModel,
    SuppressionRuleModel,
    TeamModel,
    TelemetryEventModel,
    UserModel,
    get_db,
    init_db,
)
from monitoring import (
    VALID_OUTCOMES,
    VALID_ROOT_CAUSE_TYPES,
    VALID_SUPPRESSION_KINDS,
    adjust_action,
    apply_baseline,
    apply_suppressions,
    compute_risk_score,
    compute_system_insights,
    decide_action,
    detect_drift,
    is_due,
    learn_from_outcomes,
    summarize_history,
)
from jobs.queue import enqueue, start_worker, stop_worker
from sharing import (
    VALID_SCOPES,
    can_edit as sharing_can_edit,
    check_can_create,
    enforce_edit,
    enforce_view,
    resolve_team_id,
    validate_scope,
    visible_filter,
)
from telemetry import track

# ── PCAP magic bytes ──────────────────────────────────────────────────────────
# pcap little-endian, pcap big-endian, pcapng
_PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"}


def _check_pcap_magic(data: bytes) -> bool:
    return data[:4] in _PCAP_MAGIC


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="PCAP Analyzer",
    version="3.0.0",
    description="Investigation-grade PCAP analysis platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    init_db()
    seed_admin()
    start_worker()
    if settings.COLLECTOR_ENABLED:
        from collector.service import start_collector
        start_collector()


@app.on_event("shutdown")
def shutdown():
    stop_worker()
    if settings.COLLECTOR_ENABLED:
        from collector.service import stop_collector
        stop_collector()


# ── Pydantic response schemas ─────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class MeResponse(BaseModel):
    id: int
    username: str
    is_admin: bool


# ── Investigation workflow ────────────────────────────────────────────────────
# Valid workflow states for an analysis (the "investigation" lifecycle).
# This is orthogonal to AnalysisModel.status, which tracks engine processing.
VALID_WORKFLOW_STATES = (
    "new",
    "in_progress",
    "needs_review",
    "resolved",
    "dismissed",
)
_WORKFLOW_PATTERN = "^(new|in_progress|needs_review|resolved|dismissed)$"


class AnalysisSummary(BaseModel):
    id: str
    filename: str
    status: str
    packet_count: Optional[int]
    issue_count: Optional[int]
    critical_count: Optional[int]
    current_stage: Optional[str]
    progress_pct: Optional[int]
    created_at: Optional[str]
    started_at: Optional[str]
    finished_at: Optional[str]
    error: Optional[str]
    # Investigation workflow fields
    workflow_state: Optional[str] = None
    assigned_user_id: Optional[int] = None
    assignee_username: Optional[str] = None
    workflow_updated_at: Optional[str] = None
    owner_user_id: Optional[int] = None


class AnalysisStatusResponse(BaseModel):
    id: str
    status: str
    current_stage: Optional[str]
    progress_pct: int
    packet_count: Optional[int]
    issue_count: Optional[int]
    critical_count: Optional[int]
    error: Optional[str]
    started_at: Optional[str]
    finished_at: Optional[str]


class AnalysisCreateResponse(BaseModel):
    id: str
    filename: str
    status: str
    message: str


class SuppressionResponse(BaseModel):
    id: int
    scope: str
    rule_id: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    analysis_id: Optional[str]
    reason: str
    note: Optional[str]
    is_active: bool
    expires_at: Optional[str]
    created_by: Optional[int]
    created_at: Optional[str]


class TriageResponse(BaseModel):
    id: int
    analysis_id: str
    finding_key: str
    status: str
    note: Optional[str]
    analyst_id: Optional[int]
    created_at: Optional[str]
    updated_at: Optional[str]


# ── Request schemas ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class SuppressionCreate(BaseModel):
    scope: str = Field(default="user", pattern="^(global|user|analysis)$")
    rule_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    analysis_id: Optional[str] = None
    reason: str = ""
    note: Optional[str] = None
    expires_at: Optional[str] = None   # ISO-8601 string or null


class TriageUpdate(BaseModel):
    status: str = Field(pattern="^(new|acknowledged|in_progress|resolved|false_positive)$")
    note: Optional[str] = None


class WorkflowStateUpdate(BaseModel):
    state: str = Field(pattern=_WORKFLOW_PATTERN)


class WorkflowAssigneeUpdate(BaseModel):
    user_id: Optional[int] = None


class WorkflowResponse(BaseModel):
    analysis_id: str
    workflow_state: str
    assigned_user_id: Optional[int]
    assignee_username: Optional[str]
    workflow_updated_at: Optional[str]
    workflow_updated_by: Optional[int]
    owner_user_id: int
    can_edit_state: bool
    can_assign: bool


class UserPickerEntry(BaseModel):
    id: int
    username: str
    team_id: Optional[int] = None
    is_admin: bool = False


# ── Notifications ─────────────────────────────────────────────────────────────

VALID_NOTIFICATION_TYPES = (
    "assignment",
    "review_required",
    "resolved",
    "feedback_alert",
    "mention",
    "drift_detected",
)


class NotificationResponse(BaseModel):
    id: int
    type: str
    analysis_id: Optional[str]
    analysis_filename: Optional[str]
    actor_user_id: Optional[int]
    actor_username: Optional[str]
    message: str
    read_at: Optional[str]
    created_at: Optional[str]


class NotificationUnreadCount(BaseModel):
    unread: int


class NotificationMarkReadRequest(BaseModel):
    ids: Optional[List[int]] = None
    all: bool = False


class NotificationMarkReadResponse(BaseModel):
    marked: int


# ── Work queue ────────────────────────────────────────────────────────────────

class WorkQueueItem(BaseModel):
    analysis_id: str
    filename: str
    status: str                         # engine processing status
    workflow_state: str
    owner_user_id: int
    owner_username: Optional[str] = None
    assigned_user_id: Optional[int] = None
    assignee_username: Optional[str] = None
    issue_count: Optional[int] = None
    critical_count: Optional[int] = None
    workflow_updated_at: Optional[str] = None
    created_at: Optional[str] = None
    # Latest path-analysis feedback enrichment (if any)
    primary_impairment: Optional[str] = None
    path_confidence_score: Optional[int] = None
    latest_feedback_verdict: Optional[str] = None
    latest_feedback_at: Optional[str] = None
    # Latest notification relating to this analysis for the current user
    latest_notification_type: Optional[str] = None
    latest_notification_at: Optional[str] = None


class WorkQueueSection(BaseModel):
    key: str
    label: str
    priority: int
    count: int
    items: List[WorkQueueItem]


class WorkQueueResponse(BaseModel):
    sections: List[WorkQueueSection]
    total_open: int
    counts: Dict[str, int]


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/api/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": str(user.id), "username": user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/auth/me", response_model=MeResponse)
def me(current_user: UserModel = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username, "is_admin": current_user.is_admin}


# ── Analysis CRUD ─────────────────────────────────────────────────────────────

@app.post("/api/analyses", status_code=202, response_model=AnalysisCreateResponse)
async def create_analysis(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Upload a PCAP and enqueue it for async analysis."""
    if not file.filename:
        raise HTTPException(400, "No filename provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported file type. Allowed: {settings.ALLOWED_EXTENSIONS}")

    # ── File size limit ───────────────────────────────────────────────────────
    max_bytes = settings.MAX_UPLOAD_MB * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_MB} MB limit")

    # ── Magic byte validation ─────────────────────────────────────────────────
    if len(data) < 4 or not _check_pcap_magic(data):
        raise HTTPException(400, "File does not appear to be a valid PCAP/PCAPng file")

    # ── Per-user quota ────────────────────────────────────────────────────────
    if settings.MAX_ANALYSES_PER_USER > 0:
        existing = db.query(AnalysisModel).filter(
            AnalysisModel.user_id == current_user.id
        ).count()
        if existing >= settings.MAX_ANALYSES_PER_USER:
            raise HTTPException(
                429,
                f"Analysis quota reached ({settings.MAX_ANALYSES_PER_USER}). "
                "Delete old analyses to continue.",
            )

    # ── Hash for dedup / cache key ────────────────────────────────────────────
    file_hash = hashlib.sha256(data).hexdigest()

    # ── Save to disk ──────────────────────────────────────────────────────────
    file_id = str(uuid.uuid4())
    dest = Path(settings.UPLOAD_DIR) / f"{file_id}{ext}"
    try:
        dest.write_bytes(data)
    except Exception as e:
        raise HTTPException(500, f"Failed to save file: {e}")

    analysis = AnalysisModel(
        id=file_id,
        user_id=current_user.id,
        filename=file.filename,
        file_path=str(dest),
        file_hash=file_hash,
        status="pending",
    )
    db.add(analysis)
    db.commit()
    enqueue(db, file_id)

    track("analysis.started", user_id=current_user.id, properties={
        "analysis_id": file_id,
        "file_size_bytes": len(data),
        "extension": ext,
    })

    return {
        "id": file_id,
        "filename": file.filename,
        "status": "pending",
        "message": "Analysis enqueued. Poll /api/analyses/{id}/status for progress.",
    }


@app.get("/api/analyses", response_model=List[AnalysisSummary])
def list_analyses(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    assigned_to_me: bool = Query(
        False,
        description="If true, also include analyses assigned to the current user.",
    ),
    workflow_state: Optional[str] = Query(
        None, description="Filter by investigation workflow state."
    ),
):
    q = db.query(AnalysisModel)
    if assigned_to_me:
        q = q.filter(
            or_(
                AnalysisModel.user_id == current_user.id,
                AnalysisModel.assigned_user_id == current_user.id,
            )
        )
    else:
        q = q.filter(AnalysisModel.user_id == current_user.id)
    if workflow_state:
        if workflow_state not in VALID_WORKFLOW_STATES:
            raise HTTPException(400, f"Invalid workflow_state: {workflow_state}")
        q = q.filter(AnalysisModel.workflow_state == workflow_state)
    rows = (
        q.order_by(AnalysisModel.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_summary(r, db) for r in rows]


@app.get("/api/analyses/{analysis_id}")
def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = _get_analysis_for_workflow(db, analysis_id, current_user)
    result = _summary(row, db)
    if row.result_json:
        try:
            result["data"] = json.loads(row.result_json)
        except json.JSONDecodeError:
            result["data"] = None
    return result


@app.get("/api/analyses/{analysis_id}/status", response_model=AnalysisStatusResponse)
def get_status(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Lightweight polling endpoint — returns progress without full result payload."""
    row = _get_analysis_for_workflow(db, analysis_id, current_user)
    return {
        "id": row.id,
        "status": row.status,
        "current_stage": row.current_stage,
        "progress_pct": row.progress_pct or 0,
        "packet_count": row.packet_count,
        "issue_count": row.issue_count,
        "critical_count": row.critical_count,
        "error": row.error,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }


# ── Investigation workflow ────────────────────────────────────────────────────

@app.get(
    "/api/analyses/{analysis_id}/workflow",
    response_model=WorkflowResponse,
)
def get_workflow(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return investigation workflow metadata (state, assignee, permissions)."""
    row = _get_analysis_for_workflow(db, analysis_id, current_user)
    return _workflow_dict(row, current_user, db)


@app.put(
    "/api/analyses/{analysis_id}/workflow/state",
    response_model=WorkflowResponse,
)
def update_workflow_state(
    analysis_id: str,
    req: WorkflowStateUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Transition the investigation state.

    Permitted for the owner, the current assignee, or any admin.
    """
    row = _get_analysis_for_workflow(db, analysis_id, current_user)
    is_owner = row.user_id == current_user.id
    is_assignee = (
        row.assigned_user_id is not None
        and row.assigned_user_id == current_user.id
    )
    is_admin = bool(getattr(current_user, "is_admin", False))
    if not (is_owner or is_assignee or is_admin):
        raise HTTPException(403, "Not allowed to change workflow state")
    prev_state = row.workflow_state or "new"
    row.workflow_state = req.state
    row.workflow_updated_at = datetime.utcnow()
    row.workflow_updated_by = current_user.id

    # ── Notification triggers ────────────────────────────────────────────────
    if req.state != prev_state:
        _emit_state_change_notifications(
            db,
            row=row,
            state=req.state,
            actor_user_id=current_user.id,
        )

    db.commit()
    db.refresh(row)
    track(
        "workflow.state_changed",
        user_id=current_user.id,
        properties={"analysis_id": analysis_id, "state": req.state},
    )
    return _workflow_dict(row, current_user, db)


@app.put(
    "/api/analyses/{analysis_id}/workflow/assignee",
    response_model=WorkflowResponse,
)
def update_workflow_assignee(
    analysis_id: str,
    req: WorkflowAssigneeUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Assign or unassign an analyst for this investigation.

    Only the owner or an admin may reassign.  The assignee must be an
    existing user; passing ``user_id=null`` clears the assignment.
    """
    row = _get_analysis_for_workflow(db, analysis_id, current_user)
    is_owner = row.user_id == current_user.id
    is_admin = bool(getattr(current_user, "is_admin", False))
    if not (is_owner or is_admin):
        raise HTTPException(403, "Only the owner or an admin may reassign")
    if req.user_id is not None:
        target = db.query(UserModel).filter(UserModel.id == req.user_id).first()
        if not target:
            raise HTTPException(404, "Assignee user not found")
    prev_assignee = row.assigned_user_id
    row.assigned_user_id = req.user_id
    row.workflow_updated_at = datetime.utcnow()
    row.workflow_updated_by = current_user.id

    # ── Notification trigger: notify the new assignee ────────────────────────
    if req.user_id is not None and req.user_id != prev_assignee:
        _notify(
            db,
            user_id=req.user_id,
            type="assignment",
            analysis_id=analysis_id,
            message=f"You were assigned to investigate “{row.filename}”.",
            actor_user_id=current_user.id,
        )

    db.commit()
    db.refresh(row)
    track(
        "workflow.assignee_changed",
        user_id=current_user.id,
        properties={"analysis_id": analysis_id, "assignee_id": req.user_id},
    )
    return _workflow_dict(row, current_user, db)


@app.get("/api/users", response_model=List[UserPickerEntry])
def list_users_for_picker(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return a minimal user list suitable for an assignee picker.

    - Admins see every user.
    - Non-admins see themselves and every user in the same team (if any).
    """
    q = db.query(UserModel)
    if not getattr(current_user, "is_admin", False):
        team_id = getattr(current_user, "team_id", None)
        if team_id is not None:
            q = q.filter(
                or_(
                    UserModel.id == current_user.id,
                    UserModel.team_id == team_id,
                )
            )
        else:
            q = q.filter(UserModel.id == current_user.id)
    rows = q.order_by(UserModel.username).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "team_id": u.team_id,
            "is_admin": bool(u.is_admin),
        }
        for u in rows
    ]


# ── Notifications ─────────────────────────────────────────────────────────────

@app.get("/api/notifications", response_model=List[NotificationResponse])
def list_notifications(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    unread_only: bool = Query(False),
):
    """List the current user's notifications, newest first."""
    q = db.query(NotificationModel).filter(
        NotificationModel.user_id == current_user.id
    )
    if unread_only:
        q = q.filter(NotificationModel.read_at.is_(None))
    rows = (
        q.order_by(
            NotificationModel.created_at.desc(),
            NotificationModel.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    filename_cache: dict = {}
    username_cache: dict = {}
    return [
        _notification_dict(r, filename_cache, username_cache, db) for r in rows
    ]


@app.get(
    "/api/notifications/unread-count",
    response_model=NotificationUnreadCount,
)
def notification_unread_count(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    count = (
        db.query(NotificationModel)
        .filter(
            NotificationModel.user_id == current_user.id,
            NotificationModel.read_at.is_(None),
        )
        .count()
    )
    return {"unread": count}


@app.post(
    "/api/notifications/mark-read",
    response_model=NotificationMarkReadResponse,
)
def mark_notifications_read(
    req: NotificationMarkReadRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Mark some (or all) of the current user's notifications as read.

    Either pass ``ids=[...]`` to mark specific notifications, or
    ``all=true`` to mark every unread notification for the caller.
    Notifications belonging to other users are silently ignored.
    """
    if not req.all and not req.ids:
        raise HTTPException(400, "Either 'ids' or 'all=true' must be provided")
    now = datetime.utcnow()
    q = db.query(NotificationModel).filter(
        NotificationModel.user_id == current_user.id,
        NotificationModel.read_at.is_(None),
    )
    if not req.all:
        q = q.filter(NotificationModel.id.in_(req.ids or []))
    rows = q.all()
    for r in rows:
        r.read_at = now
    db.commit()
    return {"marked": len(rows)}


# ── Work queue ────────────────────────────────────────────────────────────────

@app.get("/api/work-queue", response_model=WorkQueueResponse)
def get_work_queue(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
    recent_resolved_limit: int = Query(10, ge=1, le=50),
    recent_feedback_limit: int = Query(10, ge=1, le=50),
):
    """
    Return the operator work queue for the current user.

    The queue is grouped into ordered sections (highest priority first):

        1. ``needs_review``          — owned or assigned analyses in the
                                       ``needs_review`` state.
        2. ``recent_feedback_alerts`` — recent ``incorrect`` analyst verdicts
                                       on visible analyses.
        3. ``assigned_to_me``        — actionable analyses assigned to me
                                       (excludes needs_review/resolved/dismissed).
        4. ``new_analyses``          — owned, workflow_state == ``new``.
        5. ``unresolved_owned``      — owned, workflow_state == ``in_progress``.
        6. ``recent_resolved``       — visible resolved/dismissed analyses
                                       (last N, purely informational).

    Sections are disjoint: an analysis appearing in an earlier section is
    excluded from every later one to keep the dashboard unambiguous.
    Only analyses whose engine ``status == 'completed'`` are returned — items
    that are still pending/running or have failed processing do not belong on
    the operational queue.
    """
    uid = current_user.id

    # ── Base: all completed, visible analyses for this user ──────────────────
    visible_clause = or_(
        AnalysisModel.user_id == uid,
        AnalysisModel.assigned_user_id == uid,
    )
    visible_rows = (
        db.query(AnalysisModel)
        .filter(
            AnalysisModel.status == "completed",
            visible_clause,
        )
        .order_by(
            AnalysisModel.workflow_updated_at.desc().nullslast(),
            AnalysisModel.id.desc(),
        )
        .all()
    )

    visible_by_id: Dict[str, AnalysisModel] = {r.id: r for r in visible_rows}
    visible_ids = list(visible_by_id.keys())

    # ── Batch-fetch usernames used across all item rows ──────────────────────
    user_ids: set = set()
    for r in visible_rows:
        if r.user_id is not None:
            user_ids.add(r.user_id)
        if r.assigned_user_id is not None:
            user_ids.add(r.assigned_user_id)
    username_map: Dict[int, str] = {}
    if user_ids:
        for u in (
            db.query(UserModel.id, UserModel.username)
            .filter(UserModel.id.in_(user_ids))
            .all()
        ):
            username_map[u.id] = u.username

    # ── Batch-fetch latest path-feedback per visible analysis ────────────────
    # Used both to enrich items (primary_impairment, path_confidence_score)
    # and to build the feedback-alerts section.
    latest_fb_by_analysis: Dict[str, PathAnalysisFeedbackModel] = {}
    all_feedback: List[PathAnalysisFeedbackModel] = []
    if visible_ids:
        all_feedback = (
            db.query(PathAnalysisFeedbackModel)
            .filter(PathAnalysisFeedbackModel.analysis_id.in_(visible_ids))
            .order_by(
                PathAnalysisFeedbackModel.updated_at.desc().nullslast(),
                PathAnalysisFeedbackModel.id.desc(),
            )
            .all()
        )
        for fb in all_feedback:
            # First occurrence wins — already sorted newest-first.
            if fb.analysis_id not in latest_fb_by_analysis:
                latest_fb_by_analysis[fb.analysis_id] = fb

    # ── Batch-fetch latest notification per analysis for this user ──────────
    latest_notif_by_analysis: Dict[str, NotificationModel] = {}
    if visible_ids:
        notif_rows = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.user_id == uid,
                NotificationModel.analysis_id.in_(visible_ids),
            )
            .order_by(
                NotificationModel.created_at.desc(),
                NotificationModel.id.desc(),
            )
            .all()
        )
        for n in notif_rows:
            if n.analysis_id not in latest_notif_by_analysis:
                latest_notif_by_analysis[n.analysis_id] = n

    def _iso(dt) -> Optional[str]:
        return dt.isoformat() if dt is not None else None

    def _build_item(row: AnalysisModel) -> WorkQueueItem:
        fb = latest_fb_by_analysis.get(row.id)
        notif = latest_notif_by_analysis.get(row.id)
        return WorkQueueItem(
            analysis_id=row.id,
            filename=row.filename,
            status=row.status,
            workflow_state=row.workflow_state or "new",
            owner_user_id=row.user_id,
            owner_username=username_map.get(row.user_id),
            assigned_user_id=row.assigned_user_id,
            assignee_username=(
                username_map.get(row.assigned_user_id)
                if row.assigned_user_id is not None
                else None
            ),
            issue_count=row.issue_count,
            critical_count=row.critical_count,
            workflow_updated_at=_iso(row.workflow_updated_at),
            created_at=_iso(row.created_at),
            primary_impairment=(fb.predicted_impairment if fb else None),
            path_confidence_score=(fb.predicted_confidence if fb else None),
            latest_feedback_verdict=(fb.verdict if fb else None),
            latest_feedback_at=_iso(fb.updated_at) if fb else None,
            latest_notification_type=(notif.type if notif else None),
            latest_notification_at=_iso(notif.created_at) if notif else None,
        )

    # ── Build sections (disjoint by priority order) ──────────────────────────
    assigned_ids: set = set()   # tracks ids already claimed by a higher section

    # 1) needs_review
    needs_review_items: List[WorkQueueItem] = []
    for r in visible_rows:
        if r.workflow_state == "needs_review":
            needs_review_items.append(_build_item(r))
            assigned_ids.add(r.id)

    # 2) recent_feedback_alerts — incorrect verdicts on visible analyses,
    # newest first, limited.  These items use the feedback row's timestamp
    # (not the analysis' workflow_updated_at) to reflect when the alert fired.
    feedback_alert_items: List[WorkQueueItem] = []
    for fb in all_feedback:
        if fb.verdict != "incorrect":
            continue
        row = visible_by_id.get(fb.analysis_id)
        if row is None:
            continue
        if fb.analysis_id in assigned_ids:
            continue
        item = _build_item(row)
        # Override latest_feedback_* with this specific alert
        item.latest_feedback_verdict = fb.verdict
        item.latest_feedback_at = _iso(fb.updated_at)
        feedback_alert_items.append(item)
        assigned_ids.add(fb.analysis_id)
        if len(feedback_alert_items) >= recent_feedback_limit:
            break

    # 3) assigned_to_me — assigned to me, not in needs_review/resolved/dismissed,
    # excluding items already captured above.
    assigned_to_me_items: List[WorkQueueItem] = []
    _excluded_assigned_states = {"needs_review", "resolved", "dismissed"}
    for r in visible_rows:
        if r.id in assigned_ids:
            continue
        if r.assigned_user_id != uid:
            continue
        if (r.workflow_state or "new") in _excluded_assigned_states:
            continue
        assigned_to_me_items.append(_build_item(r))
        assigned_ids.add(r.id)

    # 4) new_analyses — I own it and it is still in the `new` bucket.
    new_items: List[WorkQueueItem] = []
    for r in visible_rows:
        if r.id in assigned_ids:
            continue
        if r.user_id != uid:
            continue
        if (r.workflow_state or "new") != "new":
            continue
        new_items.append(_build_item(r))
        assigned_ids.add(r.id)

    # 5) unresolved_owned — I own it and I'm actively working it.
    unresolved_items: List[WorkQueueItem] = []
    for r in visible_rows:
        if r.id in assigned_ids:
            continue
        if r.user_id != uid:
            continue
        if r.workflow_state != "in_progress":
            continue
        unresolved_items.append(_build_item(r))
        assigned_ids.add(r.id)

    # 6) recent_resolved — informational tail.  We intentionally do NOT move
    # these into `assigned_ids` (already at the bottom anyway).
    recent_resolved_items: List[WorkQueueItem] = []
    for r in visible_rows:
        if (r.workflow_state or "new") not in ("resolved", "dismissed"):
            continue
        recent_resolved_items.append(_build_item(r))
        if len(recent_resolved_items) >= recent_resolved_limit:
            break

    sections = [
        WorkQueueSection(
            key="needs_review",
            label="Needs review",
            priority=1,
            count=len(needs_review_items),
            items=needs_review_items,
        ),
        WorkQueueSection(
            key="recent_feedback_alerts",
            label="Feedback alerts",
            priority=2,
            count=len(feedback_alert_items),
            items=feedback_alert_items,
        ),
        WorkQueueSection(
            key="assigned_to_me",
            label="Assigned to me",
            priority=3,
            count=len(assigned_to_me_items),
            items=assigned_to_me_items,
        ),
        WorkQueueSection(
            key="new_analyses",
            label="New",
            priority=4,
            count=len(new_items),
            items=new_items,
        ),
        WorkQueueSection(
            key="unresolved_owned",
            label="In progress",
            priority=5,
            count=len(unresolved_items),
            items=unresolved_items,
        ),
        WorkQueueSection(
            key="recent_resolved",
            label="Recently resolved",
            priority=6,
            count=len(recent_resolved_items),
            items=recent_resolved_items,
        ),
    ]

    # "Open" excludes the informational `recent_resolved` tail.
    total_open = (
        len(needs_review_items)
        + len(feedback_alert_items)
        + len(assigned_to_me_items)
        + len(new_items)
        + len(unresolved_items)
    )
    counts = {s.key: s.count for s in sections}

    return WorkQueueResponse(
        sections=sections,
        total_open=total_open,
        counts=counts,
    )


@app.delete("/api/analyses/{analysis_id}", status_code=204)
def delete_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = _get_or_404(db, analysis_id, current_user.id)
    if row.file_path and Path(row.file_path).exists():
        try:
            Path(row.file_path).unlink()
        except OSError:
            pass
    # Cascade: triage records, notifications, monitors, path-analysis cache
    db.query(FindingTriageModel).filter(
        FindingTriageModel.analysis_id == analysis_id
    ).delete()
    db.query(NotificationModel).filter(
        NotificationModel.analysis_id == analysis_id
    ).delete()
    # Cascade history rows for any monitors targeting this analysis
    monitor_ids = [
        m.id for m in db.query(MonitoredPathModel).filter(
            MonitoredPathModel.analysis_id == analysis_id
        ).all()
    ]
    if monitor_ids:
        db.query(MonitoredPathRunModel).filter(
            MonitoredPathRunModel.monitored_path_id.in_(monitor_ids)
        ).delete(synchronize_session=False)
        db.query(MonitorOutcomeModel).filter(
            MonitorOutcomeModel.monitored_path_id.in_(monitor_ids)
        ).delete(synchronize_session=False)
        db.query(MonitorSuppressionModel).filter(
            MonitorSuppressionModel.monitored_path_id.in_(monitor_ids)
        ).delete(synchronize_session=False)
    db.query(MonitoredPathModel).filter(
        MonitoredPathModel.analysis_id == analysis_id
    ).delete()
    db.query(PathAnalysisCacheModel).filter(
        PathAnalysisCacheModel.analysis_id == analysis_id
    ).delete()
    db.delete(row)
    db.commit()


# ── Compare ───────────────────────────────────────────────────────────────────

@app.get("/api/analyses/compare")
def compare_analyses(
    a: str = Query(..., description="ID of baseline analysis"),
    b: str = Query(..., description="ID of incident analysis"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row_a = _get_or_404(db, a, current_user.id)
    row_b = _get_or_404(db, b, current_user.id)
    if row_a.status != "completed" or row_b.status != "completed":
        raise HTTPException(400, "Both analyses must be completed before comparing")
    try:
        data_a = json.loads(row_a.result_json)
        data_b = json.loads(row_b.result_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(500, "Failed to parse analysis results")
    from reporting.compare import compare
    result = compare(data_a, data_b)
    track("compare.executed", user_id=current_user.id, properties={"analysis_a": a, "analysis_b": b})
    return result


# ── Report ────────────────────────────────────────────────────────────────────

@app.get("/api/analyses/{analysis_id}/report")
def get_report(
    analysis_id: str,
    format: Optional[str] = Query(None, description="'executive' for non-technical summary"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Generate and stream a self-contained HTML report.

    ?format=executive returns a simplified view for non-technical stakeholders
    (impact summary + decision guidance only, no raw technical tables).
    """
    from fastapi.responses import Response

    from reporting.html_report import generate_html_report
    row = _get_or_404(db, analysis_id, current_user.id)
    if row.status != "completed":
        raise HTTPException(400, "Analysis not completed")
    if not row.result_json:
        raise HTTPException(404, "No result data")
    data = json.loads(row.result_json)
    executive_only = (format == "executive")
    html_content = generate_html_report(data, analysis_id, row.filename, executive_only=executive_only)
    safe_name = row.filename.replace(" ", "_").replace("/", "_")
    suffix = "_executive" if executive_only else ""
    track("report.downloaded", user_id=current_user.id, properties={
        "analysis_id": analysis_id, "format": format or "full",
    })
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}{suffix}_report.html"'},
    )


# ── Export ────────────────────────────────────────────────────────────────────

@app.get("/api/analyses/{analysis_id}/export")
def export_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Export full analysis result as JSON download."""
    from fastapi.responses import Response
    row = _get_or_404(db, analysis_id, current_user.id)
    if row.status != "completed":
        raise HTTPException(400, "Analysis not completed")
    if not row.result_json:
        raise HTTPException(404, "No result data")
    safe_name = row.filename.replace(" ", "_").replace("/", "_")
    return Response(
        content=row.result_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_analysis.json"'},
    )


# ── Suppression Rules ─────────────────────────────────────────────────────────

@app.get("/api/suppressions", response_model=List[SuppressionResponse])
def list_suppressions(
    scope: Optional[str] = Query(None, description="Filter by scope: global|user|analysis"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(SuppressionRuleModel)
    if scope:
        q = q.filter(SuppressionRuleModel.scope == scope)
    # Non-admins see only their own + global rules
    if not current_user.is_admin:
        q = q.filter(
            (SuppressionRuleModel.scope == "global") |
            (SuppressionRuleModel.created_by == current_user.id)
        )
    rows = q.order_by(SuppressionRuleModel.created_at.desc()).all()
    return [_suppression_dict(r) for r in rows]


@app.post("/api/suppressions", status_code=201, response_model=SuppressionResponse)
def create_suppression(
    req: SuppressionCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    if not req.rule_id and not req.src_ip and not req.dst_ip:
        raise HTTPException(400, "At least one of rule_id, src_ip, dst_ip must be specified")

    # Global scope requires admin
    if req.scope == "global" and not current_user.is_admin:
        raise HTTPException(403, "Only admins may create global suppression rules")

    # analysis-scoped rules must reference an analysis the user owns
    if req.scope == "analysis" and req.analysis_id:
        _get_or_404(db, req.analysis_id, current_user.id)

    expires_at = None
    if req.expires_at:
        try:
            expires_at = datetime.fromisoformat(req.expires_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, "expires_at must be ISO-8601 format")

    rule = SuppressionRuleModel(
        scope=req.scope,
        rule_id=req.rule_id or None,
        src_ip=req.src_ip or None,
        dst_ip=req.dst_ip or None,
        analysis_id=req.analysis_id or None,
        reason=req.reason,
        note=req.note,
        is_active=True,
        expires_at=expires_at,
        created_by=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    track("suppression.created", user_id=current_user.id, properties={"scope": req.scope, "rule_id": req.rule_id})
    return _suppression_dict(rule)


@app.patch("/api/suppressions/{rule_id}", response_model=SuppressionResponse)
def toggle_suppression(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Toggle is_active on a suppression rule (enable/disable without deleting)."""
    rule = db.query(SuppressionRuleModel).filter(SuppressionRuleModel.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Suppression rule not found")
    if not current_user.is_admin and rule.created_by != current_user.id:
        raise HTTPException(403, "Not authorized to modify this rule")
    rule.is_active = not rule.is_active
    db.commit()
    db.refresh(rule)
    return _suppression_dict(rule)


@app.delete("/api/suppressions/{rule_id}", status_code=204)
def delete_suppression(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    rule = db.query(SuppressionRuleModel).filter(SuppressionRuleModel.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Suppression rule not found")
    if not current_user.is_admin and rule.created_by != current_user.id:
        raise HTTPException(403, "Not authorized to delete this rule")
    db.delete(rule)
    db.commit()


# ── Path Analysis ─────────────────────────────────────────────────────────────

class PathAnalysisRequest(BaseModel):
    source_ip: str
    destination_ip: str
    destination_port: Optional[int] = None
    roles: Optional[dict] = None


def _normalize_roles(roles: Optional[dict]) -> Optional[dict]:
    """Return a canonical, sorted copy of *roles* for stable hashing.

    List values are sorted element-wise so that callers supplying the same IPs
    in a different order do not produce a spurious cache miss.
    """
    if not roles:
        return None
    normalized: dict = {}
    for key in sorted(roles.keys()):
        v = roles[key]
        if isinstance(v, list):
            v = sorted(str(x) for x in v)
        normalized[key] = v
    return normalized


def _compute_roles_hash(roles: Optional[dict]) -> str:
    """SHA-256 hex digest of the normalised *roles* dict."""
    canonical = json.dumps(_normalize_roles(roles), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _compute_path_cache_key(
    analysis_id: str,
    source_ip: str,
    destination_ip: str,
    destination_port: Optional[int],
    roles: Optional[dict],
    engine_version: str,
) -> str:
    """Deterministic SHA-256 cache key for a path analysis request."""
    parts = json.dumps(
        {
            "analysis_id": analysis_id,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "roles_hash": _compute_roles_hash(roles),
            "engine_version": engine_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(parts.encode()).hexdigest()


def _load_or_run_path_result(
    analysis_id: str,
    user_id: int,
    source_ip: str,
    destination_ip: str,
    destination_port: Optional[int],
    roles: Optional[dict],
    db: Session,
) -> dict:
    """Return a path-analysis result dict, using the cache when available.

    Shared by ``run_path_analysis`` and ``compare_path_analysis`` so that
    the cache + engine execution logic is not duplicated.  Raises HTTPException
    on any error (analysis not found, not completed, PCAP missing, parse fail).
    """
    from core.causal_path import CausalPathEngine, CACHE_ENGINE_VERSION

    row = _get_or_404(db, analysis_id, user_id)
    if row.status != "completed":
        raise HTTPException(400, f"Analysis {analysis_id} must be completed")

    cache_key = _compute_path_cache_key(
        analysis_id, source_ip, destination_ip,
        destination_port, roles, CACHE_ENGINE_VERSION,
    )
    cached = (
        db.query(PathAnalysisCacheModel)
        .filter(PathAnalysisCacheModel.cache_key == cache_key)
        .first()
    )
    if cached:
        return json.loads(cached.result_json)

    if not row.file_path or not Path(row.file_path).exists():
        raise HTTPException(404, f"PCAP file for analysis {analysis_id} is no longer available")

    from normalizer.pipeline import normalize

    try:
        ctx = normalize(row.file_path)
    except Exception as e:
        raise HTTPException(500, f"Failed to parse PCAP for {analysis_id}: {e}")

    engine = CausalPathEngine(ctx.packets, ctx.flows, ctx.findings, ctx)
    result = engine.analyze(source_ip, destination_ip,
                            destination_port=destination_port, roles=roles)
    result_dict = result.to_dict()

    db.add(PathAnalysisCacheModel(
        cache_key=cache_key,
        analysis_id=analysis_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        roles_hash=_compute_roles_hash(roles),
        engine_version=CACHE_ENGINE_VERSION,
        result_json=json.dumps(result_dict),
    ))
    db.commit()

    return result_dict


@app.post("/api/analyses/{analysis_id}/path-analysis")
def run_path_analysis(
    analysis_id: str,
    req: PathAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Run CausalPathEngine against the original PCAP for a specific src→dst pair.

    Results are cached by (analysis_id, source_ip, destination_ip,
    destination_port, normalised-roles, engine_version).  Cache hits skip the
    expensive PCAP normalisation step entirely and include ``from_cache: true``
    in the response.
    """
    from core.causal_path import CACHE_ENGINE_VERSION

    # Check cache first to avoid the _load_or_run_path_result check (it would
    # 400 on non-completed, but we want the same error message as before).
    row = _get_or_404(db, analysis_id, current_user.id)
    if row.status != "completed":
        raise HTTPException(400, "Analysis must be completed before running path analysis")

    cache_key = _compute_path_cache_key(
        analysis_id, req.source_ip, req.destination_ip,
        req.destination_port, req.roles, CACHE_ENGINE_VERSION,
    )
    cached = (
        db.query(PathAnalysisCacheModel)
        .filter(PathAnalysisCacheModel.cache_key == cache_key)
        .first()
    )
    if cached:
        result_dict = json.loads(cached.result_json)
        result_dict["from_cache"] = True
        track("path_analysis.cache_hit", user_id=current_user.id,
              properties={"analysis_id": analysis_id})
        return result_dict

    result_dict = _load_or_run_path_result(
        analysis_id, current_user.id,
        req.source_ip, req.destination_ip, req.destination_port, req.roles, db,
    )

    track("path_analysis.executed", user_id=current_user.id, properties={
        "analysis_id": analysis_id,
        "src": req.source_ip,
        "dst": req.destination_ip,
    })

    result_dict["from_cache"] = False
    return result_dict


# ── Path Compare ──────────────────────────────────────────────────────────────

class PathCompareRequest(BaseModel):
    baseline_analysis_id: str
    incident_analysis_id: str
    source_ip: str = Field(min_length=1)
    destination_ip: str = Field(min_length=1)
    destination_port: Optional[int] = None
    roles: Optional[dict] = None


_OUTCOME_SEVERITY: dict[str, int] = {
    "success": 0, "partial_success": 1, "failure": 2, "unknown": 3,
}

_REGRESSION_HINTS: dict[str, str] = {
    "backend_response_delay": "Backend server response time increased significantly",
    "return_path_problem":    "Return path or asymmetric routing issue emerged",
    "firewall_interference":  "Firewall policy may have changed or is now blocking traffic",
    "lb_backend_issue":       "Load balancer or backend pool health degraded",
    "connection_refused":     "Connection actively refused — service or port may have changed",
    "no_response":            "Complete loss of response from destination",
    "tls_failure":            "TLS negotiation failure introduced",
    "packet_loss":            "Significant packet loss detected on the path",
    "syn_timeout":            "TCP SYN timed out — destination may be unreachable",
}


def _compare_path_results(baseline: dict, incident: dict) -> dict:
    """Produce a structured diff between two PathAnalysisResult dicts."""

    def _summary(r: dict) -> dict:
        return {
            "connection_outcome":    r.get("connection_outcome", "unknown"),
            "primary_impairment":    r.get("primary_impairment"),
            "path_impairments":      r.get("path_impairments", []),
            "path_confidence_score": r.get("path_confidence_score", 0),
            "path_summary":          r.get("path_summary", ""),
            "likely_failure_point":  r.get("likely_failure_point", ""),
        }

    baseline_summary = _summary(baseline)
    incident_summary = _summary(incident)

    # Outcome regression
    b_outcome = baseline.get("connection_outcome", "unknown")
    i_outcome = incident.get("connection_outcome", "unknown")
    outcome_changed    = b_outcome != i_outcome
    outcome_regression = (
        _OUTCOME_SEVERITY.get(i_outcome, 3) > _OUTCOME_SEVERITY.get(b_outcome, 3)
    )

    # Impairment diff
    b_imps = set(baseline.get("path_impairments", []))
    i_imps = set(incident.get("path_impairments", []))
    new_impairments       = sorted(i_imps - b_imps)
    resolved_impairments  = sorted(b_imps - i_imps)
    persisting_impairments = sorted(b_imps & i_imps)

    # Timing diff (numeric values only)
    b_timing = baseline.get("timing_breakdown", {}) or {}
    i_timing = incident.get("timing_breakdown", {}) or {}
    timing_differences: dict = {}
    for key in sorted(set(b_timing) | set(i_timing)):
        b_val = b_timing.get(key)
        i_val = i_timing.get(key)
        if isinstance(b_val, (int, float)) and isinstance(i_val, (int, float)):
            delta = round(i_val - b_val, 3)
            timing_differences[key] = {
                "baseline": b_val,
                "incident": i_val,
                "delta":    delta,
                "worsened": delta > 0,
            }

    # Confidence diff
    b_conf = baseline.get("path_confidence_score", 0)
    i_conf = incident.get("path_confidence_score", 0)
    conf_delta = i_conf - b_conf
    confidence_changes = {
        "baseline": b_conf,
        "incident": i_conf,
        "delta":    conf_delta,
        "worsened": conf_delta < 0,
    }

    # Evidence diff (by type token)
    b_ev_types = {e.get("type") for e in baseline.get("evidence_items", [])}
    i_ev_types = {e.get("type") for e in incident.get("evidence_items", [])}
    evidence_differences = {
        "baseline_only": sorted(b_ev_types - i_ev_types),
        "incident_only": sorted(i_ev_types - b_ev_types),
    }

    # Key differences narrative
    key_differences: list[str] = []
    if outcome_changed:
        verb = "degraded" if outcome_regression else "changed"
        key_differences.append(
            f"Connection outcome {verb}: "
            f"{b_outcome.replace('_', ' ')} → {i_outcome.replace('_', ' ')}"
        )
    for imp in new_impairments:
        key_differences.append(f"New impairment detected: {imp.replace('_', ' ')}")
    for imp in resolved_impairments:
        key_differences.append(f"Impairment resolved: {imp.replace('_', ' ')}")
    if abs(conf_delta) >= 10:
        direction = "dropped" if conf_delta < 0 else "improved"
        key_differences.append(
            f"Path confidence {direction} by {abs(conf_delta)} points "
            f"({b_conf}% → {i_conf}%)"
        )

    # Most likely regression point
    regression_point: Optional[str] = None
    for imp in new_impairments:
        hint = _REGRESSION_HINTS.get(imp)
        if hint:
            regression_point = hint
            break
    if not regression_point and outcome_regression:
        if i_outcome == "failure":
            regression_point = (
                "Complete connection failure — destination unreachable or not responding"
            )
        else:
            regression_point = (
                "Partial degradation — connection established but impaired"
            )

    return {
        "baseline_summary":         baseline_summary,
        "incident_summary":         incident_summary,
        "outcome_changed":          outcome_changed,
        "outcome_regression":       outcome_regression,
        "key_differences":          key_differences,
        "impairment_changes": {
            "new":        new_impairments,
            "resolved":   resolved_impairments,
            "persisting": persisting_impairments,
        },
        "timing_differences":       timing_differences,
        "confidence_changes":       confidence_changes,
        "evidence_differences":     evidence_differences,
        "most_likely_regression_point": regression_point,
    }


@app.post("/api/path-analysis/compare")
def compare_path_analysis(
    req: PathCompareRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Compare the same src→dst path across two analyses (baseline vs incident).

    Runs or loads cached path analysis for both analysis IDs, then returns a
    structured diff that highlights regressions, new impairments, timing
    changes, and the most likely failure point.
    """
    baseline = _load_or_run_path_result(
        req.baseline_analysis_id, current_user.id,
        req.source_ip, req.destination_ip, req.destination_port, req.roles, db,
    )
    incident = _load_or_run_path_result(
        req.incident_analysis_id, current_user.id,
        req.source_ip, req.destination_ip, req.destination_port, req.roles, db,
    )

    result = _compare_path_results(baseline, incident)
    result["baseline_analysis_id"] = req.baseline_analysis_id
    result["incident_analysis_id"] = req.incident_analysis_id
    result["source_ip"]            = req.source_ip
    result["destination_ip"]       = req.destination_ip
    result["destination_port"]     = req.destination_port

    track("path_analysis.compare", user_id=current_user.id, properties={
        "baseline_id": req.baseline_analysis_id,
        "incident_id": req.incident_analysis_id,
    })

    return result


# ── Investigation Package Export ──────────────────────────────────────────────

class PathExportRequest(BaseModel):
    analysis_id: str
    source_ip: str = Field(min_length=1)
    destination_ip: str = Field(min_length=1)
    destination_port: Optional[int] = None
    roles: Optional[dict] = None
    saved_query_id: Optional[int] = None
    # Compare: include a baseline-vs-incident diff in the package
    include_compare: bool = False
    baseline_analysis_id: Optional[str] = None
    incident_analysis_id: Optional[str] = None


def _build_export_package(
    req: PathExportRequest,
    current_user: UserModel,
    db: Session,
) -> dict:
    """Shared logic for JSON and HTML export endpoints."""
    from core.causal_path import CACHE_ENGINE_VERSION
    from reporting.investigation_package import build_package

    user_id = current_user.id

    # ── Path analysis result ──────────────────────────────────────────────────
    path_result = _load_or_run_path_result(
        req.analysis_id, user_id,
        req.source_ip, req.destination_ip, req.destination_port, req.roles, db,
    )

    # ── Optional compare ──────────────────────────────────────────────────────
    compare_result: Optional[dict] = None
    if req.include_compare and req.baseline_analysis_id and req.incident_analysis_id:
        baseline = _load_or_run_path_result(
            req.baseline_analysis_id, user_id,
            req.source_ip, req.destination_ip, req.destination_port, req.roles, db,
        )
        incident = _load_or_run_path_result(
            req.incident_analysis_id, user_id,
            req.source_ip, req.destination_ip, req.destination_port, req.roles, db,
        )
        cr = _compare_path_results(baseline, incident)
        cr["baseline_analysis_id"] = req.baseline_analysis_id
        cr["incident_analysis_id"] = req.incident_analysis_id
        compare_result = cr

    # ── Analyst feedback (best-match for this src/dst/port/analysis) ──────────
    feedback_row = (
        db.query(PathAnalysisFeedbackModel)
        .filter(
            PathAnalysisFeedbackModel.analysis_id      == req.analysis_id,
            PathAnalysisFeedbackModel.source_ip        == req.source_ip,
            PathAnalysisFeedbackModel.destination_ip   == req.destination_ip,
            PathAnalysisFeedbackModel.destination_port == req.destination_port,
            PathAnalysisFeedbackModel.analyst_id       == user_id,
        )
        .first()
    )
    analyst_feedback = _feedback_dict(feedback_row, current_user) if feedback_row else None

    # ── Saved query metadata (optional, informational only) ───────────────────
    saved_query_meta: Optional[dict] = None
    if req.saved_query_id:
        sq = db.query(PathAnalysisSavedQueryModel).filter(
            PathAnalysisSavedQueryModel.id == req.saved_query_id,
            visible_filter(PathAnalysisSavedQueryModel, current_user),
        ).first()
        if sq:
            saved_query_meta = {"id": sq.id, "name": sq.name, "note": sq.note}

    return build_package(
        analysis_id=req.analysis_id,
        source_ip=req.source_ip,
        destination_ip=req.destination_ip,
        destination_port=req.destination_port,
        path_result=path_result,
        engine_version=CACHE_ENGINE_VERSION,
        compare_result=compare_result,
        analyst_feedback=analyst_feedback,
        saved_query_meta=saved_query_meta,
    )


@app.post("/api/path-analysis/export/json")
def export_investigation_json(
    req: PathExportRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Export a structured investigation package as a JSON download."""
    from fastapi.responses import Response

    package = _build_export_package(req, current_user, db)
    ep = f"{req.source_ip}_{req.destination_ip}"
    if req.destination_port:
        ep += f"_{req.destination_port}"
    filename = f"investigation_{ep}.json"
    track("path_analysis.export", user_id=current_user.id,
          properties={"format": "json", "analysis_id": req.analysis_id})
    return Response(
        content=json.dumps(package, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/path-analysis/export/html")
def export_investigation_html(
    req: PathExportRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Export a self-contained investigation package as an HTML download."""
    from fastapi.responses import Response
    from reporting.investigation_package import render_html

    package = _build_export_package(req, current_user, db)
    ep = f"{req.source_ip}_{req.destination_ip}"
    if req.destination_port:
        ep += f"_{req.destination_port}"
    filename = f"investigation_{ep}.html"
    track("path_analysis.export", user_id=current_user.id,
          properties={"format": "html", "analysis_id": req.analysis_id})
    return Response(
        content=render_html(package),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Path Analysis Feedback ────────────────────────────────────────────────────

class PathAnalysisFeedbackCreate(BaseModel):
    source_ip: str
    destination_ip: str
    destination_port: Optional[int] = None
    # Predicted values from the live result (captured at judgment time)
    predicted_outcome: str
    predicted_impairment: Optional[str] = None
    predicted_confidence: int
    # Analyst judgment
    verdict: str = Field(pattern="^(correct|partially_correct|incorrect)$")
    analyst_note: Optional[str] = None
    actual_root_cause: Optional[str] = None
    misleading_step: Optional[str] = None
    # Visibility scope: only "private" or "team" are meaningful for feedback.
    scope: str = Field(default="private", pattern="^(private|team)$")


class PathAnalysisFeedbackResponse(BaseModel):
    id: int
    analysis_id: str
    source_ip: str
    destination_ip: str
    destination_port: Optional[int]
    predicted_outcome: str
    predicted_impairment: Optional[str]
    predicted_confidence: int
    verdict: str
    analyst_note: Optional[str]
    actual_root_cause: Optional[str]
    misleading_step: Optional[str]
    analyst_id: Optional[int]
    scope: str
    team_id: Optional[int]
    can_edit: bool
    created_at: Optional[str]
    updated_at: Optional[str]


@app.post(
    "/api/analyses/{analysis_id}/path-analysis/feedback",
    response_model=PathAnalysisFeedbackResponse,
    status_code=200,
)
def upsert_path_feedback(
    analysis_id: str,
    req: PathAnalysisFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Submit (or update) analyst verdict on a path analysis result.

    Re-submitting the same source_ip / destination_ip / destination_port
    combination updates the existing record rather than creating a duplicate.

    A successful verdict also advances the investigation workflow state when
    it is still in ``new`` or ``in_progress``:
    - ``incorrect``                → ``needs_review``
    - ``correct`` / ``partially_correct`` → ``resolved``
    """
    analysis_row = _get_analysis_for_workflow(db, analysis_id, current_user)

    # "team" scope requires that the analyst actually belongs to a team
    if req.scope == "team" and not getattr(current_user, "team_id", None):
        raise HTTPException(
            403, "User must belong to a team to publish team-scoped feedback"
        )

    existing = (
        db.query(PathAnalysisFeedbackModel)
        .filter(
            PathAnalysisFeedbackModel.analysis_id      == analysis_id,
            PathAnalysisFeedbackModel.source_ip        == req.source_ip,
            PathAnalysisFeedbackModel.destination_ip   == req.destination_ip,
            PathAnalysisFeedbackModel.destination_port == req.destination_port,
            PathAnalysisFeedbackModel.analyst_id       == current_user.id,
        )
        .first()
    )

    if existing:
        existing.predicted_outcome    = req.predicted_outcome
        existing.predicted_impairment = req.predicted_impairment
        existing.predicted_confidence = req.predicted_confidence
        existing.verdict              = req.verdict
        existing.analyst_note         = req.analyst_note
        existing.actual_root_cause    = req.actual_root_cause
        existing.misleading_step      = req.misleading_step
        existing.scope                = req.scope
        existing.team_id              = (
            current_user.team_id if req.scope == "team" else None
        )
        row = existing
    else:
        row = PathAnalysisFeedbackModel(
            analysis_id=analysis_id,
            source_ip=req.source_ip,
            destination_ip=req.destination_ip,
            destination_port=req.destination_port,
            predicted_outcome=req.predicted_outcome,
            predicted_impairment=req.predicted_impairment,
            predicted_confidence=req.predicted_confidence,
            verdict=req.verdict,
            analyst_note=req.analyst_note,
            actual_root_cause=req.actual_root_cause,
            misleading_step=req.misleading_step,
            analyst_id=current_user.id,
            scope=req.scope,
            team_id=(current_user.team_id if req.scope == "team" else None),
        )
        db.add(row)

    # ── Auto-transition workflow based on verdict ────────────────────────────
    # Only move "open" states (new / in_progress); never override a deliberate
    # resolved / dismissed / needs_review set by an analyst.
    workflow_auto_state: Optional[str] = None
    if (analysis_row.workflow_state or "new") in ("new", "in_progress"):
        if req.verdict == "incorrect":
            workflow_auto_state = "needs_review"
        elif req.verdict in ("correct", "partially_correct"):
            workflow_auto_state = "resolved"
    if workflow_auto_state is not None:
        analysis_row.workflow_state = workflow_auto_state
        analysis_row.workflow_updated_at = datetime.utcnow()
        analysis_row.workflow_updated_by = current_user.id

    # ── Notification triggers ────────────────────────────────────────────────
    # 1. feedback_alert — incorrect verdict is a critical signal; alert the
    #    analysis owner AND the current assignee (if distinct from the actor).
    if req.verdict == "incorrect":
        _notify(
            db,
            user_id=analysis_row.user_id,
            type="feedback_alert",
            analysis_id=analysis_id,
            message=(
                f"Feedback marked INCORRECT on “{analysis_row.filename}”. "
                "The engine result may need review."
            ),
            actor_user_id=current_user.id,
        )
        if (
            analysis_row.assigned_user_id is not None
            and analysis_row.assigned_user_id != analysis_row.user_id
        ):
            _notify(
                db,
                user_id=analysis_row.assigned_user_id,
                type="feedback_alert",
                analysis_id=analysis_id,
                message=(
                    f"Feedback marked INCORRECT on “{analysis_row.filename}”. "
                    "The engine result may need review."
                ),
                actor_user_id=current_user.id,
            )

    # 2. State-change notifications from the auto-transition
    if workflow_auto_state is not None:
        _emit_state_change_notifications(
            db,
            row=analysis_row,
            state=workflow_auto_state,
            actor_user_id=current_user.id,
        )

    db.commit()
    db.refresh(row)
    track("path_feedback.submitted", user_id=current_user.id, properties={
        "analysis_id": analysis_id,
        "verdict": req.verdict,
    })
    if workflow_auto_state is not None:
        track(
            "workflow.state_changed",
            user_id=current_user.id,
            properties={
                "analysis_id": analysis_id,
                "state": workflow_auto_state,
                "trigger": "feedback",
            },
        )
    return _feedback_dict(row, current_user)


@app.get(
    "/api/analyses/{analysis_id}/path-analysis/feedback",
    response_model=List[PathAnalysisFeedbackResponse],
)
def list_path_feedback(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return all path-analysis feedback records visible to the current user.

    Includes the user's own records plus any team-scoped feedback authored by
    other members of the same team.  Team feedback authored by others is
    returned read-only (``can_edit: false``).
    """
    _get_or_404(db, analysis_id, current_user.id)

    # Own private feedback + any team feedback from the analyst's team
    own_clause = PathAnalysisFeedbackModel.analyst_id == current_user.id
    clauses = [own_clause]
    if getattr(current_user, "team_id", None) is not None:
        clauses.append(
            (PathAnalysisFeedbackModel.scope == "team")
            & (PathAnalysisFeedbackModel.team_id == current_user.team_id)
        )
    from sqlalchemy import or_ as _or
    rows = (
        db.query(PathAnalysisFeedbackModel)
        .filter(
            PathAnalysisFeedbackModel.analysis_id == analysis_id,
            _or(*clauses),
        )
        .order_by(PathAnalysisFeedbackModel.created_at.desc())
        .all()
    )
    return [_feedback_dict(r, current_user) for r in rows]


@app.get("/api/path-analysis/feedback/summary")
def path_feedback_summary(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Aggregate analyst feedback for calibration.

    Returns verdict distribution, per-impairment accuracy, overconfident cases
    (high confidence + incorrect), and weak-narrative cases (misleading step noted).
    """
    rows = (
        db.query(PathAnalysisFeedbackModel)
        .filter(PathAnalysisFeedbackModel.analyst_id == current_user.id)
        .all()
    )

    if not rows:
        return {
            "total": 0,
            "verdict_counts": {"correct": 0, "partially_correct": 0, "incorrect": 0},
            "accuracy_rate": None,
            "by_predicted_impairment": {},
            "overconfident": [],
            "weak_narratives": [],
        }

    verdict_counts: dict = {"correct": 0, "partially_correct": 0, "incorrect": 0}
    by_impairment: dict = {}

    for r in rows:
        verdict_counts[r.verdict] = verdict_counts.get(r.verdict, 0) + 1
        key = r.predicted_impairment or "none"
        bucket = by_impairment.setdefault(
            key, {"total": 0, "correct": 0, "partially_correct": 0, "incorrect": 0}
        )
        bucket["total"] += 1
        bucket[r.verdict] = bucket.get(r.verdict, 0) + 1

    correct_total = verdict_counts["correct"] + verdict_counts["partially_correct"]
    accuracy_rate = round(correct_total / len(rows), 3) if rows else None

    overconfident = [
        _feedback_dict(r, current_user)
        for r in rows
        if r.predicted_confidence >= 75 and r.verdict == "incorrect"
    ]

    weak_narratives = [
        _feedback_dict(r, current_user)
        for r in rows
        if r.misleading_step and r.verdict in ("partially_correct", "incorrect")
    ]

    return {
        "total": len(rows),
        "verdict_counts": verdict_counts,
        "accuracy_rate": accuracy_rate,
        "by_predicted_impairment": by_impairment,
        "overconfident": overconfident,
        "weak_narratives": weak_narratives,
    }


@app.get("/api/path-analysis/feedback/calibration")
def path_feedback_calibration(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Full calibration report over all analyst feedback records.

    Returns:
    - confidence_buckets: accuracy per 0–39 / 40–59 / 60–74 / 75–89 / 90–100 band
    - by_impairment: accuracy per predicted_impairment token
    - by_outcome: accuracy per predicted_outcome token
    - overconfident: rows with predicted_confidence >= 75 and verdict == incorrect
    - underconfident: rows with predicted_confidence <= 50 and verdict == correct
    - misleading_steps: frequency table of misleading path steps
    - root_cause_mismatches: predicted_impairment vs actual_root_cause crosstab
    """
    rows = (
        db.query(PathAnalysisFeedbackModel)
        .filter(PathAnalysisFeedbackModel.analyst_id == current_user.id)
        .all()
    )

    if not rows:
        return {
            "total": 0,
            "confidence_buckets": [],
            "by_impairment": [],
            "by_outcome": [],
            "overconfident": [],
            "underconfident": [],
            "misleading_steps": [],
            "root_cause_mismatches": [],
        }

    # ── helpers ────────────────────────────────────────────────────────────────

    def _is_correct(verdict: str) -> bool:
        return verdict in ("correct", "partially_correct")

    # ── confidence buckets ─────────────────────────────────────────────────────

    BUCKETS = [
        ("0–39",  0,  39),
        ("40–59", 40, 59),
        ("60–74", 60, 74),
        ("75–89", 75, 89),
        ("90–100", 90, 100),
    ]

    bucket_data: dict[str, dict] = {
        label: {"label": label, "min": lo, "max": hi, "total": 0, "correct": 0,
                "partially_correct": 0, "incorrect": 0}
        for label, lo, hi in BUCKETS
    }

    for r in rows:
        for label, lo, hi in BUCKETS:
            if lo <= r.predicted_confidence <= hi:
                b = bucket_data[label]
                b["total"] += 1
                b[r.verdict] = b.get(r.verdict, 0) + 1
                break

    for b in bucket_data.values():
        correct_n = b["correct"] + b["partially_correct"]
        b["accuracy_rate"] = round(correct_n / b["total"], 3) if b["total"] else None

    confidence_buckets = list(bucket_data.values())

    # ── by impairment ──────────────────────────────────────────────────────────

    imp_map: dict[str, dict] = {}
    for r in rows:
        key = r.predicted_impairment or "none"
        d = imp_map.setdefault(key, {
            "predicted_impairment": key, "total": 0,
            "correct": 0, "partially_correct": 0, "incorrect": 0,
        })
        d["total"] += 1
        d[r.verdict] = d.get(r.verdict, 0) + 1

    for d in imp_map.values():
        n = d["correct"] + d["partially_correct"]
        d["accuracy_rate"] = round(n / d["total"], 3) if d["total"] else None

    by_impairment = sorted(imp_map.values(), key=lambda x: -x["total"])

    # ── by outcome ─────────────────────────────────────────────────────────────

    out_map: dict[str, dict] = {}
    for r in rows:
        key = r.predicted_outcome or "unknown"
        d = out_map.setdefault(key, {
            "predicted_outcome": key, "total": 0,
            "correct": 0, "partially_correct": 0, "incorrect": 0,
        })
        d["total"] += 1
        d[r.verdict] = d.get(r.verdict, 0) + 1

    for d in out_map.values():
        n = d["correct"] + d["partially_correct"]
        d["accuracy_rate"] = round(n / d["total"], 3) if d["total"] else None

    by_outcome = sorted(out_map.values(), key=lambda x: -x["total"])

    # ── overconfident / underconfident ─────────────────────────────────────────

    overconfident = [
        _feedback_dict(r, current_user)
        for r in rows
        if r.predicted_confidence >= 75 and r.verdict == "incorrect"
    ]

    underconfident = [
        _feedback_dict(r, current_user)
        for r in rows
        if r.predicted_confidence <= 50 and r.verdict == "correct"
    ]

    # ── misleading step frequency ──────────────────────────────────────────────

    step_freq: dict[str, dict] = {}
    for r in rows:
        if not r.misleading_step:
            continue
        step = r.misleading_step.strip()
        if not step:
            continue
        d = step_freq.setdefault(step, {
            "step": step, "count": 0, "impairments": [],
        })
        d["count"] += 1
        imp = r.predicted_impairment or "none"
        if imp not in d["impairments"]:
            d["impairments"].append(imp)

    misleading_steps = sorted(step_freq.values(), key=lambda x: -x["count"])

    # ── root-cause mismatch crosstab ───────────────────────────────────────────

    mismatch_map: dict[tuple, dict] = {}
    for r in rows:
        if not r.actual_root_cause:
            continue
        pred = r.predicted_impairment or "none"
        actual = r.actual_root_cause.strip()
        key = (pred, actual)
        d = mismatch_map.setdefault(key, {
            "predicted_impairment": pred,
            "actual_root_cause": actual,
            "count": 0,
        })
        d["count"] += 1

    root_cause_mismatches = sorted(
        mismatch_map.values(),
        key=lambda x: -x["count"],
    )

    return {
        "total": len(rows),
        "confidence_buckets": confidence_buckets,
        "by_impairment": by_impairment,
        "by_outcome": by_outcome,
        "overconfident": overconfident,
        "underconfident": underconfident,
        "misleading_steps": misleading_steps,
        "root_cause_mismatches": root_cause_mismatches,
    }


# ── Investigation Notes (team-visible collaboration) ─────────────────────────

class InvestigationNoteCreate(BaseModel):
    source_ip:        str           = Field(min_length=1)
    destination_ip:   str           = Field(min_length=1)
    destination_port: Optional[int] = None
    body:             str           = Field(min_length=1)
    scope:            str           = Field(default="private", pattern="^(private|team)$")


class InvestigationNoteUpdate(BaseModel):
    body:  Optional[str] = Field(default=None, min_length=1)
    scope: Optional[str] = Field(default=None, pattern="^(private|team)$")


def _note_to_dict(n: InvestigationNoteModel, current_user: UserModel) -> dict:
    own = n.created_by == current_user.id
    is_admin = bool(getattr(current_user, "is_admin", False))
    return {
        "id":               n.id,
        "analysis_id":      n.analysis_id,
        "source_ip":        n.source_ip,
        "destination_ip":   n.destination_ip,
        "destination_port": n.destination_port,
        "body":             n.body,
        "scope":            n.scope,
        "team_id":          n.team_id,
        "created_by":       n.created_by,
        "updated_by":       n.updated_by,
        "can_edit":         own or is_admin,
        "created_at":       n.created_at.isoformat() if n.created_at else None,
        "updated_at":       n.updated_at.isoformat() if n.updated_at else None,
    }


def _note_visible(current_user: UserModel):
    """SQLAlchemy filter limiting notes to ones the user may see."""
    own = InvestigationNoteModel.created_by == current_user.id
    if getattr(current_user, "is_admin", False):
        return InvestigationNoteModel.id == InvestigationNoteModel.id  # always true
    team_id = getattr(current_user, "team_id", None)
    if team_id is None:
        return own
    from sqlalchemy import or_ as _or
    return _or(
        own,
        (InvestigationNoteModel.scope == "team") & (InvestigationNoteModel.team_id == team_id),
    )


@app.get("/api/analyses/{analysis_id}/investigation-notes")
def list_investigation_notes(
    analysis_id: str,
    source_ip: Optional[str] = Query(None),
    destination_ip: Optional[str] = Query(None),
    destination_port: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List investigation notes visible to the current user on this analysis.

    If ``source_ip``/``destination_ip``/``destination_port`` query params are
    provided, the list is narrowed to notes on that exact endpoint tuple.
    """
    # Access check against the analysis itself
    _get_or_404(db, analysis_id, current_user.id)
    q = db.query(InvestigationNoteModel).filter(
        InvestigationNoteModel.analysis_id == analysis_id,
        _note_visible(current_user),
    )
    if source_ip:
        q = q.filter(InvestigationNoteModel.source_ip == source_ip)
    if destination_ip:
        q = q.filter(InvestigationNoteModel.destination_ip == destination_ip)
    if destination_port is not None:
        q = q.filter(InvestigationNoteModel.destination_port == destination_port)
    rows = q.order_by(InvestigationNoteModel.created_at.desc()).all()
    return [_note_to_dict(n, current_user) for n in rows]


@app.post("/api/analyses/{analysis_id}/investigation-notes", status_code=201)
def create_investigation_note(
    analysis_id: str,
    req: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Create a new investigation note.

    ``scope`` may be ``private`` (default) or ``team``.  Team scope requires
    the user to belong to a team.
    """
    _get_or_404(db, analysis_id, current_user.id)
    if req.scope == "team" and not getattr(current_user, "team_id", None):
        raise HTTPException(
            403, "User must belong to a team to create team-scoped notes"
        )
    n = InvestigationNoteModel(
        analysis_id=analysis_id,
        source_ip=req.source_ip.strip(),
        destination_ip=req.destination_ip.strip(),
        destination_port=req.destination_port,
        body=req.body,
        scope=req.scope,
        team_id=(current_user.team_id if req.scope == "team" else None),
        created_by=current_user.id,
        updated_by=current_user.id,
    )
    db.add(n)
    db.commit()
    db.refresh(n)
    return _note_to_dict(n, current_user)


@app.put("/api/analyses/{analysis_id}/investigation-notes/{note_id}")
def update_investigation_note(
    analysis_id: str,
    note_id: int,
    req: InvestigationNoteUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Edit an existing investigation note.

    Only the author (or an admin) may edit.  Members of the same team who did
    not author the note see it read-only and receive 403 here.
    """
    n = db.query(InvestigationNoteModel).filter(
        InvestigationNoteModel.id == note_id,
        InvestigationNoteModel.analysis_id == analysis_id,
    ).first()
    if n is None:
        raise HTTPException(404, "Note not found")
    is_admin = bool(getattr(current_user, "is_admin", False))
    # Visibility check first
    visible = (
        n.created_by == current_user.id
        or is_admin
        or (
            n.scope == "team"
            and getattr(current_user, "team_id", None) == n.team_id
            and n.team_id is not None
        )
    )
    if not visible:
        raise HTTPException(403, "Not authorized to access this note")
    if not (n.created_by == current_user.id or is_admin):
        raise HTTPException(
            403, "Read-only: only the author may edit this team note"
        )
    if req.body is not None:
        n.body = req.body
    if req.scope is not None and req.scope != n.scope:
        if req.scope == "team" and not getattr(current_user, "team_id", None):
            raise HTTPException(
                403, "User must belong to a team to publish team-scoped notes"
            )
        n.scope = req.scope
        n.team_id = current_user.team_id if req.scope == "team" else None
    n.updated_by = current_user.id
    n.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(n)
    return _note_to_dict(n, current_user)


@app.delete(
    "/api/analyses/{analysis_id}/investigation-notes/{note_id}",
    status_code=204,
)
def delete_investigation_note(
    analysis_id: str,
    note_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Delete an investigation note.

    Only the author (or an admin) may delete; team members with read-only
    visibility receive 403.
    """
    n = db.query(InvestigationNoteModel).filter(
        InvestigationNoteModel.id == note_id,
        InvestigationNoteModel.analysis_id == analysis_id,
    ).first()
    if n is None:
        raise HTTPException(404, "Note not found")
    is_admin = bool(getattr(current_user, "is_admin", False))
    if not (n.created_by == current_user.id or is_admin):
        # Distinguish "not visible at all" vs "read-only"
        visible = (
            n.scope == "team"
            and getattr(current_user, "team_id", None) == n.team_id
            and n.team_id is not None
        )
        if visible:
            raise HTTPException(
                403, "Read-only: only the author may delete this team note"
            )
        raise HTTPException(403, "Not authorized to access this note")
    db.delete(n)
    db.commit()


# ── Analyst Triage ────────────────────────────────────────────────────────────

@app.get("/api/analyses/{analysis_id}/triage", response_model=List[TriageResponse])
def list_triage(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return all triage records for an analysis."""
    _get_or_404(db, analysis_id, current_user.id)
    rows = (
        db.query(FindingTriageModel)
        .filter(FindingTriageModel.analysis_id == analysis_id)
        .all()
    )
    return [_triage_dict(r) for r in rows]


@app.put(
    "/api/analyses/{analysis_id}/triage/{finding_key:path}",
    response_model=TriageResponse,
)
def upsert_triage(
    analysis_id: str,
    finding_key: str,
    req: TriageUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Create or update triage state for a single finding."""
    _get_or_404(db, analysis_id, current_user.id)

    row = (
        db.query(FindingTriageModel)
        .filter(
            FindingTriageModel.analysis_id == analysis_id,
            FindingTriageModel.finding_key == finding_key,
        )
        .first()
    )
    if row:
        row.status = req.status
        if req.note is not None:
            row.note = req.note
        row.analyst_id = current_user.id
        row.updated_at = datetime.utcnow()
    else:
        row = FindingTriageModel(
            analysis_id=analysis_id,
            finding_key=finding_key,
            status=req.status,
            note=req.note,
            analyst_id=current_user.id,
        )
        db.add(row)

    db.commit()
    db.refresh(row)
    track("triage.updated", user_id=current_user.id, properties={
        "analysis_id": analysis_id,
        "status": req.status,
    })
    return _triage_dict(row)


# ── Telemetry summary (admin only) ────────────────────────────────────────────

@app.get("/api/telemetry/summary")
def telemetry_summary(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Aggregate telemetry counts by event type. Admin only."""
    if not current_user.is_admin:
        raise HTTPException(403, "Admin access required")

    from sqlalchemy import func as sqlfunc
    rows = (
        db.query(TelemetryEventModel.event_type, sqlfunc.count(TelemetryEventModel.id))
        .group_by(TelemetryEventModel.event_type)
        .all()
    )
    counts = {event_type: count for event_type, count in rows}

    # Total analyses in DB for context
    total_analyses = db.query(AnalysisModel).count()
    completed = db.query(AnalysisModel).filter(AnalysisModel.status == "completed").count()
    failed = db.query(AnalysisModel).filter(AnalysisModel.status == "failed").count()

    return {
        "event_counts": counts,
        "analyses": {
            "total": total_analyses,
            "completed": completed,
            "failed": failed,
        },
    }


# ── Path Analysis Saved Queries ───────────────────────────────────────────────

def _query_to_dict(q: PathAnalysisSavedQueryModel, current_user: Optional[UserModel] = None) -> dict:
    return {
        "id":                 q.id,
        "name":               q.name,
        "source_ip":          q.source_ip,
        "destination_ip":     q.destination_ip,
        "destination_port":   q.destination_port,
        "role_preset_id":     q.role_preset_id,
        "firewall_ips":       json.loads(q.firewall_ips),
        "load_balancer_vips": json.loads(q.load_balancer_vips),
        "backend_ips":        json.loads(q.backend_ips),
        "backend_subnets":    json.loads(q.backend_subnets),
        "note":               q.note,
        "scope":              q.scope,
        "team_id":            q.team_id,
        "owner_user_id":      q.owner_user_id,
        "created_by":         q.created_by,
        "updated_by":         q.updated_by,
        "can_edit":           sharing_can_edit(q, current_user) if current_user is not None else False,
        "created_at":         q.created_at.isoformat() if q.created_at else None,
        "updated_at":         q.updated_at.isoformat() if q.updated_at else None,
    }


def _get_query_or_404(db: Session, query_id: int, current_user: UserModel) -> PathAnalysisSavedQueryModel:
    q = db.query(PathAnalysisSavedQueryModel).filter(
        PathAnalysisSavedQueryModel.id == query_id
    ).first()
    enforce_view(q, current_user)
    return q


def _get_query_for_edit(db: Session, query_id: int, current_user: UserModel) -> PathAnalysisSavedQueryModel:
    q = db.query(PathAnalysisSavedQueryModel).filter(
        PathAnalysisSavedQueryModel.id == query_id
    ).first()
    enforce_edit(q, current_user)
    return q


class SavedQueryCreate(BaseModel):
    name:               str              = Field(min_length=1, max_length=200)
    source_ip:          str              = Field(min_length=1)
    destination_ip:     str              = Field(min_length=1)
    destination_port:   Optional[int]   = None
    role_preset_id:     Optional[int]   = None
    firewall_ips:       Optional[List[str]] = None
    load_balancer_vips: Optional[List[str]] = None
    backend_ips:        Optional[List[str]] = None
    backend_subnets:    Optional[List[str]] = None
    note:               Optional[str]   = None
    scope:              str             = Field(default="private", pattern="^(private|team|global)$")


class SavedQueryUpdate(BaseModel):
    name:               Optional[str]       = Field(default=None, min_length=1, max_length=200)
    source_ip:          Optional[str]       = Field(default=None, min_length=1)
    destination_ip:     Optional[str]       = Field(default=None, min_length=1)
    destination_port:   Optional[int]       = None
    role_preset_id:     Optional[int]       = None
    firewall_ips:       Optional[List[str]] = None
    load_balancer_vips: Optional[List[str]] = None
    backend_ips:        Optional[List[str]] = None
    backend_subnets:    Optional[List[str]] = None
    note:               Optional[str]       = None
    scope:              Optional[str]       = Field(default=None, pattern="^(private|team|global)$")
    clear_port:         bool                = False   # explicit sentinel to set port→None
    clear_preset:       bool                = False   # explicit sentinel to set preset→None


@app.post("/api/path-analysis/saved-queries", status_code=201)
def create_saved_query(
    req: SavedQueryCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Save a new path-analysis query with an optional sharing scope.

    ``scope`` may be ``private`` (default), ``team`` (requires team
    membership) or ``global`` (admin only).  The referenced ``role_preset_id``
    must be visible to the current user under the visibility rules.
    """
    check_can_create(req.scope, current_user)

    # Preset must be visible to the caller — private presets owned by others
    # still return 404/403 through enforce_view in _get_preset_or_404.
    if req.role_preset_id is not None:
        _get_preset_or_404(db, req.role_preset_id, current_user)

    q = PathAnalysisSavedQueryModel(
        owner_user_id=      current_user.id,
        name=               req.name.strip(),
        source_ip=          req.source_ip.strip(),
        destination_ip=     req.destination_ip.strip(),
        destination_port=   req.destination_port,
        role_preset_id=     req.role_preset_id,
        firewall_ips=       json.dumps(_preset_lists(req.firewall_ips)),
        load_balancer_vips= json.dumps(_preset_lists(req.load_balancer_vips)),
        backend_ips=        json.dumps(_preset_lists(req.backend_ips)),
        backend_subnets=    json.dumps(_preset_lists(req.backend_subnets)),
        note=               req.note or None,
        scope=              req.scope,
        team_id=            resolve_team_id(req.scope, current_user),
        created_by=         current_user.id,
        updated_by=         current_user.id,
    )
    db.add(q)
    db.commit()
    db.refresh(q)
    return _query_to_dict(q, current_user)


@app.get("/api/path-analysis/saved-queries")
def list_saved_queries(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List every saved query visible to the current user (private, team,
    global) — newest first."""
    rows = (
        db.query(PathAnalysisSavedQueryModel)
        .filter(visible_filter(PathAnalysisSavedQueryModel, current_user))
        .order_by(PathAnalysisSavedQueryModel.updated_at.desc())
        .all()
    )
    return [_query_to_dict(q, current_user) for q in rows]


@app.get("/api/path-analysis/saved-queries/{query_id}")
def get_saved_query(
    query_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Get one saved query.  Returns 403 if the caller cannot see it."""
    return _query_to_dict(_get_query_or_404(db, query_id, current_user), current_user)


@app.put("/api/path-analysis/saved-queries/{query_id}")
def update_saved_query(
    query_id: int,
    req: SavedQueryUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Partial update of a saved query.

    Only the author (or an admin) may edit a shared item.  Members of the
    same team who did not create the row get a 403 read-only response.
    """
    q = _get_query_for_edit(db, query_id, current_user)

    if req.name is not None:
        q.name = req.name.strip()
    if req.source_ip is not None:
        q.source_ip = req.source_ip.strip()
    if req.destination_ip is not None:
        q.destination_ip = req.destination_ip.strip()
    if req.clear_port:
        q.destination_port = None
    elif req.destination_port is not None:
        q.destination_port = req.destination_port
    if req.clear_preset:
        q.role_preset_id = None
    elif req.role_preset_id is not None:
        _get_preset_or_404(db, req.role_preset_id, current_user)
        q.role_preset_id = req.role_preset_id
    if req.firewall_ips is not None:
        q.firewall_ips = json.dumps(_preset_lists(req.firewall_ips))
    if req.load_balancer_vips is not None:
        q.load_balancer_vips = json.dumps(_preset_lists(req.load_balancer_vips))
    if req.backend_ips is not None:
        q.backend_ips = json.dumps(_preset_lists(req.backend_ips))
    if req.backend_subnets is not None:
        q.backend_subnets = json.dumps(_preset_lists(req.backend_subnets))
    if req.note is not None:
        q.note = req.note or None
    if req.scope is not None and req.scope != q.scope:
        check_can_create(req.scope, current_user)
        q.scope = req.scope
        q.team_id = resolve_team_id(req.scope, current_user)
    q.updated_by = current_user.id
    q.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(q)
    return _query_to_dict(q, current_user)


@app.delete("/api/path-analysis/saved-queries/{query_id}", status_code=204)
def delete_saved_query(
    query_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Delete a saved query.  Only the author (or an admin) may delete."""
    q = _get_query_for_edit(db, query_id, current_user)
    monitor_ids = [
        m.id for m in db.query(MonitoredPathModel).filter(
            MonitoredPathModel.saved_query_id == query_id
        ).all()
    ]
    if monitor_ids:
        db.query(MonitoredPathRunModel).filter(
            MonitoredPathRunModel.monitored_path_id.in_(monitor_ids)
        ).delete(synchronize_session=False)
        db.query(MonitorOutcomeModel).filter(
            MonitorOutcomeModel.monitored_path_id.in_(monitor_ids)
        ).delete(synchronize_session=False)
        db.query(MonitorSuppressionModel).filter(
            MonitorSuppressionModel.monitored_path_id.in_(monitor_ids)
        ).delete(synchronize_session=False)
    db.query(MonitoredPathModel).filter(
        MonitoredPathModel.saved_query_id == query_id
    ).delete()
    db.delete(q)
    db.commit()


# ── Scheduled Path Monitoring (drift detection) ───────────────────────────────
#
# A monitored path binds a saved query (which captures src/dst/port/roles) to
# a specific analysis (the PCAP that periodic re-runs target) and a poll
# interval.  Re-runs use the path-analysis cache so an unchanged PCAP costs
# nothing.  Drift is computed from the previous snapshot via
# ``monitoring.detect_drift``; when warning/critical drift fires we create a
# notification and transition the analysis workflow to needs_review.

class MonitoredPathCreate(BaseModel):
    saved_query_id:            int
    analysis_id:               str = Field(min_length=1)
    schedule_interval_minutes: int = Field(default=60, ge=1, le=60 * 24 * 7)
    enabled:                   bool = True


class MonitoredPathUpdate(BaseModel):
    schedule_interval_minutes: Optional[int] = Field(
        default=None, ge=1, le=60 * 24 * 7,
    )
    enabled: Optional[bool] = None


def _roles_from_saved_query(q: PathAnalysisSavedQueryModel) -> Optional[dict]:
    """Build the CausalPathEngine ``roles`` dict from a saved query row.

    Returns None if all four lists are empty so that the cache key matches
    callers who passed roles=None.
    """
    fw  = json.loads(q.firewall_ips)
    lbs = json.loads(q.load_balancer_vips)
    bks = json.loads(q.backend_ips)
    sub = json.loads(q.backend_subnets)
    if not (fw or lbs or bks or sub):
        return None
    return {
        "firewall_ips":       fw,
        "load_balancer_vips": lbs,
        "backend_ips":        bks,
        "backend_subnets":    sub,
    }


def _load_outcome_dicts(db: Session, monitor_id: int) -> list:
    """Return outcome records as plain dicts for the learning module."""
    rows = (
        db.query(MonitorOutcomeModel)
        .filter(MonitorOutcomeModel.monitored_path_id == monitor_id)
        .order_by(MonitorOutcomeModel.created_at.asc())
        .all()
    )
    return [
        {
            "outcome":        r.outcome,
            "root_cause_type": r.root_cause_type,
            "signal_drivers": json.loads(r.signal_drivers_json) if r.signal_drivers_json else [],
        }
        for r in rows
    ]


def _load_suppression_dicts(db: Session, monitor_id: int) -> list:
    rows = (
        db.query(MonitorSuppressionModel)
        .filter(MonitorSuppressionModel.monitored_path_id == monitor_id)
        .all()
    )
    return [
        {
            "id":      r.id,
            "kind":    r.kind,
            "value":   r.value,
            "reason":  r.reason,
            "enabled": r.enabled,
            "until":   r.until,
        }
        for r in rows
    ]


def _load_baseline(db: Session, monitor_id: int):
    """Return the baseline dict for a monitor (or None)."""
    m = db.query(MonitoredPathModel).filter(
        MonitoredPathModel.id == monitor_id
    ).first()
    if not m or not m.baseline_json:
        return None
    return json.loads(m.baseline_json)


def _compute_monitor_risk(db: Session, monitor_id: int) -> dict:
    """Build the trend digest, score the risk, decide an action, then
    adjust it via historical outcome learnings, baseline expectations,
    and active suppression rules.

    Pipeline:
      runs → summarize_history → compute_risk_score → decide_action
        → adjust_action(learnings)
        → apply_baseline(baseline)
        → apply_suppressions(rules)

    Returns a dict combining the risk fields with the final action so the
    list endpoint can render everything with no follow-ups.
    """
    rows = _load_history_rows(db, monitor_id, limit=50)
    runs = [_run_to_dict(r) for r in rows]
    summary = summarize_history(runs)
    risk = compute_risk_score(summary)
    action = decide_action(summary, risk)

    # Outcome-aware adjustments
    outcome_dicts = _load_outcome_dicts(db, monitor_id)
    learnings = learn_from_outcomes(outcome_dicts)
    action = adjust_action(action, learnings)

    # Baseline adaptation
    baseline = _load_baseline(db, monitor_id)
    action = apply_baseline(action, summary, baseline)

    # Suppression rules (must be last — analyst explicitly said "shut up")
    suppressions = _load_suppression_dicts(db, monitor_id)
    action = apply_suppressions(action, suppressions, now=datetime.utcnow())

    return {**risk, "action": action, "learnings": learnings}


def _monitor_to_dict(m: MonitoredPathModel, db: Session) -> dict:
    """Serialize a monitored path with derived display fields.

    Includes the saved-query name and the target analysis filename so the
    frontend can render the row without N+1 follow-up requests.
    Also includes ``run_count`` so the list view can show "no history yet"
    versus "100 runs over the last month" without a follow-up call, and a
    dynamically-computed ``risk_score`` / ``risk_level`` / ``risk_drivers``
    so the list page can sort and badge each row directly.
    """
    sq = db.query(PathAnalysisSavedQueryModel).filter(
        PathAnalysisSavedQueryModel.id == m.saved_query_id,
    ).first()
    arow = db.query(AnalysisModel).filter(
        AnalysisModel.id == m.analysis_id,
    ).first()
    run_count = (
        db.query(MonitoredPathRunModel)
        .filter(MonitoredPathRunModel.monitored_path_id == m.id)
        .count()
    )
    risk = _compute_monitor_risk(db, m.id)
    return {
        "id":                        m.id,
        "saved_query_id":            m.saved_query_id,
        "saved_query_name":          sq.name if sq else None,
        "source_ip":                 sq.source_ip if sq else None,
        "destination_ip":            sq.destination_ip if sq else None,
        "destination_port":          sq.destination_port if sq else None,
        "analysis_id":               m.analysis_id,
        "analysis_filename":         arow.filename if arow else None,
        "owner_user_id":             m.owner_user_id,
        "schedule_interval_minutes": m.schedule_interval_minutes,
        "enabled":                   m.enabled,
        "last_run_at":     m.last_run_at.isoformat() if m.last_run_at else None,
        "last_change_at":  m.last_change_at.isoformat() if m.last_change_at else None,
        "last_drift_severity":  m.last_drift_severity,
        "last_change_summary":  json.loads(m.last_change_summary) if m.last_change_summary else None,
        "has_baseline":         m.last_result_json is not None,
        "run_count":            run_count,
        "risk_score":           risk["risk_score"],
        "risk_level":           risk["risk_level"],
        "risk_drivers":         risk["drivers"],
        # Action engine output (see monitoring.decide_action)
        "action_required":      risk["action"]["action_required"],
        "action_label":         risk["action"]["action_label"],
        "priority":             risk["action"]["priority"],
        "recommended_action":   risk["action"]["recommended_action"],
        "action_focus":         risk["action"]["focus"],
        "suppressed":           risk["action"].get("suppressed", False),
        "suppressed_rules":     risk["action"].get("suppressed_rules", []),
        "baseline_applied":     risk["action"].get("baseline_applied", False),
        # Outcome learnings
        "last_outcome":         m.last_outcome,
        "last_outcome_at":      m.last_outcome_at.isoformat() if m.last_outcome_at else None,
        "outcome_count":        risk.get("learnings", {}).get("total", 0),
        "outcome_hints":        risk.get("learnings", {}).get("hints", []),
        "dominant_root_cause":  risk.get("learnings", {}).get("dominant_root_cause"),
        "fp_rate":              risk.get("learnings", {}).get("fp_rate", 0),
        "created_at":     m.created_at.isoformat() if m.created_at else None,
        "updated_at":     m.updated_at.isoformat() if m.updated_at else None,
    }


def _get_monitor_or_404(
    db: Session, monitor_id: int, current_user: UserModel,
) -> MonitoredPathModel:
    """Fetch a monitor the caller owns (or any monitor for an admin).

    We do not implement team-scoped monitors yet — they belong to the
    creating user only — so this is a simple ownership check.
    """
    m = db.query(MonitoredPathModel).filter(
        MonitoredPathModel.id == monitor_id,
    ).first()
    if not m:
        raise HTTPException(404, "Monitor not found")
    if m.owner_user_id != current_user.id and not getattr(
        current_user, "is_admin", False
    ):
        raise HTTPException(404, "Monitor not found")
    return m


def _run_monitor(
    db: Session,
    monitor: MonitoredPathModel,
    *,
    actor_user_id: Optional[int] = None,
) -> dict:
    """Execute one monitor tick: re-run path analysis, detect drift, alert.

    The monitor is mutated in place — the caller is responsible for the final
    ``db.commit()``.  Returns the drift report dict (see
    ``monitoring.detect_drift``).

    Drift policy:
      - The first run always succeeds with severity=none and stores a baseline.
      - Warning/critical drift creates a ``drift_detected`` notification for
        the monitor owner and transitions the target analysis workflow to
        ``needs_review`` (unless it is already in a terminal state).
    """
    sq = db.query(PathAnalysisSavedQueryModel).filter(
        PathAnalysisSavedQueryModel.id == monitor.saved_query_id,
    ).first()
    if not sq:
        raise HTTPException(404, "Saved query for monitor no longer exists")

    roles = _roles_from_saved_query(sq)

    # _load_or_run_path_result enforces analysis ownership via _get_or_404,
    # so the monitor owner must also own the captured analysis — we already
    # check this at create time.
    current_result = _load_or_run_path_result(
        monitor.analysis_id,
        monitor.owner_user_id,
        sq.source_ip,
        sq.destination_ip,
        sq.destination_port,
        roles,
        db,
    )

    previous = (
        json.loads(monitor.last_result_json)
        if monitor.last_result_json
        else None
    )
    report = detect_drift(previous, current_result)

    now = datetime.utcnow()
    monitor.last_run_at = now
    monitor.last_result_json = json.dumps(current_result)
    monitor.last_drift_severity = report["severity"]

    if report["drift_detected"]:
        monitor.last_change_at = now
        monitor.last_change_summary = json.dumps({
            "severity": report["severity"],
            "changes":  report["changes"],
            "changed_fields": report["changed_fields"],
        })

    # ── History row (one per run, lightweight projection) ────────────────────
    # Stored even when there's no drift so the trend view can plot
    # confidence/timing over time.  The full result still lives on the
    # MonitoredPathModel.last_result_json column for the next comparison.
    db.add(MonitoredPathRunModel(
        monitored_path_id=monitor.id,
        run_at=now,
        connection_outcome=current_result.get("connection_outcome", "unknown"),
        primary_impairment=current_result.get("primary_impairment"),
        path_confidence_score=int(
            current_result.get("path_confidence_score") or 0
        ),
        drift_severity=report["severity"],
        action_required=report["action_required"],
        timing_json=json.dumps(current_result.get("timing_breakdown") or {}),
        impairments_json=json.dumps(
            current_result.get("path_impairments") or []
        ),
    ))

    # Alert + workflow integration: only when the change is action-required.
    if report["action_required"]:
        arow = db.query(AnalysisModel).filter(
            AnalysisModel.id == monitor.analysis_id,
        ).first()
        if arow is not None:
            severity_label = report["severity"].upper()
            top_change = report["changes"][0] if report["changes"] else "drift detected"
            message = (
                f"[{severity_label}] Path "
                f"{sq.source_ip} → {sq.destination_ip}"
                f" on “{arow.filename}”: {top_change}"
            )
            # actor_user_id is intentionally None: drift is detected by the
            # system, not by the analyst pressing "Run now", so it should
            # always notify the owner even when they triggered the run.
            _notify(
                db,
                user_id=monitor.owner_user_id,
                type="drift_detected",
                analysis_id=arow.id,
                message=message,
                actor_user_id=None,
            )
            # Auto-transition the analysis to needs_review unless it is in a
            # terminal state (resolved/dismissed) the analyst already chose.
            if arow.workflow_state not in ("resolved", "dismissed", "needs_review"):
                arow.workflow_state = "needs_review"
                arow.workflow_updated_at = now
                arow.workflow_updated_by = actor_user_id
                _emit_state_change_notifications(
                    db,
                    row=arow,
                    state="needs_review",
                    actor_user_id=actor_user_id or monitor.owner_user_id,
                )

    track(
        "monitor.run",
        user_id=monitor.owner_user_id,
        properties={
            "monitor_id": monitor.id,
            "severity":   report["severity"],
            "drift":      report["drift_detected"],
        },
    )
    return report


def run_due_monitors(db: Session, *, now: Optional[datetime] = None) -> int:
    """Run every enabled monitor whose interval has elapsed.

    Used by the in-process tick (or by tests calling it directly).  Returns
    the number of monitors that ran.  Errors on one monitor are swallowed so
    one bad monitor cannot block the rest of the batch.
    """
    now = now or datetime.utcnow()
    monitors = db.query(MonitoredPathModel).filter(
        MonitoredPathModel.enabled.is_(True),
    ).all()
    ran = 0
    for m in monitors:
        if not is_due(m.last_run_at, m.schedule_interval_minutes, now):
            continue
        try:
            _run_monitor(db, m)
            ran += 1
        except HTTPException:
            # Skip monitors whose target became inaccessible — surface in
            # the next manual run instead of crashing the batch.
            db.rollback()
            continue
    db.commit()
    return ran


@app.post("/api/path-monitors", status_code=201)
def create_monitor(
    req: MonitoredPathCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Create a new scheduled monitor for a saved path query."""
    sq = _get_query_or_404(db, req.saved_query_id, current_user)
    # Owner must own the target analysis (so cache reuse + access checks
    # in _load_or_run_path_result line up).
    _get_or_404(db, req.analysis_id, current_user.id)

    m = MonitoredPathModel(
        saved_query_id=req.saved_query_id,
        analysis_id=req.analysis_id,
        owner_user_id=current_user.id,
        schedule_interval_minutes=req.schedule_interval_minutes,
        enabled=req.enabled,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    track("monitor.created", user_id=current_user.id,
          properties={"monitor_id": m.id})
    return _monitor_to_dict(m, db)


@app.get("/api/path-monitors")
def list_monitors(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List monitors visible to the current user, ranked highest risk first.

    Risk is computed dynamically per row from the trend digest — see
    ``_compute_monitor_risk``.  Ties (e.g. several brand-new monitors at
    risk=0) fall back to creation order so the ordering remains stable
    across calls.
    """
    rows = (
        db.query(MonitoredPathModel)
        .filter(MonitoredPathModel.owner_user_id == current_user.id)
        .all()
    )
    serialized = [_monitor_to_dict(m, db) for m in rows]
    serialized.sort(
        key=lambda d: (-int(d.get("risk_score") or 0), -int(d.get("id") or 0)),
    )
    return serialized


@app.get("/api/path-monitors/{monitor_id}")
def get_monitor(
    monitor_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    m = _get_monitor_or_404(db, monitor_id, current_user)
    return _monitor_to_dict(m, db)


@app.put("/api/path-monitors/{monitor_id}")
def update_monitor(
    monitor_id: int,
    req: MonitoredPathUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Toggle a monitor on/off or change its poll interval."""
    m = _get_monitor_or_404(db, monitor_id, current_user)
    if req.schedule_interval_minutes is not None:
        m.schedule_interval_minutes = req.schedule_interval_minutes
    if req.enabled is not None:
        m.enabled = req.enabled
    db.commit()
    db.refresh(m)
    return _monitor_to_dict(m, db)


@app.delete("/api/path-monitors/{monitor_id}", status_code=204)
def delete_monitor(
    monitor_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    m = _get_monitor_or_404(db, monitor_id, current_user)
    db.query(MonitoredPathRunModel).filter(
        MonitoredPathRunModel.monitored_path_id == monitor_id
    ).delete()
    db.query(MonitorOutcomeModel).filter(
        MonitorOutcomeModel.monitored_path_id == monitor_id
    ).delete()
    db.query(MonitorSuppressionModel).filter(
        MonitorSuppressionModel.monitored_path_id == monitor_id
    ).delete()
    db.delete(m)
    db.commit()


@app.post("/api/path-monitors/{monitor_id}/run")
def trigger_monitor_run(
    monitor_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Force a monitor to run immediately and return the drift report.

    The interval timer is honoured by ``run_due_monitors`` but bypassed here
    on purpose — analysts pressing "Run now" expect a fresh comparison.
    """
    m = _get_monitor_or_404(db, monitor_id, current_user)
    report = _run_monitor(db, m, actor_user_id=current_user.id)
    db.commit()
    db.refresh(m)
    return {
        "monitor": _monitor_to_dict(m, db),
        "report":  report,
    }


@app.post("/api/path-monitors/tick")
def tick_monitors(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Run every enabled monitor whose interval has elapsed.  Admin only.

    This stands in for a real scheduler — the simplest way to drive monitors
    in the current deployment is for an external cron / k8s CronJob to POST
    here every minute or so.
    """
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(403, "Admin access required")
    ran = run_due_monitors(db)
    return {"ran": ran}


@app.get("/api/system-insights")
def system_insights(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return system-wide intelligence across all monitors visible to the
    current user.

    Combines global outcome aggregation, signal effectiveness, correlation
    detection (shared destination / shared impairment), and system risk
    distribution into a single payload for the dashboard widget.
    """
    # Monitors owned by the current user (same scope as list_monitors).
    monitor_rows = (
        db.query(MonitoredPathModel)
        .filter(MonitoredPathModel.owner_user_id == current_user.id)
        .all()
    )
    monitor_dicts = [_monitor_to_dict(m, db) for m in monitor_rows]

    # All outcomes across those monitors.
    monitor_ids = [m.id for m in monitor_rows]
    if monitor_ids:
        outcome_rows = (
            db.query(MonitorOutcomeModel)
            .filter(MonitorOutcomeModel.monitored_path_id.in_(monitor_ids))
            .all()
        )
        outcomes = [
            {
                "outcome":         r.outcome,
                "root_cause_type": r.root_cause_type,
                "signal_drivers":  json.loads(r.signal_drivers_json) if r.signal_drivers_json else [],
                "monitored_path_id": r.monitored_path_id,
            }
            for r in outcome_rows
        ]
    else:
        outcomes = []

    # Recent runs — last 50 per monitor so the correlation detector has a
    # window into current state without loading the whole history.
    recent_runs: list = []
    for mid in monitor_ids:
        rows = _load_history_rows(db, mid, limit=50)
        recent_runs.extend(_run_to_dict(r) for r in rows)

    return compute_system_insights(monitor_dicts, outcomes, recent_runs)


# ── Monitor history + trend endpoints ────────────────────────────────────────

def _run_to_dict(r: MonitoredPathRunModel) -> dict:
    return {
        "id":                    r.id,
        "monitored_path_id":     r.monitored_path_id,
        "run_at":                r.run_at.isoformat() if r.run_at else None,
        "connection_outcome":    r.connection_outcome,
        "primary_impairment":    r.primary_impairment,
        "path_confidence_score": r.path_confidence_score,
        "drift_severity":        r.drift_severity,
        "action_required":       r.action_required,
        "timing":                json.loads(r.timing_json) if r.timing_json else {},
        "impairments":           json.loads(r.impairments_json) if r.impairments_json else [],
    }


def _load_history_rows(
    db: Session, monitor_id: int, limit: Optional[int] = None,
):
    """Return run rows for a monitor in chronological order (oldest → newest).

    Trend analysis is most natural in chronological order, but the API list
    endpoint reverses to newest-first for human display.  Keeping the
    canonical fetch order in one helper avoids confusion.
    """
    rows = (
        db.query(MonitoredPathRunModel)
        .filter(MonitoredPathRunModel.monitored_path_id == monitor_id)
        .order_by(
            MonitoredPathRunModel.run_at.asc(),
            MonitoredPathRunModel.id.asc(),
        )
        .all()
    )
    if limit and len(rows) > limit:
        rows = rows[-limit:]
    return rows


@app.get("/api/path-monitors/{monitor_id}/history")
def get_monitor_history(
    monitor_id: int,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return the most recent ``limit`` runs for a monitor (newest first)."""
    _get_monitor_or_404(db, monitor_id, current_user)
    rows = _load_history_rows(db, monitor_id, limit=limit)
    # Newest-first for display.
    return [_run_to_dict(r) for r in reversed(rows)]


@app.get("/api/path-monitors/{monitor_id}/trend")
def get_monitor_trend(
    monitor_id: int,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return a trend digest computed over the most recent ``limit`` runs.

    The digest is intentionally a single flat dict (see
    ``monitoring.summarize_history``) so the frontend trend panel can render
    it without conditional plumbing.
    """
    _get_monitor_or_404(db, monitor_id, current_user)
    rows = _load_history_rows(db, monitor_id, limit=limit)
    # summarize_history wants the chronological dicts — same shape we store.
    runs_for_summary = [_run_to_dict(r) for r in rows]
    return summarize_history(runs_for_summary)


# ── Monitor outcomes (feedback loop) ─────────────────────────────────────────

class MonitorOutcomeCreate(BaseModel):
    outcome: str = Field(
        pattern="^(issue_confirmed|false_positive|transient_issue|root_cause_identified)$",
    )
    root_cause_type: Optional[str] = Field(
        default=None,
        pattern="^(network|firewall|app|dns|unknown)$",
    )
    note: Optional[str] = None


@app.post("/api/path-monitors/{monitor_id}/outcomes", status_code=201)
def record_outcome(
    monitor_id: int,
    req: MonitorOutcomeCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Record an analyst outcome after investigating a monitored path.

    Snapshots the current risk drivers onto the outcome row so that the
    learning module can later correlate signal → outcome.
    """
    m = _get_monitor_or_404(db, monitor_id, current_user)

    if req.outcome == "root_cause_identified" and not req.root_cause_type:
        raise HTTPException(400, "root_cause_type required for root_cause_identified")

    # Snapshot the current risk drivers
    risk = _compute_monitor_risk(db, m.id)
    drivers = risk.get("drivers") or []

    now = datetime.utcnow()
    row = MonitorOutcomeModel(
        monitored_path_id=m.id,
        outcome=req.outcome,
        root_cause_type=req.root_cause_type,
        note=req.note,
        signal_drivers_json=json.dumps(drivers),
        analyst_id=current_user.id,
        created_at=now,
    )
    db.add(row)

    # Denormalise for quick list display
    m.last_outcome = req.outcome
    m.last_outcome_at = now

    db.commit()
    db.refresh(row)
    return _outcome_to_dict(row)


@app.get("/api/path-monitors/{monitor_id}/outcomes")
def list_outcomes(
    monitor_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List all outcome records for a monitor (newest first)."""
    _get_monitor_or_404(db, monitor_id, current_user)
    rows = (
        db.query(MonitorOutcomeModel)
        .filter(MonitorOutcomeModel.monitored_path_id == monitor_id)
        .order_by(MonitorOutcomeModel.created_at.desc())
        .all()
    )
    return [_outcome_to_dict(r) for r in rows]


@app.get("/api/path-monitors/{monitor_id}/learnings")
def get_learnings(
    monitor_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return the aggregated learning digest for a monitor."""
    _get_monitor_or_404(db, monitor_id, current_user)
    outcome_dicts = _load_outcome_dicts(db, monitor_id)
    return learn_from_outcomes(outcome_dicts)


def _outcome_to_dict(r: MonitorOutcomeModel) -> dict:
    return {
        "id":              r.id,
        "monitored_path_id": r.monitored_path_id,
        "outcome":         r.outcome,
        "root_cause_type": r.root_cause_type,
        "note":            r.note,
        "signal_drivers":  json.loads(r.signal_drivers_json) if r.signal_drivers_json else [],
        "analyst_id":      r.analyst_id,
        "created_at":      r.created_at.isoformat() if r.created_at else None,
    }


# ── Monitor suppressions ─────────────────────────────────────────────────────

class MonitorSuppressionCreate(BaseModel):
    kind: str = Field(pattern="^(mute|snooze|impairment|severity)$")
    value: Optional[str] = None
    reason: Optional[str] = None
    until: Optional[str] = None      # ISO 8601 datetime


@app.post("/api/path-monitors/{monitor_id}/suppressions", status_code=201)
def create_suppression(
    monitor_id: int,
    req: MonitorSuppressionCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    m = _get_monitor_or_404(db, monitor_id, current_user)
    until_dt = None
    if req.until:
        try:
            until_dt = datetime.fromisoformat(req.until)
        except (ValueError, TypeError):
            raise HTTPException(400, "Invalid 'until' datetime")
    if req.kind == "snooze" and until_dt is None:
        raise HTTPException(400, "'until' is required for snooze rules")
    row = MonitorSuppressionModel(
        monitored_path_id=m.id,
        kind=req.kind,
        value=req.value,
        reason=req.reason,
        until=until_dt,
        created_by=current_user.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _suppression_rule_dict(row)


@app.get("/api/path-monitors/{monitor_id}/suppressions")
def list_suppressions(
    monitor_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    _get_monitor_or_404(db, monitor_id, current_user)
    rows = (
        db.query(MonitorSuppressionModel)
        .filter(MonitorSuppressionModel.monitored_path_id == monitor_id)
        .order_by(MonitorSuppressionModel.id.desc())
        .all()
    )
    return [_suppression_rule_dict(r) for r in rows]


@app.delete(
    "/api/path-monitors/{monitor_id}/suppressions/{rule_id}",
    status_code=204,
)
def delete_suppression(
    monitor_id: int,
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    _get_monitor_or_404(db, monitor_id, current_user)
    row = db.query(MonitorSuppressionModel).filter(
        MonitorSuppressionModel.id == rule_id,
        MonitorSuppressionModel.monitored_path_id == monitor_id,
    ).first()
    if not row:
        raise HTTPException(404, "Suppression rule not found")
    db.delete(row)
    db.commit()


def _suppression_rule_dict(r: MonitorSuppressionModel) -> dict:
    return {
        "id":         r.id,
        "kind":       r.kind,
        "value":      r.value,
        "reason":     r.reason,
        "enabled":    r.enabled,
        "until":      r.until.isoformat() if r.until else None,
        "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


# ── Monitor baseline expectations ────────────────────────────────────────────

class BaselineUpdate(BaseModel):
    accepted_delay_max_ms: Optional[float] = None
    accepted_confidence_min: Optional[int] = None
    known_noisy_impairments: Optional[List[str]] = None
    known_visibility_gaps: Optional[List[str]] = None


@app.put("/api/path-monitors/{monitor_id}/baseline")
def update_baseline(
    monitor_id: int,
    req: BaselineUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    m = _get_monitor_or_404(db, monitor_id, current_user)
    baseline = {}
    if req.accepted_delay_max_ms is not None:
        baseline["accepted_delay_max_ms"] = req.accepted_delay_max_ms
    if req.accepted_confidence_min is not None:
        baseline["accepted_confidence_min"] = req.accepted_confidence_min
    if req.known_noisy_impairments is not None:
        baseline["known_noisy_impairments"] = req.known_noisy_impairments
    if req.known_visibility_gaps is not None:
        baseline["known_visibility_gaps"] = req.known_visibility_gaps
    m.baseline_json = json.dumps(baseline) if baseline else None
    db.commit()
    return {"baseline": baseline}


@app.get("/api/path-monitors/{monitor_id}/baseline")
def get_baseline(
    monitor_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    m = _get_monitor_or_404(db, monitor_id, current_user)
    baseline = json.loads(m.baseline_json) if m.baseline_json else {}
    return {"baseline": baseline}


# ── Dashboard summary ────────────────────────────────────────────────────────

_risk_cache: dict = {"ts": 0.0, "data": []}
_RISK_CACHE_TTL = 30.0  # seconds


@app.get("/api/dashboard/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Single endpoint that returns everything the dashboard needs.

    Aggregates collector status, live event counts, risk scores,
    auto-detection notifications, work-queue counts, and analysis
    stats into one response so the frontend needs only one fetch
    on page load.
    """
    import time as _time
    from sqlalchemy import func as sqlfunc, case

    now = datetime.utcnow()
    five_min_ago = now - __import__("datetime").timedelta(minutes=5)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # ── Collector ────────────────────────────────────────────────────────
    from collector.service import collector_stats
    collector = collector_stats()

    # ── Live events (last 5 min) ─────────────────────────────────────────
    from database import LiveEventModel
    le_q = db.query(
        sqlfunc.count(LiveEventModel.id).label("total"),
        sqlfunc.sum(case((LiveEventModel.action == "allow", 1), else_=0)).label("allow"),
        sqlfunc.sum(case((LiveEventModel.action == "deny", 1), else_=0)).label("deny"),
        sqlfunc.sum(case((LiveEventModel.action == "drop", 1), else_=0)).label("drop"),
    ).filter(LiveEventModel.event_time >= five_min_ago).first()

    live_total = int(le_q.total or 0) if le_q else 0
    live_allow = int(le_q.allow or 0) if le_q else 0
    live_deny  = int(le_q.deny or 0) if le_q else 0
    live_drop  = int(le_q.drop or 0) if le_q else 0

    # ── Risk scores (cached) ─────────────────────────────────────────────
    mono = _time.monotonic()
    if mono - _risk_cache["ts"] > _RISK_CACHE_TTL:
        from collector.live_risk import compute_live_risk_scores
        _risk_cache["data"] = compute_live_risk_scores(db, now=now)
        _risk_cache["ts"] = mono

    all_risk = _risk_cache["data"]
    top5 = [e for e in all_risk if e["risk_score"] >= 30][:5]
    top_entry = all_risk[0] if all_risk else None

    # ── Auto-detections ──────────────────────────────────────────────────
    auto_notifs = (
        db.query(NotificationModel)
        .filter(
            NotificationModel.user_id == current_user.id,
            NotificationModel.type == "drift_detected",
            NotificationModel.message.startswith("[AUTO]"),
        )
        .order_by(NotificationModel.created_at.desc())
        .limit(5)
        .all()
    )
    auto_detections = [
        {
            "id":          n.id,
            "message":     n.message,
            "analysis_id": n.analysis_id,
            "created_at":  n.created_at.isoformat() if n.created_at else None,
        }
        for n in auto_notifs
    ]

    # ── Work queue counts (current user) ─────────────────────────────────
    uid = current_user.id
    is_admin = bool(getattr(current_user, "is_admin", False))
    wq_base = db.query(AnalysisModel).filter(
        AnalysisModel.status == "completed",
    )
    if not is_admin:
        wq_base = wq_base.filter(
            or_(
                AnalysisModel.user_id == uid,
                AnalysisModel.assigned_user_id == uid,
            )
        )

    total_open = wq_base.filter(
        AnalysisModel.workflow_state.in_(("new", "in_progress", "needs_review")),
    ).count()
    needs_review = wq_base.filter(
        AnalysisModel.workflow_state == "needs_review",
    ).count()
    new_analyses = wq_base.filter(
        AnalysisModel.workflow_state == "new",
    ).count()

    # ── Analysis stats (current user) ────────────────────────────────────
    my_analyses = db.query(AnalysisModel).filter(
        AnalysisModel.user_id == uid,
    )
    total_analyses = my_analyses.count()
    pending = my_analyses.filter(
        AnalysisModel.status.in_(("pending", "running")),
    ).count()
    completed_today = my_analyses.filter(
        AnalysisModel.status == "completed",
        AnalysisModel.finished_at >= midnight,
    ).count()
    failed_today = my_analyses.filter(
        AnalysisModel.status == "failed",
        AnalysisModel.finished_at >= midnight,
    ).count()

    return {
        "collector": collector,
        "live_events": {
            "total_last_5min":  live_total,
            "allow_last_5min":  live_allow,
            "deny_last_5min":   live_deny,
            "drop_last_5min":   live_drop,
            "top_risk_ip":      top_entry["source_ip"] if top_entry else None,
            "top_risk_score":   top_entry["risk_score"] if top_entry else None,
        },
        "risk_scores": top5,
        "auto_detections": auto_detections,
        "work_queue": {
            "total_open":    total_open,
            "needs_review":  needs_review,
            "new_analyses":  new_analyses,
        },
        "analyses": {
            "total":           total_analyses,
            "completed_today": completed_today,
            "failed_today":    failed_today,
            "pending":         pending,
        },
    }


# ── Live flows API ───────────────────────────────────────────────────────────

from database import LiveFlowModel


def _live_flow_dict(r: LiveFlowModel) -> dict:
    return {
        "id":                    r.id,
        "source_id":             r.source_id,
        "device_type":           r.device_type,
        "device_role":           r.device_role,
        "parser_id":             r.parser_id,
        "source_ip":             r.source_ip,
        "destination_ip":        r.destination_ip,
        "source_port":           r.source_port,
        "destination_port":      r.destination_port,
        "protocol":              r.protocol,
        "first_seen":            r.first_seen.isoformat() if r.first_seen else None,
        "last_seen":             r.last_seen.isoformat() if r.last_seen else None,
        "duration_ms":           r.duration_ms,
        "event_count":           r.event_count,
        "total_bytes_in":        r.total_bytes_in,
        "total_bytes_out":       r.total_bytes_out,
        "total_packets_in":      r.total_packets_in,
        "total_packets_out":     r.total_packets_out,
        "allow_count":           r.allow_count,
        "deny_count":            r.deny_count,
        "drop_count":            r.drop_count,
        "reset_count":           r.reset_count,
        "alert_count":           r.alert_count,
        "action_summary":        r.action_summary,
        "reason_summary":        r.reason_summary,
        "nat_source_ip":         r.nat_source_ip,
        "nat_destination_ip":    r.nat_destination_ip,
        "application":           r.application,
        "service":               r.service,
        "backend_ip":            r.backend_ip,
        "state":                 r.state,
        "flow_type":             r.flow_type,
        "reset_ratio":           r.reset_ratio,
        "deny_ratio":            r.deny_ratio,
        "burst_score":           r.burst_score,
        "asymmetric_behavior":   r.asymmetric_behavior,
        "suspicious_reasons":    json.loads(r.suspicious_reasons) if r.suspicious_reasons else [],
        "suppressed":            r.suppressed,
    }


@app.get("/api/live-flows")
def list_live_flows(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    state: Optional[str] = None,
    application: Optional[str] = None,
    action_summary: Optional[str] = None,
    flow_type: Optional[str] = None,
    suppressed: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Query reconstructed live flows with optional filters."""
    q = db.query(LiveFlowModel)
    if source_ip:
        q = q.filter(LiveFlowModel.source_ip == source_ip)
    if destination_ip:
        q = q.filter(LiveFlowModel.destination_ip == destination_ip)
    if protocol:
        q = q.filter(LiveFlowModel.protocol == protocol.upper())
    if state:
        q = q.filter(LiveFlowModel.state == state)
    if application:
        q = q.filter(LiveFlowModel.application == application)
    if action_summary:
        q = q.filter(LiveFlowModel.action_summary == action_summary)
    if flow_type:
        q = q.filter(LiveFlowModel.flow_type == flow_type)
    if suppressed is not None:
        q = q.filter(LiveFlowModel.suppressed.is_(suppressed))
    total = q.count()
    rows = (
        q.order_by(LiveFlowModel.last_seen.desc(), LiveFlowModel.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "flows": [_live_flow_dict(r) for r in rows],
    }


@app.get("/api/live-flows/stats")
def live_flows_stats(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Aggregated statistics over reconstructed live flows."""
    from sqlalchemy import func as sqlfunc

    total = db.query(LiveFlowModel).count()
    state_counts = dict(
        db.query(LiveFlowModel.state, sqlfunc.count(LiveFlowModel.id))
        .group_by(LiveFlowModel.state)
        .all()
    )
    flow_type_counts = dict(
        db.query(LiveFlowModel.flow_type, sqlfunc.count(LiveFlowModel.id))
        .filter(LiveFlowModel.flow_type.isnot(None))
        .group_by(LiveFlowModel.flow_type)
        .all()
    )
    top_talkers = [
        {"ip": ip, "flow_count": c, "total_bytes": b}
        for ip, c, b in (
            db.query(
                LiveFlowModel.source_ip,
                sqlfunc.count(LiveFlowModel.id),
                sqlfunc.sum(LiveFlowModel.total_bytes_in + LiveFlowModel.total_bytes_out),
            )
            .group_by(LiveFlowModel.source_ip)
            .order_by(sqlfunc.count(LiveFlowModel.id).desc())
            .limit(10)
            .all()
        )
    ]
    top_reset = [
        {"ip": ip, "count": c}
        for ip, c in (
            db.query(LiveFlowModel.source_ip, sqlfunc.count(LiveFlowModel.id))
            .filter(LiveFlowModel.state == "reset")
            .group_by(LiveFlowModel.source_ip)
            .order_by(sqlfunc.count(LiveFlowModel.id).desc())
            .limit(10)
            .all()
        )
    ]
    top_denied = [
        {"ip": ip, "count": c}
        for ip, c in (
            db.query(LiveFlowModel.source_ip, sqlfunc.count(LiveFlowModel.id))
            .filter(LiveFlowModel.state == "denied")
            .group_by(LiveFlowModel.source_ip)
            .order_by(sqlfunc.count(LiveFlowModel.id).desc())
            .limit(10)
            .all()
        )
    ]

    return {
        "total_flows":     total,
        "active_flows":    state_counts.get("active", 0),
        "completed_flows": state_counts.get("completed", 0),
        "denied_flows":    state_counts.get("denied", 0),
        "reset_flows":     state_counts.get("reset", 0),
        "dropped_flows":   state_counts.get("dropped", 0),
        "top_talkers":     top_talkers,
        "top_reset_sources":  top_reset,
        "top_denied_sources": top_denied,
        "flow_type_counts": flow_type_counts,
    }


@app.get("/api/live-flows/timeline")
def live_flows_timeline(
    minutes: int = Query(60, ge=1, le=1440),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Per-minute flow state counts for the last *minutes* minutes."""
    from sqlalchemy import case, literal_column
    from sqlalchemy import func as sqlfunc

    cutoff = datetime.utcnow() - __import__("datetime").timedelta(minutes=minutes)

    is_sqlite = "sqlite" in str(db.bind.url)
    if is_sqlite:
        bucket_expr = sqlfunc.strftime("%Y-%m-%dT%H:%M:00", LiveFlowModel.last_seen)
    else:
        bucket_expr = sqlfunc.date_trunc(
            literal_column("'minute'"), LiveFlowModel.last_seen,
        )

    rows = (
        db.query(
            bucket_expr.label("bucket"),
            sqlfunc.sum(case((LiveFlowModel.state == "active", 1), else_=0)).label("active"),
            sqlfunc.sum(case((LiveFlowModel.state == "completed", 1), else_=0)).label("completed"),
            sqlfunc.sum(case((LiveFlowModel.state == "denied", 1), else_=0)).label("denied"),
            sqlfunc.sum(case((LiveFlowModel.state == "reset", 1), else_=0)).label("reset"),
            sqlfunc.sum(case((LiveFlowModel.state == "dropped", 1), else_=0)).label("dropped"),
        )
        .filter(LiveFlowModel.last_seen >= cutoff)
        .group_by(literal_column("bucket"))
        .order_by(literal_column("bucket"))
        .all()
    )
    return [
        {
            "bucket":    str(r.bucket),
            "active":    int(r.active or 0),
            "completed": int(r.completed or 0),
            "denied":    int(r.denied or 0),
            "reset":     int(r.reset or 0),
            "dropped":   int(r.dropped or 0),
        }
        for r in rows
    ]


# ── Live incidents API ────────────────────────────────────────────────────────

from database import LiveIncidentModel


@app.get("/api/live-incidents")
def list_live_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    behavior_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List behavior-derived incidents, newest first."""
    q = db.query(LiveIncidentModel)
    if status:
        q = q.filter(LiveIncidentModel.status == status)
    if severity:
        q = q.filter(LiveIncidentModel.severity == severity)
    if source_ip:
        q = q.filter(LiveIncidentModel.source_ip == source_ip)
    if behavior_type:
        q = q.filter(LiveIncidentModel.behavior_type == behavior_type)
    total = q.count()
    rows = (
        q.order_by(
            LiveIncidentModel.priority_score.desc().nullslast(),
            LiveIncidentModel.last_activity_at.desc().nullslast(),
            LiveIncidentModel.last_seen.desc(),
        )
        .offset(offset).limit(limit).all()
    )
    return {
        "total": total,
        "incidents": [_incident_dict(r) for r in rows],
    }


@app.get("/api/live-incidents/{incident_id}")
def get_live_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(LiveIncidentModel).filter(
        LiveIncidentModel.id == incident_id
    ).first()
    if not row:
        raise HTTPException(404, "Incident not found")
    return _incident_dict(row)


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved|dismissed)$")


@app.put("/api/live-incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    req: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(LiveIncidentModel).filter(
        LiveIncidentModel.id == incident_id
    ).first()
    if not row:
        raise HTTPException(404, "Incident not found")
    now = datetime.utcnow()
    row.status = req.status
    row.last_activity_at = now
    row.updated_at = now
    from collector.incidents import update_priority
    update_priority(row, now=now)
    db.commit()
    return _incident_dict(row)


def _incident_dict(r: LiveIncidentModel) -> dict:
    return {
        "id":                r.id,
        "source_ip":         r.source_ip,
        "behavior_type":     r.behavior_type,
        "severity":          r.severity,
        "status":            r.status,
        "first_seen":        r.first_seen.isoformat() if r.first_seen else None,
        "last_seen":         r.last_seen.isoformat() if r.last_seen else None,
        "event_count":       r.event_count,
        "linked_flow_count": r.linked_flow_count,
        "latest_confidence": r.latest_confidence,
        "summary":           r.summary,
        "top_destination_ips":    json.loads(r.top_destination_ips) if r.top_destination_ips else [],
        "top_ports":              json.loads(r.top_ports) if r.top_ports else [],
        "total_distinct_destinations": r.total_distinct_destinations,
        "total_distinct_ports":        r.total_distinct_ports,
        "sample_flows":           json.loads(r.sample_flows) if r.sample_flows else [],
        "last_activity_summary":  r.last_activity_summary,
        "impacted_assets_count":       r.impacted_assets_count,
        "highest_target_criticality":  r.highest_target_criticality,
        "target_summary":              r.target_summary,
        "priority_score":    r.priority_score,
        "last_activity_at":  r.last_activity_at.isoformat() if r.last_activity_at else None,
        "decay_factor":      r.decay_factor,
        "created_at":        r.created_at.isoformat() if r.created_at else None,
        "updated_at":        r.updated_at.isoformat() if r.updated_at else None,
    }


@app.get("/api/live-flows/behaviors")
def live_flow_behaviors(
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return correlated behavior signals per source IP."""
    from collector.flow_correlation import compute_flow_behaviors

    entries = compute_flow_behaviors(db)
    if min_confidence > 0:
        entries = [e for e in entries if e["confidence"] >= min_confidence]
    return entries


# ── Baselines API ────────────────────────────────────────────────────────────

from database import IPBaselineModel
from collector.baseline import baseline_dict


@app.get("/api/baselines")
def list_baselines(
    source_ip: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(IPBaselineModel)
    if source_ip:
        q = q.filter(IPBaselineModel.source_ip == source_ip)
    q = q.order_by(IPBaselineModel.source_ip)
    return [baseline_dict(r) for r in q.all()]


@app.get("/api/baselines/{source_ip}")
def get_baseline(
    source_ip: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(IPBaselineModel).filter(
        IPBaselineModel.source_ip == source_ip,
    ).first()
    if not row:
        raise HTTPException(404, "Baseline not found")
    return baseline_dict(row)


# ── Attack sessions API ──────────────────────────────────────────────────────

from database import AttackSessionModel
from collector.sessions import session_dict


@app.get("/api/attack-sessions")
def list_attack_sessions(
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(AttackSessionModel)
    if status:
        q = q.filter(AttackSessionModel.status == status)
    if source_ip:
        q = q.filter(AttackSessionModel.source_ip == source_ip)
    q = q.order_by(
        AttackSessionModel.priority_score.desc(),
        AttackSessionModel.last_activity.desc(),
    )
    rows = q.offset(offset).limit(limit).all()
    return [session_dict(r) for r in rows]


@app.get("/api/attack-sessions/{session_id}")
def get_attack_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(AttackSessionModel).filter(AttackSessionModel.id == session_id).first()
    if not row:
        raise HTTPException(404, "Attack session not found")
    return session_dict(row)


# ── Live events API ──────────────────────────────────────────────────────────

from database import LiveEventModel


def _live_event_dict(r: LiveEventModel) -> dict:
    return {
        "id":                    r.id,
        "source_id":             r.source_id,
        "device_type":           r.device_type,
        "device_role":           r.device_role,
        "parser_id":             r.parser_id,
        "event_time":            r.event_time.isoformat() if r.event_time else None,
        "received_at":           r.received_at.isoformat() if r.received_at else None,
        "source_ip":             r.source_ip,
        "destination_ip":        r.destination_ip,
        "source_port":           r.source_port,
        "destination_port":      r.destination_port,
        "protocol":              r.protocol,
        "action":                r.action,
        "reason":                r.reason,
        "bytes_in":              r.bytes_in,
        "bytes_out":             r.bytes_out,
        "packets_in":            r.packets_in,
        "packets_out":           r.packets_out,
        "duration_ms":           r.duration_ms,
        "nat_source_ip":         r.nat_source_ip,
        "nat_destination_ip":    r.nat_destination_ip,
        "nat_source_port":       r.nat_source_port,
        "nat_destination_port":  r.nat_destination_port,
        "application":           r.application,
        "service":               r.service,
        "backend_ip":            r.backend_ip,
        "backend_port":          r.backend_port,
        "response_time_ms":      r.response_time_ms,
        "health_status":         r.health_status,
    }


@app.get("/api/live-events")
def list_live_events(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    action: Optional[str] = None,
    source_id: Optional[str] = None,
    device_type: Optional[str] = None,
    protocol: Optional[str] = None,
    application: Optional[str] = None,
    suppressed: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Query ingested live events with optional filters.

    Returns the most recent events first.  All filters are optional and
    combined with AND.
    """
    q = db.query(LiveEventModel)
    if source_ip:
        q = q.filter(LiveEventModel.source_ip == source_ip)
    if destination_ip:
        q = q.filter(LiveEventModel.destination_ip == destination_ip)
    if action:
        q = q.filter(LiveEventModel.action == action)
    if source_id:
        q = q.filter(LiveEventModel.source_id == source_id)
    if device_type:
        q = q.filter(LiveEventModel.device_type == device_type)
    if protocol:
        q = q.filter(LiveEventModel.protocol == protocol.upper())
    if application:
        q = q.filter(LiveEventModel.application == application)
    if suppressed is not None:
        q = q.filter(LiveEventModel.suppressed.is_(suppressed))
    total = q.count()
    rows = (
        q.order_by(LiveEventModel.event_time.desc(), LiveEventModel.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": [_live_event_dict(r) for r in rows],
    }


@app.get("/api/live-events/stats")
def live_events_stats(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Aggregated statistics over ingested live events.

    Returns counts by action, device_type, top talkers, and a time
    histogram for the last 24 hours.
    """
    from sqlalchemy import func as sqlfunc

    total = db.query(LiveEventModel).count()

    # By action
    action_counts = dict(
        db.query(LiveEventModel.action, sqlfunc.count(LiveEventModel.id))
        .group_by(LiveEventModel.action)
        .all()
    )

    # By device type
    device_counts = dict(
        db.query(LiveEventModel.device_type, sqlfunc.count(LiveEventModel.id))
        .group_by(LiveEventModel.device_type)
        .all()
    )

    # By parser
    parser_counts = dict(
        db.query(LiveEventModel.parser_id, sqlfunc.count(LiveEventModel.id))
        .group_by(LiveEventModel.parser_id)
        .all()
    )

    # Top source IPs (by event count)
    top_sources = [
        {"ip": ip, "count": c}
        for ip, c in (
            db.query(LiveEventModel.source_ip, sqlfunc.count(LiveEventModel.id))
            .group_by(LiveEventModel.source_ip)
            .order_by(sqlfunc.count(LiveEventModel.id).desc())
            .limit(10)
            .all()
        )
    ]

    # Top destination IPs
    top_destinations = [
        {"ip": ip, "count": c}
        for ip, c in (
            db.query(LiveEventModel.destination_ip, sqlfunc.count(LiveEventModel.id))
            .group_by(LiveEventModel.destination_ip)
            .order_by(sqlfunc.count(LiveEventModel.id).desc())
            .limit(10)
            .all()
        )
    ]

    # Top denied sources (deny + drop + reset)
    denied_actions = ("deny", "drop", "reset")
    top_denied = [
        {"ip": ip, "count": c}
        for ip, c in (
            db.query(LiveEventModel.source_ip, sqlfunc.count(LiveEventModel.id))
            .filter(LiveEventModel.action.in_(denied_actions))
            .group_by(LiveEventModel.source_ip)
            .order_by(sqlfunc.count(LiveEventModel.id).desc())
            .limit(10)
            .all()
        )
    ]

    # Collector status
    from collector.service import collector_stats
    collector = collector_stats()

    return {
        "total_events": total,
        "by_action": action_counts,
        "by_device_type": device_counts,
        "by_parser": parser_counts,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "top_denied_sources": top_denied,
        "collector": collector,
    }


@app.get("/api/live-events/timeline")
def live_events_timeline(
    minutes: int = Query(60, ge=1, le=1440),
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return per-minute action counts for the last *minutes* minutes.

    Each bucket is a 1-minute interval.  The response is a list of dicts
    sorted oldest → newest so Chart.js can render left-to-right::

        [{"bucket": "2026-04-13T10:15:00", "allow": 42, "deny": 3, "drop": 1}, ...]

    Uses ``strftime`` for SQLite and ``date_trunc`` for PostgreSQL.
    """
    from sqlalchemy import case, literal_column, text
    from sqlalchemy import func as sqlfunc

    cutoff = datetime.utcnow() - __import__("datetime").timedelta(minutes=minutes)

    # Build the 1-minute bucket expression (DB-portable)
    is_sqlite = "sqlite" in str(db.bind.url)
    if is_sqlite:
        bucket_expr = sqlfunc.strftime("%Y-%m-%dT%H:%M:00", LiveEventModel.event_time)
    else:
        bucket_expr = sqlfunc.date_trunc(
            literal_column("'minute'"), LiveEventModel.event_time,
        )

    q = db.query(
        bucket_expr.label("bucket"),
        sqlfunc.sum(case((LiveEventModel.action == "allow", 1), else_=0)).label("allow"),
        sqlfunc.sum(case((LiveEventModel.action == "deny", 1), else_=0)).label("deny"),
        sqlfunc.sum(case((LiveEventModel.action == "drop", 1), else_=0)).label("drop"),
    ).filter(
        LiveEventModel.event_time >= cutoff,
    )
    if source_ip:
        q = q.filter(LiveEventModel.source_ip == source_ip)
    if destination_ip:
        q = q.filter(LiveEventModel.destination_ip == destination_ip)

    rows = (
        q.group_by(literal_column("bucket"))
        .order_by(literal_column("bucket"))
        .all()
    )
    return [
        {
            "bucket": str(r.bucket),
            "allow":  int(r.allow or 0),
            "deny":   int(r.deny or 0),
            "drop":   int(r.drop or 0),
        }
        for r in rows
    ]


@app.get("/api/live-events/risk-scores")
def live_risk_scores(
    min_risk_score: int = Query(0, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Per-source-IP risk scores from the live event stream."""
    from collector.live_risk import compute_live_risk_scores

    entries = compute_live_risk_scores(db)
    if min_risk_score > 0:
        entries = [e for e in entries if e["risk_score"] >= min_risk_score]
    return entries


@app.get("/api/collector/status")
def get_collector_status(
    current_user: UserModel = Depends(get_current_user),
):
    """Return the current collector service status."""
    from collector.service import collector_stats
    return collector_stats()


# ── Path Analysis Role Presets ────────────────────────────────────────────────

def _preset_lists(raw: Optional[List[str]]) -> List[str]:
    """Deduplicate and sort a list of IP/CIDR strings for stable storage."""
    return sorted(set(s.strip() for s in (raw or []) if s.strip()))


def _preset_to_dict(p: PathAnalysisRolePresetModel, current_user: Optional[UserModel] = None) -> dict:
    return {
        "id":                 p.id,
        "name":               p.name,
        "firewall_ips":       json.loads(p.firewall_ips),
        "load_balancer_vips": json.loads(p.load_balancer_vips),
        "backend_ips":        json.loads(p.backend_ips),
        "backend_subnets":    json.loads(p.backend_subnets),
        "scope":              p.scope,
        "team_id":            p.team_id,
        "owner_user_id":      p.owner_user_id,
        "created_by":         p.created_by,
        "updated_by":         p.updated_by,
        "can_edit":           sharing_can_edit(p, current_user) if current_user is not None else False,
        "created_at":         p.created_at.isoformat() if p.created_at else None,
        "updated_at":         p.updated_at.isoformat() if p.updated_at else None,
    }


class RolePresetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    firewall_ips:       Optional[List[str]] = None
    load_balancer_vips: Optional[List[str]] = None
    backend_ips:        Optional[List[str]] = None
    backend_subnets:    Optional[List[str]] = None
    scope:              str = Field(default="private", pattern="^(private|team|global)$")


class RolePresetUpdate(BaseModel):
    name:               Optional[str]       = Field(default=None, min_length=1, max_length=120)
    firewall_ips:       Optional[List[str]] = None
    load_balancer_vips: Optional[List[str]] = None
    backend_ips:        Optional[List[str]] = None
    backend_subnets:    Optional[List[str]] = None
    scope:              Optional[str]       = Field(default=None, pattern="^(private|team|global)$")


def _get_preset_or_404(
    db: Session,
    preset_id: int,
    current_user: UserModel,
) -> PathAnalysisRolePresetModel:
    """Return a preset the caller is allowed to *view* or raise 404/403."""
    p = db.query(PathAnalysisRolePresetModel).filter(
        PathAnalysisRolePresetModel.id == preset_id
    ).first()
    enforce_view(p, current_user)
    return p


def _get_preset_for_edit(
    db: Session,
    preset_id: int,
    current_user: UserModel,
) -> PathAnalysisRolePresetModel:
    """Return a preset the caller is allowed to *edit* or raise 404/403."""
    p = db.query(PathAnalysisRolePresetModel).filter(
        PathAnalysisRolePresetModel.id == preset_id
    ).first()
    enforce_edit(p, current_user)
    return p


@app.post("/api/path-analysis/presets", status_code=201)
def create_preset(
    req: RolePresetCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Create a new role preset.

    ``scope`` determines visibility: ``private`` (default), ``team`` (requires
    team membership) or ``global`` (admin only).
    """
    check_can_create(req.scope, current_user)

    p = PathAnalysisRolePresetModel(
        owner_user_id=current_user.id,
        name=req.name.strip(),
        firewall_ips=       json.dumps(_preset_lists(req.firewall_ips)),
        load_balancer_vips= json.dumps(_preset_lists(req.load_balancer_vips)),
        backend_ips=        json.dumps(_preset_lists(req.backend_ips)),
        backend_subnets=    json.dumps(_preset_lists(req.backend_subnets)),
        scope=req.scope,
        team_id=resolve_team_id(req.scope, current_user),
        created_by=current_user.id,
        updated_by=current_user.id,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return _preset_to_dict(p, current_user)


@app.get("/api/path-analysis/presets")
def list_presets(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List every role preset visible to the current user, newest first."""
    rows = (
        db.query(PathAnalysisRolePresetModel)
        .filter(visible_filter(PathAnalysisRolePresetModel, current_user))
        .order_by(PathAnalysisRolePresetModel.updated_at.desc())
        .all()
    )
    return [_preset_to_dict(p, current_user) for p in rows]


@app.get("/api/path-analysis/presets/{preset_id}")
def get_preset(
    preset_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Get a single preset.  Returns 403 if the caller cannot view it."""
    return _preset_to_dict(_get_preset_or_404(db, preset_id, current_user), current_user)


@app.put("/api/path-analysis/presets/{preset_id}")
def update_preset(
    preset_id: int,
    req: RolePresetUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Update name, role lists, and/or scope of an existing preset."""
    p = _get_preset_for_edit(db, preset_id, current_user)
    if req.name is not None:
        p.name = req.name.strip()
    if req.firewall_ips is not None:
        p.firewall_ips = json.dumps(_preset_lists(req.firewall_ips))
    if req.load_balancer_vips is not None:
        p.load_balancer_vips = json.dumps(_preset_lists(req.load_balancer_vips))
    if req.backend_ips is not None:
        p.backend_ips = json.dumps(_preset_lists(req.backend_ips))
    if req.backend_subnets is not None:
        p.backend_subnets = json.dumps(_preset_lists(req.backend_subnets))
    if req.scope is not None and req.scope != p.scope:
        check_can_create(req.scope, current_user)
        p.scope = req.scope
        p.team_id = resolve_team_id(req.scope, current_user)
    p.updated_by = current_user.id
    p.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(p)
    return _preset_to_dict(p, current_user)


@app.delete("/api/path-analysis/presets/{preset_id}", status_code=204)
def delete_preset(
    preset_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Delete a preset.  Only the author (or an admin) may delete."""
    p = _get_preset_for_edit(db, preset_id, current_user)
    db.delete(p)
    db.commit()


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.0.0"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_or_404(db: Session, analysis_id: str, user_id: int) -> AnalysisModel:
    row = db.query(AnalysisModel).filter(
        AnalysisModel.id == analysis_id,
        AnalysisModel.user_id == user_id,
    ).first()
    if not row:
        raise HTTPException(404, "Analysis not found")
    return row


def _get_analysis_for_workflow(
    db: Session, analysis_id: str, current_user: UserModel
) -> AnalysisModel:
    """Fetch an analysis that the caller may view/modify for workflow purposes.

    Access is granted to the owner, the current assignee, and any admin.  All
    other callers receive 404 so we never disclose existence of analyses they
    cannot see.
    """
    row = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.id == analysis_id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Analysis not found")
    is_owner = row.user_id == current_user.id
    is_assignee = (
        row.assigned_user_id is not None
        and row.assigned_user_id == current_user.id
    )
    is_admin = bool(getattr(current_user, "is_admin", False))
    if not (is_owner or is_assignee or is_admin):
        raise HTTPException(404, "Analysis not found")
    return row


def _emit_state_change_notifications(
    db: Session,
    *,
    row: AnalysisModel,
    state: str,
    actor_user_id: int,
) -> None:
    """Emit workflow state-change notifications.

    Called whenever a workflow state transitions to a value that warrants a
    notification — either via an explicit PUT or via feedback auto-transition.
    Self-notifications are suppressed by ``_notify``.

    Rules:
      - ``needs_review`` → notify the owner; if the assignee differs from
        both the owner and the actor, they also get notified.
      - ``resolved``     → notify the owner.
    """
    if state == "needs_review":
        _notify(
            db,
            user_id=row.user_id,
            type="review_required",
            analysis_id=row.id,
            message=f"“{row.filename}” needs review.",
            actor_user_id=actor_user_id,
        )
        if (
            row.assigned_user_id is not None
            and row.assigned_user_id != row.user_id
        ):
            _notify(
                db,
                user_id=row.assigned_user_id,
                type="review_required",
                analysis_id=row.id,
                message=f"“{row.filename}” needs review.",
                actor_user_id=actor_user_id,
            )
    elif state == "resolved":
        _notify(
            db,
            user_id=row.user_id,
            type="resolved",
            analysis_id=row.id,
            message=f"“{row.filename}” was marked resolved.",
            actor_user_id=actor_user_id,
        )


def _notify(
    db: Session,
    *,
    user_id: int,
    type: str,
    analysis_id: Optional[str],
    message: str,
    actor_user_id: Optional[int] = None,
) -> Optional[NotificationModel]:
    """Create a single notification row.

    Skips self-notifications (recipient == actor) because a user does not
    need to be told about an action they performed themselves.  Returns the
    newly-created row, or ``None`` if the notification was skipped.  The
    caller is responsible for ``db.commit()`` (usually as part of a larger
    transaction).
    """
    if actor_user_id is not None and actor_user_id == user_id:
        return None
    if type not in VALID_NOTIFICATION_TYPES:
        return None
    row = NotificationModel(
        user_id=user_id,
        type=type,
        analysis_id=analysis_id,
        actor_user_id=actor_user_id,
        message=message,
    )
    db.add(row)
    return row


def _notification_dict(
    row: NotificationModel,
    filename_cache: Optional[dict] = None,
    username_cache: Optional[dict] = None,
    db: Optional[Session] = None,
) -> dict:
    filename: Optional[str] = None
    actor_username: Optional[str] = None
    if row.analysis_id is not None:
        if filename_cache is not None and row.analysis_id in filename_cache:
            filename = filename_cache[row.analysis_id]
        elif db is not None:
            arow = db.query(AnalysisModel).filter(
                AnalysisModel.id == row.analysis_id
            ).first()
            if arow:
                filename = arow.filename
            if filename_cache is not None:
                filename_cache[row.analysis_id] = filename
    if row.actor_user_id is not None:
        if username_cache is not None and row.actor_user_id in username_cache:
            actor_username = username_cache[row.actor_user_id]
        elif db is not None:
            urow = db.query(UserModel).filter(
                UserModel.id == row.actor_user_id
            ).first()
            if urow:
                actor_username = urow.username
            if username_cache is not None:
                username_cache[row.actor_user_id] = actor_username
    return {
        "id":                row.id,
        "type":              row.type,
        "analysis_id":       row.analysis_id,
        "analysis_filename": filename,
        "actor_user_id":     row.actor_user_id,
        "actor_username":    actor_username,
        "message":           row.message,
        "read_at":           row.read_at.isoformat() if row.read_at else None,
        "created_at":        row.created_at.isoformat() if row.created_at else None,
    }


def _workflow_dict(row: AnalysisModel, current_user: UserModel, db: Session) -> dict:
    is_owner = row.user_id == current_user.id
    is_assignee = (
        row.assigned_user_id is not None
        and row.assigned_user_id == current_user.id
    )
    is_admin = bool(getattr(current_user, "is_admin", False))
    assignee_username: Optional[str] = None
    if row.assigned_user_id is not None:
        u = db.query(UserModel).filter(UserModel.id == row.assigned_user_id).first()
        if u:
            assignee_username = u.username
    return {
        "analysis_id": row.id,
        "workflow_state": row.workflow_state or "new",
        "assigned_user_id": row.assigned_user_id,
        "assignee_username": assignee_username,
        "workflow_updated_at": row.workflow_updated_at.isoformat() if row.workflow_updated_at else None,
        "workflow_updated_by": row.workflow_updated_by,
        "owner_user_id": row.user_id,
        "can_edit_state": is_owner or is_assignee or is_admin,
        "can_assign": is_owner or is_admin,
    }


def _suppression_dict(r: SuppressionRuleModel) -> dict:
    return {
        "id": r.id,
        "scope": r.scope,
        "rule_id": r.rule_id,
        "src_ip": r.src_ip,
        "dst_ip": r.dst_ip,
        "analysis_id": r.analysis_id,
        "reason": r.reason,
        "note": r.note,
        "is_active": r.is_active,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _triage_dict(r: FindingTriageModel) -> dict:
    return {
        "id": r.id,
        "analysis_id": r.analysis_id,
        "finding_key": r.finding_key,
        "status": r.status,
        "note": r.note,
        "analyst_id": r.analyst_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


def _feedback_dict(
    r: PathAnalysisFeedbackModel,
    current_user: Optional[UserModel] = None,
) -> dict:
    # The author is always allowed to edit their own feedback; admins as well.
    # Other team members see team-scoped feedback read-only.
    own = current_user is not None and r.analyst_id == current_user.id
    is_admin = bool(current_user and getattr(current_user, "is_admin", False))
    can_edit = own or is_admin
    return {
        "id":                   r.id,
        "analysis_id":          r.analysis_id,
        "source_ip":            r.source_ip,
        "destination_ip":       r.destination_ip,
        "destination_port":     r.destination_port,
        "predicted_outcome":    r.predicted_outcome,
        "predicted_impairment": r.predicted_impairment,
        "predicted_confidence": r.predicted_confidence,
        "verdict":              r.verdict,
        "analyst_note":         r.analyst_note,
        "actual_root_cause":    r.actual_root_cause,
        "misleading_step":      r.misleading_step,
        "analyst_id":           r.analyst_id,
        "scope":                r.scope,
        "team_id":              r.team_id,
        "can_edit":             can_edit,
        "created_at":  r.created_at.isoformat() if r.created_at else None,
        "updated_at":  r.updated_at.isoformat() if r.updated_at else None,
    }


def _summary(row: AnalysisModel, db: Optional[Session] = None) -> dict:
    assignee_username: Optional[str] = None
    if db is not None and row.assigned_user_id is not None:
        u = db.query(UserModel).filter(UserModel.id == row.assigned_user_id).first()
        if u:
            assignee_username = u.username
    return {
        "id": row.id,
        "filename": row.filename,
        "status": row.status,
        "current_stage": row.current_stage,
        "progress_pct": row.progress_pct or 0,
        "packet_count": row.packet_count,
        "issue_count": row.issue_count,
        "critical_count": row.critical_count,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "error": row.error,
        "workflow_state": row.workflow_state or "new",
        "assigned_user_id": row.assigned_user_id,
        "assignee_username": assignee_username,
        "workflow_updated_at": row.workflow_updated_at.isoformat() if row.workflow_updated_at else None,
        "owner_user_id": row.user_id,
    }
