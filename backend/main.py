"""FastAPI application — PCAP Analyzer v3 (async + investigation-grade)."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import create_token, get_current_user, seed_admin, verify_password
from config import settings
from database import (
    AnalysisModel,
    FindingTriageModel,
    PathAnalysisFeedbackModel,
    SuppressionRuleModel,
    TelemetryEventModel,
    UserModel,
    get_db,
    init_db,
)
from jobs.queue import enqueue, start_worker, stop_worker
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


@app.on_event("shutdown")
def shutdown():
    stop_worker()


# ── Pydantic response schemas ─────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class MeResponse(BaseModel):
    id: int
    username: str
    is_admin: bool


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
):
    rows = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.user_id == current_user.id)
        .order_by(AnalysisModel.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_summary(r) for r in rows]


@app.get("/api/analyses/{analysis_id}")
def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = _get_or_404(db, analysis_id, current_user.id)
    result = _summary(row)
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
    row = _get_or_404(db, analysis_id, current_user.id)
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
    # Cascade: triage records
    db.query(FindingTriageModel).filter(
        FindingTriageModel.analysis_id == analysis_id
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


@app.post("/api/analyses/{analysis_id}/path-analysis")
def run_path_analysis(
    analysis_id: str,
    req: PathAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Run CausalPathEngine against the original PCAP for a specific src→dst pair."""
    row = _get_or_404(db, analysis_id, current_user.id)
    if row.status != "completed":
        raise HTTPException(400, "Analysis must be completed before running path analysis")
    if not row.file_path or not Path(row.file_path).exists():
        raise HTTPException(404, "Original PCAP file is no longer available")

    from normalizer.pipeline import normalize
    from core.causal_path import CausalPathEngine

    try:
        ctx = normalize(row.file_path)
    except Exception as e:
        raise HTTPException(500, f"Failed to parse PCAP: {e}")

    engine = CausalPathEngine(ctx.packets, ctx.flows, ctx.findings, ctx)
    result = engine.analyze(
        req.source_ip,
        req.destination_ip,
        destination_port=req.destination_port,
        roles=req.roles,
    )
    track("path_analysis.executed", user_id=current_user.id, properties={
        "analysis_id": analysis_id,
        "src": req.source_ip,
        "dst": req.destination_ip,
    })
    return result.to_dict()


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
    """
    _get_or_404(db, analysis_id, current_user.id)

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
        )
        db.add(row)

    db.commit()
    db.refresh(row)
    track("path_feedback.submitted", user_id=current_user.id, properties={
        "analysis_id": analysis_id,
        "verdict": req.verdict,
    })
    return _feedback_dict(row)


@app.get(
    "/api/analyses/{analysis_id}/path-analysis/feedback",
    response_model=List[PathAnalysisFeedbackResponse],
)
def list_path_feedback(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return all path analysis feedback records for this analysis (current user only)."""
    _get_or_404(db, analysis_id, current_user.id)
    rows = (
        db.query(PathAnalysisFeedbackModel)
        .filter(
            PathAnalysisFeedbackModel.analysis_id == analysis_id,
            PathAnalysisFeedbackModel.analyst_id  == current_user.id,
        )
        .order_by(PathAnalysisFeedbackModel.created_at.desc())
        .all()
    )
    return [_feedback_dict(r) for r in rows]


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
        _feedback_dict(r)
        for r in rows
        if r.predicted_confidence >= 75 and r.verdict == "incorrect"
    ]

    weak_narratives = [
        _feedback_dict(r)
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


def _feedback_dict(r: PathAnalysisFeedbackModel) -> dict:
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
        "created_at":  r.created_at.isoformat() if r.created_at else None,
        "updated_at":  r.updated_at.isoformat() if r.updated_at else None,
    }


def _summary(row: AnalysisModel) -> dict:
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
    }
