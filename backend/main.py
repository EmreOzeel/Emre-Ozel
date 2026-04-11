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
    PathAnalysisCacheModel,
    PathAnalysisFeedbackModel,
    PathAnalysisRolePresetModel,
    PathAnalysisSavedQueryModel,
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
        _feedback_dict(r)
        for r in rows
        if r.predicted_confidence >= 75 and r.verdict == "incorrect"
    ]

    underconfident = [
        _feedback_dict(r)
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

def _query_to_dict(q: PathAnalysisSavedQueryModel) -> dict:
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
        "created_at":         q.created_at.isoformat() if q.created_at else None,
        "updated_at":         q.updated_at.isoformat() if q.updated_at else None,
    }


def _get_query_or_404(db: Session, query_id: int, user_id: int) -> PathAnalysisSavedQueryModel:
    q = db.query(PathAnalysisSavedQueryModel).filter(
        PathAnalysisSavedQueryModel.id == query_id
    ).first()
    if not q:
        raise HTTPException(404, "Saved query not found")
    if q.owner_user_id != user_id:
        raise HTTPException(403, "Not authorized to access this saved query")
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
    clear_port:         bool                = False   # explicit sentinel to set port→None
    clear_preset:       bool                = False   # explicit sentinel to set preset→None


@app.post("/api/path-analysis/saved-queries", status_code=201)
def create_saved_query(
    req: SavedQueryCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Save a new path-analysis query owned by the current user."""
    # Validate preset ownership when a preset is referenced
    if req.role_preset_id is not None:
        _get_preset_or_404(db, req.role_preset_id, current_user.id)

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
    )
    db.add(q)
    db.commit()
    db.refresh(q)
    return _query_to_dict(q)


@app.get("/api/path-analysis/saved-queries")
def list_saved_queries(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List all saved queries for the current user, newest first."""
    rows = (
        db.query(PathAnalysisSavedQueryModel)
        .filter(PathAnalysisSavedQueryModel.owner_user_id == current_user.id)
        .order_by(PathAnalysisSavedQueryModel.updated_at.desc())
        .all()
    )
    return [_query_to_dict(q) for q in rows]


@app.get("/api/path-analysis/saved-queries/{query_id}")
def get_saved_query(
    query_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Get one saved query. Returns 403 if it belongs to a different user."""
    return _query_to_dict(_get_query_or_404(db, query_id, current_user.id))


@app.put("/api/path-analysis/saved-queries/{query_id}")
def update_saved_query(
    query_id: int,
    req: SavedQueryUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Partial update of a saved query. Only provided fields are changed."""
    q = _get_query_or_404(db, query_id, current_user.id)

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
        _get_preset_or_404(db, req.role_preset_id, current_user.id)
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
    q.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(q)
    return _query_to_dict(q)


@app.delete("/api/path-analysis/saved-queries/{query_id}", status_code=204)
def delete_saved_query(
    query_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Delete a saved query. Returns 403 if it belongs to a different user."""
    q = _get_query_or_404(db, query_id, current_user.id)
    db.delete(q)
    db.commit()


# ── Path Analysis Role Presets ────────────────────────────────────────────────

def _preset_lists(raw: Optional[List[str]]) -> List[str]:
    """Deduplicate and sort a list of IP/CIDR strings for stable storage."""
    return sorted(set(s.strip() for s in (raw or []) if s.strip()))


def _preset_to_dict(p: PathAnalysisRolePresetModel) -> dict:
    return {
        "id":                 p.id,
        "name":               p.name,
        "firewall_ips":       json.loads(p.firewall_ips),
        "load_balancer_vips": json.loads(p.load_balancer_vips),
        "backend_ips":        json.loads(p.backend_ips),
        "backend_subnets":    json.loads(p.backend_subnets),
        "created_at":         p.created_at.isoformat() if p.created_at else None,
        "updated_at":         p.updated_at.isoformat() if p.updated_at else None,
    }


class RolePresetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    firewall_ips:       Optional[List[str]] = None
    load_balancer_vips: Optional[List[str]] = None
    backend_ips:        Optional[List[str]] = None
    backend_subnets:    Optional[List[str]] = None


class RolePresetUpdate(BaseModel):
    name:               Optional[str]       = Field(default=None, min_length=1, max_length=120)
    firewall_ips:       Optional[List[str]] = None
    load_balancer_vips: Optional[List[str]] = None
    backend_ips:        Optional[List[str]] = None
    backend_subnets:    Optional[List[str]] = None


def _get_preset_or_404(db: Session, preset_id: int, user_id: int) -> PathAnalysisRolePresetModel:
    p = db.query(PathAnalysisRolePresetModel).filter(
        PathAnalysisRolePresetModel.id == preset_id
    ).first()
    if not p:
        raise HTTPException(404, "Preset not found")
    if p.owner_user_id != user_id:
        raise HTTPException(403, "Not authorized to access this preset")
    return p


@app.post("/api/path-analysis/presets", status_code=201)
def create_preset(
    req: RolePresetCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Create a new role preset owned by the current user."""
    p = PathAnalysisRolePresetModel(
        owner_user_id=current_user.id,
        name=req.name.strip(),
        firewall_ips=       json.dumps(_preset_lists(req.firewall_ips)),
        load_balancer_vips= json.dumps(_preset_lists(req.load_balancer_vips)),
        backend_ips=        json.dumps(_preset_lists(req.backend_ips)),
        backend_subnets=    json.dumps(_preset_lists(req.backend_subnets)),
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return _preset_to_dict(p)


@app.get("/api/path-analysis/presets")
def list_presets(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """List all role presets owned by the current user, newest first."""
    rows = (
        db.query(PathAnalysisRolePresetModel)
        .filter(PathAnalysisRolePresetModel.owner_user_id == current_user.id)
        .order_by(PathAnalysisRolePresetModel.updated_at.desc())
        .all()
    )
    return [_preset_to_dict(p) for p in rows]


@app.get("/api/path-analysis/presets/{preset_id}")
def get_preset(
    preset_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Get a single preset. Returns 403 if it belongs to a different user."""
    return _preset_to_dict(_get_preset_or_404(db, preset_id, current_user.id))


@app.put("/api/path-analysis/presets/{preset_id}")
def update_preset(
    preset_id: int,
    req: RolePresetUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Update name and/or role lists of an existing preset."""
    p = _get_preset_or_404(db, preset_id, current_user.id)
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
    p.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(p)
    return _preset_to_dict(p)


@app.delete("/api/path-analysis/presets/{preset_id}", status_code=204)
def delete_preset(
    preset_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Delete a preset. Returns 403 if it belongs to a different user."""
    p = _get_preset_or_404(db, preset_id, current_user.id)
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
