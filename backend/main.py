"""FastAPI application — PCAP Analyzer v3 (async + investigation-grade)."""
import os
import json
import uuid
import shutil
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from database import get_db, init_db, UserModel, AnalysisModel
from auth import verify_password, create_token, get_current_user, seed_admin
from jobs.queue import enqueue, start_worker, stop_worker

app = FastAPI(title="PCAP Analyzer", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": str(user.id), "username": user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/auth/me")
def me(current_user: UserModel = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username}


# ── Analysis CRUD ─────────────────────────────────────────────────────────────

@app.post("/api/analyses", status_code=202)
async def create_analysis(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Upload a PCAP and enqueue it for async analysis. Returns immediately."""
    if not file.filename:
        raise HTTPException(400, "No filename provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(400, "Only .pcap, .pcapng, .cap files are supported")

    file_id = str(uuid.uuid4())
    dest = Path(settings.UPLOAD_DIR) / f"{file_id}{ext}"
    try:
        with dest.open("wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(500, f"Failed to save file: {e}")

    analysis = AnalysisModel(
        id=file_id,
        user_id=current_user.id,
        filename=file.filename,
        file_path=str(dest),
        status="pending",
    )
    db.add(analysis)
    db.commit()

    # Enqueue job (worker picks it up within poll_interval seconds)
    enqueue(db, file_id)

    return {
        "id": file_id,
        "filename": file.filename,
        "status": "pending",
        "message": "Analysis enqueued. Poll /api/analyses/{id} for status.",
    }


@app.get("/api/analyses")
def list_analyses(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
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


@app.get("/api/analyses/{analysis_id}/status")
def get_status(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Lightweight status-only endpoint for polling."""
    row = _get_or_404(db, analysis_id, current_user.id)
    return {
        "id": row.id,
        "status": row.status,
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
    db.delete(row)
    db.commit()


# ── Compare ───────────────────────────────────────────────────────────────────

@app.get("/api/analyses/compare")
def compare_analyses(
    a: str = Query(..., description="ID of baseline analysis"),
    b: str = Query(..., description="ID of new analysis"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row_a = _get_or_404(db, a, current_user.id)
    row_b = _get_or_404(db, b, current_user.id)
    if row_a.status != "completed" or row_b.status != "completed":
        raise HTTPException(400, "Both analyses must be completed")
    try:
        data_a = json.loads(row_a.result_json)
        data_b = json.loads(row_b.result_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(500, "Failed to parse analysis results")

    from reporting.compare import compare
    return compare(data_a, data_b)


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


def _summary(row: AnalysisModel) -> dict:
    return {
        "id": row.id,
        "filename": row.filename,
        "status": row.status,
        "packet_count": row.packet_count,
        "issue_count": row.issue_count,
        "critical_count": row.critical_count,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "error": row.error,
    }
