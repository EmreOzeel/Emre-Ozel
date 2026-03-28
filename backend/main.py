"""FastAPI application — PCAP Analyzer backend."""
import os
import json
import uuid
import shutil
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from database import get_db, init_db, UserModel, AnalysisModel
from auth import verify_password, create_token, get_current_user, seed_admin
from core.analyzer import run_analysis


# ── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="PCAP Analyzer", version="2.0.0")

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


# ── Analysis ──────────────────────────────────────────────────────────────────

@app.post("/api/analyses")
async def create_analysis(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    # Validate file
    if not file.filename:
        raise HTTPException(400, "No filename")
    ext = Path(file.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(400, "Only .pcap, .pcapng, .cap files are supported")

    # Save upload
    file_id = str(uuid.uuid4())
    dest = Path(settings.UPLOAD_DIR) / f"{file_id}{ext}"
    try:
        with dest.open("wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(500, f"Failed to save file: {e}")

    # Create DB record
    analysis = AnalysisModel(
        id=file_id,
        user_id=current_user.id,
        filename=file.filename,
        file_path=str(dest),
        status="processing",
    )
    db.add(analysis)
    db.commit()

    # Run analysis
    try:
        result = run_analysis(str(dest))
        analysis.status = "completed"
        analysis.result_json = json.dumps(result)
        analysis.issue_count = result.get("issue_counts", {}).get("total", 0)
        analysis.critical_count = result.get("issue_counts", {}).get("critical", 0)
        analysis.packet_count = result.get("file_info", {}).get("total_packets", 0)
    except Exception as e:
        analysis.status = "failed"
        analysis.error = str(e)
        db.commit()
        raise HTTPException(500, f"Analysis failed: {e}")

    db.commit()
    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "status": analysis.status,
        "packet_count": analysis.packet_count,
        "issue_count": analysis.issue_count,
        "critical_count": analysis.critical_count,
    }


@app.get("/api/analyses")
def list_analyses(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    rows = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.user_id == current_user.id)
        .order_by(AnalysisModel.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": r.id,
            "filename": r.filename,
            "status": r.status,
            "packet_count": r.packet_count,
            "issue_count": r.issue_count,
            "critical_count": r.critical_count,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "error": r.error,
        }
        for r in rows
    ]


@app.get("/api/analyses/{analysis_id}")
def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(AnalysisModel).filter(
        AnalysisModel.id == analysis_id,
        AnalysisModel.user_id == current_user.id,
    ).first()
    if not row:
        raise HTTPException(404, "Analysis not found")

    result = {
        "id": row.id,
        "filename": row.filename,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "error": row.error,
    }
    if row.result_json:
        try:
            result["data"] = json.loads(row.result_json)
        except json.JSONDecodeError:
            result["data"] = None
    return result


@app.delete("/api/analyses/{analysis_id}", status_code=204)
def delete_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(AnalysisModel).filter(
        AnalysisModel.id == analysis_id,
        AnalysisModel.user_id == current_user.id,
    ).first()
    if not row:
        raise HTTPException(404, "Analysis not found")

    # Remove file
    if row.file_path and Path(row.file_path).exists():
        try:
            Path(row.file_path).unlink()
        except OSError:
            pass

    db.delete(row)
    db.commit()


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "2.0.0"}
