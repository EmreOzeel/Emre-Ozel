"""
SQLite/PostgreSQL-backed async job queue for PCAP analysis.
Workers poll this table; API creates jobs and polls status.

Key properties:
  - Atomic job claiming via SELECT … FOR UPDATE SKIP LOCKED
  - Per-job timeout (ANALYSIS_TIMEOUT_SEC from settings)
  - Stage-level progress reported back to AnalysisModel
  - Scoped suppression filtering: global + user-owned + unexpired only
"""
from __future__ import annotations
import threading
import time
import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, Any
from sqlalchemy.orm import Session as DBSession

from config import settings

log = logging.getLogger(__name__)


class JobStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def enqueue(db: DBSession, analysis_id: str) -> None:
    """Mark analysis as pending — worker will pick it up."""
    from database import AnalysisModel
    row = db.query(AnalysisModel).filter(AnalysisModel.id == analysis_id).first()
    if row:
        row.status = JobStatus.PENDING
        db.commit()


def _load_suppressions(user_id: int) -> list[Dict]:
    """
    Load active, non-expired suppression rules that apply to user_id:
      - scope == "global"
      - scope == "user" AND created_by == user_id

    Returns plain dicts (no ORM objects cross thread boundaries).
    """
    from database import SessionLocal, SuppressionRuleModel
    now = datetime.utcnow()
    db = SessionLocal()
    extra = []
    try:
        rows = (
            db.query(SuppressionRuleModel)
            .filter(SuppressionRuleModel.is_active == True)
            .filter(
                (SuppressionRuleModel.expires_at == None) |
                (SuppressionRuleModel.expires_at > now)
            )
            .filter(
                (SuppressionRuleModel.scope == "global") |
                (
                    (SuppressionRuleModel.scope == "user") &
                    (SuppressionRuleModel.created_by == user_id)
                )
            )
            .all()
        )
        extra = [
            {k: v for k, v in {
                "rule_id": r.rule_id,
                "src_ip":  r.src_ip,
                "dst_ip":  r.dst_ip,
            }.items() if v is not None}
            for r in rows
        ]
    except Exception:
        log.warning("Could not load DB suppressions — using YAML only")
    finally:
        db.close()
    return extra


def _run_one(
    analysis_id: str,
    pcap_path: str,
    user_id: int,
    progress_cb: Optional[Callable[[str, int], None]] = None,
) -> Dict[str, Any]:
    """Execute the full analysis pipeline. Returns result dict."""
    from core.pipeline import run_pipeline
    extra = _load_suppressions(user_id)
    return run_pipeline(
        pcap_path,
        extra_suppressions=extra or None,
        progress_cb=progress_cb,
    )


class AnalysisWorker(threading.Thread):
    """
    Background worker thread.
    Polls the database every `poll_interval` seconds for pending jobs,
    claims one, runs it with a timeout, and persists results.
    """
    def __init__(self, poll_interval: float = 2.0):
        super().__init__(daemon=True, name="AnalysisWorker")
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info("Analysis worker started")
        while not self._stop_event.is_set():
            try:
                self._process_one()
            except Exception:
                log.exception("Worker loop error")
            self._stop_event.wait(self.poll_interval)
        log.info("Analysis worker stopped")

    def _process_one(self) -> None:
        from database import SessionLocal, AnalysisModel
        db: DBSession = SessionLocal()
        try:
            row = (
                db.query(AnalysisModel)
                .filter(AnalysisModel.status == JobStatus.PENDING)
                .order_by(AnalysisModel.created_at)
                .with_for_update(skip_locked=True)
                .first()
            )
            if not row:
                return

            row.status = JobStatus.RUNNING
            row.started_at = datetime.utcnow()
            row.progress_pct = 0
            row.current_stage = "queued"
            db.commit()

            analysis_id = row.id
            pcap_path = row.file_path
            user_id = row.user_id
            log.info(f"Processing analysis {analysis_id}: {pcap_path}")

            # ── Progress reporter (writes back to DB) ─────────────────────────
            def _progress(stage: str, pct: int) -> None:
                try:
                    prog_db = SessionLocal()
                    try:
                        r = prog_db.query(AnalysisModel).filter(
                            AnalysisModel.id == analysis_id
                        ).first()
                        if r:
                            r.current_stage = stage
                            r.progress_pct = pct
                            prog_db.commit()
                    finally:
                        prog_db.close()
                except Exception:
                    pass  # progress errors must never abort the job

            # ── Timeout enforcement via a thread ──────────────────────────────
            result_holder: list = []
            error_holder: list = []
            timeout_sec = settings.ANALYSIS_TIMEOUT_SEC

            def _run():
                try:
                    result_holder.append(
                        _run_one(analysis_id, pcap_path, user_id, progress_cb=_progress)
                    )
                except Exception as exc:
                    error_holder.append(exc)

            job_thread = threading.Thread(target=_run, daemon=True)
            job_thread.start()
            job_thread.join(timeout=timeout_sec)

            if job_thread.is_alive():
                # Timeout — the thread is still running but we give up on it
                row = db.query(AnalysisModel).filter(AnalysisModel.id == analysis_id).first()
                if row:
                    row.status = JobStatus.FAILED
                    row.error = (
                        f"Analysis exceeded timeout of {timeout_sec}s. "
                        "Try a smaller capture file."
                    )
                    row.finished_at = datetime.utcnow()
                    row.progress_pct = 0
                    row.current_stage = None
                    db.commit()
                log.error(f"Analysis {analysis_id} timed out after {timeout_sec}s")
                return

            if error_holder:
                exc = error_holder[0]
                log.exception(f"Analysis {analysis_id} failed", exc_info=exc)
                row = db.query(AnalysisModel).filter(AnalysisModel.id == analysis_id).first()
                if row:
                    row.status = JobStatus.FAILED
                    row.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}"
                    row.finished_at = datetime.utcnow()
                    row.current_stage = None
                    db.commit()
                return

            result = result_holder[0]
            row = db.query(AnalysisModel).filter(AnalysisModel.id == analysis_id).first()
            if row:
                row.status = JobStatus.COMPLETED
                row.result_json = json.dumps(result, default=str)
                row.issue_count = result.get("issue_counts", {}).get("total", 0)
                row.critical_count = result.get("issue_counts", {}).get("critical", 0)
                row.packet_count = result.get("file_info", {}).get("total_packets", 0)
                row.finished_at = datetime.utcnow()
                row.progress_pct = 100
                row.current_stage = None
                db.commit()
            log.info(f"Analysis {analysis_id} completed")

        finally:
            db.close()


# ── Global singleton worker ────────────────────────────────────────────────────

_worker: Optional[AnalysisWorker] = None


def start_worker() -> None:
    global _worker
    if _worker is None or not _worker.is_alive():
        _worker = AnalysisWorker()
        _worker.start()


def stop_worker() -> None:
    global _worker
    if _worker:
        _worker.stop()
        _worker.join(timeout=5)
