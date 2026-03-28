"""
SQLite-backed async job queue for PCAP analysis.
Workers poll this table; API creates jobs and polls status.
"""
from __future__ import annotations
import threading
import time
import json
import logging
import traceback
from datetime import datetime
from typing import Optional, Callable, Dict, Any
from sqlalchemy.orm import Session as DBSession

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


def _run_one(analysis_id: str, pcap_path: str) -> Dict[str, Any]:
    """Execute full analysis pipeline for one job. Returns result dict."""
    from core.pipeline import run_pipeline
    return run_pipeline(pcap_path)


class AnalysisWorker(threading.Thread):
    """
    Background worker thread.
    Polls the database every `poll_interval` seconds for pending jobs,
    runs them, and saves results.
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
            # Claim one pending job
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
            db.commit()

            analysis_id = row.id
            pcap_path = row.file_path
            log.info(f"Processing analysis {analysis_id}: {pcap_path}")

            try:
                result = _run_one(analysis_id, pcap_path)
                # Re-fetch row (may have changed)
                row = db.query(AnalysisModel).filter(AnalysisModel.id == analysis_id).first()
                if row:
                    row.status = JobStatus.COMPLETED
                    row.result_json = json.dumps(result, default=str)
                    row.issue_count = result.get("issue_counts", {}).get("total", 0)
                    row.critical_count = result.get("issue_counts", {}).get("critical", 0)
                    row.packet_count = result.get("file_info", {}).get("total_packets", 0)
                    row.finished_at = datetime.utcnow()
                    db.commit()
                log.info(f"Analysis {analysis_id} completed")

            except Exception as exc:
                log.exception(f"Analysis {analysis_id} failed")
                row = db.query(AnalysisModel).filter(AnalysisModel.id == analysis_id).first()
                if row:
                    row.status = JobStatus.FAILED
                    row.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}"
                    row.finished_at = datetime.utcnow()
                    db.commit()
        finally:
            db.close()


# Global singleton worker
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
