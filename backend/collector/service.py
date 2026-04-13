"""
Collector service — top-level daemon that orchestrates the live ingestion
layer inside the FastAPI process.

Lifecycle:
  ``start_collector()`` is called from ``main.py`` startup if
  ``settings.COLLECTOR_ENABLED`` is True.  It:

    1. Registers the built-in parsers (Palo Alto, Generic KV).
    2. Creates a Pipeline with the configured source_id / device_role.
    3. Starts the SyslogListener (UDP + TCP).
    4. Starts a background retention sweep thread.

  ``stop_collector()`` is called from ``main.py`` shutdown.

The service is intentionally thin — all heavy logic lives in the
pipeline, parsers, and listener modules.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

from config import settings
from database import SessionLocal

logger = logging.getLogger("collector")

# ── Module-level singleton ───────────────────────────────────────────────────
_listener = None
_retention_thread: Optional[threading.Thread] = None
_running = False


def start_collector() -> None:
    """Start the live ingestion collector (called from FastAPI startup)."""
    global _listener, _retention_thread, _running

    if _running:
        return

    from collector.parsers.base import register_parser, clear_registry
    from collector.parsers.paloalto import PaloAltoParser
    from collector.parsers.generic_kv import GenericKVParser
    from collector.pipeline import Pipeline
    from collector.listeners.syslog_listener import SyslogListener

    # 1. Register parsers (vendor-specific first, generic fallback last)
    clear_registry()
    register_parser(PaloAltoParser())
    register_parser(GenericKVParser())

    # 2. Create pipeline
    source_id = settings.COLLECTOR_SOURCE_ID or _default_source_id()
    pipe = Pipeline(
        source_id=source_id,
        device_role=settings.COLLECTOR_DEVICE_ROLE,
    )

    # 3. Start syslog listener
    _listener = SyslogListener(
        pipeline=pipe,
        db_factory=SessionLocal,
        host=settings.SYSLOG_HOST,
        port=settings.SYSLOG_PORT,
        flush_interval=settings.COLLECTOR_FLUSH_INTERVAL,
        batch_size=settings.COLLECTOR_BATCH_SIZE,
    )
    _listener.start()

    # 4. Start retention sweep
    _running = True
    _retention_thread = threading.Thread(
        target=_retention_loop,
        name="collector-retention",
        daemon=True,
    )
    _retention_thread.start()

    logger.info(
        "Collector started: source_id=%s syslog=%s:%d retention=%dd",
        source_id,
        settings.SYSLOG_HOST,
        settings.SYSLOG_PORT,
        settings.RETENTION_DAYS,
    )


def stop_collector() -> None:
    """Stop the collector and flush remaining events."""
    global _listener, _running

    _running = False
    if _listener is not None:
        _listener.stop()
        _listener = None
    logger.info("Collector stopped")


def collector_stats() -> dict:
    """Return current collector statistics (for the /api/collector/status endpoint)."""
    if _listener is None:
        return {
            "enabled": settings.COLLECTOR_ENABLED,
            "running": False,
            "source_id": None,
            "syslog_port": settings.SYSLOG_PORT,
            "pipeline_stats": None,
            "buffer_size": 0,
        }
    return {
        "enabled": settings.COLLECTOR_ENABLED,
        "running": _listener.running,
        "source_id": _listener.pipeline.source_id,
        "syslog_port": _listener.port,
        "pipeline_stats": _listener.pipeline.stats,
        "buffer_size": _listener.pipeline.buffer_size,
    }


# ── Retention sweep ──────────────────────────────────────────────────────────

def _retention_loop() -> None:
    """Periodically delete live events older than RETENTION_DAYS.

    Runs every hour — retention is not latency-sensitive.
    """
    while _running:
        try:
            _run_retention()
        except Exception:
            logger.exception("Retention sweep failed")
        # Sleep in short intervals so stop_collector() is responsive.
        for _ in range(3600):
            if not _running:
                return
            time.sleep(1)


def _run_retention() -> int:
    """Delete expired events.  Returns the number of rows removed."""
    from database import LiveEventModel

    cutoff = datetime.utcnow() - timedelta(days=settings.RETENTION_DAYS)
    db = SessionLocal()
    try:
        n = (
            db.query(LiveEventModel)
            .filter(LiveEventModel.event_time < cutoff)
            .delete(synchronize_session=False)
        )
        db.commit()
        if n:
            logger.info("Retention: purged %d events older than %s", n, cutoff.isoformat())
        return n
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _default_source_id() -> str:
    """Best-effort hostname for the collector source_id."""
    try:
        return socket.gethostname()
    except Exception:
        return "collector"
