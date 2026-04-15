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
_netflow_listener = None
_flow_engine = None
_flow_lock = threading.Lock()
_retention_thread: Optional[threading.Thread] = None
_running = False


def start_collector() -> None:
    """Start the live ingestion collector (called from FastAPI startup)."""
    global _listener, _retention_thread, _running

    if _running:
        return

    from collector.parsers.base import register_parser, clear_registry
    from collector.parsers.paloalto import PaloAltoParser
    from collector.parsers.fortigate import FortiGateParser
    from collector.parsers.generic_kv import GenericKVParser
    from collector.pipeline import Pipeline
    from collector.listeners.syslog_listener import SyslogListener

    # 1. Register parsers (vendor-specific first, generic fallback last)
    clear_registry()
    register_parser(PaloAltoParser())
    register_parser(FortiGateParser())
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
        max_eps=settings.SYSLOG_MAX_EPS,
        per_ip_max_eps=settings.SYSLOG_PER_IP_MAX_EPS,
    )
    _listener.start()

    # 4. Create flow engine and attach to pipeline
    global _flow_engine
    from collector.flows import FlowEngine
    _flow_engine = FlowEngine(timeout_seconds=60)
    pipe.set_flow_engine(_flow_engine, _flow_lock)

    # 5. Optionally start NetFlow/IPFIX listener
    global _netflow_listener
    if settings.NETFLOW_ENABLED:
        from collector.listeners.netflow_listener import NetflowListener
        _netflow_listener = NetflowListener(
            pipeline=pipe,
            host=settings.NETFLOW_HOST,
            port=settings.NETFLOW_PORT,
        )
        _netflow_listener.start()

    # 5. Start retention sweep
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
    global _listener, _netflow_listener, _running

    _running = False
    if _netflow_listener is not None:
        _netflow_listener.stop()
        _netflow_listener = None
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
    from collector.bridge import auto_paths_created_total, suppression_matches_count
    from collector.intelligence import intelligence_triggers_total, intelligence_last_run_at

    pstats = _listener.pipeline.stats
    pstats["queue_dropped"] = _listener.dropped_count
    pstats["rate_limited"] = _listener.rate_limited_count
    pstats["suppression_matches"] = suppression_matches_count
    nf = {}
    if _netflow_listener is not None:
        nf = {
            "netflow_packets_received": _netflow_listener.packets_received,
            "netflow_flows_decoded":    _netflow_listener.flows_decoded,
            "netflow_templates_known":  _netflow_listener.templates_known,
        }
    return {
        "enabled": settings.COLLECTOR_ENABLED,
        "running": _listener.running,
        "source_id": _listener.pipeline.source_id,
        "syslog_port": _listener.port,
        "pipeline_stats": pstats,
        "buffer_size": _listener.pipeline.buffer_size,
        "intelligence_triggers_total": intelligence_triggers_total,
        "intelligence_last_run_at": intelligence_last_run_at,
        "auto_paths_created_total": auto_paths_created_total,
        "flow_engine": _flow_engine.stats() if _flow_engine else None,
        **nf,
    }


# ── Retention sweep ──────────────────────────────────────────────────────────

def _retention_loop() -> None:
    """Periodically run the live-event bridge scan (every 60 s) and the
    retention sweep (every 3600 s).

    Both tasks share one thread.  The bridge scan is cheap (a few SQL
    aggregates) so running it every minute is fine.
    """
    ticks = 0
    while _running:
        ticks += 1

        # Flow flush — every minute
        try:
            _flush_flows()
        except Exception:
            logger.exception("Flow flush failed")

        # Bridge scan — every minute
        try:
            _run_bridge_scan()
        except Exception:
            logger.exception("Bridge scan failed")

        # Intelligence scan + auto-create monitors — every 5 minutes
        if ticks % 5 == 0:
            try:
                _run_intelligence_scan()
            except Exception:
                logger.exception("Intelligence scan failed")
            try:
                _run_auto_create_paths()
            except Exception:
                logger.exception("Auto-create paths failed")

        # Retention sweep — every hour (every 60th tick)
        if ticks % 60 == 0:
            try:
                _run_retention()
            except Exception:
                logger.exception("Retention sweep failed")

        # Sleep 60 s in 1-s intervals so stop_collector() is responsive.
        for _ in range(60):
            if not _running:
                return
            time.sleep(1)


def _flush_flows() -> int:
    """Flush expired flows from the engine to the database."""
    if _flow_engine is None:
        return 0

    from database import LiveFlowModel

    with _flow_lock:
        emitted = _flow_engine.flush_expired()
    if not emitted:
        return 0

    db = SessionLocal()
    try:
        rows = [LiveFlowModel(**f) for f in emitted]
        db.bulk_save_objects(rows)
        db.commit()
        if len(rows):
            logger.debug("Flushed %d flows to DB", len(rows))
        return len(rows)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _run_bridge_scan() -> int:
    """Scan recent live events for anomaly patterns and apply suppression rules."""
    from collector.bridge import apply_suppressions, scan_live_events

    db = SessionLocal()
    try:
        apply_suppressions(db)
        n = scan_live_events(db)
        if n:
            logger.info("Bridge scan detected %d pattern(s)", n)
        return n
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _run_intelligence_scan() -> dict:
    """Run the intelligence scanner for anomalous IP pairs."""
    from collector.intelligence import run_intelligence_scan

    db = SessionLocal()
    try:
        result = run_intelligence_scan(db)
        if result.get("triggers"):
            logger.info(
                "Intelligence scan: %d triggers, %d skipped, %d errors",
                result["triggers"], result["skipped"], result["errors"],
            )
        return result
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _run_auto_create_paths() -> int:
    """Auto-create monitored paths for high-risk live pairs."""
    from collector.bridge import auto_create_monitored_paths

    db = SessionLocal()
    try:
        n = auto_create_monitored_paths(db)
        if n:
            logger.info("Auto-created %d monitored path(s)", n)
        return n
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


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
