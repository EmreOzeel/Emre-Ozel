"""
Non-sensitive usage telemetry.

Tracks structural events (counts, durations, feature usage) with no
user-identifying information and no PCAP content.

Usage:
    from telemetry import track
    track("analysis.completed", user_id=user.id, properties={"packet_count": 5000, "duration_sec": 12.3})

Events:
    analysis.started      — file uploaded, job queued
    analysis.completed    — job finished successfully
    analysis.failed       — job ended with error or timeout
    suppression.created   — suppression rule added
    triage.updated        — analyst changed a finding's triage status
    report.downloaded     — HTML/PDF report exported
    compare.executed      — compare endpoint called
"""
from __future__ import annotations
import json
import logging
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)


def track(
    event_type: str,
    user_id: Optional[int] = None,
    properties: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Record a telemetry event. Silently swallows all errors to never
    interrupt the main request path.
    """
    try:
        from database import SessionLocal, TelemetryEventModel
        db = SessionLocal()
        try:
            db.add(TelemetryEventModel(
                event_type=event_type,
                user_id=user_id,
                properties_json=json.dumps(properties or {}),
            ))
            db.commit()
        finally:
            db.close()
    except Exception:
        log.debug("telemetry.track failed silently", exc_info=True)
