"""
Intelligence scanner — triggers CausalPathEngine analysis for anomalous
IP pairs identified from ``LiveFlowModel`` (reconstructed sessions).

Trigger conditions (query LiveFlowModel, last 10 minutes):

  - **connection_blocked**: ≥ 2 flows in state "denied" or "dropped"
    for the same src→dst pair
  - **connection_unstable**: ≥ 2 flows in state "reset" for the same
    src→dst pair
  - **slow_connection**: any flow with duration_ms > 30 000 AND
    state "completed" (slow but succeeded)
  - **already_flagged**: source IP appears in a recent bridge
    ``drift_detected`` notification

A 30-minute cooldown prevents re-running expensive PCAP analysis for
the same src→dst pair on every scan cycle.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from database import (
    AnalysisModel,
    LiveFlowModel,
    NotificationModel,
    PathAnalysisCacheModel,
)

logger = logging.getLogger("collector.intelligence")

# ── Tunables ─────────────────────────────────────────────────────────────────
WINDOW_MINUTES = 10
BLOCKED_FLOW_THRESHOLD = 2
RESET_FLOW_THRESHOLD = 2
SLOW_DURATION_MS = 30_000
SUSPICIOUS_FLOW_THRESHOLD = 1
SCANNING_FLOW_THRESHOLD = 2
COOLDOWN_MINUTES = 30
ANALYSIS_SEARCH_LIMIT = 50

# ── Module-level stats ───────────────────────────────────────────────────────
intelligence_triggers_total = 0
intelligence_last_run_at: Optional[str] = None


def run_intelligence_scan(db: Session, *, now: Optional[datetime] = None) -> Dict[str, int]:
    global intelligence_triggers_total, intelligence_last_run_at

    now = now or datetime.utcnow()
    intelligence_last_run_at = now.isoformat()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)
    cooldown_cutoff = now - timedelta(minutes=COOLDOWN_MINUTES)

    pairs = _find_anomalous_pairs(db, cutoff)
    if not pairs:
        return {"triggers": 0, "skipped": 0, "errors": 0}

    triggers = 0
    skipped = 0
    errors = 0

    for src_ip, dst_ip, pattern in pairs:
        if _has_recent_cache(db, src_ip, dst_ip, cooldown_cutoff):
            skipped += 1
            continue
        try:
            triggered = _trigger_analysis(db, src_ip, dst_ip, pattern, now)
            if triggered:
                triggers += 1
                # Trigger targeted PCAP capture if enabled
                _try_pcap_trigger(src_ip, dst_ip, reason=pattern)
            else:
                skipped += 1
        except Exception:
            logger.exception("Intelligence scan error for %s → %s", src_ip, dst_ip)
            errors += 1

    intelligence_triggers_total += triggers
    return {"triggers": triggers, "skipped": skipped, "errors": errors}


# ── Flow-based anomalous pair discovery ──────────────────────────────────────

def _find_anomalous_pairs(
    db: Session, cutoff: datetime,
) -> List[Tuple[str, str, str]]:
    seen: Set[Tuple[str, str]] = set()
    result: List[Tuple[str, str, str]] = []

    def _add(src, dst, pat):
        key = (src, dst)
        if key not in seen:
            seen.add(key)
            result.append((src, dst, pat))

    # connection_blocked: ≥ 2 denied/dropped flows for same src→dst
    for src, dst, n in (
        db.query(
            LiveFlowModel.source_ip,
            LiveFlowModel.destination_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.state.in_(("denied", "dropped")),
        )
        .group_by(LiveFlowModel.source_ip, LiveFlowModel.destination_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= BLOCKED_FLOW_THRESHOLD)
        .all()
    ):
        _add(src, dst, "connection_blocked")

    # connection_unstable: ≥ 2 reset flows for same src→dst
    for src, dst, n in (
        db.query(
            LiveFlowModel.source_ip,
            LiveFlowModel.destination_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.state == "reset",
        )
        .group_by(LiveFlowModel.source_ip, LiveFlowModel.destination_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= RESET_FLOW_THRESHOLD)
        .all()
    ):
        _add(src, dst, "connection_unstable")

    # slow_connection: any completed flow with duration_ms > threshold
    for src, dst in (
        db.query(
            LiveFlowModel.source_ip,
            LiveFlowModel.destination_ip,
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.state == "completed",
            LiveFlowModel.duration_ms > SLOW_DURATION_MS,
        )
        .distinct()
        .limit(50)
        .all()
    ):
        _add(src, dst, "slow_connection")

    # suspicious flows (flow_type = suspicious)
    for src, dst in (
        db.query(
            LiveFlowModel.source_ip,
            LiveFlowModel.destination_ip,
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.flow_type == "suspicious",
        )
        .distinct()
        .limit(50)
        .all()
    ):
        _add(src, dst, "suspicious_flow")

    # scanning flows (flow_type = scanning, threshold ≥ 2 per src→dst)
    for src, dst, n in (
        db.query(
            LiveFlowModel.source_ip,
            LiveFlowModel.destination_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.flow_type == "scanning",
        )
        .group_by(LiveFlowModel.source_ip, LiveFlowModel.destination_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= SCANNING_FLOW_THRESHOLD)
        .all()
    ):
        _add(src, dst, "scanning_flow")

    # Behavior-based triggers (scanning/suspicious with confidence > 0.7)
    from collector.flow_correlation import compute_flow_behaviors
    behaviors = compute_flow_behaviors(db, now=cutoff + timedelta(minutes=WINDOW_MINUTES))
    behavior_map = {
        b["source_ip"]: b["behavior_type"]
        for b in behaviors
        if b["behavior_type"] in ("scanning", "suspicious") and b["confidence"] > 0.7
    }
    if behavior_map:
        for src, dst in (
            db.query(
                LiveFlowModel.source_ip,
                LiveFlowModel.destination_ip,
            )
            .filter(
                LiveFlowModel.last_seen >= cutoff,
                LiveFlowModel.source_ip.in_(list(behavior_map.keys())),
            )
            .distinct()
            .limit(50)
            .all()
        ):
            btype = behavior_map.get(src, "correlated")
            _add(src, dst, f"behavior_{btype}")

    # already_flagged (notification-based, unchanged)
    flagged_ips = _flagged_source_ips(db, cutoff)
    if flagged_ips:
        for src, dst in (
            db.query(
                LiveFlowModel.source_ip,
                LiveFlowModel.destination_ip,
            )
            .filter(
                LiveFlowModel.last_seen >= cutoff,
                LiveFlowModel.source_ip.in_(flagged_ips),
            )
            .distinct()
            .limit(50)
            .all()
        ):
            _add(src, dst, "already_flagged")

    return result


def _flagged_source_ips(db: Session, cutoff: datetime) -> Set[str]:
    notifs = (
        db.query(NotificationModel.message)
        .filter(
            NotificationModel.type == "drift_detected",
            NotificationModel.created_at >= cutoff,
        )
        .all()
    )
    ips: Set[str] = set()
    ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for (msg,) in notifs:
        m = ip_re.search(msg or "")
        if m:
            ips.add(m.group(1))
    return ips


# ── Cooldown ─────────────────────────────────────────────────────────────────

def _has_recent_cache(db: Session, src_ip: str, dst_ip: str, cutoff: datetime) -> bool:
    return (
        db.query(PathAnalysisCacheModel)
        .filter(
            PathAnalysisCacheModel.source_ip == src_ip,
            PathAnalysisCacheModel.destination_ip == dst_ip,
            PathAnalysisCacheModel.created_at >= cutoff,
        )
        .first()
    ) is not None


# ── Trigger analysis ─────────────────────────────────────────────────────────

def _trigger_analysis(db, src_ip, dst_ip, pattern, now) -> bool:
    analysis = _find_analysis_for_ips(db, src_ip, dst_ip)
    if analysis is None:
        return False

    result_dict = _run_path_analysis(db, analysis, src_ip, dst_ip)
    if result_dict is None:
        return False

    outcome = result_dict.get("connection_outcome", "unknown")
    impairment = result_dict.get("primary_impairment")

    if outcome == "failure" or impairment is not None:
        detail = impairment or outcome
        msg = (
            f"[AUTO] Path {src_ip} → {dst_ip} shows {outcome}: "
            f"{detail} (trigger: {pattern})"
        )
        _create_notification(db, analysis, msg)

    db.commit()
    return True


def _find_analysis_for_ips(db, src_ip, dst_ip):
    candidates = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.status == "completed")
        .order_by(AnalysisModel.finished_at.desc())
        .limit(ANALYSIS_SEARCH_LIMIT)
        .all()
    )
    for a in candidates:
        rj = a.result_json or ""
        if src_ip in rj or dst_ip in rj:
            return a
    return None


def _run_path_analysis(db, analysis, src_ip, dst_ip):
    from core.causal_path import CausalPathEngine, CACHE_ENGINE_VERSION

    parts = json.dumps(
        {
            "analysis_id": analysis.id,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": None,
            "roles_hash": hashlib.sha256(b"null").hexdigest(),
            "engine_version": CACHE_ENGINE_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    cache_key = hashlib.sha256(parts.encode()).hexdigest()

    cached = (
        db.query(PathAnalysisCacheModel)
        .filter(PathAnalysisCacheModel.cache_key == cache_key)
        .first()
    )
    if cached:
        return json.loads(cached.result_json)

    if not analysis.file_path or not Path(analysis.file_path).exists():
        return None

    from normalizer.pipeline import normalize

    try:
        ctx = normalize(analysis.file_path)
    except Exception:
        logger.exception("Failed to parse PCAP for %s", analysis.id)
        return None

    engine = CausalPathEngine(ctx.packets, ctx.flows, ctx.findings, ctx)
    result = engine.analyze(src_ip, dst_ip)
    result_dict = result.to_dict()

    db.add(PathAnalysisCacheModel(
        cache_key=cache_key,
        analysis_id=analysis.id,
        source_ip=src_ip,
        destination_ip=dst_ip,
        destination_port=None,
        roles_hash=hashlib.sha256(b"null").hexdigest(),
        engine_version=CACHE_ENGINE_VERSION,
        result_json=json.dumps(result_dict),
    ))
    return result_dict


def _create_notification(db, analysis, message):
    existing = (
        db.query(NotificationModel)
        .filter(
            NotificationModel.user_id == analysis.user_id,
            NotificationModel.type == "drift_detected",
            NotificationModel.message == message,
            NotificationModel.read_at.is_(None),
        )
        .first()
    )
    if existing:
        return
    db.add(NotificationModel(
        user_id=analysis.user_id,
        type="drift_detected",
        analysis_id=analysis.id,
        message=message,
    ))


def _try_pcap_trigger(src_ip: str, dst_ip: str, reason: str = "") -> None:
    """Trigger a targeted PCAP capture if the trigger is enabled."""
    try:
        from collector.service import get_pcap_trigger
        trigger = get_pcap_trigger()
        if trigger is not None:
            trigger.trigger(src_ip=src_ip, dst_ip=dst_ip, reason=reason)
    except Exception:
        pass
