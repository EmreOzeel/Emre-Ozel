"""
Per-source-IP risk scoring from live flows.

Queries ``LiveFlowModel`` (reconstructed sessions) instead of raw events.
Same scoring formula and return shape as before, but the input metrics
are now flow-level aggregates.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import case
from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from database import LiveFlowModel

# ── Tunables ─────────────────────────────────────────────────────────────────
WINDOW_MINUTES = 15
MIN_FLOWS = 3

# ── Risk-level thresholds ────────────────────────────────────────────────────
_LEVELS = (
    (80, "critical"),
    (60, "high"),
    (30, "medium"),
    (0,  "low"),
)


def _level(score: int) -> str:
    for cutoff, label in _LEVELS:
        if score >= cutoff:
            return label
    return "low"


def compute_live_risk_scores(
    db: Session,
    *,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Compute a risk entry per active source IP from flows.

    Uses ``LiveFlowModel`` with ``last_seen >= now - 15 min``.
    Only includes source IPs with >= 3 flows.
    Returns a list sorted by ``risk_score`` descending.
    """
    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)

    rows = (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(LiveFlowModel.id).label("flow_count"),
            sqlfunc.sum(
                case(
                    (LiveFlowModel.state.in_(("denied", "dropped")), 1),
                    else_=0,
                )
            ).label("denied_flows"),
            sqlfunc.sum(
                case(
                    (LiveFlowModel.state == "reset", 1),
                    else_=0,
                )
            ).label("reset_count"),
            sqlfunc.count(
                sqlfunc.distinct(LiveFlowModel.destination_ip)
            ).label("distinct_destinations"),
            sqlfunc.sum(LiveFlowModel.raw_event_count).label("total_events"),
            sqlfunc.max(LiveFlowModel.last_seen).label("last_seen"),
            # flow_type counts
            sqlfunc.sum(
                case((LiveFlowModel.flow_type == "scanning", 1), else_=0)
            ).label("scanning_count"),
            sqlfunc.sum(
                case((LiveFlowModel.flow_type == "suspicious", 1), else_=0)
            ).label("suspicious_count"),
            sqlfunc.sum(
                case((LiveFlowModel.flow_type == "unstable", 1), else_=0)
            ).label("unstable_count"),
        )
        .filter(LiveFlowModel.last_seen >= cutoff)
        .group_by(LiveFlowModel.source_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= MIN_FLOWS)
        .all()
    )

    result: List[Dict[str, Any]] = []
    for r in rows:
        flow_count = int(r.flow_count or 0)
        denied_flows = int(r.denied_flows or 0)
        reset_count = int(r.reset_count or 0)
        distinct_destinations = int(r.distinct_destinations or 0)
        event_count = int(r.total_events or 0)
        scanning_count = int(r.scanning_count or 0)
        suspicious_count = int(r.suspicious_count or 0)
        unstable_count = int(r.unstable_count or 0)

        entry = _score_ip(
            source_ip=r.source_ip,
            event_count=event_count,
            deny_count=denied_flows,
            flow_count=flow_count,
            reset_count=reset_count,
            distinct_destinations=distinct_destinations,
            last_seen=r.last_seen,
            scanning_count=scanning_count,
            suspicious_count=suspicious_count,
            unstable_count=unstable_count,
        )
        result.append(entry)

    # Behavior-level boost (additive, non-destructive)
    _apply_behavior_boost(db, result, now=now)

    result.sort(key=lambda e: -e["risk_score"])
    return result


def _apply_behavior_boost(
    db: Session,
    entries: List[Dict[str, Any]],
    *,
    now: Optional[datetime] = None,
) -> None:
    """Add risk score points based on correlated behavior signals."""
    from collector.flow_correlation import compute_flow_behaviors

    behaviors = compute_flow_behaviors(db, now=now)
    behavior_map = {b["source_ip"]: b for b in behaviors}

    _BOOST = {
        "scanning": 20,
        "lateral_movement": 15,
        "unstable": 10,
        "suspicious": 12,
    }

    for entry in entries:
        b = behavior_map.get(entry["source_ip"])
        if not b or b["behavior_type"] == "normal":
            continue
        boost = _BOOST.get(b["behavior_type"], 0)
        if boost and b["confidence"] >= 0.6:
            entry["risk_score"] = min(entry["risk_score"] + boost, 100)
            entry["risk_level"] = _level(entry["risk_score"])
            driver = f"behavior_{b['behavior_type']}"
            if driver not in entry["drivers"]:
                entry["drivers"].append(driver)


def _score_ip(
    *,
    source_ip: str,
    event_count: int,
    deny_count: int,
    flow_count: int = 0,
    reset_count: int,
    distinct_destinations: int,
    last_seen,
    scanning_count: int = 0,
    suspicious_count: int = 0,
    unstable_count: int = 0,
) -> Dict[str, Any]:
    score = 0
    drivers: List[str] = []

    # Deny rate: denied_flows / total_flows
    denom = flow_count if flow_count > 0 else max(deny_count, 1)
    deny_rate = deny_count / denom if denom else 0.0

    if deny_rate > 0.5:
        score += 40
        drivers.append("deny_rate_high")
    elif deny_rate > 0.2:
        score += 20
        drivers.append("deny_rate_elevated")

    if reset_count > 10:
        score += 20
        drivers.append("repeated_resets")
    elif reset_count > 5:
        score += 10
        drivers.append("repeated_resets")

    if distinct_destinations > 20:
        score += 25
        drivers.append("lateral_movement")
    elif distinct_destinations > 10:
        score += 15
        drivers.append("broad_targeting")
    elif distinct_destinations > 5:
        score += 5
        drivers.append("multi_destination")

    if event_count > 1000:
        score += 15
        drivers.append("high_volume")
    elif event_count > 500:
        score += 8
        drivers.append("elevated_volume")

    # flow_type contributions
    if scanning_count >= 3:
        score += 20
        drivers.append("scanning_behavior")
    elif scanning_count >= 1:
        score += 10
        drivers.append("scanning_behavior")

    if suspicious_count >= 2:
        score += 15
        drivers.append("suspicious_flows")
    elif suspicious_count >= 1:
        score += 8
        drivers.append("suspicious_flows")

    if unstable_count >= 3:
        score += 10
        drivers.append("unstable_connections")

    score = min(score, 100)

    return {
        "source_ip": source_ip,
        "risk_score": score,
        "risk_level": _level(score),
        "drivers": drivers,
        "event_count": event_count,
        "deny_count": deny_count,
        "reset_count": reset_count,
        "distinct_destinations": distinct_destinations,
        "scanning_count": scanning_count,
        "suspicious_count": suspicious_count,
        "unstable_count": unstable_count,
        "last_seen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else str(last_seen) if last_seen else None,
    }
