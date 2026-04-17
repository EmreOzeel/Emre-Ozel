"""
Flow Correlation Engine — aggregates multiple flows per source IP
and produces higher-level behavior signals.

Sits on top of ``LiveFlowModel`` without modifying it.  Computed
on-demand (no persistent table) with an optional in-memory cache.

Behavior detection rules (priority order):

  1. **scanning**         — many distinct ports/destinations, mostly
                            blocked or scanning-typed flows
  2. **lateral_movement** — many distinct destinations, mostly allowed
  3. **unstable**         — high reset ratio, mix of completed + reset
  4. **suspicious**       — high deny ratio or many suspicious-typed flows
  5. **normal**           — none of the above
"""
from __future__ import annotations

import time
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import case
from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from database import LiveFlowModel

# ── Tunables ─────────────────────────────────────────────────────────────────
WINDOW_MINUTES = 10
MIN_FLOWS = 5

# Scanning thresholds
SCAN_MIN_FLOWS = 10
SCAN_PORT_SPREAD = 15
SCAN_DST_SPREAD = 10
SCAN_BLOCKED_RATIO = 0.4

# Lateral movement thresholds
LATERAL_DST_SPREAD = 8
LATERAL_ALLOW_RATIO = 0.5

# Unstable thresholds
UNSTABLE_RESET_RATIO = 0.3

# Suspicious thresholds
SUSPICIOUS_DENY_RATIO = 0.5
SUSPICIOUS_FLOW_COUNT = 2

# ── In-memory cache ──────────────────────────────────────────────────────────
_cache_lock = threading.Lock()
_cache: Dict[str, Any] = {"ts": 0.0, "data": []}
_CACHE_TTL = 30.0  # seconds


def compute_flow_behaviors(
    db: Session,
    *,
    now: Optional[datetime] = None,
    use_cache: bool = True,
) -> List[Dict[str, Any]]:
    """Aggregate recent flows per source IP and classify behavior.

    Returns a list sorted by confidence descending.
    """
    if use_cache:
        with _cache_lock:
            if time.monotonic() - _cache["ts"] < _CACHE_TTL and _cache["data"]:
                return _cache["data"]

    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)

    rows = (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(LiveFlowModel.id).label("total_flows"),
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_ip)).label("distinct_dsts"),
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_port)).label("distinct_ports"),
            # Action counters via flow state
            sqlfunc.sum(case((LiveFlowModel.state == "completed", 1), else_=0)).label("completed"),
            sqlfunc.sum(case((LiveFlowModel.state.in_(("denied", "dropped")), 1), else_=0)).label("blocked"),
            sqlfunc.sum(case((LiveFlowModel.state == "reset", 1), else_=0)).label("resets"),
            # flow_type counters
            sqlfunc.sum(case((LiveFlowModel.flow_type == "scanning", 1), else_=0)).label("ft_scanning"),
            sqlfunc.sum(case((LiveFlowModel.flow_type == "suspicious", 1), else_=0)).label("ft_suspicious"),
            sqlfunc.sum(case((LiveFlowModel.flow_type == "blocked", 1), else_=0)).label("ft_blocked"),
            sqlfunc.sum(case((LiveFlowModel.flow_type == "unstable", 1), else_=0)).label("ft_unstable"),
        )
        .filter(LiveFlowModel.last_seen >= cutoff)
        .group_by(LiveFlowModel.source_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= MIN_FLOWS)
        .all()
    )

    result: List[Dict[str, Any]] = []
    for r in rows:
        total = int(r.total_flows or 0)
        distinct_dsts = int(r.distinct_dsts or 0)
        distinct_ports = int(r.distinct_ports or 0)
        completed = int(r.completed or 0)
        blocked = int(r.blocked or 0)
        resets = int(r.resets or 0)
        ft_scanning = int(r.ft_scanning or 0)
        ft_suspicious = int(r.ft_suspicious or 0)
        ft_blocked = int(r.ft_blocked or 0)
        ft_unstable = int(r.ft_unstable or 0)

        reset_ratio = round(resets / max(total, 1), 4)
        deny_ratio = round(blocked / max(total, 1), 4)
        blocked_or_scanning = blocked + ft_scanning
        blocked_scanning_ratio = blocked_or_scanning / max(total, 1)

        entry = _classify(
            source_ip=r.source_ip,
            total_flows=total,
            distinct_dsts=distinct_dsts,
            distinct_ports=distinct_ports,
            completed=completed,
            blocked=blocked,
            resets=resets,
            ft_scanning=ft_scanning,
            ft_suspicious=ft_suspicious,
            ft_blocked=ft_blocked,
            ft_unstable=ft_unstable,
            reset_ratio=reset_ratio,
            deny_ratio=deny_ratio,
            blocked_scanning_ratio=blocked_scanning_ratio,
        )
        result.append(entry)

    result.sort(key=lambda e: (-e["confidence"], -e["flow_count"]))

    # Enrich with deviation scores against IP baselines
    from collector.baseline import detect_deviations
    result = detect_deviations(db, result)

    if use_cache:
        with _cache_lock:
            _cache["ts"] = time.monotonic()
            _cache["data"] = result

    return result


def _classify(
    *,
    source_ip: str,
    total_flows: int,
    distinct_dsts: int,
    distinct_ports: int,
    completed: int,
    blocked: int,
    resets: int,
    ft_scanning: int,
    ft_suspicious: int,
    ft_blocked: int,
    ft_unstable: int,
    reset_ratio: float,
    deny_ratio: float,
    blocked_scanning_ratio: float,
) -> Dict[str, Any]:
    """Classify a source IP's behavior from its aggregated flow metrics."""
    behavior = "normal"
    confidence = 0.5
    drivers: List[str] = []

    # ── A. Scanning ──────────────────────────────────────────────────────
    is_scanning = False
    if total_flows >= SCAN_MIN_FLOWS:
        wide_ports = distinct_ports >= SCAN_PORT_SPREAD
        wide_dsts = distinct_dsts >= SCAN_DST_SPREAD
        high_blocked = blocked_scanning_ratio >= SCAN_BLOCKED_RATIO

        if (wide_ports or wide_dsts) and (high_blocked or ft_scanning >= 3):
            is_scanning = True
            behavior = "scanning"
            confidence = 0.7
            if wide_ports:
                drivers.append("wide_port_spread")
                confidence += 0.1
            if wide_dsts:
                drivers.append("broad_destination_spread")
                confidence += 0.05
            if ft_scanning >= 3:
                drivers.append("multiple_scanning_flows")
                confidence += 0.05
            if high_blocked:
                drivers.append("many_denied_flows")

    # ── B. Lateral movement ──────────────────────────────────────────────
    if not is_scanning and distinct_dsts >= LATERAL_DST_SPREAD:
        allow_ratio = completed / max(total_flows, 1)
        if allow_ratio >= LATERAL_ALLOW_RATIO:
            behavior = "lateral_movement"
            confidence = 0.6
            drivers.append("broad_destination_spread")
            if distinct_dsts >= 15:
                confidence += 0.1
                drivers.append("very_wide_destination_spread")
            if allow_ratio > 0.8:
                confidence += 0.1
                drivers.append("mostly_allowed")

    # ── C. Unstable ──────────────────────────────────────────────────────
    if behavior == "normal" and reset_ratio > UNSTABLE_RESET_RATIO:
        if completed > 0 or ft_unstable > 0:
            behavior = "unstable"
            confidence = 0.6
            drivers.append("high_reset_ratio")
            if reset_ratio > 0.5:
                confidence += 0.1
            if ft_unstable >= 2:
                drivers.append("multiple_unstable_flows")
                confidence += 0.05

    # ── D. Suspicious ────────────────────────────────────────────────────
    if behavior == "normal":
        if ft_suspicious >= SUSPICIOUS_FLOW_COUNT:
            behavior = "suspicious"
            confidence = 0.65
            drivers.append("multiple_suspicious_flows")
            if ft_suspicious >= 4:
                confidence += 0.1
        elif deny_ratio > SUSPICIOUS_DENY_RATIO:
            behavior = "suspicious"
            confidence = 0.6
            drivers.append("high_deny_ratio")
            if deny_ratio > 0.8:
                confidence += 0.1

    # Cap confidence
    confidence = round(min(confidence, 0.95), 2)

    return {
        "source_ip": source_ip,
        "behavior_type": behavior,
        "confidence": confidence,
        "flow_count": total_flows,
        "distinct_destinations": distinct_dsts,
        "distinct_ports": distinct_ports,
        "reset_ratio": reset_ratio,
        "deny_ratio": deny_ratio,
        "time_window_minutes": WINDOW_MINUTES,
        "drivers": drivers,
    }
