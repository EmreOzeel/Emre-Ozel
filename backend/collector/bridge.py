"""
Bridge between the flow/session layer and the monitoring/notification layer.

Scans ``LiveFlowModel`` (reconstructed flows) for anomaly patterns and
emits ``drift_detected`` notifications.  Also applies SuppressionRule
records to both live events and live flows.

Patterns (flow-based)
---------------------

A — **blocked_flow_spike**: a single source_ip has > BLOCKED_FLOW_THRESHOLD
    flows in state "denied" or "dropped" in the last 10 minutes.

B — **port_scan**: a single source_ip has > PORT_SCAN_DST_THRESHOLD
    distinct destination_ips OR > PORT_SCAN_PORT_THRESHOLD distinct
    destination_ports across all flows in the last 10 minutes.

C — **repeated_reset**: the same src→dst pair has > RESET_FLOW_THRESHOLD
    flows in state "reset" in the last 10 minutes.

The module also auto-creates ``MonitoredPath`` + ``SavedQuery`` records
for high-risk src→dst pairs (unchanged from previous version).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import List, Optional, Set, Tuple

from sqlalchemy import and_, or_
from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from database import (
    AnalysisModel,
    LiveEventModel,
    LiveFlowModel,
    MonitoredPathModel,
    NotificationModel,
    PathAnalysisSavedQueryModel,
    SuppressionRuleModel,
)

# ── Thresholds ───────────────────────────────────────────────────────────────
WINDOW_MINUTES = 10
BLOCKED_FLOW_THRESHOLD = 5
PORT_SCAN_DST_THRESHOLD = 10
PORT_SCAN_PORT_THRESHOLD = 15
RESET_FLOW_THRESHOLD = 3
SCANNING_FLOW_THRESHOLD = 3
SUSPICIOUS_FLOW_THRESHOLD = 2

ADMIN_USER_ID = 1

# Module-level counters exposed via collector_stats().
suppression_matches_count = 0
auto_paths_created_total = 0


# ── Suppression ──────────────────────────────────────────────────────────────

def _load_active_rules(db: Session, now: datetime) -> list:
    return (
        db.query(SuppressionRuleModel)
        .filter(
            SuppressionRuleModel.is_active.is_(True),
            or_(
                SuppressionRuleModel.expires_at.is_(None),
                SuppressionRuleModel.expires_at > now,
            ),
        )
        .all()
    )


def _suppressed_source_ips(db: Session, now: datetime) -> Set[str]:
    """Source IPs covered by active suppression rules."""
    rules = _load_active_rules(db, now)
    ips = {r.src_ip for r in rules if r.src_ip}
    # Also include IPs from recently denied flows that match dst rules
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)
    for r in rules:
        if r.dst_ip and not r.src_ip:
            flow_srcs = (
                db.query(LiveFlowModel.source_ip)
                .filter(
                    LiveFlowModel.last_seen >= cutoff,
                    LiveFlowModel.destination_ip == r.dst_ip,
                    LiveFlowModel.state.in_(("denied", "dropped")),
                )
                .distinct()
                .all()
            )
            ips.update(s[0] for s in flow_srcs)
    return ips


def apply_suppressions(
    db: Session, *, now: Optional[datetime] = None,
) -> int:
    """Apply active SuppressionRule records to recent live events AND flows.

    Returns the number of suppression rules that matched.
    """
    global suppression_matches_count

    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)
    rules = _load_active_rules(db, now)
    if not rules:
        return 0

    matched_rules = 0
    for rule in rules:
        if not rule.src_ip and not rule.dst_ip and not rule.rule_id:
            continue

        # Apply to LiveEventModel — set suppressed=True
        ev_conds = [
            LiveEventModel.event_time >= cutoff,
            or_(
                LiveEventModel.suppressed.is_(None),
                LiveEventModel.suppressed.is_(False),
            ),
        ]
        if rule.src_ip:
            ev_conds.append(LiveEventModel.source_ip == rule.src_ip)
        if rule.dst_ip:
            ev_conds.append(LiveEventModel.destination_ip == rule.dst_ip)
        if rule.rule_id:
            ev_conds.append(LiveEventModel.application == rule.rule_id)

        n_ev = (
            db.query(LiveEventModel)
            .filter(and_(*ev_conds))
            .update({LiveEventModel.suppressed: True}, synchronize_session=False)
        )

        # Apply to LiveFlowModel — set suppressed=True
        fl_conds = [
            LiveFlowModel.last_seen >= cutoff,
            or_(
                LiveFlowModel.suppressed.is_(None),
                LiveFlowModel.suppressed.is_(False),
            ),
        ]
        if rule.src_ip:
            fl_conds.append(LiveFlowModel.source_ip == rule.src_ip)
        if rule.dst_ip:
            fl_conds.append(LiveFlowModel.destination_ip == rule.dst_ip)
        if rule.rule_id:
            fl_conds.append(LiveFlowModel.application == rule.rule_id)

        n_fl = (
            db.query(LiveFlowModel)
            .filter(and_(*fl_conds))
            .update({LiveFlowModel.suppressed: True}, synchronize_session=False)
        )

        total = n_ev + n_fl
        if total > 0:
            matched_rules += 1
            suppression_matches_count += total

    if matched_rules:
        db.commit()
    return matched_rules


# ── Flow-based scanning ──────────────────────────────────────────────────────

def scan_live_events(db: Session, *, now: datetime | None = None) -> int:
    """Scan recent flows for anomaly patterns and emit notifications.

    Returns the total number of patterns detected (≥ 0).
    """
    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)
    suppressed_ips = _suppressed_source_ips(db, now)
    detected = 0

    detected += _scan_blocked_flow_spike(db, cutoff, suppressed_ips)
    detected += _scan_port_scan(db, cutoff, suppressed_ips)
    detected += _scan_repeated_reset(db, cutoff, suppressed_ips)
    detected += _scan_scanning_flows(db, cutoff, suppressed_ips)
    detected += _scan_suspicious_flows(db, cutoff, suppressed_ips)
    detected += _scan_behaviors(db, suppressed_ips)

    if detected:
        db.commit()
    return detected


def _scan_blocked_flow_spike(
    db: Session, cutoff: datetime, suppressed_ips: Set[str],
) -> int:
    """Source IPs with many blocked flows (state OR flow_type)."""
    rows = (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            or_(
                LiveFlowModel.state.in_(("denied", "dropped")),
                LiveFlowModel.flow_type == "blocked",
            ),
        )
        .group_by(LiveFlowModel.source_ip)
        .having(sqlfunc.count(LiveFlowModel.id) > BLOCKED_FLOW_THRESHOLD)
        .all()
    )
    count = 0
    for src_ip, n in rows:
        if src_ip in suppressed_ips:
            continue
        msg = (
            f"[BLOCKED FLOW SPIKE] {src_ip} has {n} blocked flows "
            f"in the last {WINDOW_MINUTES} minutes"
        )
        if _emit(db, msg):
            count += 1
    return count


def _scan_port_scan(
    db: Session, cutoff: datetime, suppressed_ips: Set[str],
) -> int:
    """Source IPs targeting many distinct destinations or ports.

    Also triggers on flow_type='scanning' even below the count threshold.
    """
    flagged: dict = {}

    # flow_type = scanning with ≥ SCANNING_FLOW_THRESHOLD flows
    for src_ip, n in (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.flow_type == "scanning",
        )
        .group_by(LiveFlowModel.source_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= SCANNING_FLOW_THRESHOLD)
        .all()
    ):
        flagged[src_ip] = f"{n} scanning flows detected"

    # Distinct destination IPs
    for src_ip, n in (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_ip)),
        )
        .filter(LiveFlowModel.last_seen >= cutoff)
        .group_by(LiveFlowModel.source_ip)
        .having(
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_ip))
            > PORT_SCAN_DST_THRESHOLD
        )
        .all()
    ):
        if src_ip not in flagged:
            flagged[src_ip] = f"{n} distinct destination IPs"

    # Distinct destination ports
    for src_ip, n in (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_port)),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.destination_port.isnot(None),
        )
        .group_by(LiveFlowModel.source_ip)
        .having(
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_port))
            > PORT_SCAN_PORT_THRESHOLD
        )
        .all()
    ):
        if src_ip not in flagged:
            flagged[src_ip] = f"{n} distinct ports"

    count = 0
    for src_ip, detail in flagged.items():
        if src_ip in suppressed_ips:
            continue
        msg = (
            f"[PORT SCAN] {src_ip} targeting {detail} "
            f"in the last {WINDOW_MINUTES} minutes"
        )
        if _emit(db, msg):
            count += 1
    return count


def _scan_repeated_reset(
    db: Session, cutoff: datetime, suppressed_ips: Set[str],
) -> int:
    """Src→dst pairs with many reset or unstable flows."""
    rows = (
        db.query(
            LiveFlowModel.source_ip,
            LiveFlowModel.destination_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            or_(
                LiveFlowModel.state == "reset",
                LiveFlowModel.flow_type == "unstable",
            ),
        )
        .group_by(LiveFlowModel.source_ip, LiveFlowModel.destination_ip)
        .having(sqlfunc.count(LiveFlowModel.id) > RESET_FLOW_THRESHOLD)
        .all()
    )
    count = 0
    for src_ip, dst_ip, n in rows:
        if src_ip in suppressed_ips:
            continue
        msg = (
            f"[REPEATED RESET] {src_ip} → {dst_ip} had {n} reset/unstable flows "
            f"in the last {WINDOW_MINUTES} minutes"
        )
        if _emit(db, msg):
            count += 1
    return count


def _scan_scanning_flows(
    db: Session, cutoff: datetime, suppressed_ips: Set[str],
) -> int:
    """Source IPs with multiple flow_type='scanning' flows."""
    rows = (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.flow_type == "scanning",
        )
        .group_by(LiveFlowModel.source_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= SCANNING_FLOW_THRESHOLD)
        .all()
    )
    count = 0
    for src_ip, n in rows:
        if src_ip in suppressed_ips:
            continue
        msg = (
            f"[SCANNING] {src_ip} has {n} probe-like flows "
            f"in the last {WINDOW_MINUTES} minutes"
        )
        if _emit(db, msg):
            count += 1
    return count


def _scan_suspicious_flows(
    db: Session, cutoff: datetime, suppressed_ips: Set[str],
) -> int:
    """Source IPs with multiple flow_type='suspicious' flows."""
    rows = (
        db.query(
            LiveFlowModel.source_ip,
            sqlfunc.count(LiveFlowModel.id),
        )
        .filter(
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.flow_type == "suspicious",
        )
        .group_by(LiveFlowModel.source_ip)
        .having(sqlfunc.count(LiveFlowModel.id) >= SUSPICIOUS_FLOW_THRESHOLD)
        .all()
    )
    count = 0
    for src_ip, n in rows:
        if src_ip in suppressed_ips:
            continue
        msg = (
            f"[SUSPICIOUS] {src_ip} has {n} suspicious flows "
            f"in the last {WINDOW_MINUTES} minutes"
        )
        if _emit(db, msg):
            count += 1
    return count


def _scan_behaviors(
    db: Session, suppressed_ips: Set[str],
) -> int:
    """Create/update incidents from correlated behaviors and emit
    notifications only for new medium+ incidents or severity escalations.

    Returns the number of new detections (incidents created or updated).
    """
    from collector.flow_correlation import compute_flow_behaviors
    from collector.incidents import upsert_incidents_from_behaviors

    behaviors = compute_flow_behaviors(db, use_cache=False)
    # Filter out suppressed IPs and low-confidence normals
    eligible = [
        b for b in behaviors
        if b["behavior_type"] != "normal"
        and b["confidence"] >= 0.6
        and b["source_ip"] not in suppressed_ips
    ]
    if not eligible:
        return 0

    result = upsert_incidents_from_behaviors(db, eligible)
    return result["created"] + result["updated"]


# ── Notification helper ──────────────────────────────────────────────────────

def _emit(db: Session, message: str) -> bool:
    existing = (
        db.query(NotificationModel)
        .filter(
            NotificationModel.user_id == ADMIN_USER_ID,
            NotificationModel.type == "drift_detected",
            NotificationModel.message == message,
            NotificationModel.read_at.is_(None),
        )
        .first()
    )
    if existing:
        return False
    db.add(NotificationModel(
        user_id=ADMIN_USER_ID,
        type="drift_detected",
        analysis_id=None,
        message=message,
    ))
    return True


# ── Auto-create monitored paths ──────────────────────────────────────────────

AUTO_RISK_THRESHOLD = 60
AUTO_WINDOW_MINUTES = 10
AUTO_ANALYSIS_SEARCH_LIMIT = 50


def auto_create_monitored_paths(
    db: Session, *, now: Optional[datetime] = None,
) -> int:
    global auto_paths_created_total

    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=AUTO_WINDOW_MINUTES)

    from collector.live_risk import compute_live_risk_scores
    risk_entries = compute_live_risk_scores(db, now=now)
    high_risk = [e for e in risk_entries if e["risk_score"] >= AUTO_RISK_THRESHOLD]
    if not high_risk:
        return 0

    created = 0
    for entry in high_risk:
        src_ip = entry["source_ip"]

        # Top destination from flows
        top_dst = (
            db.query(
                LiveFlowModel.destination_ip,
                sqlfunc.count(LiveFlowModel.id).label("cnt"),
            )
            .filter(
                LiveFlowModel.last_seen >= cutoff,
                LiveFlowModel.source_ip == src_ip,
            )
            .group_by(LiveFlowModel.destination_ip)
            .order_by(sqlfunc.count(LiveFlowModel.id).desc())
            .first()
        )
        if not top_dst:
            continue
        dst_ip = top_dst[0]

        existing_sq = (
            db.query(PathAnalysisSavedQueryModel)
            .filter(
                PathAnalysisSavedQueryModel.source_ip == src_ip,
                PathAnalysisSavedQueryModel.destination_ip == dst_ip,
                PathAnalysisSavedQueryModel.owner_user_id == ADMIN_USER_ID,
            )
            .first()
        )
        if existing_sq:
            continue

        analysis = _find_analysis_for_pair(db, src_ip, dst_ip)
        if analysis is None:
            continue

        sq = PathAnalysisSavedQueryModel(
            owner_user_id=ADMIN_USER_ID,
            name=f"auto: {src_ip} → {dst_ip}",
            source_ip=src_ip,
            destination_ip=dst_ip,
            firewall_ips=json.dumps([]),
            load_balancer_vips=json.dumps([]),
            backend_ips=json.dumps([]),
            backend_subnets=json.dumps([]),
            scope="global",
            created_by=ADMIN_USER_ID,
            updated_by=ADMIN_USER_ID,
            note=f"Auto-created by live intelligence on {now.isoformat()}",
        )
        db.add(sq)
        db.flush()

        mp = MonitoredPathModel(
            saved_query_id=sq.id,
            analysis_id=analysis.id,
            owner_user_id=ADMIN_USER_ID,
            schedule_interval_minutes=15,
            enabled=True,
        )
        db.add(mp)
        created += 1

    if created:
        db.commit()
        auto_paths_created_total += created

    return created


def _find_analysis_for_pair(
    db: Session, src_ip: str, dst_ip: str,
) -> Optional[AnalysisModel]:
    candidates = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.status == "completed")
        .order_by(AnalysisModel.finished_at.desc())
        .limit(AUTO_ANALYSIS_SEARCH_LIMIT)
        .all()
    )
    for a in candidates:
        rj = a.result_json or ""
        if src_ip in rj or dst_ip in rj:
            return a
    return None
