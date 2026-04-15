"""
Behavior-to-incident conversion layer.

Converts repeated behavior detections (from ``flow_correlation.py``)
into persistent ``LiveIncidentModel`` records.  Grouping rule: same
``source_ip`` + ``behavior_type`` within a rolling time window maps
to the same incident.

Severity is derived deterministically from confidence, repetition
count, and the behavior type itself.  Escalation is one-way: a
subsequent detection can raise severity but never lower it.

The bridge integration calls ``upsert_incidents_from_behaviors(db)``
on the same cadence as the behavior scan.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from database import AssetModel, LiveFlowModel, LiveIncidentModel, NotificationModel

# ── Tunables ─────────────────────────────────────────────────────────────────
# If the last_seen of an open incident is older than this, a new detection
# of the same (source_ip, behavior_type) creates a NEW incident instead of
# updating the old one.
MERGE_WINDOW_MINUTES = 30

# Admin user for notifications.
ADMIN_USER_ID = 1

# Severity ladder (index = numeric rank for comparisons).
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_RANK_SEV = ["low", "medium", "high", "critical"]


def _derive_severity(
    behavior_type: str,
    confidence: float,
    event_count: int,
) -> str:
    """Deterministic severity from behavior signals.

    Rules:
      - scanning / suspicious with confidence ≥ 0.8 → high
      - scanning / suspicious with confidence ≥ 0.7 → medium
      - lateral_movement → medium (at least)
      - unstable with ≥ 3 repetitions → medium
      - repetition ≥ 5 on any non-normal → escalate by one level
      - confidence ≥ 0.9 + repetition ≥ 3 → critical
    """
    sev = "low"

    if behavior_type in ("scanning", "suspicious"):
        if confidence >= 0.8:
            sev = "high"
        elif confidence >= 0.7:
            sev = "medium"
    elif behavior_type == "lateral_movement":
        sev = "medium"
    elif behavior_type == "unstable":
        if event_count >= 3:
            sev = "medium"

    # Repetition escalation
    if event_count >= 5 and _SEV_RANK[sev] < _SEV_RANK["high"]:
        sev = _RANK_SEV[_SEV_RANK[sev] + 1]

    # Critical threshold
    if confidence >= 0.9 and event_count >= 3:
        sev = "critical"

    return sev


def _build_summary(behavior: Dict[str, Any], event_count: int) -> str:
    btype = behavior.get("behavior_type", "unknown")
    drivers = behavior.get("drivers", [])
    conf = behavior.get("confidence", 0)
    top = ", ".join(drivers[:3]) if drivers else "multiple signals"
    return (
        f"{btype} behavior detected {event_count} time(s) "
        f"(confidence {conf:.0%}) — {top}"
    )


def upsert_incidents_from_behaviors(
    db: Session,
    behaviors: List[Dict[str, Any]],
    *,
    now: Optional[datetime] = None,
) -> Dict[str, int]:
    """Create or update incidents from a behavior list.

    Returns ``{"created": N, "updated": N, "notified": N}``.
    """
    now = now or datetime.utcnow()
    merge_cutoff = now - timedelta(minutes=MERGE_WINDOW_MINUTES)

    created = 0
    updated = 0
    notified = 0

    for b in behaviors:
        if b["behavior_type"] == "normal":
            continue

        src_ip = b["source_ip"]
        btype = b["behavior_type"]

        # Find open/investigating incident within the merge window
        existing = (
            db.query(LiveIncidentModel)
            .filter(
                LiveIncidentModel.source_ip == src_ip,
                LiveIncidentModel.behavior_type == btype,
                LiveIncidentModel.status.in_(("open", "investigating")),
                LiveIncidentModel.last_seen >= merge_cutoff,
            )
            .first()
        )

        if existing:
            # Update existing incident
            existing.last_seen = now
            existing.last_activity_at = now
            existing.event_count += 1
            existing.linked_flow_count = b.get("flow_count", 0)
            existing.latest_confidence = b.get("confidence")
            existing.updated_at = now
            _enrich_incident(db, existing, now=now)
            _enrich_asset_impact(db, existing)

            # Severity escalation (never downgrade)
            old_sev = existing.severity
            new_sev = _derive_severity(btype, b.get("confidence", 0), existing.event_count)
            if _SEV_RANK.get(new_sev, 0) > _SEV_RANK.get(existing.severity, 0):
                existing.severity = new_sev
            # Asset-based severity boost (additive, after base escalation)
            _apply_asset_severity_boost(existing)
            # Notify if severity increased at all (base or asset)
            if _SEV_RANK.get(existing.severity, 0) > _SEV_RANK.get(old_sev, 0):
                if _notify_escalation(db, existing, old_sev, existing.severity):
                    notified += 1

            update_priority(existing, now=now)
            updated += 1
        else:
            # Create new incident
            sev = _derive_severity(btype, b.get("confidence", 0), 1)
            incident = LiveIncidentModel(
                source_ip=src_ip,
                behavior_type=btype,
                severity=sev,
                status="open",
                first_seen=now,
                last_seen=now,
                event_count=1,
                linked_flow_count=b.get("flow_count", 0),
                latest_confidence=b.get("confidence"),
                summary=_build_summary(b, 1),
                created_at=now,
                updated_at=now,
            )
            db.add(incident)
            db.flush()
            _enrich_incident(db, incident, now=now)
            _enrich_asset_impact(db, incident)
            _apply_asset_severity_boost(incident)
            incident.last_activity_at = now
            update_priority(incident, now=now)
            sev = incident.severity  # may have been boosted
            created += 1

            # Notify on creation (only for medium+ severity)
            if _SEV_RANK.get(sev, 0) >= _SEV_RANK["medium"]:
                if _notify_new(db, incident):
                    notified += 1

    if created or updated:
        db.commit()

    return {"created": created, "updated": updated, "notified": notified}


def _enrich_incident(
    db: Session,
    incident: LiveIncidentModel,
    *,
    now: Optional[datetime] = None,
) -> None:
    """Populate enrichment fields from recent flows of the same source_ip."""
    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=10)

    # Top destination IPs (max 5)
    dst_rows = (
        db.query(
            LiveFlowModel.destination_ip,
            sqlfunc.count(LiveFlowModel.id).label("cnt"),
        )
        .filter(
            LiveFlowModel.source_ip == incident.source_ip,
            LiveFlowModel.last_seen >= cutoff,
        )
        .group_by(LiveFlowModel.destination_ip)
        .order_by(sqlfunc.count(LiveFlowModel.id).desc())
        .limit(5)
        .all()
    )
    top_dsts = [r[0] for r in dst_rows]

    # Top destination ports (max 5)
    port_rows = (
        db.query(
            LiveFlowModel.destination_port,
            sqlfunc.count(LiveFlowModel.id).label("cnt"),
        )
        .filter(
            LiveFlowModel.source_ip == incident.source_ip,
            LiveFlowModel.last_seen >= cutoff,
            LiveFlowModel.destination_port.isnot(None),
        )
        .group_by(LiveFlowModel.destination_port)
        .order_by(sqlfunc.count(LiveFlowModel.id).desc())
        .limit(5)
        .all()
    )
    top_ports = [r[0] for r in port_rows]

    # Distinct counts
    counts = (
        db.query(
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_ip)),
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_port)),
        )
        .filter(
            LiveFlowModel.source_ip == incident.source_ip,
            LiveFlowModel.last_seen >= cutoff,
        )
        .first()
    )
    total_dsts = int(counts[0] or 0)
    total_ports = int(counts[1] or 0)

    # Sample flows (3 most recent)
    sample_rows = (
        db.query(LiveFlowModel)
        .filter(
            LiveFlowModel.source_ip == incident.source_ip,
            LiveFlowModel.last_seen >= cutoff,
        )
        .order_by(LiveFlowModel.last_seen.desc())
        .limit(3)
        .all()
    )
    samples = [
        {
            "src": f.source_ip,
            "dst": f"{f.destination_ip}:{f.destination_port or '*'}",
            "state": f.state,
            "duration_ms": f.duration_ms,
        }
        for f in sample_rows
    ]

    # Write enrichment
    incident.top_destination_ips = json.dumps(top_dsts)
    incident.top_ports = json.dumps(top_ports)
    incident.total_distinct_destinations = total_dsts
    incident.total_distinct_ports = total_ports
    incident.sample_flows = json.dumps(samples)

    # Improved summary
    port_hint = ", ".join(str(p) for p in top_ports[:3]) if top_ports else "various"
    incident.summary = (
        f"{incident.source_ip} {incident.behavior_type} "
        f"{total_dsts} host(s) across {total_ports} port(s) "
        f"(top: {port_hint})"
    )

    # Last activity summary
    if sample_rows:
        latest = sample_rows[0]
        incident.last_activity_summary = (
            f"{latest.source_ip} → {latest.destination_ip}:"
            f"{latest.destination_port or '*'} "
            f"({latest.state}, {latest.duration_ms or 0}ms)"
        )


def _enrich_asset_impact(
    db: Session,
    incident: LiveIncidentModel,
) -> None:
    """Match destination IPs to known assets and compute impact."""
    if not incident.top_destination_ips:
        incident.impacted_assets_count = 0
        incident.highest_target_criticality = None
        incident.target_summary = None
        return

    dst_ips = json.loads(incident.top_destination_ips)
    if not dst_ips:
        incident.impacted_assets_count = 0
        return

    # Also include all distinct destinations from recent flows
    cutoff = (incident.last_seen or datetime.utcnow()) - timedelta(minutes=10)
    all_dst_rows = (
        db.query(LiveFlowModel.destination_ip)
        .filter(
            LiveFlowModel.source_ip == incident.source_ip,
            LiveFlowModel.last_seen >= cutoff,
        )
        .distinct()
        .all()
    )
    all_dst_ips = list({r[0] for r in all_dst_rows} | set(dst_ips))

    assets = (
        db.query(AssetModel)
        .filter(AssetModel.ip_address.in_(all_dst_ips))
        .all()
    )

    if not assets:
        incident.impacted_assets_count = 0
        incident.highest_target_criticality = None
        incident.target_summary = None
        return

    incident.impacted_assets_count = len(assets)

    # Highest criticality
    crit_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    highest = max(assets, key=lambda a: crit_rank.get(a.criticality, 0))
    incident.highest_target_criticality = highest.criticality

    # Target summary
    type_crit_counts: dict = {}
    for a in assets:
        key = f"{a.criticality} {a.asset_type}"
        type_crit_counts[key] = type_crit_counts.get(key, 0) + 1
    parts = []
    for key in sorted(type_crit_counts, key=lambda k: -crit_rank.get(k.split()[0], 0)):
        cnt = type_crit_counts[key]
        parts.append(f"{cnt} {key}(s)")
    incident.target_summary = ", ".join(parts[:4])

    # Update summary to include asset info
    hostnames = [a.hostname for a in assets if a.hostname and a.criticality in ("high", "critical")]
    if hostnames:
        host_hint = ", ".join(hostnames[:3])
        incident.summary = (
            f"{incident.source_ip} {incident.behavior_type} "
            f"{incident.total_distinct_destinations or 0} host(s) "
            f"including {host_hint}"
        )


def _apply_asset_severity_boost(incident: LiveIncidentModel) -> None:
    """Escalate severity based on highest target criticality.

    high target → +1 tier, critical target → +2 tiers.
    """
    crit = incident.highest_target_criticality
    if not crit:
        return
    rank = _SEV_RANK.get(incident.severity, 0)
    if crit == "critical":
        rank = min(rank + 2, _SEV_RANK["critical"])
    elif crit == "high":
        rank = min(rank + 1, _SEV_RANK["critical"])
    incident.severity = _RANK_SEV[rank]


def compute_priority(
    incident: LiveIncidentModel,
    *,
    now: Optional[datetime] = None,
) -> float:
    """Deterministic priority score (0–100) with time-based decay.

    Base:
      low=20, medium=40, high=70, critical=90

    Boosts:
      +10 if critical asset involved
      +5 per repetition (capped at +25 for 5 repetitions)
      +5 if behavior is scanning or lateral_movement

    Decay (based on time since last_activity_at):
      < 10 min → 0
      10–30 min → -10
      30–60 min → -20
      > 60 min → -40
    """
    now = now or datetime.utcnow()

    _BASE = {"low": 20, "medium": 40, "high": 70, "critical": 90}
    score = _BASE.get(incident.severity, 20)

    # Asset boost
    if incident.highest_target_criticality == "critical":
        score += 10
    elif incident.highest_target_criticality == "high":
        score += 5

    # Repetition boost (capped at +25)
    reps = min(incident.event_count or 1, 5)
    score += (reps - 1) * 5

    # Behavior boost
    if incident.behavior_type in ("scanning", "lateral_movement"):
        score += 5

    # Decay
    ref = incident.last_activity_at or incident.last_seen or incident.created_at
    if ref:
        age_min = (now - ref).total_seconds() / 60
        if age_min > 60:
            decay = 40
        elif age_min > 30:
            decay = 20
        elif age_min > 10:
            decay = 10
        else:
            decay = 0
    else:
        decay = 0

    score = max(score - decay, 0)
    return round(min(score, 100), 1)


def update_priority(
    incident: LiveIncidentModel,
    *,
    now: Optional[datetime] = None,
) -> None:
    """Recompute and persist priority_score + decay_factor."""
    now = now or datetime.utcnow()
    ref = incident.last_activity_at or incident.last_seen or now
    age_min = (now - ref).total_seconds() / 60

    if age_min > 60:
        decay = 40.0
    elif age_min > 30:
        decay = 20.0
    elif age_min > 10:
        decay = 10.0
    else:
        decay = 0.0

    incident.priority_score = compute_priority(incident, now=now)
    incident.decay_factor = decay


def _notify_new(db: Session, incident: LiveIncidentModel) -> bool:
    msg = (
        f"[INCIDENT] New {incident.severity.upper()} incident: "
        f"{incident.behavior_type} from {incident.source_ip}"
    )
    return _emit_once(db, msg)


def _notify_escalation(
    db: Session, incident: LiveIncidentModel,
    old_sev: str, new_sev: str,
) -> bool:
    msg = (
        f"[INCIDENT] Severity escalated {old_sev}→{new_sev}: "
        f"{incident.behavior_type} from {incident.source_ip} "
        f"(detection #{incident.event_count})"
    )
    return _emit_once(db, msg)


def _emit_once(db: Session, message: str) -> bool:
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
