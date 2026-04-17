"""
Attack session correlation layer.

Groups related incidents from the same source IP into attack sessions
based on temporal proximity and behavior diversity.  A session absorbs
incidents whose ``last_seen`` falls within a rolling window of the
session's ``last_activity``.

Priority is derived from the highest-severity incident, with bonuses
for behavioral diversity, incident count, and critical-asset involvement.

Status transitions:  active → idle (30 min) → closed (60 min).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from collections import Counter

from database import AssetModel, AttackSessionModel, LiveIncidentModel

# ── Tunables ──────────────────────────────────────────────────────────────────
SESSION_MERGE_MINUTES = 60       # incidents within this window join same session
IDLE_AFTER_MINUTES = 30          # no activity → idle
CLOSE_AFTER_MINUTES = 60         # no activity → closed

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_RANK_SEV = ["low", "medium", "high", "critical"]


# ── Public API ────────────────────────────────────────────────────────────────

def correlate_sessions(
    db: Session,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, int]:
    """Scan open/investigating incidents and group them into attack sessions.

    Returns ``{"created": N, "updated": N, "idled": N, "closed": N}``.
    """
    now = now or datetime.utcnow()
    merge_cutoff = now - timedelta(minutes=SESSION_MERGE_MINUTES)

    # Fetch all non-resolved/dismissed incidents in the merge window
    incidents = (
        db.query(LiveIncidentModel)
        .filter(
            LiveIncidentModel.status.in_(("open", "investigating")),
            LiveIncidentModel.last_seen >= merge_cutoff,
        )
        .all()
    )

    # Group by source_ip
    by_ip: Dict[str, List[LiveIncidentModel]] = {}
    for inc in incidents:
        by_ip.setdefault(inc.source_ip, []).append(inc)

    created = 0
    updated = 0

    for src_ip, ip_incidents in by_ip.items():
        # Find active/idle session for this IP
        session = (
            db.query(AttackSessionModel)
            .filter(
                AttackSessionModel.source_ip == src_ip,
                AttackSessionModel.status.in_(("active", "idle")),
                AttackSessionModel.last_activity >= merge_cutoff,
            )
            .first()
        )

        if session:
            _update_session(session, ip_incidents, now)
            _enrich_session(db, session, ip_incidents)
            updated += 1
        else:
            session = _create_session(src_ip, ip_incidents, now)
            db.add(session)
            db.flush()
            _enrich_session(db, session, ip_incidents)
            created += 1

    # Age existing sessions
    idled, closed = _age_sessions(db, now)

    if created or updated:
        db.commit()

    return {"created": created, "updated": updated, "idled": idled, "closed": closed}


# ── Session construction / update ─────────────────────────────────────────────

def _create_session(
    source_ip: str,
    incidents: List[LiveIncidentModel],
    now: datetime,
) -> AttackSessionModel:
    inc_ids = [i.id for i in incidents]
    behaviors = list({i.behavior_type for i in incidents})
    severity = _max_severity(incidents)
    priority = _compute_session_priority(incidents, behaviors)

    total_dests = sum(i.total_distinct_destinations or 0 for i in incidents)
    total_ports = sum(i.total_distinct_ports or 0 for i in incidents)

    earliest = min(i.first_seen for i in incidents)

    return AttackSessionModel(
        source_ip=source_ip,
        start_time=earliest,
        last_activity=now,
        incident_ids=json.dumps(inc_ids),
        behaviors=json.dumps(sorted(behaviors)),
        severity=severity,
        priority_score=priority,
        status="active",
        total_incidents=len(inc_ids),
        total_destinations=total_dests,
        total_ports=total_ports,
        created_at=now,
        updated_at=now,
    )


def _update_session(
    session: AttackSessionModel,
    incidents: List[LiveIncidentModel],
    now: datetime,
) -> None:
    existing_ids = set(json.loads(session.incident_ids or "[]"))
    new_ids = {i.id for i in incidents}
    merged_ids = sorted(existing_ids | new_ids)

    existing_behaviors = set(json.loads(session.behaviors or "[]"))
    new_behaviors = {i.behavior_type for i in incidents}
    merged_behaviors = sorted(existing_behaviors | new_behaviors)

    session.incident_ids = json.dumps(merged_ids)
    session.behaviors = json.dumps(merged_behaviors)
    session.total_incidents = len(merged_ids)
    session.severity = _max_severity(incidents, current=session.severity)
    session.priority_score = _compute_session_priority(
        incidents, merged_behaviors, current_ids=merged_ids,
    )
    # Only bump last_activity to the most recent incident activity,
    # not to 'now', so aging still works when no new incidents arrive.
    latest_incident_time = max(i.last_seen for i in incidents)
    if latest_incident_time > session.last_activity:
        session.last_activity = latest_incident_time
        session.status = "active"
    session.updated_at = now

    session.total_destinations = sum(
        i.total_distinct_destinations or 0 for i in incidents
    )
    session.total_ports = sum(i.total_distinct_ports or 0 for i in incidents)


# ── Enrichment ────────────────────────────────────────────────────────────────

_CRIT_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_RANK_CRIT = ["low", "medium", "high", "critical"]

_NEXT_STEP_GENERIC = {
    "scanning": "Review top ports and target spread",
    "unstable": "Inspect reset-heavy flows",
    "suspicious": "Inspect denied and reset patterns",
    "lateral_movement": "Inspect internal target set",
}

_INTENT_NEXT_STEP = {
    "possible exploitation attempt":
        "Inspect affected services and logs for compromise indicators",
    "lateral movement preparation":
        "Check authentication logs and east-west traffic",
    "probing / policy violation":
        "Review denied traffic patterns and validate source authorization",
    "service instability / potential DoS":
        "Inspect reset-heavy flows and check service health metrics",
}

# Intent classification rules: (sequence_tuple, intent_string)
# Checked in order; first match wins.
_INTENT_RULES: List[tuple] = [
    # scanning → unstable → suspicious  (or superset)
    (("scanning", "unstable", "suspicious"), "possible exploitation attempt"),
    (("scanning", "unstable"),               "possible exploitation attempt"),
    # scanning → lateral_movement
    (("scanning", "lateral_movement"),       "lateral movement preparation"),
]


def _enrich_session(
    db: Session,
    session: AttackSessionModel,
    incidents: List[LiveIncidentModel],
) -> None:
    """Populate enrichment fields from linked incidents and assets."""
    # ── Top destination IPs ───────────────────────────────────────────────
    dest_counter: Counter = Counter()
    for inc in incidents:
        if inc.top_destination_ips:
            for ip in json.loads(inc.top_destination_ips):
                dest_counter[ip] += 1
    session.top_destination_ips = json.dumps(
        [ip for ip, _ in dest_counter.most_common(5)]
    )

    # ── Top ports ─────────────────────────────────────────────────────────
    port_counter: Counter = Counter()
    for inc in incidents:
        if inc.top_ports:
            for port in json.loads(inc.top_ports):
                port_counter[port] += 1
    session.top_ports = json.dumps(
        [port for port, _ in port_counter.most_common(5)]
    )

    # ── Highest target criticality ────────────────────────────────────────
    max_crit_rank = _CRIT_RANK.get(session.highest_target_criticality, -1)
    for inc in incidents:
        r = _CRIT_RANK.get(inc.highest_target_criticality, -1)
        if r > max_crit_rank:
            max_crit_rank = r
    if max_crit_rank >= 0:
        session.highest_target_criticality = _RANK_CRIT[max_crit_rank]

    # ── Target summary ────────────────────────────────────────────────────
    all_dest_ips = list(dest_counter.keys())
    session.target_summary = _build_target_summary(db, all_dest_ips)

    # ── Timeline & intent ────────────────────────────────────────────────
    timeline = _extract_timeline(incidents)
    session.behavior_timeline = json.dumps(timeline)
    sequence = _compress_sequence(timeline)
    session.behavior_sequence = " → ".join(sequence) if sequence else None

    # ── Multi-intent with confidence ──────────────────────────────────────
    intents = _classify_intents(sequence, incidents, session)
    session.attack_intents = json.dumps(intents)
    if intents:
        primary = intents[0]
        session.attack_intent = primary["intent"]
        session.intent_confidence = primary["confidence"]
    else:
        session.attack_intent = None
        session.intent_confidence = None

    # ── Tempo analysis ────────────────────────────────────────────────────
    _compute_tempo(session, incidents)

    # Burst boosts confidence
    if session.burst_flag and session.intent_confidence is not None:
        session.intent_confidence = round(
            min(session.intent_confidence + 0.1, 0.95), 2,
        )
        # Update intents list too
        if intents:
            intents[0]["confidence"] = session.intent_confidence
            session.attack_intents = json.dumps(intents)

    intent = session.attack_intent

    # ── Decision engine ───────────────────────────────────────────────────
    session.recommended_action = _decide_action(
        session.severity, session.intent_confidence,
    )

    # ── Session summary (intent-aware) ────────────────────────────────────
    behaviors = json.loads(session.behaviors or "[]")
    session.session_summary = _build_session_summary(
        session.source_ip,
        session.total_destinations,
        session.total_ports,
        behaviors,
        intent=intent,
        highest_criticality=session.highest_target_criticality,
    )

    # ── Recommended next step (intent-aware) ──────────────────────────────
    session.recommended_next_step = _derive_next_step(behaviors, intent=intent)


def _build_target_summary(db: Session, dest_ips: List[str]) -> str:
    """Summarise target composition, e.g. '2 critical servers, 4 workstations'."""
    if not dest_ips:
        return "No targets identified"

    assets = (
        db.query(AssetModel)
        .filter(AssetModel.ip_address.in_(dest_ips))
        .all()
    )

    if not assets:
        return f"{len(dest_ips)} unknown host(s)"

    # Group by (criticality, asset_type)
    buckets: Counter = Counter()
    for a in assets:
        label = f"{a.criticality} {a.asset_type}{'s' if a.asset_type[-1] != 's' else ''}"
        buckets[label] += 1

    unknown = len(dest_ips) - len(assets)
    parts = [f"{count} {label}" for label, count in buckets.most_common()]
    if unknown > 0:
        parts.append(f"{unknown} unknown host(s)")
    return ", ".join(parts)


def _extract_timeline(incidents: List[LiveIncidentModel]) -> List[Dict[str, str]]:
    """Order incidents by time and return [{time, behavior}, ...]."""
    sorted_incs = sorted(incidents, key=lambda i: i.first_seen)
    return [
        {"time": i.first_seen.isoformat(), "behavior": i.behavior_type}
        for i in sorted_incs
    ]


def _compress_sequence(timeline: List[Dict[str, str]]) -> List[str]:
    """Deduplicate consecutive identical behaviors.

    ["scanning", "scanning", "unstable", "suspicious"]
    → ["scanning", "unstable", "suspicious"]
    """
    if not timeline:
        return []
    result: List[str] = []
    for entry in timeline:
        b = entry["behavior"]
        if not result or result[-1] != b:
            result.append(b)
    return result


def _classify_intent(sequence: List[str]) -> Optional[str]:
    """Match the compressed behavior sequence against known intent patterns."""
    if not sequence:
        return None

    seq_set = set(sequence)

    # Rule-based matching: check if sequence contains the rule's
    # behaviors in order (subsequence match).
    for pattern, intent in _INTENT_RULES:
        if _is_subsequence(pattern, sequence):
            return intent

    # Fallback heuristics
    if seq_set == {"suspicious"} or (len(sequence) > 1 and all(b == "suspicious" for b in sequence)):
        return "probing / policy violation"
    if "unstable" in seq_set and len(seq_set) == 1:
        return "service instability / potential DoS"
    # Single unstable dominant
    if sequence.count("unstable") > len(sequence) // 2:
        return "service instability / potential DoS"

    return None


def _is_subsequence(pattern: tuple, sequence: List[str]) -> bool:
    """Check if pattern appears as a subsequence of sequence."""
    it = iter(sequence)
    return all(p in it for p in pattern)


# ── Multi-intent & confidence ─────────────────────────────────────────────────

# All known intent patterns with their sequence tuples for scoring.
_ALL_INTENT_PATTERNS: List[tuple] = [
    (("scanning", "unstable", "suspicious"), "possible exploitation attempt"),
    (("scanning", "unstable"),               "possible exploitation attempt"),
    (("scanning", "lateral_movement"),       "lateral movement preparation"),
]

# Fallback intents (no pattern tuple — matched by heuristic).
_FALLBACK_INTENTS = [
    "probing / policy violation",
    "service instability / potential DoS",
]

BURST_THRESHOLD = 5.0  # flows/min to flag as burst


def _classify_intents(
    sequence: List[str],
    incidents: List[LiveIncidentModel],
    session: AttackSessionModel,
) -> List[Dict[str, Any]]:
    """Return all matching intents with confidence, sorted descending."""
    if not sequence:
        return []

    results: List[Dict[str, Any]] = []
    seen_intents: set = set()
    seq_set = set(sequence)

    # Rule-based patterns
    for pattern, intent in _ALL_INTENT_PATTERNS:
        if intent in seen_intents:
            continue
        if _is_subsequence(pattern, sequence):
            conf = _compute_intent_confidence(
                pattern, sequence, incidents, session,
            )
            results.append({"intent": intent, "confidence": conf})
            seen_intents.add(intent)

    # Fallback heuristics
    if "probing / policy violation" not in seen_intents:
        if seq_set == {"suspicious"} or (
            len(sequence) > 1 and all(b == "suspicious" for b in sequence)
        ):
            conf = _compute_intent_confidence(
                ("suspicious",), sequence, incidents, session,
            )
            results.append({"intent": "probing / policy violation", "confidence": conf})
            seen_intents.add("probing / policy violation")

    if "service instability / potential DoS" not in seen_intents:
        if (
            "unstable" in seq_set and len(seq_set) == 1
        ) or sequence.count("unstable") > len(sequence) // 2:
            conf = _compute_intent_confidence(
                ("unstable",), sequence, incidents, session,
            )
            results.append({
                "intent": "service instability / potential DoS",
                "confidence": conf,
            })

    # Sort by confidence descending
    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


def _compute_intent_confidence(
    pattern: tuple,
    sequence: List[str],
    incidents: List[LiveIncidentModel],
    session: AttackSessionModel,
) -> float:
    """Compute confidence for a specific intent pattern.

    - base 0.5
    - +0.1 per matching behavior in sequence
    - +0.1 if critical assets involved
    - +0.1 if high repetition (>= 3 incidents)
    - -0.1 if gaps in sequence (non-pattern behaviors between pattern steps)
    - cap at 0.95
    """
    conf = 0.5

    # +0.1 per matching behavior in sequence
    for step in pattern:
        if step in sequence:
            conf += 0.1

    # +0.1 if critical assets involved
    if session.highest_target_criticality == "critical":
        conf += 0.1

    # +0.1 if high repetition
    if len(incidents) >= 3:
        conf += 0.1

    # -0.1 if gaps in sequence
    if len(pattern) > 1 and _has_gaps(pattern, sequence):
        conf -= 0.1

    return round(min(max(conf, 0.0), 0.95), 2)


def _has_gaps(pattern: tuple, sequence: List[str]) -> bool:
    """Check if there are non-pattern behaviors between pattern steps."""
    pat_idx = 0
    in_pattern = False
    for b in sequence:
        if pat_idx < len(pattern) and b == pattern[pat_idx]:
            in_pattern = True
            pat_idx += 1
        elif in_pattern and pat_idx < len(pattern):
            return True  # found a gap
    return False


# ── Tempo analysis ────────────────────────────────────────────────────────────

def _compute_tempo(
    session: AttackSessionModel,
    incidents: List[LiveIncidentModel],
) -> None:
    """Compute activity_rate (flows/min) and burst_flag."""
    total_flows = sum(i.linked_flow_count or 0 for i in incidents)

    if session.start_time and session.last_activity:
        duration_min = max(
            (session.last_activity - session.start_time).total_seconds() / 60,
            1.0,  # avoid division by zero; minimum 1 minute
        )
    else:
        duration_min = 1.0

    rate = round(total_flows / duration_min, 2)
    session.activity_rate = rate
    session.burst_flag = rate >= BURST_THRESHOLD


# ── Decision engine ───────────────────────────────────────────────────────────

def _decide_action(
    severity: Optional[str],
    confidence: Optional[float],
) -> str:
    """Determine recommended action from severity and intent confidence.

    Rules:
      critical + high confidence (>= 0.7) → block
      high + medium confidence (>= 0.5)   → contain
      medium severity                      → investigate
      low / fallback                       → monitor
    """
    sev_rank = _SEV_RANK.get(severity, 0)
    conf = confidence or 0.0

    if sev_rank >= 3 and conf >= 0.7:
        return "block"
    if sev_rank >= 2 and conf >= 0.5:
        return "contain"
    if sev_rank >= 1:
        return "investigate"
    return "monitor"


def _build_session_summary(
    source_ip: str,
    total_dests: int,
    total_ports: int,
    behaviors: List[str],
    *,
    intent: Optional[str] = None,
    highest_criticality: Optional[str] = None,
) -> str:
    """Human-readable one-liner for the session, including intent."""
    parts = []
    if total_dests:
        parts.append(f"{total_dests} host(s)")
    if total_ports:
        parts.append(f"{total_ports} port(s)")
    spread = " across ".join(parts) if parts else "multiple targets"

    # Build behavior narrative
    if len(behaviors) > 1:
        blist = ", then ".join(behaviors)
    else:
        blist = behaviors[0] if behaviors else "unknown"

    summary = f"{source_ip} targeted {spread} with {blist} behavior"

    if intent:
        summary += f" — {intent}"
    if highest_criticality and highest_criticality in ("high", "critical"):
        summary += f" targeting {highest_criticality} assets"

    return summary


def _derive_next_step(behaviors: List[str], *, intent: Optional[str] = None) -> str:
    """Pick the recommended action — intent-aware when available."""
    if intent and intent in _INTENT_NEXT_STEP:
        return _INTENT_NEXT_STEP[intent]

    # Fall back to behavior-based recommendation
    for dominant in ("lateral_movement", "scanning", "suspicious", "unstable"):
        if dominant in behaviors:
            return _NEXT_STEP_GENERIC[dominant]
    return "Review session details"


# ── Session aging ─────────────────────────────────────────────────────────────

def _age_sessions(db: Session, now: datetime) -> tuple[int, int]:
    """Transition sessions: active → idle (30 min), idle/active → closed (60 min)."""
    idle_cutoff = now - timedelta(minutes=IDLE_AFTER_MINUTES)
    close_cutoff = now - timedelta(minutes=CLOSE_AFTER_MINUTES)

    # Close first (superset of idle window)
    closed = (
        db.query(AttackSessionModel)
        .filter(
            AttackSessionModel.status.in_(("active", "idle")),
            AttackSessionModel.last_activity < close_cutoff,
        )
        .update({"status": "closed", "updated_at": now}, synchronize_session="fetch")
    )

    # Idle (only those still active, within 30-60 min)
    idled = (
        db.query(AttackSessionModel)
        .filter(
            AttackSessionModel.status == "active",
            AttackSessionModel.last_activity < idle_cutoff,
            AttackSessionModel.last_activity >= close_cutoff,
        )
        .update({"status": "idle", "updated_at": now}, synchronize_session="fetch")
    )

    if idled or closed:
        db.commit()

    return idled, closed


# ── Helpers ───────────────────────────────────────────────────────────────────

def _max_severity(
    incidents: List[LiveIncidentModel],
    *,
    current: Optional[str] = None,
) -> str:
    rank = _SEV_RANK.get(current, 0) if current else 0
    for i in incidents:
        rank = max(rank, _SEV_RANK.get(i.severity, 0))
    return _RANK_SEV[min(rank, len(_RANK_SEV) - 1)]


def _compute_session_priority(
    incidents: List[LiveIncidentModel],
    behaviors: list,
    *,
    current_ids: Optional[list] = None,
) -> float:
    """Aggregate priority: max incident priority + bonuses.

    Bonuses:
      +10 if multiple behavior_types
      +10 if more than 2 incidents
      +10 if critical assets involved
    """
    base = max((i.priority_score or 0) for i in incidents)

    bonus = 0
    if len(behaviors) > 1:
        bonus += 10
    total = len(current_ids) if current_ids else len(incidents)
    if total > 2:
        bonus += 10
    if any(i.highest_target_criticality == "critical" for i in incidents):
        bonus += 10

    return round(min(base + bonus, 100), 1)


def session_dict(s: AttackSessionModel) -> dict:
    """Serialize an AttackSessionModel for API responses."""
    return {
        "id": s.id,
        "source_ip": s.source_ip,
        "start_time": s.start_time.isoformat() if s.start_time else None,
        "last_activity": s.last_activity.isoformat() if s.last_activity else None,
        "incident_ids": json.loads(s.incident_ids) if s.incident_ids else [],
        "behaviors": json.loads(s.behaviors) if s.behaviors else [],
        "severity": s.severity,
        "priority_score": s.priority_score,
        "status": s.status,
        "total_incidents": s.total_incidents,
        "total_destinations": s.total_destinations,
        "total_ports": s.total_ports,
        "top_destination_ips": json.loads(s.top_destination_ips) if s.top_destination_ips else [],
        "top_ports": json.loads(s.top_ports) if s.top_ports else [],
        "target_summary": s.target_summary,
        "highest_target_criticality": s.highest_target_criticality,
        "session_summary": s.session_summary,
        "recommended_next_step": s.recommended_next_step,
        "behavior_timeline": json.loads(s.behavior_timeline) if s.behavior_timeline else [],
        "behavior_sequence": s.behavior_sequence,
        "attack_intent": s.attack_intent,
        "attack_intents": json.loads(s.attack_intents) if s.attack_intents else [],
        "intent_confidence": s.intent_confidence,
        "activity_rate": s.activity_rate,
        "burst_flag": s.burst_flag,
        "recommended_action": s.recommended_action,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
    }
