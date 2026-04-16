"""
User-defined correlation rule evaluation engine.

Periodically evaluates ``CorrelationRuleModel`` rules against recent
``LiveFlowModel`` data and creates/updates ``LiveIncidentModel`` records
when thresholds are exceeded.

The engine is additive — it does NOT replace the existing bridge /
intelligence / flow-correlation incident pipeline.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from database import CorrelationRuleModel, LiveFlowModel, LiveIncidentModel

logger = logging.getLogger("rule_engine")

# ── Valid field / operator sets ───────────────────────────────────────────────

VALID_CONDITION_FIELDS = {
    "source_ip", "destination_ip", "destination_port",
    "protocol", "application", "flow_type", "behavior_type",
    "action", "deny_ratio", "reset_ratio", "deviation_score",
}

VALID_CONDITION_OPERATORS = {
    "eq", "neq", "gt", "lt", "gte", "lte", "in", "contains",
}

VALID_AGGREGATION_TYPES = {
    "count", "distinct_count", "sum", "avg", "any",
}


def evaluate_rules(db: Session, *, now: Optional[datetime] = None) -> int:
    """Evaluate all enabled correlation rules.

    Returns the count of incidents created or updated.
    """
    now = now or datetime.utcnow()

    rules = (
        db.query(CorrelationRuleModel)
        .filter(CorrelationRuleModel.enabled.is_(True))
        .all()
    )
    if not rules:
        return 0

    total = 0
    for rule in rules:
        try:
            total += _evaluate_single_rule(db, rule, now)
        except Exception:
            logger.exception("Rule %d (%s) evaluation failed", rule.id, rule.name)

    if total:
        db.commit()

    return total


def _evaluate_single_rule(
    db: Session,
    rule: CorrelationRuleModel,
    now: datetime,
) -> int:
    """Evaluate a single rule against recent flows. Returns incident count."""
    cutoff = now - timedelta(minutes=rule.time_window_minutes)

    # 1. Query recent flows within the time window
    base_q = db.query(LiveFlowModel).filter(
        LiveFlowModel.last_seen >= cutoff,
        LiveFlowModel.suppressed.isnot(True),
    )

    # 2. Determine grouping column(s) based on target_entity
    if rule.target_entity == "source_ip":
        group_col = LiveFlowModel.source_ip
    elif rule.target_entity == "destination_ip":
        group_col = LiveFlowModel.destination_ip
    elif rule.target_entity == "src_dst_pair":
        # For src_dst_pair, we group by both — handled specially below
        group_col = None
    else:
        logger.warning("Rule %d: unknown target_entity %s", rule.id, rule.target_entity)
        return 0

    # 3. Get all flows in window
    flows = base_q.all()
    if not flows:
        return 0

    # 4. Group flows by target entity
    groups: Dict[str, List[LiveFlowModel]] = {}
    for f in flows:
        if rule.target_entity == "source_ip":
            key = f.source_ip
        elif rule.target_entity == "destination_ip":
            key = f.destination_ip
        else:  # src_dst_pair
            key = f"{f.source_ip}|{f.destination_ip}"
        groups.setdefault(key, []).append(f)

    # 5. Evaluate each group
    incidents_created = 0
    for entity_key, entity_flows in groups.items():
        # a. Apply condition filter
        matching = _apply_condition(entity_flows, rule)
        if not matching:
            continue

        # b. Compute aggregation
        agg_result = _compute_aggregation(matching, rule)

        # c. Check threshold
        if agg_result is None or agg_result < rule.threshold:
            continue

        # d. Check cooldown
        source_ip = entity_key.split("|")[0] if "|" in entity_key else entity_key
        if _in_cooldown(db, source_ip, rule, now):
            continue

        # e. Create/update incident
        _create_rule_incident(db, rule, entity_key, source_ip, agg_result, now)
        incidents_created += 1

    return incidents_created


def _apply_condition(
    flows: List[LiveFlowModel],
    rule: CorrelationRuleModel,
) -> List[LiveFlowModel]:
    """Filter flows matching the rule's condition."""
    field = rule.condition_field
    op = rule.condition_operator
    raw_value = rule.condition_value

    # Parse condition value
    if op == "in":
        try:
            cond_values = json.loads(raw_value)
            if not isinstance(cond_values, list):
                cond_values = [raw_value]
        except (json.JSONDecodeError, TypeError):
            cond_values = [raw_value]
    else:
        cond_value = raw_value

    result = []
    for f in flows:
        flow_val = _get_flow_field(f, field)
        if flow_val is None:
            continue

        if op == "eq":
            match = str(flow_val) == str(cond_value)
        elif op == "neq":
            match = str(flow_val) != str(cond_value)
        elif op == "gt":
            match = _to_float(flow_val) > _to_float(cond_value)
        elif op == "lt":
            match = _to_float(flow_val) < _to_float(cond_value)
        elif op == "gte":
            match = _to_float(flow_val) >= _to_float(cond_value)
        elif op == "lte":
            match = _to_float(flow_val) <= _to_float(cond_value)
        elif op == "in":
            match = str(flow_val) in [str(v) for v in cond_values]
        elif op == "contains":
            match = str(cond_value) in str(flow_val)
        else:
            match = False

        if match:
            result.append(f)

    return result


def _get_flow_field(flow: LiveFlowModel, field: str) -> Any:
    """Extract a field value from a flow."""
    # Direct model attributes
    direct_fields = {
        "source_ip": flow.source_ip,
        "destination_ip": flow.destination_ip,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol,
        "application": flow.application,
        "flow_type": flow.flow_type,
        "deny_ratio": flow.deny_ratio,
        "reset_ratio": flow.reset_ratio,
    }
    if field in direct_fields:
        return direct_fields[field]

    # Derive "action" from action counters
    if field == "action":
        if flow.deny_count and flow.deny_count > 0 and (flow.allow_count or 0) == 0:
            return "deny"
        if flow.drop_count and flow.drop_count > 0 and (flow.allow_count or 0) == 0:
            return "drop"
        if flow.allow_count and flow.allow_count > 0:
            return "allow"
        return None

    return None


def _to_float(val: Any) -> float:
    """Safe float conversion."""
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0.0


def _compute_aggregation(
    flows: List[LiveFlowModel],
    rule: CorrelationRuleModel,
) -> Optional[float]:
    """Compute the aggregation result over matching flows."""
    agg_type = rule.aggregation_type
    agg_field = rule.aggregation_field

    if agg_type == "count":
        return float(len(flows))

    if agg_type == "any":
        return 1.0 if flows else 0.0

    if agg_type == "distinct_count":
        if not agg_field:
            return float(len(flows))
        values = set()
        for f in flows:
            v = _get_flow_field(f, agg_field)
            if v is not None:
                values.add(v)
        return float(len(values))

    if agg_type in ("sum", "avg"):
        if not agg_field:
            return None
        vals = []
        for f in flows:
            v = _get_flow_field(f, agg_field)
            if v is not None:
                vals.append(_to_float(v))
        if not vals:
            return None
        if agg_type == "sum":
            return sum(vals)
        return sum(vals) / len(vals)

    return None


def _in_cooldown(
    db: Session,
    source_ip: str,
    rule: CorrelationRuleModel,
    now: datetime,
) -> bool:
    """Check if a recent incident exists for this source_ip + rule within cooldown."""
    cooldown_cutoff = now - timedelta(minutes=rule.cooldown_minutes)
    existing = (
        db.query(LiveIncidentModel)
        .filter(
            LiveIncidentModel.source_ip == source_ip,
            LiveIncidentModel.behavior_type == rule.incident_behavior_type,
            LiveIncidentModel.status.in_(("open", "investigating")),
            LiveIncidentModel.last_seen >= cooldown_cutoff,
        )
        .first()
    )
    return existing is not None


def _create_rule_incident(
    db: Session,
    rule: CorrelationRuleModel,
    entity_key: str,
    source_ip: str,
    agg_result: float,
    now: datetime,
) -> LiveIncidentModel:
    """Create an incident from a triggered rule."""
    summary = (
        f"Rule \"{rule.name}\": {rule.condition_field} "
        f"{rule.condition_operator} {rule.condition_value} "
        f"({rule.aggregation_type}={agg_result:.0f}, "
        f"threshold={rule.threshold:.0f}) for {entity_key}"
    )

    incident = LiveIncidentModel(
        source_ip=source_ip,
        behavior_type=rule.incident_behavior_type,
        severity=rule.severity,
        status="open",
        first_seen=now,
        last_seen=now,
        event_count=1,
        linked_flow_count=int(agg_result),
        latest_confidence=None,
        summary=summary,
        last_activity_at=now,
        priority_score=_base_priority(rule.severity),
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()
    logger.info(
        "Rule %d (%s) triggered for %s: %s=%s (threshold %s)",
        rule.id, rule.name, entity_key,
        rule.aggregation_type, agg_result, rule.threshold,
    )
    return incident


def _base_priority(severity: str) -> float:
    """Base priority score for a severity level."""
    return {"low": 20, "medium": 40, "high": 70, "critical": 90}.get(severity, 20)


# ── Default rules seed ──────────────────────────────────────────────────────

DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "name": "Repeated denied connections",
        "description": "Fires when a source IP has 10+ denied flows in 10 minutes",
        "condition_field": "action",
        "condition_operator": "eq",
        "condition_value": "deny",
        "aggregation_type": "count",
        "aggregation_field": None,
        "threshold": 10,
        "time_window_minutes": 10,
        "target_entity": "source_ip",
        "severity": "medium",
        "incident_behavior_type": "blocked",
        "cooldown_minutes": 30,
        "scope": "global",
    },
    {
        "name": "Port sweep detection",
        "description": "Fires when a source IP contacts 15+ distinct ports via scanning/blocked flows",
        "condition_field": "flow_type",
        "condition_operator": "in",
        "condition_value": json.dumps(["scanning", "blocked"]),
        "aggregation_type": "distinct_count",
        "aggregation_field": "destination_port",
        "threshold": 15,
        "time_window_minutes": 10,
        "target_entity": "source_ip",
        "severity": "high",
        "incident_behavior_type": "scanning",
        "cooldown_minutes": 30,
        "scope": "global",
    },
    {
        "name": "Service instability",
        "description": "Fires when a src-dst pair has 3+ unstable flows in 10 minutes",
        "condition_field": "flow_type",
        "condition_operator": "eq",
        "condition_value": "unstable",
        "aggregation_type": "count",
        "aggregation_field": None,
        "threshold": 3,
        "time_window_minutes": 10,
        "target_entity": "src_dst_pair",
        "severity": "medium",
        "incident_behavior_type": "unstable",
        "cooldown_minutes": 30,
        "scope": "global",
    },
    {
        "name": "Lateral movement",
        "description": "Fires when a source IP contacts 8+ distinct destination IPs with allowed flows",
        "condition_field": "action",
        "condition_operator": "eq",
        "condition_value": "allow",
        "aggregation_type": "distinct_count",
        "aggregation_field": "destination_ip",
        "threshold": 8,
        "time_window_minutes": 10,
        "target_entity": "source_ip",
        "severity": "high",
        "incident_behavior_type": "lateral_movement",
        "cooldown_minutes": 30,
        "scope": "global",
    },
]


def seed_default_rules(db: Session) -> int:
    """Seed built-in rules if the table is empty. Returns count of rules created."""
    count = db.query(CorrelationRuleModel).count()
    if count > 0:
        return 0

    created = 0
    for rule_def in DEFAULT_RULES:
        rule = CorrelationRuleModel(
            name=rule_def["name"],
            description=rule_def["description"],
            enabled=True,
            created_by=None,
            scope=rule_def["scope"],
            condition_field=rule_def["condition_field"],
            condition_operator=rule_def["condition_operator"],
            condition_value=rule_def["condition_value"],
            aggregation_type=rule_def["aggregation_type"],
            aggregation_field=rule_def.get("aggregation_field"),
            threshold=rule_def["threshold"],
            time_window_minutes=rule_def["time_window_minutes"],
            target_entity=rule_def["target_entity"],
            severity=rule_def["severity"],
            incident_behavior_type=rule_def["incident_behavior_type"],
            cooldown_minutes=rule_def["cooldown_minutes"],
        )
        db.add(rule)
        created += 1

    db.commit()
    logger.info("Seeded %d default correlation rules", created)
    return created
