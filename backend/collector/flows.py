"""
Flow reconstruction engine for the live ingestion layer.

Maintains active flows in memory, updates them from incoming normalised
live events, and emits completed/expired flow summary dicts when a flow
reaches a terminal state or times out.

Flow key
--------
(source_ip, destination_ip, source_port, destination_port, protocol)

NAT fields, application, service, backend_ip etc. are stored as
attributes on the flow but do NOT participate in the key — the same
pre-NAT 5-tuple always maps to the same flow.

Flow lifecycle
--------------

  1. First event with a new 5-tuple → create ``_ActiveFlow``
  2. Subsequent matching events → update counters, last_seen, state
  3. Flush triggers:
     a. ``flush_expired(now)`` — called periodically; emits flows whose
        ``last_seen`` is older than ``timeout_seconds``
     b. Terminal action — a reset/deny/drop on a flow that previously
        had no allow events immediately marks it terminal; the flow
        remains in memory until the next flush (to accumulate further
        events from the same burst) but its state will not revert.

Thread safety: the engine is NOT thread-safe.  The caller (collector
service) must hold a lock around ``process_event`` and ``flush_expired``.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


def _flow_key(event: dict) -> Tuple:
    return (
        event.get("source_ip", ""),
        event.get("destination_ip", ""),
        event.get("source_port"),
        event.get("destination_port"),
        (event.get("protocol") or "").upper(),
    )


class _ActiveFlow:
    """In-memory representation of a flow being assembled."""

    __slots__ = (
        "key",
        "source_id", "device_type", "device_role", "parser_id",
        "source_ip", "destination_ip", "source_port", "destination_port",
        "protocol",
        "first_seen", "last_seen",
        "event_count",
        "total_bytes_in", "total_bytes_out",
        "total_packets_in", "total_packets_out",
        "allow_count", "deny_count", "drop_count", "reset_count", "alert_count",
        "reasons", "applications", "services",
        "nat_source_ip", "nat_destination_ip",
        "nat_source_port", "nat_destination_port",
        "backend_ip", "backend_port",
    )

    def __init__(self, key: Tuple, event: dict, now: datetime):
        self.key = key
        self.source_ip = key[0]
        self.destination_ip = key[1]
        self.source_port = key[2]
        self.destination_port = key[3]
        self.protocol = key[4] or None

        self.source_id = event.get("source_id", "")
        self.device_type = event.get("device_type", "")
        self.device_role = event.get("device_role")
        self.parser_id = event.get("parser_id", "")

        ts = event.get("event_time") or now
        self.first_seen = ts
        self.last_seen = ts

        self.event_count = 0
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        self.total_packets_in = 0
        self.total_packets_out = 0

        self.allow_count = 0
        self.deny_count = 0
        self.drop_count = 0
        self.reset_count = 0
        self.alert_count = 0

        self.reasons: Counter = Counter()
        self.applications: Counter = Counter()
        self.services: Counter = Counter()

        self.nat_source_ip = None
        self.nat_destination_ip = None
        self.nat_source_port = None
        self.nat_destination_port = None
        self.backend_ip = None
        self.backend_port = None

    def update(self, event: dict, now: datetime) -> None:
        ts = event.get("event_time") or now
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts

        self.event_count += 1
        self.total_bytes_in += int(event.get("bytes_in") or 0)
        self.total_bytes_out += int(event.get("bytes_out") or 0)
        self.total_packets_in += int(event.get("packets_in") or 0)
        self.total_packets_out += int(event.get("packets_out") or 0)

        action = (event.get("action") or "").lower()
        if action == "allow":
            self.allow_count += 1
        elif action == "deny":
            self.deny_count += 1
        elif action == "drop":
            self.drop_count += 1
        elif action == "reset":
            self.reset_count += 1
        elif action == "alert":
            self.alert_count += 1

        reason = event.get("reason")
        if reason:
            self.reasons[reason] += 1
        app = event.get("application")
        if app:
            self.applications[app] += 1
        svc = event.get("service")
        if svc:
            self.services[svc] += 1

        # Carry over NAT / backend info (last write wins)
        for attr in (
            "nat_source_ip", "nat_destination_ip",
            "nat_source_port", "nat_destination_port",
            "backend_ip", "backend_port",
        ):
            v = event.get(attr)
            if v is not None:
                setattr(self, attr, v)

    def to_dict(self) -> Dict[str, Any]:
        dur = None
        if self.first_seen and self.last_seen:
            delta = self.last_seen - self.first_seen
            dur = int(delta.total_seconds() * 1000)

        classification = classify_flow(self)

        return {
            "source_id":          self.source_id,
            "device_type":        self.device_type,
            "device_role":        self.device_role,
            "parser_id":          self.parser_id,
            "source_ip":          self.source_ip,
            "destination_ip":     self.destination_ip,
            "source_port":        self.source_port,
            "destination_port":   self.destination_port,
            "protocol":           self.protocol,
            "first_seen":         self.first_seen,
            "last_seen":          self.last_seen,
            "duration_ms":        dur,
            "event_count":        self.event_count,
            "total_bytes_in":     self.total_bytes_in,
            "total_bytes_out":    self.total_bytes_out,
            "total_packets_in":   self.total_packets_in,
            "total_packets_out":  self.total_packets_out,
            "allow_count":        self.allow_count,
            "deny_count":         self.deny_count,
            "drop_count":         self.drop_count,
            "reset_count":        self.reset_count,
            "alert_count":        self.alert_count,
            "action_summary":     _derive_action_summary(self),
            "reason_summary":     _derive_reason_summary(self),
            "nat_source_ip":      self.nat_source_ip,
            "nat_destination_ip": self.nat_destination_ip,
            "nat_source_port":    self.nat_source_port,
            "nat_destination_port": self.nat_destination_port,
            "application":        self.applications.most_common(1)[0][0] if self.applications else None,
            "service":            self.services.most_common(1)[0][0] if self.services else None,
            "backend_ip":         self.backend_ip,
            "backend_port":       self.backend_port,
            "state":              _derive_state(self),
            "raw_event_count":    self.event_count,
            # ── Behavioral classification ────────────────────────────────
            "flow_type":            classification["flow_type"],
            "reset_ratio":          classification["reset_ratio"],
            "deny_ratio":           classification["deny_ratio"],
            "burst_score":          classification["burst_score"],
            "asymmetric_behavior":  classification["asymmetric_behavior"],
            "suspicious_reasons":   json.dumps(classification["suspicious_reasons"]),
        }


# ── State / summary derivation ──────────────────────────────────────────────

def _derive_state(f: _ActiveFlow) -> str:
    if f.reset_count > 0:
        return "reset"
    if f.deny_count > 0 and f.allow_count == 0:
        return "denied"
    if f.drop_count > 0 and f.allow_count == 0:
        return "dropped"
    if f.allow_count > 0:
        return "completed"
    return "expired"


def _derive_action_summary(f: _ActiveFlow) -> str:
    if f.reset_count > 0:
        return "reset_seen"
    total = f.allow_count + f.deny_count + f.drop_count + f.alert_count
    if total == 0:
        return "unknown"
    if f.deny_count > 0 and f.allow_count > 0:
        return "mixed"
    if f.deny_count > total * 0.5:
        return "mostly_deny"
    if f.allow_count > total * 0.5:
        return "mostly_allow"
    return "mixed"


def _derive_reason_summary(f: _ActiveFlow) -> Optional[str]:
    if not f.reasons:
        return None
    top, count = f.reasons.most_common(1)[0]
    if len(f.reasons) == 1:
        return top
    return f"{top} (+{len(f.reasons) - 1} others)"


# ── Behavioral classification ────────────────────────────────────────────────
#
# Classifies a flow into one of:
#   normal     — healthy, mostly-allow traffic
#   unstable   — resets mixed with other actions
#   blocked    — deny-only or drop-only, no allow
#   suspicious — high reset ratio on completed flows, or alerts present
#   scanning   — short denied flow with low bytes (probe-like)
#
# Also computes:
#   reset_ratio  — reset_count / total_actions
#   deny_ratio   — (deny+drop) / total_actions
#   burst_score  — events per second of flow duration (0 if duration==0)
#   asymmetric_behavior — bytes_in much larger or much smaller than bytes_out
#   suspicious_reasons  — list of human-readable strings

def classify_flow(f: _ActiveFlow) -> Dict[str, Any]:
    """Return a classification dict for the given active flow."""
    total_actions = (
        f.allow_count + f.deny_count + f.drop_count
        + f.reset_count + f.alert_count
    )
    total_actions = max(total_actions, 1)  # avoid division by zero

    reset_ratio = round(f.reset_count / total_actions, 4)
    deny_ratio = round((f.deny_count + f.drop_count) / total_actions, 4)

    # Burst score: events per second of flow duration
    dur_secs = 0.0
    if f.first_seen and f.last_seen:
        dur_secs = max((f.last_seen - f.first_seen).total_seconds(), 0)
    burst_score = round(f.event_count / max(dur_secs, 0.001), 2)

    # Asymmetric behavior: one direction has 10× the bytes of the other
    asymmetric = False
    if f.total_bytes_in > 0 and f.total_bytes_out > 0:
        ratio = max(f.total_bytes_in, f.total_bytes_out) / min(f.total_bytes_in, f.total_bytes_out)
        asymmetric = ratio >= 10
    elif (f.total_bytes_in > 1000 and f.total_bytes_out == 0) or \
         (f.total_bytes_out > 1000 and f.total_bytes_in == 0):
        asymmetric = True

    # Classification + reasons
    flow_type = "normal"
    reasons: List[str] = []

    # scanning: short denied flows with very low bytes (probe behavior)
    # — checked before "blocked" because scanning is a specific sub-case
    if f.allow_count == 0 and f.deny_count > 0 and f.reset_count == 0 and \
       f.total_bytes_in + f.total_bytes_out < 500 and \
       dur_secs < 5:
        flow_type = "scanning"
        reasons.append("short denied flow with minimal bytes (probe-like)")

    # blocked: deny/drop only, no allow at all
    elif f.allow_count == 0 and (f.deny_count + f.drop_count) > 0 and f.reset_count == 0:
        flow_type = "blocked"
        reasons.append("deny/drop only, no successful connections")

    # unstable: resets mixed with other actions
    elif f.reset_count > 0 and (f.allow_count > 0 or f.deny_count > 0):
        flow_type = "unstable"
        reasons.append("resets mixed with other actions")
        if reset_ratio > 0.5:
            reasons.append(f"high reset ratio ({reset_ratio:.0%})")

    # suspicious: high reset ratio on completed flows, or alerts
    elif f.reset_count > 0 and f.allow_count == 0:
        flow_type = "suspicious"
        reasons.append("resets without successful connections")
    elif f.alert_count > 0:
        flow_type = "suspicious"
        reasons.append(f"{f.alert_count} alert(s) triggered")
    elif f.allow_count > 0 and reset_ratio > 0.3:
        flow_type = "suspicious"
        reasons.append(f"high reset ratio ({reset_ratio:.0%}) despite some allow")

    # asymmetric is an additional flag, not a flow_type override
    if asymmetric:
        reasons.append("highly asymmetric byte ratio")

    return {
        "flow_type":           flow_type,
        "reset_ratio":         reset_ratio,
        "deny_ratio":          deny_ratio,
        "burst_score":         burst_score,
        "asymmetric_behavior": asymmetric,
        "suspicious_reasons":  reasons,
    }


# ── Flow Engine ──────────────────────────────────────────────────────────────

class FlowEngine:
    """In-memory flow reconstruction engine.

    NOT thread-safe — the caller must synchronise access.
    """

    def __init__(self, timeout_seconds: int = 60):
        self.timeout_seconds = timeout_seconds
        self._flows: Dict[Tuple, _ActiveFlow] = {}
        self._total_created = 0
        self._total_flushed = 0

    def process_event(self, event: dict) -> Optional[Dict[str, Any]]:
        """Ingest one normalised live event into the flow table.

        Returns ``None`` in most cases.  If the event completes a flow
        that is already in a terminal state *and* the caller wants
        immediate emission, this could return the flow dict — but for
        the first version we always return None and rely on
        ``flush_expired`` for batch emission.
        """
        key = _flow_key(event)
        if not key[0] or not key[1]:
            return None

        now = datetime.utcnow()
        flow = self._flows.get(key)
        if flow is None:
            flow = _ActiveFlow(key, event, now)
            self._flows[key] = flow
            self._total_created += 1

        flow.update(event, now)
        return None

    def flush_expired(
        self, *, now: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Emit flows that have been idle longer than ``timeout_seconds``.

        Removes them from the active table and returns their summary
        dicts ready for DB insertion.
        """
        now = now or datetime.utcnow()
        cutoff = now - timedelta(seconds=self.timeout_seconds)
        emitted: List[Dict[str, Any]] = []
        expired_keys: List[Tuple] = []

        for key, flow in self._flows.items():
            if flow.last_seen <= cutoff:
                expired_keys.append(key)
                emitted.append(flow.to_dict())

        for key in expired_keys:
            del self._flows[key]

        self._total_flushed += len(emitted)
        return emitted

    @property
    def active_count(self) -> int:
        return len(self._flows)

    def stats(self) -> dict:
        return {
            "active_flows":  self.active_count,
            "total_created": self._total_created,
            "total_flushed": self._total_flushed,
        }
