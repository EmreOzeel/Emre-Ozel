"""
Palo Alto Networks TRAFFIC + THREAT log parser.

Palo Alto firewalls emit CSV-formatted syslog with a well-known field
order.  The TRAFFIC log type is the primary source of session metadata
(5-tuple, NAT, bytes, duration, app-id, action).  THREAT logs carry
threat intelligence (threat ID, category, severity, direction, Wildfire
verdict) and are parsed into the same normalised schema by reusing
existing columns:

  threat_id          → reason
  threat_category    → application
  severity           → health_status
  direction          → service
  wildfire verdict   → appended to reason as " [wildfire: X]"

References:
  - PAN-OS 10.x/11.x Syslog Field Reference (TRAFFIC + THREAT types)
  - Fields are comma-separated; the log type token is at index 3.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from collector.parsers.base import BaseParser

# ── Shared field positions (TRAFFIC + THREAT) ────────────────────────────────
_F_TYPE               = 3
_F_TIMESTAMP          = 1     # receive_time: "YYYY/MM/DD HH:MM:SS"
_F_SRC_IP             = 7
_F_DST_IP             = 8
_F_NAT_SRC_IP         = 9
_F_NAT_DST_IP         = 10
_F_RULE_NAME          = 11
_F_SRC_PORT           = 24
_F_DST_PORT           = 25
_F_NAT_SRC_PORT       = 26
_F_NAT_DST_PORT       = 27
_F_APPLICATION        = 14

# ── TRAFFIC-specific positions ───────────────────────────────────────────────
_F_PROTOCOL           = 29
_F_ACTION             = 30
_F_BYTES_SENT         = 31
_F_BYTES_RECEIVED     = 32
_F_SESSION_DURATION   = 33    # elapsed seconds
_F_PACKETS_SENT       = 34
_F_PACKETS_RECEIVED   = 35

# ── THREAT-specific positions ────────────────────────────────────────────────
_F_THREAT_ID          = 29    # threat/content name (same index as proto for TRAFFIC)
_F_THREAT_ACTION      = 30    # alert|allow|block|reset-*|drop (same index as TRAFFIC action)
_F_THREAT_CATEGORY    = 35
_F_THREAT_SEVERITY    = 36
_F_THREAT_DIRECTION   = 39
_F_THREAT_WILDFIRE    = 40

# Severity mapping (PAN-OS label → normalised)
_SEVERITY_MAP: Dict[str, str] = {
    "informational": "info",
    "low":           "low",
    "medium":        "medium",
    "high":          "high",
    "critical":      "critical",
}

# Quick prefix check — Palo Alto lines start with "1," or a digit then
# a comma, followed by a date-like token.
_PREFIX_RE = re.compile(r"^\d+,\d{4}/")


class PaloAltoParser(BaseParser):
    PARSER_ID = "paloalto"
    DEVICE_TYPE = "firewall"

    def can_parse(self, line: str) -> bool:
        if not _PREFIX_RE.match(line[:20]):
            return False
        # Confirm TRAFFIC or THREAT at field 3
        parts = line.split(",", 5)
        if len(parts) < 5:
            return False
        return parts[_F_TYPE].strip() in ("TRAFFIC", "THREAT")

    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        fields = line.split(",")
        if len(fields) < 36:
            return None

        log_type = fields[_F_TYPE].strip()
        if log_type not in ("TRAFFIC", "THREAT"):
            return None

        event_time = _parse_pa_time(fields[_F_TIMESTAMP].strip())
        if event_time is None:
            return None

        if log_type == "THREAT":
            return self._parse_threat(fields, event_time)
        return self._parse_traffic(fields, event_time)

    # ── TRAFFIC ──────────────────────────────────────────────────────────────

    def _parse_traffic(
        self, fields: list, event_time: datetime,
    ) -> Dict[str, Any]:
        action_raw = _safe(fields, _F_ACTION).lower()
        action = _normalize_action(action_raw)

        result: Dict[str, Any] = {
            "event_time":       event_time,
            "source_ip":        _safe(fields, _F_SRC_IP),
            "destination_ip":   _safe(fields, _F_DST_IP),
            "source_port":      _safe_int(fields, _F_SRC_PORT),
            "destination_port": _safe_int(fields, _F_DST_PORT),
            "protocol":         _safe(fields, _F_PROTOCOL).upper() or None,
            "action":           action,
            "reason":           _safe(fields, _F_RULE_NAME) or None,
            "bytes_in":         _safe_int(fields, _F_BYTES_RECEIVED),
            "bytes_out":        _safe_int(fields, _F_BYTES_SENT),
            "packets_in":       _safe_int(fields, _F_PACKETS_RECEIVED),
            "packets_out":      _safe_int(fields, _F_PACKETS_SENT),
            "application":      _safe(fields, _F_APPLICATION) or None,
        }

        # Duration (seconds → ms), capped at PostgreSQL integer max
        dur = _safe_int(fields, _F_SESSION_DURATION)
        if dur is not None:
            result["duration_ms"] = min(dur * 1000, 2_147_483_647)

        # NAT fields
        self._extract_nat(fields, result)
        return result

    # ── THREAT ───────────────────────────────────────────────────────────────

    def _parse_threat(
        self, fields: list, event_time: datetime,
    ) -> Dict[str, Any]:
        action_raw = _safe(fields, _F_THREAT_ACTION).lower()
        action = _normalize_threat_action(action_raw)

        # Threat ID → reason
        threat_id = _safe(fields, _F_THREAT_ID) or None
        reason = threat_id

        # Wildfire verdict → append to reason
        wildfire = _safe(fields, _F_THREAT_WILDFIRE).lower() if len(fields) > _F_THREAT_WILDFIRE else ""
        if wildfire and wildfire != "unknown":
            suffix = f" [wildfire: {wildfire}]"
            reason = f"{reason}{suffix}" if reason else suffix.strip()

        # Severity → health_status
        severity_raw = _safe(fields, _F_THREAT_SEVERITY).lower()
        severity = _SEVERITY_MAP.get(severity_raw, severity_raw or None)

        # Direction → service
        direction = _safe(fields, _F_THREAT_DIRECTION) or None

        # Category → application
        category = _safe(fields, _F_THREAT_CATEGORY) or None

        result: Dict[str, Any] = {
            "event_time":       event_time,
            "source_ip":        _safe(fields, _F_SRC_IP),
            "destination_ip":   _safe(fields, _F_DST_IP),
            "source_port":      _safe_int(fields, _F_SRC_PORT),
            "destination_port": _safe_int(fields, _F_DST_PORT),
            "action":           action,
            "reason":           reason,
            "application":      category,
            "health_status":    severity,
            "service":          direction,
        }

        # NAT fields
        self._extract_nat(fields, result)
        return result

    # ── Shared NAT extraction ────────────────────────────────────────────────

    @staticmethod
    def _extract_nat(fields: list, result: Dict[str, Any]) -> None:
        nat_src = _safe(fields, _F_NAT_SRC_IP)
        nat_dst = _safe(fields, _F_NAT_DST_IP)
        if nat_src and nat_src != result.get("source_ip"):
            result["nat_source_ip"] = nat_src
            result["nat_source_port"] = _safe_int(fields, _F_NAT_SRC_PORT)
        if nat_dst and nat_dst != result.get("destination_ip"):
            result["nat_destination_ip"] = nat_dst
            result["nat_destination_port"] = _safe_int(fields, _F_NAT_DST_PORT)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe(fields, idx) -> str:
    try:
        return fields[idx].strip()
    except (IndexError, AttributeError):
        return ""


def _safe_int(fields, idx) -> Optional[int]:
    v = _safe(fields, idx)
    if not v:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _parse_pa_time(s: str) -> Optional[datetime]:
    """Parse Palo Alto timestamp: 'YYYY/MM/DD HH:MM:SS'."""
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _normalize_action(raw: str) -> str:
    """Map Palo Alto TRAFFIC action tokens to the normalised vocabulary."""
    if raw in ("allow", "allowed"):
        return "allow"
    if raw in ("deny", "denied"):
        return "deny"
    if raw in ("drop", "dropped", "drop-all-packets"):
        return "drop"
    if raw.startswith("reset"):
        return "reset"
    return raw or "unknown"


def _normalize_threat_action(raw: str) -> str:
    """Map Palo Alto THREAT action tokens to the normalised vocabulary.

    THREAT logs use "alert" as the default action — we keep it as-is
    because it's semantically different from allow/deny.
    """
    if raw == "alert":
        return "alert"
    if raw in ("allow", "allowed"):
        return "allow"
    if raw in ("block", "blocked"):
        return "deny"
    if raw.startswith("reset"):
        return "deny"
    if raw in ("drop", "dropped", "drop-all-packets"):
        return "drop"
    if raw in ("deny", "denied"):
        return "deny"
    return raw or "unknown"
