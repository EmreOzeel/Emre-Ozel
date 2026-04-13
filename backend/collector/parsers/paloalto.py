"""
Palo Alto Networks traffic log parser.

Palo Alto firewalls emit CSV-formatted syslog with a well-known field
order.  The TRAFFIC log type is the primary source of session metadata
(5-tuple, NAT, bytes, duration, app-id, action).

References:
  - PAN-OS 10.x/11.x Syslog Field Reference (TRAFFIC type)
  - Fields are comma-separated; the log type token is at index 3.

Example line (abbreviated):
  1,2025/04/13 10:15:00,0009C100001,...,TRAFFIC,end,...,
  10.0.0.5,192.168.1.1,10.0.0.5,203.0.113.1,web-allow,...,
  443,443,53211,53211,0x400000,...,web-browsing,...,tcp,...,
  allow,...,1234,567,...

The parser also handles THREAT logs (index 3 == "THREAT") in a reduced
fashion — extracting the 5-tuple and action but ignoring threat-specific
fields.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from collector.parsers.base import BaseParser

# Palo Alto TRAFFIC log field positions (0-indexed).
# The exact offsets vary slightly between PAN-OS major versions but the
# critical fields are stable at the positions listed here.
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
_F_PROTOCOL           = 29
_F_ACTION             = 30
_F_BYTES_SENT         = 31
_F_BYTES_RECEIVED     = 32
_F_PACKETS_SENT       = 34
_F_PACKETS_RECEIVED   = 35
_F_SESSION_DURATION   = 33    # elapsed seconds
_F_APPLICATION        = 14

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

        # Duration (seconds → ms)
        dur = _safe_int(fields, _F_SESSION_DURATION)
        if dur is not None:
            result["duration_ms"] = dur * 1000

        # NAT fields
        nat_src = _safe(fields, _F_NAT_SRC_IP)
        nat_dst = _safe(fields, _F_NAT_DST_IP)
        if nat_src and nat_src != result["source_ip"]:
            result["nat_source_ip"] = nat_src
            result["nat_source_port"] = _safe_int(fields, _F_NAT_SRC_PORT)
        if nat_dst and nat_dst != result["destination_ip"]:
            result["nat_destination_ip"] = nat_dst
            result["nat_destination_port"] = _safe_int(fields, _F_NAT_DST_PORT)

        return result


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
    """Map Palo Alto action tokens to the normalised vocabulary."""
    if raw in ("allow", "allowed"):
        return "allow"
    if raw in ("deny", "denied"):
        return "deny"
    if raw in ("drop", "dropped", "drop-all-packets"):
        return "drop"
    if raw.startswith("reset"):
        return "reset"
    return raw or "unknown"
