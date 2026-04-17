"""
Generic key=value syslog parser (fallback).

Many firewalls and security appliances emit logs in a ``key=value``
format where pairs are separated by spaces and values may be quoted.
This parser handles the common patterns:

    key=value
    key="quoted value"
    key='single-quoted'

It then maps well-known keys from multiple vendors (FortiGate,
SonicWall, Juniper SRX, generic CEF-like) to the normalised
LiveEvent field names.

This is intentionally the **most permissive** parser — it will accept
any line that contains at least 3 key=value pairs with recognisable
network fields (src/dst IP and action).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from collector.parsers.base import BaseParser

# Regex to extract key=value pairs.  Handles:
#   key=value   key="quoted value"   key='quoted'
_KV_RE = re.compile(
    r"""(\w+)=("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)""",
)

# ── Key aliases: vendor-specific field name → normalised field name ───────────
# Multiple vendors use different names for the same concept.  This map
# collapses them so the normaliser can extract fields without knowing which
# vendor sent the log.

_ALIASES: Dict[str, str] = {
    # Source IP
    "src":            "source_ip",
    "srcip":          "source_ip",
    "src_ip":         "source_ip",
    "source":         "source_ip",
    # Destination IP
    "dst":            "destination_ip",
    "dstip":          "destination_ip",
    "dst_ip":         "destination_ip",
    "destination":    "destination_ip",
    # Source port
    "sport":          "source_port",
    "srcport":        "source_port",
    "src_port":       "source_port",
    # Destination port
    "dport":          "destination_port",
    "dstport":        "destination_port",
    "dst_port":       "destination_port",
    # Protocol
    "proto":          "protocol",
    "protocol":       "protocol",
    # Action
    "action":         "action",
    "act":            "action",
    # Bytes / packets
    "sentbyte":       "bytes_out",
    "rcvdbyte":       "bytes_in",
    "bytes_sent":     "bytes_out",
    "bytes_received": "bytes_in",
    "bytesin":        "bytes_in",
    "bytesout":       "bytes_out",
    "sentpkt":        "packets_out",
    "rcvdpkt":        "packets_in",
    # Duration
    "duration":       "duration_ms",
    "elapsed":        "duration_ms",
    # NAT
    "transip":        "nat_source_ip",
    "transsip":       "nat_source_ip",
    "transdip":       "nat_destination_ip",
    "tranport":       "nat_source_port",
    "transsp":        "nat_source_port",
    "transdp":        "nat_destination_port",
    "nat_src":        "nat_source_ip",
    "nat_dst":        "nat_destination_ip",
    # Application
    "app":            "application",
    "appname":        "application",
    "application":    "application",
    # Service
    "service":        "service",
    # Policy / rule
    "policyname":     "reason",
    "policy":         "reason",
    "rule":           "reason",
    "rulename":       "reason",
    # Timestamp
    "date":           "_date",
    "time":           "_time",
    "eventtime":      "_eventtime",
    "timestamp":      "_timestamp",
    "start":          "_timestamp",
}

# Integer fields — parse as int
_INT_FIELDS = {
    "source_port", "destination_port",
    "bytes_in", "bytes_out", "packets_in", "packets_out",
    "duration_ms",
    "nat_source_port", "nat_destination_port",
}

# Minimum required fields for a valid network event
_REQUIRED = {"source_ip", "destination_ip", "action"}


class GenericKVParser(BaseParser):
    PARSER_ID = "generic_kv"
    DEVICE_TYPE = "firewall"

    def can_parse(self, line: str) -> bool:
        # Must contain at least 3 key=value pairs
        pairs = _KV_RE.findall(line[:500])
        if len(pairs) < 3:
            return False
        # At least one recognisable network key
        keys_lower = {k.lower() for k, _ in pairs}
        has_src = bool(keys_lower & {"src", "srcip", "src_ip", "source"})
        has_dst = bool(keys_lower & {"dst", "dstip", "dst_ip", "destination"})
        has_act = bool(keys_lower & {"action", "act"})
        return has_src and has_dst and has_act

    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        pairs = _KV_RE.findall(line)
        if not pairs:
            return None

        raw: Dict[str, str] = {}
        for key, val in pairs:
            # Strip quotes
            if (val.startswith('"') and val.endswith('"')) or \
               (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            raw[key.lower()] = val

        # Map to normalised field names
        normalised: Dict[str, Any] = {}
        for raw_key, raw_val in raw.items():
            norm_key = _ALIASES.get(raw_key)
            if norm_key is None:
                continue
            if norm_key in _INT_FIELDS:
                try:
                    normalised[norm_key] = int(raw_val)
                except (ValueError, TypeError):
                    pass
            else:
                normalised[norm_key] = raw_val

        # Check minimum fields
        if not _REQUIRED.issubset(normalised.keys()):
            return None

        # Normalise action
        act = normalised.get("action", "").lower()
        normalised["action"] = _normalize_action(act)

        # Normalise protocol
        proto = normalised.get("protocol", "")
        if proto:
            normalised["protocol"] = proto.upper()

        # Build event_time from date+time or timestamp fields
        normalised["event_time"] = _build_event_time(raw)

        # Duration: some vendors report in seconds, convert to ms
        dur = normalised.get("duration_ms")
        if dur is not None and dur < 1000 and "duration" in raw:
            # Heuristic: if the raw value was < 1000 and the field name
            # was "duration" (not "duration_ms"), assume seconds.
            normalised["duration_ms"] = dur * 1000

        return normalised


def _normalize_action(raw: str) -> str:
    if raw in ("accept", "allow", "pass", "permit", "allowed"):
        return "allow"
    if raw in ("deny", "denied", "reject", "block", "blocked"):
        return "deny"
    if raw in ("drop", "dropped", "discard"):
        return "drop"
    if raw.startswith("reset"):
        return "reset"
    return raw or "unknown"


def _build_event_time(raw: Dict[str, str]) -> Optional[datetime]:
    """Try to extract a datetime from the raw key-value pairs."""
    # Try combined timestamp field
    for key in ("_timestamp", "_eventtime"):
        ts = raw.get(key.lstrip("_")) or raw.get(key)
        if ts:
            dt = _try_parse_time(ts)
            if dt:
                return dt

    # FortiGate-style: date=YYYY-MM-DD time=HH:MM:SS
    d = raw.get("date", "")
    t = raw.get("time", "")
    if d and t:
        dt = _try_parse_time(f"{d} {t}")
        if dt:
            return dt

    return None


def _try_parse_time(s: str) -> Optional[datetime]:
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            return datetime.strptime(s.strip(), fmt)
        except (ValueError, TypeError):
            continue
    # Try epoch seconds
    try:
        epoch = float(s)
        if epoch > 1_000_000_000:  # sanity: after 2001
            return datetime.utcfromtimestamp(epoch)
    except (ValueError, TypeError):
        pass
    return None
