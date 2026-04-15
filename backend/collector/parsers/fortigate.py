"""
FortiGate traffic / UTM log parser.

FortiGate firewalls emit key=value syslog with well-known field names.
A line is identified as FortiGate when it contains ``logid=`` or
``devname=`` combined with a recognisable source-IP field (``srcip=``
or ``src=``).

Example line (traffic/forward):

    date=2025-04-13 time=14:30:00 devname=FGT60F devid=FG100E
    logid="0000000013" type=traffic subtype=forward level=notice
    srcip=10.0.1.50 srcport=49812 dstip=8.8.8.8 dstport=443
    proto=6 action=accept sentbyte=5400 rcvdbyte=12300 sentpkt=42
    rcvdpkt=38 duration=45 policyname=outbound-allow app=SSL
    service=HTTPS transip=203.0.113.5 transport=49812

References:
  - FortiOS 7.x Log Message Reference (traffic type)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from collector.parsers.base import BaseParser

# key=value regex — handles quoted and unquoted values.
_KV_RE = re.compile(
    r"""(\w+)=("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)""",
)

# Protocol number → name mapping (covers the common cases).
_PROTO_MAP: Dict[str, str] = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "89": "OSPF",
}


class FortiGateParser(BaseParser):
    PARSER_ID = "fortigate"
    DEVICE_TYPE = "firewall"

    def can_parse(self, line: str) -> bool:
        snippet = line[:500].lower()
        has_fg_marker = "logid=" in snippet or "devname=" in snippet
        has_src = "srcip=" in snippet or "src=" in snippet
        return has_fg_marker and has_src

    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        raw = _extract_kv(line)
        if not raw:
            return None

        src = raw.get("srcip") or raw.get("src")
        dst = raw.get("dstip") or raw.get("dst")
        if not src or not dst:
            return None

        event_time = _build_timestamp(raw)
        action = _normalize_action(raw.get("action", ""))
        protocol = _map_protocol(raw.get("proto", ""))

        result: Dict[str, Any] = {
            "event_time":       event_time,
            "source_ip":        src,
            "destination_ip":   dst,
            "source_port":      _to_int(raw.get("srcport")),
            "destination_port": _to_int(raw.get("dstport")),
            "protocol":         protocol,
            "action":           action,
            "reason":           raw.get("policyname") or raw.get("policy") or None,
            "bytes_in":         _to_int(raw.get("rcvdbyte")),
            "bytes_out":        _to_int(raw.get("sentbyte")),
            "packets_in":       _to_int(raw.get("rcvdpkt")),
            "packets_out":      _to_int(raw.get("sentpkt")),
            "application":      raw.get("app") or raw.get("appname") or None,
            "service":          raw.get("service") or None,
        }

        # Duration (seconds → ms)
        dur = _to_int(raw.get("duration"))
        if dur is not None:
            result["duration_ms"] = dur * 1000

        # NAT fields
        transip = raw.get("transip") or raw.get("transsip")
        if transip and transip != src:
            result["nat_source_ip"] = transip
        transport = _to_int(raw.get("transport") or raw.get("transsp"))
        if transport is not None:
            result["nat_source_port"] = transport
        transdip = raw.get("transdip")
        if transdip and transdip != dst:
            result["nat_destination_ip"] = transdip
        transdp = _to_int(raw.get("transdp"))
        if transdp is not None:
            result["nat_destination_port"] = transdp

        return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_kv(line: str) -> Dict[str, str]:
    """Parse all key=value pairs from *line* into a lowercase-keyed dict."""
    pairs = _KV_RE.findall(line)
    result: Dict[str, str] = {}
    for key, val in pairs:
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        result[key.lower()] = val
    return result


def _to_int(val: Optional[str]) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _normalize_action(raw: str) -> str:
    r = raw.lower().strip()
    if r in ("accept", "allow", "pass", "permit"):
        return "allow"
    if r in ("deny", "denied", "block", "blocked", "reject"):
        return "deny"
    if r in ("drop", "dropped", "discard"):
        return "drop"
    if r.startswith("reset"):
        return "reset"
    return r or "unknown"


def _map_protocol(raw: str) -> Optional[str]:
    """Map a protocol number string or name to a canonical upper-case name."""
    r = raw.strip()
    if not r:
        return None
    mapped = _PROTO_MAP.get(r)
    if mapped:
        return mapped
    # Already a name like "TCP" / "udp"
    if r.isalpha():
        return r.upper()
    return r


def _build_timestamp(raw: Dict[str, str]) -> Optional[datetime]:
    """Build a datetime from FortiGate date= + time= fields."""
    d = raw.get("date", "").strip()
    t = raw.get("time", "").strip()
    if d and t:
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ):
            try:
                return datetime.strptime(f"{d} {t}", fmt)
            except (ValueError, TypeError):
                continue
    # Fallback: eventtime= or timestamp= as epoch
    for key in ("eventtime", "timestamp"):
        val = raw.get(key, "").strip()
        if val:
            try:
                epoch = float(val)
                if epoch > 1_000_000_000:
                    return datetime.utcfromtimestamp(epoch)
            except (ValueError, TypeError):
                pass
    return None
