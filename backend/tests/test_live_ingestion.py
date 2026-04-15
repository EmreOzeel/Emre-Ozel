"""
Tests for the live network ingestion layer.

Covers:

- Parser correctness:
    * PaloAltoParser: TRAFFIC line, THREAT line, non-PA line rejected,
      malformed line, NAT fields, action normalisation
    * GenericKVParser: FortiGate-style, SonicWall-style, quoted values,
      missing required fields, action normalisation, timestamp formats
    * detect_format auto-detection and priority ordering

- Pipeline normalisation:
    * field whitelist enforcement
    * syslog priority stripping
    * default fallbacks (event_time, source_ip, action)
    * raw_line truncation
    * buffer + flush to DB
    * stats tracking

- REST API endpoints:
    * GET /api/live-events (filters, pagination, ordering)
    * GET /api/live-events/stats (aggregation correctness)
    * GET /api/collector/status
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
from datetime import datetime, timedelta
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import (
    Base, LiveEventModel, LiveFlowModel, MonitoredPathModel,
    NotificationModel, PathAnalysisSavedQueryModel,
    SuppressionRuleModel, UserModel,
)
from main import app, get_db
from collector.bridge import (
    apply_suppressions,
    auto_create_monitored_paths,
    scan_live_events,
    BLOCKED_FLOW_THRESHOLD,
    PORT_SCAN_DST_THRESHOLD,
    RESET_FLOW_THRESHOLD,
)
from collector.intelligence import run_intelligence_scan
from collector.live_risk import compute_live_risk_scores

from collector.parsers.base import (
    BaseParser,
    clear_registry,
    detect_format,
    register_parser,
)
from collector.parsers.paloalto import PaloAltoParser
from collector.parsers.fortigate import FortiGateParser
from collector.parsers.generic_kv import GenericKVParser
from collector.pipeline import Pipeline, _strip_syslog_priority


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def db_session():
    eng = sa_create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    db = Session()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(eng)


@pytest.fixture(scope="function", autouse=True)
def _clear(db_session):
    clear_registry()
    register_parser(PaloAltoParser())
    register_parser(FortiGateParser())
    register_parser(GenericKVParser())
    yield
    clear_registry()
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def tmp_pcap(tmp_path):
    f = tmp_path / "test.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return str(f)


def _seed_user(db, username="admin"):
    u = UserModel(username=username, hashed_password="x")
    db.add(u)
    db.flush()
    uid = u.id
    db.commit()
    return uid


def _make_client(db_session, uid):
    def _override_db():
        yield db_session
    def _override_user():
        return SimpleNamespace(id=uid, is_admin=False, team_id=None)
    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True)


# ── Sample log lines ────────────────────────────────────────────────────────

_PA_TRAFFIC = (
    "1,2025/04/13 10:15:00,0009C100001,TRAFFIC,end,2049,2025/04/13 10:15:00,"
    "10.0.0.5,192.168.1.1,10.0.0.5,203.0.113.1,web-allow,,,web-browsing,"
    "vsys1,trust,untrust,ae1.100,ae2.200,syslog-fwd,2025/04/13 10:15:00,"
    "12345,1,53211,443,53211,443,0x400000,tcp,allow,1234,567,0,33,"
    "456,789,,,,0,,,,,,,,,"
)

_PA_THREAT = (
    "1,2025/04/13 10:16:00,0009C100001,THREAT,vulnerability,2049,2025/04/13 10:16:00,"
    "10.0.0.5,192.168.1.1,10.0.0.5,203.0.113.1,web-allow,,,web-browsing,"
    "vsys1,trust,untrust,ae1.100,ae2.200,syslog-fwd,2025/04/13 10:16:00,"
    "12345,1,53211,443,53211,443,0x400000,tcp,alert,0,0,0,0,"
    "0,0,,,,0,,,,,,,,,"
)

# THREAT log — 41+ fields, alert action, severity high, wildfire malware
# Fields: 0..7=src_ip, 8=dst_ip, 9=nat_src, 10=nat_dst, 11=rule,
# 14=app, 24=sport, 25=dport, 29=threat_id, 30=action, 35=category,
# 36=severity, 39=direction, 40=wildfire
_PA_THREAT_FULL = ",".join([
    "1",                            # 0
    "2025/04/13 10:16:00",          # 1 timestamp
    "0009C100001",                  # 2 serial
    "THREAT",                       # 3 type
    "vulnerability",                # 4 subtype
    "2049",                         # 5
    "2025/04/13 10:16:00",          # 6
    "10.0.0.5",                     # 7 src_ip
    "192.168.1.1",                  # 8 dst_ip
    "10.0.0.5",                     # 9 nat_src
    "203.0.113.1",                  # 10 nat_dst
    "web-allow",                    # 11 rule
    "",                             # 12
    "",                             # 13
    "web-browsing",                 # 14 app (not used for THREAT)
    "vsys1",                        # 15
    "trust",                        # 16
    "untrust",                      # 17
    "ae1.100",                      # 18
    "ae2.200",                      # 19
    "syslog-fwd",                   # 20
    "2025/04/13 10:16:00",          # 21
    "12345",                        # 22
    "1",                            # 23
    "53211",                        # 24 sport
    "443",                          # 25 dport
    "53211",                        # 26 nat_sport
    "443",                          # 27 nat_dport
    "0x400000",                     # 28
    "Apache Struts RCE(54321)",     # 29 threat_id
    "alert",                        # 30 action
    "0",                            # 31
    "0",                            # 32
    "0",                            # 33
    "0",                            # 34
    "code-execution",               # 35 category
    "high",                         # 36 severity
    "",                             # 37
    "",                             # 38
    "client-to-server",             # 39 direction
    "malware",                      # 40 wildfire
])

_PA_THREAT_BLOCK = ",".join([
    "1", "2025/04/13 10:17:00", "0009C100001", "THREAT", "vulnerability",
    "2049", "2025/04/13 10:17:00",
    "10.0.0.5", "192.168.1.1", "10.0.0.5", "203.0.113.1", "block-rule",
    "", "", "ssl",
    "vsys1", "trust", "untrust", "ae1", "ae2", "syslog",
    "2025/04/13 10:17:00", "99", "1",
    "44100", "443", "44100", "443", "0x0",
    "Suspicious PDF(99999)",        # 29 threat_id
    "reset-both",                   # 30 action
    "0", "0", "0", "0",
    "phishing",                     # 35 category
    "critical",                     # 36 severity
    "", "",
    "server-to-client",             # 39 direction
    "unknown",                      # 40 wildfire (unknown → not appended)
])

_PA_DENY = (
    "1,2025/04/13 10:17:00,0009C100001,TRAFFIC,deny,2049,2025/04/13 10:17:00,"
    "10.0.1.10,10.0.2.20,10.0.1.10,10.0.2.20,block-ssh,,,ssh,"
    "vsys1,trust,dmz,ae1.100,ae3.300,syslog-fwd,2025/04/13 10:17:00,"
    "12346,2,44100,22,44100,22,0x400000,tcp,deny,0,0,0,0,"
    "0,0,,,,0,,,,,,,,,"
)

_FG_KV = (
    "date=2025-04-13 time=10:20:00 devname=FW01 devid=FG100D "
    "logid=0000000013 type=traffic subtype=forward "
    "srcip=10.0.1.50 srcport=49812 dstip=8.8.8.8 dstport=443 "
    "proto=6 action=accept sentbyte=5400 rcvdbyte=12300 "
    "duration=45 policyname=outbound-allow appname=SSL service=HTTPS"
)

_SONIC_KV = (
    'src=192.168.10.5 dst=10.0.0.1 sport=12345 dport=80 '
    'proto=TCP action=allow sentbyte=900 rcvdbyte=4500 '
    'duration=12 rule="web-out"'
)

_FG_NATIVE = (
    "date=2025-04-13 time=14:30:00 devname=FGT60F devid=FG100E "
    'logid="0000000013" type=traffic subtype=forward level=notice '
    "srcip=10.0.1.50 srcport=49812 dstip=8.8.8.8 dstport=443 "
    "proto=6 action=accept sentbyte=5400 rcvdbyte=12300 sentpkt=42 "
    "rcvdpkt=38 duration=45 policyname=outbound-allow app=SSL "
    "service=HTTPS transip=203.0.113.5 transport=49812"
)

_FG_UDP = (
    "date=2025-04-13 time=14:31:00 devname=FGT60F "
    "logid=0000000013 type=traffic subtype=forward "
    "srcip=10.0.1.60 srcport=12345 dstip=8.8.4.4 dstport=53 "
    "proto=17 action=accept sentbyte=80 rcvdbyte=200 duration=0"
)

_FG_DENY = (
    "date=2025-04-13 time=14:32:00 devname=FGT60F "
    "logid=0000000020 type=traffic subtype=forward "
    "srcip=10.0.2.10 srcport=55000 dstip=10.0.3.1 dstport=22 "
    "proto=6 action=deny sentbyte=0 rcvdbyte=0 duration=0 policyname=block-ssh"
)

_SYSLOG_WRAPPED = "<134>" + _FG_KV


# ══════════════════════════════════════════════════════════════════════════════
# PaloAltoParser
# ══════════════════════════════════════════════════════════════════════════════

class TestPaloAltoParser:
    pa = PaloAltoParser()

    def test_can_parse_traffic(self):
        assert self.pa.can_parse(_PA_TRAFFIC) is True

    def test_can_parse_threat(self):
        assert self.pa.can_parse(_PA_THREAT) is True

    def test_rejects_non_pa_line(self):
        assert self.pa.can_parse("random log line") is False
        assert self.pa.can_parse(_FG_KV) is False

    def test_parse_traffic_fields(self):
        r = self.pa.parse(_PA_TRAFFIC)
        assert r is not None
        assert r["source_ip"] == "10.0.0.5"
        assert r["destination_ip"] == "192.168.1.1"
        assert r["source_port"] == 53211
        assert r["destination_port"] == 443
        assert r["protocol"] == "TCP"
        assert r["action"] == "allow"
        assert r["application"] == "web-browsing"
        assert r["reason"] == "web-allow"
        assert r["bytes_out"] == 1234
        assert r["bytes_in"] == 567
        assert isinstance(r["event_time"], datetime)

    def test_parse_nat_fields(self):
        r = self.pa.parse(_PA_TRAFFIC)
        # NAT src differs from original src → should be captured
        assert r.get("nat_source_ip") is None or r["nat_source_ip"] == "10.0.0.5"
        # NAT dst differs
        assert r.get("nat_destination_ip") == "203.0.113.1"

    def test_parse_deny_action(self):
        r = self.pa.parse(_PA_DENY)
        assert r["action"] == "deny"

    def test_parse_threat_returns_dict(self):
        r = self.pa.parse(_PA_THREAT)
        assert r is not None
        assert r["source_ip"] == "10.0.0.5"

    def test_parse_duration_in_ms(self):
        r = self.pa.parse(_PA_TRAFFIC)
        # Field 33 in the sample line is "0" (session_duration=0 seconds)
        assert r.get("duration_ms") == 0

    def test_malformed_short_line_returns_none(self):
        assert self.pa.parse("1,2025/04/13,short") is None


# ══════════════════════════════════════════════════════════════════════════════
# PaloAltoParser — THREAT logs
# ══════════════════════════════════════════════════════════════════════════════

class TestPaloAltoThreat:
    pa = PaloAltoParser()

    def test_threat_log_detected(self):
        assert self.pa.can_parse(_PA_THREAT_FULL) is True
        assert self.pa.can_parse(_PA_THREAT_BLOCK) is True

    def test_threat_id_into_reason(self):
        r = self.pa.parse(_PA_THREAT_FULL)
        assert r is not None
        assert "Apache Struts RCE(54321)" in r["reason"]

    def test_threat_category_into_application(self):
        r = self.pa.parse(_PA_THREAT_FULL)
        assert r["application"] == "code-execution"

    def test_severity_mapping(self):
        # Build minimal THREAT lines with each severity level
        base = _PA_THREAT_FULL.split(",")
        for raw, expected in [
            ("informational", "info"),
            ("low", "low"),
            ("medium", "medium"),
            ("high", "high"),
            ("critical", "critical"),
        ]:
            fields = list(base)
            fields[36] = raw
            line = ",".join(fields)
            r = self.pa.parse(line)
            assert r is not None
            assert r["health_status"] == expected, f"{raw} → expected {expected}"

    def test_wildfire_malware_appended(self):
        r = self.pa.parse(_PA_THREAT_FULL)
        assert "[wildfire: malware]" in r["reason"]

    def test_wildfire_unknown_not_appended(self):
        r = self.pa.parse(_PA_THREAT_BLOCK)
        assert "wildfire" not in (r["reason"] or "").lower()

    def test_direction_into_service(self):
        r = self.pa.parse(_PA_THREAT_FULL)
        assert r["service"] == "client-to-server"
        r2 = self.pa.parse(_PA_THREAT_BLOCK)
        assert r2["service"] == "server-to-client"

    def test_threat_action_alert_stays_alert(self):
        r = self.pa.parse(_PA_THREAT_FULL)
        assert r["action"] == "alert"

    def test_threat_action_reset_becomes_deny(self):
        r = self.pa.parse(_PA_THREAT_BLOCK)
        assert r["action"] == "deny"


# ══════════════════════════════════════════════════════════════════════════════
# GenericKVParser
# ══════════════════════════════════════════════════════════════════════════════

class TestGenericKVParser:
    kv = GenericKVParser()

    def test_can_parse_fortigate(self):
        assert self.kv.can_parse(_FG_KV) is True

    def test_can_parse_sonicwall_style(self):
        assert self.kv.can_parse(_SONIC_KV) is True

    def test_rejects_non_kv(self):
        assert self.kv.can_parse("just a plain text message") is False

    def test_rejects_missing_action(self):
        assert self.kv.can_parse("srcip=1.1.1.1 dstip=2.2.2.2") is False

    def test_parse_fortigate_fields(self):
        r = self.kv.parse(_FG_KV)
        assert r is not None
        assert r["source_ip"] == "10.0.1.50"
        assert r["destination_ip"] == "8.8.8.8"
        assert r["source_port"] == 49812
        assert r["destination_port"] == 443
        assert r["action"] == "allow"
        assert r["bytes_out"] == 5400
        assert r["bytes_in"] == 12300
        assert r["application"] == "SSL"
        assert r["reason"] == "outbound-allow"

    def test_parse_sonicwall_quoted_values(self):
        r = self.kv.parse(_SONIC_KV)
        assert r is not None
        assert r["source_ip"] == "192.168.10.5"
        assert r["reason"] == "web-out"  # stripped quotes

    def test_parse_fortigate_timestamp(self):
        r = self.kv.parse(_FG_KV)
        assert r["event_time"] is not None
        assert isinstance(r["event_time"], datetime)
        assert r["event_time"].year == 2025

    def test_action_normalisation(self):
        base = "srcip=1.1.1.1 dstip=2.2.2.2 "
        for raw, expected in [
            ("action=accept", "allow"),
            ("action=permit", "allow"),
            ("action=deny", "deny"),
            ("action=block", "deny"),
            ("action=drop", "drop"),
            ("action=reset-both", "reset"),
        ]:
            r = self.kv.parse(base + raw)
            assert r is not None
            assert r["action"] == expected, f"{raw} → expected {expected}, got {r['action']}"

    def test_epoch_timestamp(self):
        line = "srcip=1.1.1.1 dstip=2.2.2.2 action=allow timestamp=1681387200"
        r = self.kv.parse(line)
        assert r["event_time"] is not None

    def test_duration_seconds_to_ms(self):
        r = self.kv.parse(_FG_KV)
        # 45 seconds → 45000 ms
        assert r["duration_ms"] == 45000

    def test_missing_required_returns_none(self):
        # Has src and action but no dst
        assert self.kv.parse("srcip=1.1.1.1 action=allow") is None


# ══════════════════════════════════════════════════════════════════════════════
# FortiGateParser
# ══════════════════════════════════════════════════════════════════════════════

class TestFortiGateParser:
    fg = FortiGateParser()

    def test_can_parse_fortigate_native(self):
        assert self.fg.can_parse(_FG_NATIVE) is True

    def test_can_parse_fortigate_udp(self):
        assert self.fg.can_parse(_FG_UDP) is True

    def test_can_parse_fortigate_deny(self):
        assert self.fg.can_parse(_FG_DENY) is True

    def test_rejects_non_fortigate(self):
        assert self.fg.can_parse(_PA_TRAFFIC) is False
        assert self.fg.can_parse("random log line without kv") is False
        assert self.fg.can_parse(_SONIC_KV) is False

    def test_full_field_extraction(self):
        r = self.fg.parse(_FG_NATIVE)
        assert r is not None
        assert r["source_ip"] == "10.0.1.50"
        assert r["destination_ip"] == "8.8.8.8"
        assert r["source_port"] == 49812
        assert r["destination_port"] == 443
        assert r["protocol"] == "TCP"
        assert r["action"] == "allow"
        assert r["bytes_out"] == 5400
        assert r["bytes_in"] == 12300
        assert r["packets_out"] == 42
        assert r["packets_in"] == 38
        assert r["duration_ms"] == 45000
        assert r["application"] == "SSL"
        assert r["service"] == "HTTPS"
        assert r["reason"] == "outbound-allow"
        assert r["nat_source_ip"] == "203.0.113.5"
        assert r["nat_source_port"] == 49812

    def test_protocol_number_mapping_tcp(self):
        r = self.fg.parse(_FG_NATIVE)
        assert r["protocol"] == "TCP"

    def test_protocol_number_mapping_udp(self):
        r = self.fg.parse(_FG_UDP)
        assert r["protocol"] == "UDP"

    def test_protocol_number_mapping_icmp(self):
        line = (
            "date=2025-04-13 time=15:00:00 devname=FGT60F logid=1234 "
            "srcip=10.0.0.1 dstip=10.0.0.2 proto=1 action=accept"
        )
        r = self.fg.parse(line)
        assert r["protocol"] == "ICMP"

    def test_action_normalisation(self):
        for raw_action, expected in [
            ("accept", "allow"),
            ("allow", "allow"),
            ("deny", "deny"),
            ("block", "deny"),
            ("drop", "drop"),
            ("reset-both", "reset"),
        ]:
            line = (
                f"date=2025-04-13 time=15:00:00 devname=FGT60F logid=1 "
                f"srcip=1.1.1.1 dstip=2.2.2.2 proto=6 action={raw_action}"
            )
            r = self.fg.parse(line)
            assert r is not None
            assert r["action"] == expected, f"{raw_action} → expected {expected}"

    def test_date_time_parsing(self):
        r = self.fg.parse(_FG_NATIVE)
        assert r["event_time"] is not None
        assert isinstance(r["event_time"], datetime)
        assert r["event_time"] == datetime(2025, 4, 13, 14, 30, 0)

    def test_deny_line(self):
        r = self.fg.parse(_FG_DENY)
        assert r is not None
        assert r["action"] == "deny"
        assert r["reason"] == "block-ssh"
        assert r["bytes_in"] == 0

    def test_missing_src_returns_none(self):
        line = "date=2025-04-13 time=15:00:00 devname=FGT60F logid=1 dstip=2.2.2.2 action=accept"
        r = self.fg.parse(line)
        assert r is None


# ══════════════════════════════════════════════════════════════════════════════
# detect_format auto-detection
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectFormat:

    def test_pa_detected_first(self):
        p = detect_format(_PA_TRAFFIC)
        assert p is not None
        assert p.PARSER_ID == "paloalto"

    def test_kv_fallback(self):
        # _FG_KV has devname=/logid= so FortiGate parser grabs it now.
        # Use the SonicWall-style line (no FortiGate markers) to test
        # the generic KV fallback.
        p = detect_format(_SONIC_KV)
        assert p is not None
        assert p.PARSER_ID == "generic_kv"

    def test_fortigate_detected_before_generic_kv(self):
        p = detect_format(_FG_NATIVE)
        assert p is not None
        assert p.PARSER_ID == "fortigate"

    def test_pa_not_hijacked_by_kv(self):
        # PA line doesn't have kv pairs, so kv should NOT match.
        # But even if it did, PA is registered first and should win.
        p = detect_format(_PA_TRAFFIC)
        assert p.PARSER_ID == "paloalto"

    def test_empty_returns_none(self):
        assert detect_format("") is None
        assert detect_format("   ") is None

    def test_garbage_returns_none(self):
        assert detect_format("aaaa bbb ccc") is None


# ══════════════════════════════════════════════════════════════════════════════
# Pipeline
# ══════════════════════════════════════════════════════════════════════════════

class TestPipeline:

    def test_process_pa_line(self):
        pipe = Pipeline(source_id="fw01", device_role="perimeter")
        e = pipe.process_line(_PA_TRAFFIC)
        assert e is not None
        assert e["source_id"] == "fw01"
        assert e["device_type"] == "firewall"
        assert e["device_role"] == "perimeter"
        assert e["parser_id"] == "paloalto"
        assert e["source_ip"] == "10.0.0.5"

    def test_process_kv_line(self):
        pipe = Pipeline(source_id="fg01")
        e = pipe.process_line(_FG_KV)
        assert e is not None
        # _FG_KV has devname=/logid= so FortiGate parser catches it now
        assert e["parser_id"] == "fortigate"
        assert e["bytes_in"] == 12300

    def test_syslog_priority_stripped(self):
        pipe = Pipeline(source_id="fw01")
        e = pipe.process_line(_SYSLOG_WRAPPED)
        assert e is not None
        assert e["source_ip"] == "10.0.1.50"

    def test_empty_line_returns_none(self):
        pipe = Pipeline()
        assert pipe.process_line("") is None
        assert pipe.process_line("   \n") is None

    def test_garbage_returns_none(self):
        pipe = Pipeline()
        assert pipe.process_line("this is not a log line at all") is None

    def test_stats_tracking(self):
        pipe = Pipeline()
        pipe.process_line(_FG_KV)
        pipe.process_line("garbage")
        pipe.process_line(_PA_TRAFFIC)
        s = pipe.stats
        assert s["received"] == 3
        assert s["parsed"] == 2
        assert s["dropped"] == 1

    def test_field_whitelist(self):
        pipe = Pipeline()
        e = pipe.process_line(_FG_KV)
        # Known whitelisted fields are present
        assert "source_ip" in e
        assert "action" in e
        # Internal pipeline fields
        assert "parser_id" in e
        assert "source_id" in e
        assert "raw_line" in e
        # No unexpected vendor-specific keys leaked through
        for key in e:
            assert key in {
                "source_id", "device_type", "device_role", "parser_id",
                "event_time", "received_at", "raw_line",
                "source_ip", "destination_ip", "source_port", "destination_port",
                "protocol", "action", "reason",
                "bytes_in", "bytes_out", "packets_in", "packets_out",
                "duration_ms",
                "nat_source_ip", "nat_destination_ip",
                "nat_source_port", "nat_destination_port",
                "application", "service",
                "backend_ip", "backend_port", "response_time_ms", "health_status",
            }, f"unexpected key: {key}"

    def test_raw_line_truncated(self):
        pipe = Pipeline()
        long_line = "srcip=1.1.1.1 dstip=2.2.2.2 action=allow " + "x" * 5000
        e = pipe.process_line(long_line)
        assert e is not None
        assert len(e["raw_line"]) <= 2000

    def test_defaults_when_parser_omits_fields(self):
        pipe = Pipeline()
        e = pipe.process_line(_FG_KV)
        assert e.get("event_time") is not None
        assert e.get("source_ip") is not None
        assert e.get("action") is not None

    def test_buffer_and_flush(self, db_session):
        pipe = Pipeline(source_id="fw01")
        e1 = pipe.process_line(_PA_TRAFFIC)
        e2 = pipe.process_line(_FG_KV)
        pipe.buffer(e1)
        pipe.buffer(e2)
        assert pipe.buffer_size == 2
        n = pipe.flush(db_session)
        assert n == 2
        assert pipe.buffer_size == 0
        assert db_session.query(LiveEventModel).count() == 2

    def test_flush_empty_buffer(self, db_session):
        pipe = Pipeline()
        assert pipe.flush(db_session) == 0


class TestRateLimiter:
    """Verify the token-bucket RateLimiter."""

    def test_allow_within_limit(self):
        from collector.listeners.syslog_listener import RateLimiter
        rl = RateLimiter(max_eps=100, per_ip_max_eps=10)
        # First call should always pass — bucket starts full
        assert rl.allow("10.0.0.1") is True

    def test_reject_when_per_ip_exceeded(self):
        from collector.listeners.syslog_listener import RateLimiter
        rl = RateLimiter(max_eps=100000, per_ip_max_eps=5)
        ip = "10.0.0.99"
        allowed = sum(1 for _ in range(20) if rl.allow(ip))
        # Should allow exactly per_ip_max_eps (5) then reject the rest
        assert allowed == 5

    def test_independent_ip_limits(self):
        from collector.listeners.syslog_listener import RateLimiter
        rl = RateLimiter(max_eps=100000, per_ip_max_eps=3)
        a = sum(1 for _ in range(10) if rl.allow("10.0.0.1"))
        b = sum(1 for _ in range(10) if rl.allow("10.0.0.2"))
        assert a == 3
        assert b == 3

    def test_rate_limited_count_increments(self):
        from collector.listeners.syslog_listener import SyslogListener
        pipe = Pipeline(source_id="rl-test")
        listener = SyslogListener(
            pipeline=pipe,
            db_factory=lambda: None,
            port=0,
            queue_size=50000,
            per_ip_max_eps=3,
            max_eps=100000,
        )
        ip = "10.0.0.77"
        for _ in range(10):
            listener.ingest("srcip=1.1.1.1 dstip=2.2.2.2 action=allow", source_ip=ip)
        assert listener.rate_limited_count == 7   # 10 - 3 allowed
        assert listener._queue.qsize() == 3


class TestSyslogListenerQueue:
    """Verify the queue-based ingestion path and drop counter."""

    def test_queue_ingestion_end_to_end(self, db_session):
        """Lines enqueued via ingest() flow through the queue → consumer
        → pipeline → buffer and are flushed to the DB."""
        import time
        from collector.listeners.syslog_listener import SyslogListener

        pipe = Pipeline(source_id="q-test")
        listener = SyslogListener(
            pipeline=pipe,
            db_factory=lambda: db_session,
            port=0,           # we won't actually bind
            queue_size=100,
            batch_size=999,   # disable batch-triggered flush
        )
        # Start only the consumer + flush threads (not the sockets)
        listener._running = True
        listener._consumer_thread = __import__("threading").Thread(
            target=listener._consume_loop, daemon=True,
        )
        listener._consumer_thread.start()

        # Enqueue lines directly
        listener.ingest(_FG_NATIVE)
        listener.ingest(_PA_TRAFFIC)
        listener.ingest("garbage that will be dropped by parser")

        # Give the consumer time to process
        time.sleep(0.3)

        assert pipe.stats["received"] == 3
        assert pipe.stats["parsed"] == 2
        assert pipe.buffer_size == 2

        # Flush manually
        n = pipe.flush(db_session)
        assert n == 2
        assert db_session.query(LiveEventModel).count() == 2

        listener._running = False

    def test_dropped_count_increments_on_full_queue(self):
        """When the queue is full, ingest() drops the line and increments
        the counter instead of blocking."""
        from collector.listeners.syslog_listener import SyslogListener

        pipe = Pipeline(source_id="drop-test")
        listener = SyslogListener(
            pipeline=pipe,
            db_factory=lambda: None,
            port=0,
            queue_size=5,     # tiny queue
        )
        # Do NOT start consumer — queue will fill up
        assert listener.dropped_count == 0
        for _ in range(10):
            listener.ingest("srcip=1.1.1.1 dstip=2.2.2.2 action=allow")
        # 5 fit in queue, 5 dropped
        assert listener.dropped_count == 5
        assert listener._queue.qsize() == 5


class TestSyslogPriorityStrip:

    def test_strip_priority(self):
        assert _strip_syslog_priority("<134>hello world") == "hello world"

    def test_strip_low_number(self):
        assert _strip_syslog_priority("<0>msg") == "msg"

    def test_no_prefix(self):
        assert _strip_syslog_priority("no prefix here") == "no prefix here"

    def test_partial_prefix(self):
        assert _strip_syslog_priority("<abc>msg") == "<abc>msg"


# ══════════════════════════════════════════════════════════════════════════════
# REST API endpoints
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def seeded(db_session):
    uid = _seed_user(db_session)
    for i in range(8):
        db_session.add(LiveEventModel(
            source_id="fw01",
            device_type="firewall",
            device_role="perimeter",
            parser_id="generic_kv",
            event_time=datetime(2025, 4, 13, 10, 0, i),
            source_ip=f"10.0.0.{i % 3}",
            destination_ip="8.8.8.8" if i < 5 else "1.1.1.1",
            source_port=50000 + i,
            destination_port=443 if i < 6 else 80,
            protocol="TCP",
            action="allow" if i < 5 else "deny",
            application="SSL" if i < 5 else None,
            bytes_in=1000 * i,
            bytes_out=500 * i,
        ))
    db_session.commit()
    client = _make_client(db_session, uid)
    return SimpleNamespace(db=db_session, uid=uid, client=client)


class TestLiveEventsEndpoint:

    def test_list_returns_200(self, seeded):
        r = seeded.client.get("/api/live-events")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 8
        assert len(body["events"]) == 8

    def test_newest_first_ordering(self, seeded):
        rows = seeded.client.get("/api/live-events").json()["events"]
        times = [r["event_time"] for r in rows]
        assert times == sorted(times, reverse=True)

    def test_filter_by_action(self, seeded):
        body = seeded.client.get("/api/live-events?action=deny").json()
        assert body["total"] == 3
        assert all(e["action"] == "deny" for e in body["events"])

    def test_filter_by_source_ip(self, seeded):
        body = seeded.client.get("/api/live-events?source_ip=10.0.0.0").json()
        assert body["total"] >= 1
        assert all(e["source_ip"] == "10.0.0.0" for e in body["events"])

    def test_filter_by_destination_ip(self, seeded):
        body = seeded.client.get("/api/live-events?destination_ip=1.1.1.1").json()
        assert body["total"] == 3

    def test_filter_by_protocol(self, seeded):
        body = seeded.client.get("/api/live-events?protocol=tcp").json()
        assert body["total"] == 8  # all TCP

    def test_filter_by_application(self, seeded):
        body = seeded.client.get("/api/live-events?application=SSL").json()
        assert body["total"] == 5

    def test_pagination(self, seeded):
        body = seeded.client.get("/api/live-events?limit=3&offset=2").json()
        assert len(body["events"]) == 3
        assert body["offset"] == 2
        assert body["total"] == 8

    def test_combined_filters(self, seeded):
        body = seeded.client.get(
            "/api/live-events?action=allow&destination_ip=8.8.8.8"
        ).json()
        assert body["total"] == 5
        assert all(
            e["action"] == "allow" and e["destination_ip"] == "8.8.8.8"
            for e in body["events"]
        )

    def test_empty_result(self, seeded):
        body = seeded.client.get("/api/live-events?source_ip=99.99.99.99").json()
        assert body["total"] == 0
        assert body["events"] == []


class TestLiveEventsStatsEndpoint:

    def test_stats_shape(self, seeded):
        r = seeded.client.get("/api/live-events/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["total_events"] == 8
        assert "by_action" in body
        assert "by_device_type" in body
        assert "by_parser" in body
        assert "top_sources" in body
        assert "top_destinations" in body
        assert "top_denied_sources" in body
        assert "collector" in body

    def test_action_counts(self, seeded):
        stats = seeded.client.get("/api/live-events/stats").json()
        assert stats["by_action"]["allow"] == 5
        assert stats["by_action"]["deny"] == 3

    def test_top_destinations(self, seeded):
        stats = seeded.client.get("/api/live-events/stats").json()
        dsts = {d["ip"]: d["count"] for d in stats["top_destinations"]}
        assert dsts["8.8.8.8"] == 5
        assert dsts["1.1.1.1"] == 3

    def test_top_denied_sources(self, seeded):
        stats = seeded.client.get("/api/live-events/stats").json()
        assert len(stats["top_denied_sources"]) >= 1


class TestTimelineEndpoint:

    def test_empty_returns_empty_list(self, seeded):
        # Seed has data but at fixed times in 2025 — timeline default
        # window is last 60 minutes, so nothing matches.
        r = seeded.client.get("/api/live-events/timeline?minutes=60")
        assert r.status_code == 200
        assert r.json() == []

    def test_events_bucketed_by_minute(self, db_session):
        uid = _seed_user(db_session, "tl_user")
        now = datetime.utcnow()
        from datetime import timedelta
        # 5 events at minute :00, 3 events at minute :01, 2 deny at :01
        for i in range(5):
            db_session.add(LiveEventModel(
                source_id="fw01", device_type="firewall", parser_id="test",
                event_time=now - timedelta(minutes=2, seconds=i),
                source_ip="10.0.0.1", destination_ip="10.0.0.2",
                protocol="TCP", action="allow",
            ))
        for i in range(3):
            db_session.add(LiveEventModel(
                source_id="fw01", device_type="firewall", parser_id="test",
                event_time=now - timedelta(minutes=1, seconds=i),
                source_ip="10.0.0.1", destination_ip="10.0.0.2",
                protocol="TCP", action="allow",
            ))
        for i in range(2):
            db_session.add(LiveEventModel(
                source_id="fw01", device_type="firewall", parser_id="test",
                event_time=now - timedelta(minutes=1, seconds=30 + i),
                source_ip="10.0.0.1", destination_ip="10.0.0.2",
                protocol="TCP", action="deny",
            ))
        db_session.commit()

        client = _make_client(db_session, uid)
        r = client.get("/api/live-events/timeline?minutes=10")
        assert r.status_code == 200
        buckets = r.json()
        assert len(buckets) >= 2
        # Total allows across all buckets should be 8 (5+3)
        total_allow = sum(b["allow"] for b in buckets)
        assert total_allow == 8
        # Total denies should be 2
        total_deny = sum(b["deny"] for b in buckets)
        assert total_deny == 2
        # Each bucket has the expected keys
        for b in buckets:
            assert "bucket" in b
            assert "allow" in b
            assert "deny" in b
            assert "drop" in b

    def test_minutes_capped_at_1440(self, seeded):
        r = seeded.client.get("/api/live-events/timeline?minutes=9999")
        assert r.status_code == 422  # validation error


class TestCollectorStatusEndpoint:

    def test_returns_200(self, db_session):
        uid = _seed_user(db_session)
        client = _make_client(db_session, uid)
        r = client.get("/api/collector/status")
        assert r.status_code == 200
        body = r.json()
        assert "enabled" in body
        assert "running" in body
        assert "syslog_port" in body


# ══════════════════════════════════════════════════════════════════════════════
# Bridge — scan_live_events pattern detection
# ══════════════════════════════════════════════════════════════════════════════

def _seed_admin(db):
    """Ensure user id=1 exists (admin, the notification target)."""
    from database import UserModel
    if not db.query(UserModel).filter(UserModel.id == 1).first():
        u = UserModel(username="admin", hashed_password="x")
        db.add(u)
        db.flush()
        db.commit()


def _bulk_events(db, n, *, src="10.0.0.99", dst="10.0.0.1",
                 action="deny", port=443, time_offset_minutes=2):
    """Insert *n* identical live events with event_time inside the window."""
    now = datetime.utcnow()
    for i in range(n):
        db.add(LiveEventModel(
            source_id="fw01", device_type="firewall",
            parser_id="generic_kv",
            event_time=now - timedelta(minutes=time_offset_minutes, seconds=i),
            source_ip=src, destination_ip=dst,
            source_port=50000 + i, destination_port=port,
            protocol="TCP", action=action,
        ))
    db.commit()


def _bulk_flows(db, n, *, src="10.0.0.99", dst="10.0.0.1",
                state="denied", port=443, time_offset_minutes=2,
                raw_event_count=5):
    """Insert *n* LiveFlowModel rows."""
    now = datetime.utcnow()
    for i in range(n):
        deny_c = raw_event_count if state in ("denied", "dropped") else 0
        allow_c = raw_event_count if state == "completed" else 0
        reset_c = raw_event_count if state == "reset" else 0
        db.add(LiveFlowModel(
            source_id="fw01", device_type="firewall", parser_id="test",
            source_ip=src, destination_ip=dst,
            source_port=50000 + i, destination_port=port,
            protocol="TCP",
            first_seen=now - timedelta(minutes=time_offset_minutes, seconds=i + 10),
            last_seen=now - timedelta(minutes=time_offset_minutes, seconds=i),
            event_count=raw_event_count,
            total_bytes_in=1000, total_bytes_out=500,
            total_packets_in=10, total_packets_out=5,
            allow_count=allow_c, deny_count=deny_c, drop_count=0,
            reset_count=reset_c, alert_count=0,
            action_summary="mostly_deny" if state == "denied" else state,
            state=state,
            raw_event_count=raw_event_count,
        ))
    db.commit()


class TestNetflowParsing:
    """NetFlow v9 / IPFIX header parsing, template caching, and flow decoding."""

    def _build_v9_packet(self, flowsets_data: bytes, count: int = 0,
                          unix_secs: int = 1681387200, source_id: int = 1):
        """Build a minimal NetFlow v9 packet with the given FlowSet payload."""
        header = struct.pack("!HHIIII",
            9,           # version
            count,       # count
            0,           # uptime
            unix_secs,   # unix_secs
            0,           # sequence
            source_id,   # source_id
        )
        return header + flowsets_data

    def _build_template_flowset(self, template_id: int, fields: list):
        """Build a Template FlowSet (id=0) with one template record."""
        body = struct.pack("!HH", template_id, len(fields))
        for ftype, flen in fields:
            body += struct.pack("!HH", ftype, flen)
        fs_header = struct.pack("!HH", 0, 4 + len(body))
        return fs_header + body

    def _build_data_flowset(self, template_id: int, records: list):
        """Build a Data FlowSet with pre-packed record bytes."""
        body = b"".join(records)
        fs_header = struct.pack("!HH", template_id, 4 + len(body))
        return fs_header + body

    def test_v9_header_parsing(self):
        from collector.listeners.netflow_listener import parse_header
        pkt = self._build_v9_packet(b"", count=5, unix_secs=1681387200, source_id=42)
        h = parse_header(pkt)
        assert h is not None
        assert h.version == 9
        assert h.count == 5
        assert h.unix_secs == 1681387200
        assert h.source_id == 42

    def test_template_flowset_stored(self):
        from collector.listeners.netflow_listener import (
            parse_header, parse_flowsets, TemplateCache,
            FIELD_IPV4_SRC_ADDR, FIELD_IPV4_DST_ADDR,
            FIELD_L4_SRC_PORT, FIELD_L4_DST_PORT, FIELD_PROTOCOL,
        )
        cache = TemplateCache()
        fields = [
            (FIELD_IPV4_SRC_ADDR, 4),
            (FIELD_IPV4_DST_ADDR, 4),
            (FIELD_L4_SRC_PORT, 2),
            (FIELD_L4_DST_PORT, 2),
            (FIELD_PROTOCOL, 1),
        ]
        tpl_fs = self._build_template_flowset(256, fields)
        pkt = self._build_v9_packet(tpl_fs, source_id=10)
        header = parse_header(pkt)
        parse_flowsets(pkt, header, cache)
        assert cache.count == 1
        stored = cache.get(10, 256)
        assert stored is not None
        assert len(stored) == 5
        assert stored[0] == (FIELD_IPV4_SRC_ADDR, 4)

    def test_data_flowset_decoded(self):
        from collector.listeners.netflow_listener import (
            parse_header, parse_flowsets, TemplateCache,
            FIELD_IPV4_SRC_ADDR, FIELD_IPV4_DST_ADDR,
            FIELD_L4_SRC_PORT, FIELD_L4_DST_PORT, FIELD_PROTOCOL,
        )
        cache = TemplateCache()
        fields = [
            (FIELD_IPV4_SRC_ADDR, 4),
            (FIELD_IPV4_DST_ADDR, 4),
            (FIELD_L4_SRC_PORT, 2),
            (FIELD_L4_DST_PORT, 2),
            (FIELD_PROTOCOL, 1),
        ]
        # Pre-populate template
        cache.put(1, 256, fields)
        # Build a data record: 10.0.0.1 → 10.0.0.2 :12345 → :443 TCP(6)
        record = (
            socket.inet_aton("10.0.0.1")
            + socket.inet_aton("10.0.0.2")
            + struct.pack("!H", 12345)
            + struct.pack("!H", 443)
            + struct.pack("!B", 6)
        )
        data_fs = self._build_data_flowset(256, [record])
        pkt = self._build_v9_packet(data_fs, source_id=1)
        header = parse_header(pkt)
        flows = parse_flowsets(pkt, header, cache)
        assert len(flows) == 1
        f = flows[0]
        assert f["source_ip"] == "10.0.0.1"
        assert f["destination_ip"] == "10.0.0.2"
        assert f["source_port"] == 12345
        assert f["destination_port"] == 443
        assert f["protocol"] == "TCP"
        assert f["action"] == "allow"

    def test_ipfix_header_parsing(self):
        from collector.listeners.netflow_listener import parse_header
        # IPFIX header: version=10, length=16, export_time, seq, obs_domain
        hdr = struct.pack("!HHIII", 10, 16, 1681387200, 0, 99)
        h = parse_header(hdr)
        assert h is not None
        assert h.version == 10
        assert h.export_time == 1681387200
        assert h.observation_domain == 99

    def test_process_flow_builds_event(self):
        pipe = Pipeline(source_id="router01", device_role="internal")
        flow = {
            "event_time": datetime(2025, 4, 13, 12, 0, 0),
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 55000,
            "destination_port": 80,
            "protocol": "TCP",
            "action": "allow",
            "bytes_in": 5000,
            "bytes_out": 300,
        }
        event = pipe.process_flow(flow, parser_id="netflow_v9")
        assert event is not None
        assert event["source_id"] == "router01"
        assert event["device_type"] == "flow_exporter"
        assert event["parser_id"] == "netflow_v9"
        assert event["source_ip"] == "10.0.0.1"
        assert event["bytes_in"] == 5000
        assert event["action"] == "allow"

    def test_unknown_template_silently_skipped(self):
        from collector.listeners.netflow_listener import (
            parse_header, parse_flowsets, TemplateCache,
        )
        cache = TemplateCache()
        # Data FlowSet referencing template 999 which doesn't exist
        data_fs = struct.pack("!HH", 999, 4 + 13)  # header + dummy bytes
        data_fs += b"\x00" * 13
        pkt = self._build_v9_packet(data_fs, source_id=1)
        header = parse_header(pkt)
        flows = parse_flowsets(pkt, header, cache)
        assert flows == []


class TestBridgeScan:

    def test_zero_flows_returns_zero(self, db_session):
        _seed_admin(db_session)
        assert scan_live_events(db_session) == 0

    def test_blocked_flow_spike_detected(self, db_session):
        _seed_admin(db_session)
        _bulk_flows(db_session, BLOCKED_FLOW_THRESHOLD + 1, state="denied")
        n = scan_live_events(db_session)
        assert n >= 1
        notif = (
            db_session.query(NotificationModel)
            .filter(NotificationModel.type == "drift_detected")
            .first()
        )
        assert notif is not None
        assert "BLOCKED FLOW SPIKE" in notif.message
        assert "10.0.0.99" in notif.message

    def test_port_scan_detected(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        # 12 flows to 12 distinct dst IPs → > PORT_SCAN_DST_THRESHOLD (10)
        for i in range(PORT_SCAN_DST_THRESHOLD + 2):
            db_session.add(LiveFlowModel(
                source_id="fw01", device_type="firewall", parser_id="test",
                source_ip="10.0.0.88",
                destination_ip=f"10.0.{i // 256}.{i % 256 + 1}",
                source_port=50000 + i, destination_port=443,
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=3, total_bytes_in=0, total_bytes_out=0,
                total_packets_in=0, total_packets_out=0,
                allow_count=3, deny_count=0, drop_count=0,
                reset_count=0, alert_count=0,
                state="completed", raw_event_count=3,
            ))
        db_session.commit()
        n = scan_live_events(db_session)
        assert n >= 1
        notif = (
            db_session.query(NotificationModel)
            .filter(NotificationModel.message.contains("PORT SCAN"))
            .first()
        )
        assert notif is not None
        assert "10.0.0.88" in notif.message

    def test_repeated_reset_detected(self, db_session):
        _seed_admin(db_session)
        _bulk_flows(
            db_session, RESET_FLOW_THRESHOLD + 1,
            src="10.0.0.77", dst="10.0.0.2", state="reset",
        )
        n = scan_live_events(db_session)
        assert n >= 1
        notif = (
            db_session.query(NotificationModel)
            .filter(NotificationModel.message.contains("REPEATED RESET"))
            .first()
        )
        assert notif is not None
        assert "10.0.0.77" in notif.message

    def test_duplicate_notification_suppressed(self, db_session):
        _seed_admin(db_session)
        _bulk_flows(db_session, BLOCKED_FLOW_THRESHOLD + 1, state="denied")
        n1 = scan_live_events(db_session)
        assert n1 >= 1
        count_after_first = (
            db_session.query(NotificationModel)
            .filter(NotificationModel.type == "drift_detected")
            .count()
        )
        # Second scan: same data — per-flow pattern notifications should
        # not duplicate.  Incident-based notifications use dedup too.
        scan_live_events(db_session)
        # Third scan: everything already notified
        scan_live_events(db_session)
        count_after_third = (
            db_session.query(NotificationModel)
            .filter(NotificationModel.type == "drift_detected")
            .count()
        )
        # No new notifications on the third pass
        count_before_fourth = count_after_third
        scan_live_events(db_session)
        count_after_fourth = (
            db_session.query(NotificationModel)
            .filter(NotificationModel.type == "drift_detected")
            .count()
        )
        assert count_after_fourth == count_before_fourth

    def test_scanning_flow_type_triggers_notification(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        for i in range(4):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.55", destination_ip=f"10.0.{i}.1",
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=1, total_bytes_in=0, total_bytes_out=0,
                total_packets_in=0, total_packets_out=0,
                allow_count=0, deny_count=1, drop_count=0,
                reset_count=0, alert_count=0,
                state="denied", flow_type="scanning",
                raw_event_count=1,
            ))
        db_session.commit()
        n = scan_live_events(db_session)
        assert n >= 1
        notif = db_session.query(NotificationModel).filter(
            NotificationModel.message.contains("SCANNING")
        ).first()
        assert notif is not None
        assert "10.0.0.55" in notif.message

    def test_suspicious_flow_type_triggers_notification(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        for i in range(3):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.66", destination_ip="10.0.0.1",
                source_port=50000 + i, destination_port=443,
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=5, total_bytes_in=500, total_bytes_out=100,
                total_packets_in=0, total_packets_out=0,
                allow_count=2, deny_count=0, drop_count=0,
                reset_count=3, alert_count=0,
                state="reset", flow_type="suspicious",
                raw_event_count=5,
            ))
        db_session.commit()
        n = scan_live_events(db_session)
        assert n >= 1
        notif = db_session.query(NotificationModel).filter(
            NotificationModel.message.contains("SUSPICIOUS")
        ).first()
        assert notif is not None


# ══════════════════════════════════════════════════════════════════════════════
# Bridge — SuppressionRule integration with live events
# ══════════════════════════════════════════════════════════════════════════════

def _seed_suppression_rule(
    db, *, src_ip=None, dst_ip=None, rule_id=None,
    reason="test suppression", is_active=True, expires_at=None,
):
    r = SuppressionRuleModel(
        scope="global",
        src_ip=src_ip,
        dst_ip=dst_ip,
        rule_id=rule_id,
        reason=reason,
        is_active=is_active,
        expires_at=expires_at,
    )
    db.add(r)
    db.commit()
    return r


class TestBridgeSuppressionRules:

    def test_active_src_ip_rule_sets_suppressed_flag_on_events(self, db_session):
        _seed_admin(db_session)
        _bulk_events(db_session, 3, src="10.0.0.99", dst="10.0.0.1", action="allow")
        _seed_suppression_rule(db_session, src_ip="10.0.0.99", reason="known scanner")
        n = apply_suppressions(db_session)
        assert n == 1
        rows = db_session.query(LiveEventModel).all()
        for r in rows:
            assert r.suppressed is True

    def test_suppression_sets_flag_on_flows(self, db_session):
        _seed_admin(db_session)
        _bulk_flows(db_session, 2, src="10.0.0.99", dst="10.0.0.1", state="denied")
        _seed_suppression_rule(db_session, src_ip="10.0.0.99", reason="known scanner")
        n = apply_suppressions(db_session)
        assert n >= 1
        flows = db_session.query(LiveFlowModel).all()
        for f in flows:
            assert f.suppressed is True

    def test_expired_rule_does_not_suppress(self, db_session):
        _seed_admin(db_session)
        _bulk_events(db_session, 3, src="10.0.0.88", dst="10.0.0.1", action="allow")
        past = datetime.utcnow() - timedelta(hours=1)
        _seed_suppression_rule(db_session, src_ip="10.0.0.88", reason="old", expires_at=past)
        n = apply_suppressions(db_session)
        assert n == 0

    def test_inactive_rule_does_not_suppress(self, db_session):
        _seed_admin(db_session)
        _bulk_events(db_session, 3, src="10.0.0.77", dst="10.0.0.1", action="allow")
        _seed_suppression_rule(db_session, src_ip="10.0.0.77", reason="disabled", is_active=False)
        n = apply_suppressions(db_session)
        assert n == 0

    def test_dst_ip_rule_matches(self, db_session):
        _seed_admin(db_session)
        _bulk_events(db_session, 5, src="10.0.0.50", dst="10.0.0.200", action="allow")
        _seed_suppression_rule(db_session, dst_ip="10.0.0.200", reason="dst suppressed")
        n = apply_suppressions(db_session)
        assert n == 1

    def test_scan_skips_notification_for_suppressed_src(self, db_session):
        _seed_admin(db_session)
        _bulk_flows(db_session, BLOCKED_FLOW_THRESHOLD + 1, src="10.0.0.99", state="denied")
        _seed_suppression_rule(db_session, src_ip="10.0.0.99", reason="known scanner")
        n = scan_live_events(db_session)
        assert n == 0


# ══════════════════════════════════════════════════════════════════════════════
# Intelligence scanner
# ══════════════════════════════════════════════════════════════════════════════

def _seed_completed_analysis(db, uid, *, file_path="/nonexistent.pcap",
                              aid="ana-intel-1", src_ip="10.0.0.99",
                              dst_ip="10.0.0.1"):
    """Seed a completed analysis whose result_json mentions the given IPs."""
    from database import AnalysisModel
    result_json = json.dumps({
        "findings": [],
        "hosts": {src_ip: {}, dst_ip: {}},
    })
    db.add(AnalysisModel(
        id=aid, user_id=uid, filename="test.pcap",
        file_path=file_path, status="completed",
        result_json=result_json,
        finished_at=datetime.utcnow(),
    ))
    db.commit()
    return aid


class TestIntelligenceScan:

    def test_connection_blocked_triggers(self, db_session, tmp_pcap):
        """≥ 2 denied flows for src→dst triggers analysis."""
        uid = _seed_user(db_session, "intel_user")
        _seed_completed_analysis(db_session, uid, file_path=tmp_pcap,
                                  src_ip="10.0.0.99", dst_ip="10.0.0.1")
        _bulk_flows(db_session, 3, src="10.0.0.99", dst="10.0.0.1",
                    state="denied", time_offset_minutes=2)
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "connection_outcome": "failure",
            "primary_impairment": "firewall_interference",
            "path_confidence_score": 80,
        }
        mock_cls = MagicMock()
        mock_cls.return_value.analyze.return_value = mock_result
        with patch("normalizer.pipeline.normalize", return_value=MagicMock(
            packets=[], flows={}, findings=[],
        )), patch("core.causal_path.CausalPathEngine", mock_cls):
            result = run_intelligence_scan(db_session)
        assert result["triggers"] >= 1
        notif = db_session.query(NotificationModel).filter(
            NotificationModel.message.contains("[AUTO]")).first()
        assert notif is not None
        assert "10.0.0.99" in notif.message

    def test_connection_unstable_triggers(self, db_session, tmp_pcap):
        """≥ 2 reset flows for src→dst triggers analysis."""
        uid = _seed_user(db_session, "intel2")
        _seed_completed_analysis(db_session, uid, file_path=tmp_pcap,
                                  src_ip="10.0.0.88", dst_ip="10.0.0.2")
        _bulk_flows(db_session, 3, src="10.0.0.88", dst="10.0.0.2",
                    state="reset", time_offset_minutes=2)
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "connection_outcome": "failure",
            "primary_impairment": "connection_refused",
            "path_confidence_score": 70,
        }
        mock_cls = MagicMock()
        mock_cls.return_value.analyze.return_value = mock_result
        with patch("normalizer.pipeline.normalize", return_value=MagicMock(
            packets=[], flows={}, findings=[],
        )), patch("core.causal_path.CausalPathEngine", mock_cls):
            result = run_intelligence_scan(db_session)
        assert result["triggers"] >= 1

    def test_slow_connection_triggers(self, db_session, tmp_pcap):
        """Completed flow with duration > 30s triggers analysis."""
        uid = _seed_user(db_session, "intel_slow")
        _seed_completed_analysis(db_session, uid, file_path=tmp_pcap,
                                  src_ip="10.0.0.55", dst_ip="10.0.0.5")
        now = datetime.utcnow()
        db_session.add(LiveFlowModel(
            source_id="fw", device_type="firewall", parser_id="test",
            source_ip="10.0.0.55", destination_ip="10.0.0.5",
            protocol="TCP",
            first_seen=now - timedelta(minutes=5),
            last_seen=now - timedelta(minutes=2),
            duration_ms=45000,
            event_count=10, total_bytes_in=0, total_bytes_out=0,
            total_packets_in=0, total_packets_out=0,
            allow_count=10, deny_count=0, drop_count=0,
            reset_count=0, alert_count=0,
            state="completed", raw_event_count=10,
        ))
        db_session.commit()
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "connection_outcome": "failure",
            "primary_impairment": "backend_response_delay",
            "path_confidence_score": 75,
        }
        mock_cls = MagicMock()
        mock_cls.return_value.analyze.return_value = mock_result
        with patch("normalizer.pipeline.normalize", return_value=MagicMock(
            packets=[], flows={}, findings=[],
        )), patch("core.causal_path.CausalPathEngine", mock_cls):
            result = run_intelligence_scan(db_session)
        assert result["triggers"] >= 1

    def test_no_analysis_found_skipped(self, db_session):
        _seed_admin(db_session)
        _bulk_flows(db_session, 3, src="10.99.99.99", dst="10.99.99.1",
                    state="denied", time_offset_minutes=2)
        result = run_intelligence_scan(db_session)
        assert result["triggers"] == 0
        assert result["skipped"] >= 1

    def test_cooldown_respected(self, db_session, tmp_pcap):
        uid = _seed_user(db_session, "intel3")
        _seed_completed_analysis(db_session, uid, file_path=tmp_pcap,
                                  src_ip="10.0.0.77", dst_ip="10.0.0.3")
        _bulk_flows(db_session, 3, src="10.0.0.77", dst="10.0.0.3",
                    state="denied", time_offset_minutes=2)
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "connection_outcome": "success",
            "primary_impairment": None,
            "path_confidence_score": 95,
        }
        mock_cls = MagicMock()
        mock_cls.return_value.analyze.return_value = mock_result
        with patch("normalizer.pipeline.normalize", return_value=MagicMock(
            packets=[], flows={}, findings=[],
        )), patch("core.causal_path.CausalPathEngine", mock_cls):
            r1 = run_intelligence_scan(db_session)
            assert r1["triggers"] >= 1
            r2 = run_intelligence_scan(db_session)
            assert r2["triggers"] == 0
            assert r2["skipped"] >= 1

    def test_clean_result_no_notification(self, db_session, tmp_pcap):
        uid = _seed_user(db_session, "intel4")
        _seed_completed_analysis(db_session, uid, file_path=tmp_pcap,
                                  src_ip="10.0.0.66", dst_ip="10.0.0.4")
        _bulk_flows(db_session, 3, src="10.0.0.66", dst="10.0.0.4",
                    state="denied", time_offset_minutes=2)
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "connection_outcome": "success",
            "primary_impairment": None,
            "path_confidence_score": 95,
        }
        mock_cls = MagicMock()
        mock_cls.return_value.analyze.return_value = mock_result
        with patch("normalizer.pipeline.normalize", return_value=MagicMock(
            packets=[], flows={}, findings=[],
        )), patch("core.causal_path.CausalPathEngine", mock_cls):
            run_intelligence_scan(db_session)
        notifs = db_session.query(NotificationModel).filter(
            NotificationModel.message.contains("[AUTO]")).all()
        assert len(notifs) == 0

    def test_suspicious_flow_type_auto_triggers(self, db_session, tmp_pcap):
        """flow_type='suspicious' triggers analysis automatically."""
        uid = _seed_user(db_session, "intel_sus")
        _seed_completed_analysis(db_session, uid, file_path=tmp_pcap,
                                  src_ip="10.0.0.44", dst_ip="10.0.0.5")
        now = datetime.utcnow()
        db_session.add(LiveFlowModel(
            source_id="fw", device_type="firewall", parser_id="test",
            source_ip="10.0.0.44", destination_ip="10.0.0.5",
            protocol="TCP",
            first_seen=now - timedelta(minutes=5),
            last_seen=now - timedelta(minutes=2),
            event_count=8, total_bytes_in=500, total_bytes_out=100,
            total_packets_in=0, total_packets_out=0,
            allow_count=3, deny_count=0, drop_count=0,
            reset_count=5, alert_count=0,
            state="reset", flow_type="suspicious",
            raw_event_count=8,
        ))
        db_session.commit()
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "connection_outcome": "failure",
            "primary_impairment": "connection_refused",
            "path_confidence_score": 60,
        }
        mock_cls = MagicMock()
        mock_cls.return_value.analyze.return_value = mock_result
        with patch("normalizer.pipeline.normalize", return_value=MagicMock(
            packets=[], flows={}, findings=[],
        )), patch("core.causal_path.CausalPathEngine", mock_cls):
            result = run_intelligence_scan(db_session)
        assert result["triggers"] >= 1

    def test_scanning_flow_type_auto_triggers(self, db_session, tmp_pcap):
        """flow_type='scanning' with ≥2 flows triggers analysis."""
        uid = _seed_user(db_session, "intel_scan")
        _seed_completed_analysis(db_session, uid, file_path=tmp_pcap,
                                  src_ip="10.0.0.33", dst_ip="10.0.0.6")
        now = datetime.utcnow()
        for i in range(3):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.33", destination_ip="10.0.0.6",
                source_port=50000 + i, destination_port=22 + i,
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=1, total_bytes_in=0, total_bytes_out=0,
                total_packets_in=0, total_packets_out=0,
                allow_count=0, deny_count=1, drop_count=0,
                reset_count=0, alert_count=0,
                state="denied", flow_type="scanning",
                raw_event_count=1,
            ))
        db_session.commit()
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "connection_outcome": "failure",
            "primary_impairment": "firewall_interference",
            "path_confidence_score": 70,
        }
        mock_cls = MagicMock()
        mock_cls.return_value.analyze.return_value = mock_result
        with patch("normalizer.pipeline.normalize", return_value=MagicMock(
            packets=[], flows={}, findings=[],
        )), patch("core.causal_path.CausalPathEngine", mock_cls):
            result = run_intelligence_scan(db_session)
        assert result["triggers"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# Live risk scoring
# ══════════════════════════════════════════════════════════════════════════════

class TestLiveRiskScoring:

    def test_high_deny_rate_from_flows(self, db_session):
        # 3 denied + 1 completed = 4 flows, deny_rate 3/4 = 75% → +40
        _bulk_flows(db_session, 3, src="10.1.1.1", dst="10.2.2.2", state="denied")
        _bulk_flows(db_session, 1, src="10.1.1.1", dst="10.2.2.2", state="completed")
        entries = compute_live_risk_scores(db_session)
        e = next((x for x in entries if x["source_ip"] == "10.1.1.1"), None)
        assert e is not None
        assert e["risk_score"] >= 20
        assert "deny_rate_high" in e["drivers"] or "deny_rate_elevated" in e["drivers"]

    def test_lateral_movement_from_flows(self, db_session):
        now = datetime.utcnow()
        for i in range(25):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="t",
                source_ip="10.3.3.3",
                destination_ip=f"10.0.{i // 256}.{i % 256 + 1}",
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=5, total_bytes_in=0, total_bytes_out=0,
                total_packets_in=0, total_packets_out=0,
                allow_count=5, deny_count=0, drop_count=0,
                reset_count=0, alert_count=0,
                state="completed", raw_event_count=5,
            ))
        db_session.commit()
        entries = compute_live_risk_scores(db_session)
        e = next(x for x in entries if x["source_ip"] == "10.3.3.3")
        assert e["risk_score"] >= 25
        assert "lateral_movement" in e["drivers"]

    def test_high_volume_from_flows(self, db_session):
        # 5 flows × raw_event_count=250 = 1250 total events → +15
        _bulk_flows(db_session, 5, src="10.4.4.4", dst="10.5.5.5",
                    state="completed", raw_event_count=250)
        entries = compute_live_risk_scores(db_session)
        e = next(x for x in entries if x["source_ip"] == "10.4.4.4")
        assert e["risk_score"] >= 15
        assert "high_volume" in e["drivers"]

    def test_min_risk_score_filter(self, db_session):
        uid = _seed_user(db_session, "risk_user")
        # Low risk: 3 completed flows
        _bulk_flows(db_session, 3, src="10.7.7.7", dst="10.8.8.8", state="completed")
        # High risk: 3 denied flows
        _bulk_flows(db_session, 3, src="10.9.9.9", dst="10.8.8.8", state="denied")
        client = _make_client(db_session, uid)
        r = client.get("/api/live-events/risk-scores")
        assert r.status_code == 200
        all_e = r.json()
        r2 = client.get("/api/live-events/risk-scores?min_risk_score=30")
        filtered = r2.json()
        assert all(e["risk_score"] >= 30 for e in filtered)

    def test_ip_below_min_flows_excluded(self, db_session):
        # Only 2 flows → below MIN_FLOWS (3)
        _bulk_flows(db_session, 2, src="10.99.99.99", dst="10.1.1.1", state="denied")
        entries = compute_live_risk_scores(db_session)
        ips = [e["source_ip"] for e in entries]
        assert "10.99.99.99" not in ips

    def test_scanning_flow_type_boosts_risk(self, db_session):
        now = datetime.utcnow()
        for i in range(4):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="t",
                source_ip="10.50.50.50", destination_ip=f"10.0.{i}.1",
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=2, total_bytes_in=0, total_bytes_out=0,
                total_packets_in=0, total_packets_out=0,
                allow_count=0, deny_count=2, drop_count=0,
                reset_count=0, alert_count=0,
                state="denied", flow_type="scanning",
                raw_event_count=2,
            ))
        db_session.commit()
        entries = compute_live_risk_scores(db_session)
        e = next(x for x in entries if x["source_ip"] == "10.50.50.50")
        assert "scanning_behavior" in e["drivers"]
        assert e["scanning_count"] >= 3
        # Score should include scanning bonus (+20)
        assert e["risk_score"] >= 20

    def test_suspicious_flow_type_boosts_risk(self, db_session):
        now = datetime.utcnow()
        for i in range(3):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="t",
                source_ip="10.60.60.60", destination_ip="10.0.0.1",
                source_port=50000 + i, destination_port=443,
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=5, total_bytes_in=500, total_bytes_out=100,
                total_packets_in=0, total_packets_out=0,
                allow_count=2, deny_count=0, drop_count=0,
                reset_count=3, alert_count=0,
                state="reset", flow_type="suspicious",
                raw_event_count=5,
            ))
        db_session.commit()
        entries = compute_live_risk_scores(db_session)
        e = next(x for x in entries if x["source_ip"] == "10.60.60.60")
        assert "suspicious_flows" in e["drivers"]
        assert e["suspicious_count"] >= 2


# ══════════════════════════════════════════════════════════════════════════════
# Auto-create monitored paths
# ══════════════════════════════════════════════════════════════════════════════

def _make_high_risk_flows(db, src, dst, n=25):
    """Insert flows that produce risk_score >= 60 for src.

    Strategy: deny_rate > 50% (+40) + >20 distinct destinations (+25)
    → total ≥ 65.
    """
    now = datetime.utcnow()
    for i in range(n):
        d = dst if i < 3 else f"10.200.{i // 256}.{i % 256 + 1}"
        state = "denied" if i < 15 else ("reset" if i < 19 else "completed")
        deny_c = 5 if state == "denied" else 0
        allow_c = 5 if state == "completed" else 0
        reset_c = 5 if state == "reset" else 0
        db.add(LiveFlowModel(
            source_id="fw", device_type="firewall", parser_id="t",
            source_ip=src, destination_ip=d,
            protocol="TCP",
            first_seen=now - timedelta(minutes=5, seconds=i),
            last_seen=now - timedelta(minutes=2, seconds=i),
            event_count=5, total_bytes_in=0, total_bytes_out=0,
            total_packets_in=0, total_packets_out=0,
            allow_count=allow_c, deny_count=deny_c, drop_count=0,
            reset_count=reset_c, alert_count=0,
            state=state, raw_event_count=5,
        ))
    db.commit()


class TestAutoCreateMonitoredPaths:

    def test_high_risk_pair_creates_sq_and_monitor(self, db_session, tmp_pcap):
        uid = _seed_admin(db_session)
        _seed_completed_analysis(
            db_session, uid or 1, file_path=tmp_pcap,
            src_ip="10.0.0.50", dst_ip="10.0.0.1",
        )
        _make_high_risk_flows(db_session, "10.0.0.50", "10.0.0.1")
        n = auto_create_monitored_paths(db_session)
        assert n >= 1
        sq = (
            db_session.query(PathAnalysisSavedQueryModel)
            .filter(PathAnalysisSavedQueryModel.source_ip == "10.0.0.50")
            .first()
        )
        assert sq is not None
        assert "auto:" in sq.name
        mp = (
            db_session.query(MonitoredPathModel)
            .filter(MonitoredPathModel.saved_query_id == sq.id)
            .first()
        )
        assert mp is not None
        assert mp.enabled is True
        assert mp.schedule_interval_minutes == 15

    def test_already_monitored_skipped(self, db_session, tmp_pcap):
        uid = _seed_admin(db_session)
        _seed_completed_analysis(
            db_session, uid or 1, file_path=tmp_pcap,
            src_ip="10.0.0.51", dst_ip="10.0.0.2",
        )
        _make_high_risk_flows(db_session, "10.0.0.51", "10.0.0.2")
        # First call creates
        n1 = auto_create_monitored_paths(db_session)
        assert n1 >= 1
        # Second call should skip (already exists)
        n2 = auto_create_monitored_paths(db_session)
        assert n2 == 0

    def test_no_analysis_found_skipped(self, db_session):
        _seed_admin(db_session)
        # No completed analysis exists
        _make_high_risk_flows(db_session, "10.99.1.1", "10.99.2.2")
        n = auto_create_monitored_paths(db_session)
        assert n == 0
        assert db_session.query(PathAnalysisSavedQueryModel).filter(
            PathAnalysisSavedQueryModel.source_ip == "10.99.1.1"
        ).count() == 0

    def test_low_risk_pair_not_created(self, db_session, tmp_pcap):
        uid = _seed_admin(db_session)
        _seed_completed_analysis(
            db_session, uid or 1, file_path=tmp_pcap,
            src_ip="10.0.0.52", dst_ip="10.0.0.3",
        )
        # Only 4 completed flows → low risk
        _bulk_flows(db_session, 4, src="10.0.0.52", dst="10.0.0.3", state="completed")
        n = auto_create_monitored_paths(db_session)
        assert n == 0
