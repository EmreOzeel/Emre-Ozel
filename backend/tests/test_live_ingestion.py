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
import sys
from datetime import datetime
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import Base, LiveEventModel, UserModel
from main import app, get_db

from collector.parsers.base import (
    BaseParser,
    clear_registry,
    detect_format,
    register_parser,
)
from collector.parsers.paloalto import PaloAltoParser
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
    register_parser(GenericKVParser())
    yield
    clear_registry()
    app.dependency_overrides.clear()


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
# detect_format auto-detection
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectFormat:

    def test_pa_detected_first(self):
        p = detect_format(_PA_TRAFFIC)
        assert p is not None
        assert p.PARSER_ID == "paloalto"

    def test_kv_fallback(self):
        p = detect_format(_FG_KV)
        assert p is not None
        assert p.PARSER_ID == "generic_kv"

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
        assert e["parser_id"] == "generic_kv"
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
