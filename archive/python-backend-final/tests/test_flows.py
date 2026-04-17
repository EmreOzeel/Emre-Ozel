"""
Tests for the flow/session engine layer.

Covers:
  - FlowEngine: creation, update/merge, key isolation, timeout flush,
    terminal states, action_summary derivation
  - DB persistence via LiveFlowModel
  - REST API: list + filter, stats shape
"""
from __future__ import annotations

import json
import os
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
from database import Base, LiveFlowModel, UserModel
from main import app, get_db
from collector.flows import FlowEngine, classify_flow, _ActiveFlow
from collector.flow_correlation import compute_flow_behaviors
from collector.incidents import compute_priority, upsert_incidents_from_behaviors
from database import AssetModel, LiveIncidentModel, NotificationModel


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
def clear_overrides():
    yield
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


def _event(
    src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=443,
    proto="TCP", action="allow", bytes_in=100, bytes_out=50,
    reason=None, application=None, event_time=None,
    source_id="fw01", device_type="firewall", parser_id="test",
):
    return {
        "source_ip": src, "destination_ip": dst,
        "source_port": sport, "destination_port": dport,
        "protocol": proto, "action": action,
        "bytes_in": bytes_in, "bytes_out": bytes_out,
        "reason": reason, "application": application,
        "event_time": event_time or datetime.utcnow(),
        "source_id": source_id, "device_type": device_type,
        "parser_id": parser_id, "device_role": "perimeter",
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. Flow creation
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowCreation:

    def test_first_event_creates_active_flow(self):
        fe = FlowEngine(timeout_seconds=60)
        fe.process_event(_event())
        assert fe.active_count == 1
        s = fe.stats()
        assert s["total_created"] == 1
        assert s["active_flows"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 2. Flow update / merge
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowMerge:

    def test_matching_events_merge(self):
        fe = FlowEngine(timeout_seconds=60)
        fe.process_event(_event(bytes_in=100, bytes_out=50))
        fe.process_event(_event(bytes_in=200, bytes_out=75))
        fe.process_event(_event(bytes_in=300, bytes_out=100))
        assert fe.active_count == 1
        # Flush to inspect the merged flow
        flows = fe.flush_expired(now=datetime.utcnow() + timedelta(seconds=120))
        assert len(flows) == 1
        f = flows[0]
        assert f["event_count"] == 3
        assert f["total_bytes_in"] == 600
        assert f["total_bytes_out"] == 225
        assert f["allow_count"] == 3


# ══════════════════════════════════════════════════════════════════════════════
# 3. Different 5-tuples do not merge
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowKeyIsolation:

    def test_different_tuples_create_separate_flows(self):
        fe = FlowEngine(timeout_seconds=60)
        fe.process_event(_event(src="10.0.0.1", dst="10.0.0.2", dport=443))
        fe.process_event(_event(src="10.0.0.1", dst="10.0.0.2", dport=80))
        fe.process_event(_event(src="10.0.0.3", dst="10.0.0.2", dport=443))
        assert fe.active_count == 3

    def test_same_tuple_different_protocol_separate(self):
        fe = FlowEngine(timeout_seconds=60)
        fe.process_event(_event(proto="TCP"))
        fe.process_event(_event(proto="UDP"))
        assert fe.active_count == 2


# ══════════════════════════════════════════════════════════════════════════════
# 4. Timeout flush
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowTimeout:

    def test_inactive_flow_flushed_after_timeout(self):
        fe = FlowEngine(timeout_seconds=30)
        now = datetime.utcnow()
        fe.process_event(_event(event_time=now))
        # Not yet expired
        emitted = fe.flush_expired(now=now + timedelta(seconds=10))
        assert emitted == []
        assert fe.active_count == 1
        # Now expired
        emitted = fe.flush_expired(now=now + timedelta(seconds=60))
        assert len(emitted) == 1
        assert fe.active_count == 0

    def test_expired_allow_flow_state_completed(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="allow", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["state"] == "completed"

    def test_expired_no_action_flow_state_expired(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        # Event with an unknown action → no allow/deny/drop/reset counted
        fe.process_event(_event(action="unknown", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["state"] == "expired"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Terminal states
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowTerminalStates:

    def test_reset_produces_reset_state(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="allow", event_time=now))
        fe.process_event(_event(action="reset", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["state"] == "reset"

    def test_deny_only_produces_denied_state(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="deny", event_time=now))
        fe.process_event(_event(action="deny", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["state"] == "denied"
        assert emitted[0]["deny_count"] == 2

    def test_drop_only_produces_dropped_state(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="drop", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["state"] == "dropped"

    def test_deny_plus_allow_is_completed_not_denied(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="deny", event_time=now))
        fe.process_event(_event(action="allow", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        # allow_count > 0 prevents "denied"
        assert emitted[0]["state"] == "completed"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Action summary derivation
# ══════════════════════════════════════════════════════════════════════════════

class TestActionSummary:

    def test_mostly_allow(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        for _ in range(5):
            fe.process_event(_event(action="allow", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["action_summary"] == "mostly_allow"

    def test_mostly_deny(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        for _ in range(5):
            fe.process_event(_event(action="deny", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["action_summary"] == "mostly_deny"

    def test_mixed(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="allow", event_time=now))
        fe.process_event(_event(action="deny", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["action_summary"] == "mixed"

    def test_reset_seen(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="allow", event_time=now))
        fe.process_event(_event(action="reset", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["action_summary"] == "reset_seen"

    def test_reason_summary_single(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="deny", reason="block-ssh", event_time=now))
        fe.process_event(_event(action="deny", reason="block-ssh", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert emitted[0]["reason_summary"] == "block-ssh"

    def test_reason_summary_multiple(self):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(reason="rule-A", event_time=now))
        fe.process_event(_event(reason="rule-B", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert "+1 others" in emitted[0]["reason_summary"]


# ══════════════════════════════════════════════════════════════════════════════
# 7. DB persistence
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowPersistence:

    def test_flushed_flows_stored_in_db(self, db_session):
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="allow", event_time=now, bytes_in=500))
        fe.process_event(_event(action="deny", event_time=now, bytes_in=100))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        assert len(emitted) == 1

        rows = [LiveFlowModel(**f) for f in emitted]
        db_session.bulk_save_objects(rows)
        db_session.commit()

        stored = db_session.query(LiveFlowModel).all()
        assert len(stored) == 1
        r = stored[0]
        assert r.source_ip == "10.0.0.1"
        assert r.destination_ip == "10.0.0.2"
        assert r.event_count == 2
        assert r.total_bytes_in == 600
        assert r.allow_count == 1
        assert r.deny_count == 1
        assert r.state == "completed"   # allow + deny → completed


# ══════════════════════════════════════════════════════════════════════════════
# 8. REST API
# ══════════════════════════════════════════════════════════════════════════════

def _seed_flows(db, n=5):
    now = datetime.utcnow()
    for i in range(n):
        db.add(LiveFlowModel(
            source_id="fw01", device_type="firewall",
            parser_id="test", source_ip=f"10.0.0.{i}",
            destination_ip="10.0.0.100",
            source_port=50000 + i, destination_port=443,
            protocol="TCP",
            first_seen=now - timedelta(minutes=5, seconds=i),
            last_seen=now - timedelta(seconds=i),
            event_count=10 + i,
            total_bytes_in=1000 * i, total_bytes_out=500 * i,
            total_packets_in=0, total_packets_out=0,
            allow_count=8 + i, deny_count=1 if i % 2 == 0 else 0,
            drop_count=0, reset_count=1 if i == 3 else 0,
            alert_count=0,
            action_summary="mostly_allow" if i != 3 else "reset_seen",
            state="completed" if i != 3 else "reset",
        ))
    db.commit()


class TestFlowListEndpoint:

    def test_list_returns_200(self, db_session):
        uid = _seed_user(db_session)
        _seed_flows(db_session)
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 5
        assert len(body["flows"]) == 5

    def test_filter_by_state(self, db_session):
        uid = _seed_user(db_session)
        _seed_flows(db_session)
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows?state=reset")
        body = r.json()
        assert body["total"] == 1
        assert body["flows"][0]["state"] == "reset"

    def test_filter_by_source_ip(self, db_session):
        uid = _seed_user(db_session)
        _seed_flows(db_session)
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows?source_ip=10.0.0.2")
        body = r.json()
        assert body["total"] == 1

    def test_filter_by_action_summary(self, db_session):
        uid = _seed_user(db_session)
        _seed_flows(db_session)
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows?action_summary=reset_seen")
        body = r.json()
        assert body["total"] == 1

    def test_pagination(self, db_session):
        uid = _seed_user(db_session)
        _seed_flows(db_session, n=10)
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows?limit=3&offset=2")
        body = r.json()
        assert body["total"] == 10
        assert len(body["flows"]) == 3
        assert body["offset"] == 2


class TestFlowStatsEndpoint:

    def test_stats_shape(self, db_session):
        uid = _seed_user(db_session)
        _seed_flows(db_session)
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows/stats")
        assert r.status_code == 200
        body = r.json()
        for k in (
            "total_flows", "active_flows", "completed_flows",
            "denied_flows", "reset_flows", "dropped_flows",
            "top_talkers", "top_reset_sources", "top_denied_sources",
        ):
            assert k in body
        assert body["total_flows"] == 5
        assert body["reset_flows"] == 1
        assert body["completed_flows"] == 4


# ══════════════════════════════════════════════════════════════════════════════
# Timeline endpoint
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowTimelineEndpoint:

    def test_empty_returns_empty_list(self, db_session):
        uid = _seed_user(db_session, "tl_user")
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows/timeline?minutes=60")
        assert r.status_code == 200
        assert r.json() == []

    def test_flows_bucketed_by_minute(self, db_session):
        uid = _seed_user(db_session, "tl_user2")
        now = datetime.utcnow()
        from datetime import timedelta
        # 3 completed flows at minute :02, 2 denied + 1 reset at minute :01
        for i in range(3):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.1", destination_ip="10.0.0.2",
                protocol="TCP",
                first_seen=now - timedelta(minutes=3),
                last_seen=now - timedelta(minutes=2, seconds=i),
                event_count=5, total_bytes_in=0, total_bytes_out=0,
                total_packets_in=0, total_packets_out=0,
                allow_count=5, deny_count=0, drop_count=0,
                reset_count=0, alert_count=0,
                state="completed", raw_event_count=5,
            ))
        for i in range(2):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.1", destination_ip="10.0.0.2",
                protocol="TCP",
                first_seen=now - timedelta(minutes=2),
                last_seen=now - timedelta(minutes=1, seconds=i),
                event_count=3, total_bytes_in=0, total_bytes_out=0,
                total_packets_in=0, total_packets_out=0,
                allow_count=0, deny_count=3, drop_count=0,
                reset_count=0, alert_count=0,
                state="denied", raw_event_count=3,
            ))
        db_session.add(LiveFlowModel(
            source_id="fw", device_type="firewall", parser_id="test",
            source_ip="10.0.0.1", destination_ip="10.0.0.2",
            protocol="TCP",
            first_seen=now - timedelta(minutes=2),
            last_seen=now - timedelta(minutes=1, seconds=30),
            event_count=2, total_bytes_in=0, total_bytes_out=0,
            total_packets_in=0, total_packets_out=0,
            allow_count=0, deny_count=0, drop_count=0,
            reset_count=2, alert_count=0,
            state="reset", raw_event_count=2,
        ))
        db_session.commit()

        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows/timeline?minutes=10")
        assert r.status_code == 200
        buckets = r.json()
        assert len(buckets) >= 2
        total_completed = sum(b["completed"] for b in buckets)
        total_denied = sum(b["denied"] for b in buckets)
        total_reset = sum(b["reset"] for b in buckets)
        assert total_completed == 3
        assert total_denied == 2
        assert total_reset == 1
        for b in buckets:
            for k in ("bucket", "completed", "denied", "reset", "dropped", "active"):
                assert k in b

    def test_minutes_capped_at_1440(self, db_session):
        uid = _seed_user(db_session, "tl_user3")
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows/timeline?minutes=9999")
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# Flow behavioral classification
# ══════════════════════════════════════════════════════════════════════════════

def _make_flow(**kw):
    """Build an _ActiveFlow and apply events, then classify."""
    fe = FlowEngine(timeout_seconds=10)
    now = datetime.utcnow()
    defaults = dict(
        src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=443,
        proto="TCP", action="allow", bytes_in=100, bytes_out=50,
        source_id="fw", device_type="firewall", parser_id="test",
    )
    defaults.update(kw)
    base = {
        "source_ip": defaults["src"], "destination_ip": defaults["dst"],
        "source_port": defaults["sport"], "destination_port": defaults["dport"],
        "protocol": defaults["proto"], "action": defaults["action"],
        "bytes_in": defaults["bytes_in"], "bytes_out": defaults["bytes_out"],
        "event_time": now, "source_id": defaults["source_id"],
        "device_type": defaults["device_type"], "parser_id": defaults["parser_id"],
        "device_role": "perimeter",
    }
    fe.process_event(base)
    return fe


class TestFlowClassification:

    def test_blocked_classification(self):
        """Deny-only flow with significant bytes/duration → blocked (not scanning)."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        for i in range(5):
            fe.process_event(_event(
                action="deny", bytes_in=200, bytes_out=100,
                event_time=now + timedelta(seconds=i * 2),
            ))
        emitted = fe.flush_expired(now=now + timedelta(seconds=30))
        f = emitted[0]
        assert f["flow_type"] == "blocked"
        assert f["deny_ratio"] > 0
        assert "deny/drop only" in f["suspicious_reasons"]

    def test_unstable_classification(self):
        """Resets mixed with allow → unstable."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        for _ in range(3):
            fe.process_event(_event(action="allow", event_time=now))
        for _ in range(3):
            fe.process_event(_event(action="reset", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        f = emitted[0]
        assert f["flow_type"] == "unstable"
        assert f["reset_ratio"] == 0.5
        assert any("resets mixed" in r for r in json.loads(f["suspicious_reasons"]))

    def test_scanning_classification(self):
        """Short denied flow with minimal bytes → scanning."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(
            action="deny", bytes_in=0, bytes_out=0,
            event_time=now,
        ))
        fe.process_event(_event(
            action="deny", bytes_in=0, bytes_out=0,
            event_time=now + timedelta(seconds=1),
        ))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        f = emitted[0]
        assert f["flow_type"] == "scanning"
        assert "probe-like" in f["suspicious_reasons"]

    def test_suspicious_alert(self):
        """Flow with alerts → suspicious."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="allow", event_time=now))
        fe.process_event(_event(action="alert", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        f = emitted[0]
        assert f["flow_type"] == "suspicious"
        assert any("alert" in r for r in json.loads(f["suspicious_reasons"]))

    def test_suspicious_high_reset_ratio_with_allow(self):
        """High reset ratio (>30%) despite some allow → suspicious."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        for _ in range(2):
            fe.process_event(_event(action="allow", event_time=now))
        for _ in range(3):
            fe.process_event(_event(action="reset", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        f = emitted[0]
        # reset_ratio = 3/5 = 0.6 which is > 0.3 but also mixed → unstable takes priority
        assert f["flow_type"] in ("unstable", "suspicious")

    def test_normal_classification(self):
        """Pure allow traffic → normal."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        for _ in range(10):
            fe.process_event(_event(action="allow", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        f = emitted[0]
        assert f["flow_type"] == "normal"
        assert f["reset_ratio"] == 0.0
        assert f["deny_ratio"] == 0.0

    def test_asymmetric_behavior_flag(self):
        """Highly asymmetric byte ratio → flag set."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(
            action="allow", bytes_in=50000, bytes_out=100,
            event_time=now,
        ))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        f = emitted[0]
        assert f["asymmetric_behavior"] is True
        assert any("asymmetric" in r for r in json.loads(f["suspicious_reasons"]))

    def test_burst_score_computed(self):
        """Burst score = events / duration_seconds."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        for i in range(10):
            fe.process_event(_event(
                action="allow",
                event_time=now + timedelta(seconds=i),
            ))
        emitted = fe.flush_expired(now=now + timedelta(seconds=30))
        f = emitted[0]
        # 10 events over ~9 seconds → ~1.1 eps
        assert f["burst_score"] > 0

    def test_classification_fields_in_to_dict(self):
        """to_dict includes all classification fields."""
        fe = FlowEngine(timeout_seconds=10)
        now = datetime.utcnow()
        fe.process_event(_event(action="allow", event_time=now))
        emitted = fe.flush_expired(now=now + timedelta(seconds=20))
        f = emitted[0]
        for key in ("flow_type", "reset_ratio", "deny_ratio",
                     "burst_score", "asymmetric_behavior", "suspicious_reasons"):
            assert key in f


# ══════════════════════════════════════════════════════════════════════════════
# Flow correlation / behavior detection
# ══════════════════════════════════════════════════════════════════════════════

def _seed_corr_flows(db, src, *, n=12, dsts=1, ports=1,
                      state="completed", flow_type="normal",
                      deny_count=0, reset_count=0, allow_count=5):
    """Seed n flows for a source IP with controllable spread."""
    now = datetime.utcnow()
    for i in range(n):
        db.add(LiveFlowModel(
            source_id="fw", device_type="firewall", parser_id="test",
            source_ip=src,
            destination_ip=f"10.0.{(i % dsts) // 256}.{(i % dsts) % 256 + 1}",
            source_port=50000 + i,
            destination_port=(i % ports) + 1 if ports > 1 else 443,
            protocol="TCP",
            first_seen=now - timedelta(minutes=5, seconds=i),
            last_seen=now - timedelta(minutes=2, seconds=i),
            event_count=5, total_bytes_in=500, total_bytes_out=100,
            total_packets_in=5, total_packets_out=3,
            allow_count=allow_count, deny_count=deny_count, drop_count=0,
            reset_count=reset_count, alert_count=0,
            state=state, flow_type=flow_type,
            raw_event_count=5,
        ))
    db.commit()


class TestFlowCorrelation:

    def test_scanning_detection(self, db_session):
        """Many distinct ports + blocked flows → scanning."""
        _seed_corr_flows(
            db_session, "10.0.0.1",
            n=15, dsts=5, ports=20,
            state="denied", flow_type="scanning",
            deny_count=5, allow_count=0,
        )
        results = compute_flow_behaviors(db_session, use_cache=False)
        e = next(x for x in results if x["source_ip"] == "10.0.0.1")
        assert e["behavior_type"] == "scanning"
        assert e["confidence"] >= 0.7
        assert "wide_port_spread" in e["drivers"]

    def test_lateral_movement_detection(self, db_session):
        """Many distinct destinations, mostly allowed → lateral_movement."""
        _seed_corr_flows(
            db_session, "10.0.0.2",
            n=12, dsts=12, ports=1,
            state="completed", flow_type="normal",
            allow_count=5, deny_count=0,
        )
        results = compute_flow_behaviors(db_session, use_cache=False)
        e = next(x for x in results if x["source_ip"] == "10.0.0.2")
        assert e["behavior_type"] == "lateral_movement"
        assert "broad_destination_spread" in e["drivers"]

    def test_unstable_detection(self, db_session):
        """High reset ratio + completed flows → unstable."""
        now = datetime.utcnow()
        for i in range(8):
            st = "reset" if i < 5 else "completed"
            rc = 5 if st == "reset" else 0
            ac = 5 if st == "completed" else 0
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.3", destination_ip="10.0.0.100",
                source_port=50000 + i, destination_port=443,
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=5, total_bytes_in=500, total_bytes_out=100,
                total_packets_in=0, total_packets_out=0,
                allow_count=ac, deny_count=0, drop_count=0,
                reset_count=rc, alert_count=0,
                state=st, flow_type="unstable" if st == "reset" else "normal",
                raw_event_count=5,
            ))
        db_session.commit()
        results = compute_flow_behaviors(db_session, use_cache=False)
        e = next(x for x in results if x["source_ip"] == "10.0.0.3")
        assert e["behavior_type"] == "unstable"
        assert "high_reset_ratio" in e["drivers"]

    def test_suspicious_detection(self, db_session):
        """High deny ratio → suspicious."""
        _seed_corr_flows(
            db_session, "10.0.0.4",
            n=8, dsts=2, ports=2,
            state="denied", flow_type="blocked",
            deny_count=5, allow_count=0,
        )
        results = compute_flow_behaviors(db_session, use_cache=False)
        e = next(x for x in results if x["source_ip"] == "10.0.0.4")
        assert e["behavior_type"] == "suspicious"
        assert "high_deny_ratio" in e["drivers"]

    def test_normal_fallback(self, db_session):
        """All healthy flows → normal."""
        _seed_corr_flows(
            db_session, "10.0.0.5",
            n=6, dsts=2, ports=1,
            state="completed", flow_type="normal",
            allow_count=5, deny_count=0,
        )
        results = compute_flow_behaviors(db_session, use_cache=False)
        e = next(x for x in results if x["source_ip"] == "10.0.0.5")
        assert e["behavior_type"] == "normal"
        assert e["drivers"] == []

    def test_confidence_capped(self, db_session):
        """Even extreme signals cap confidence at 0.95."""
        _seed_corr_flows(
            db_session, "10.0.0.6",
            n=30, dsts=25, ports=25,
            state="denied", flow_type="scanning",
            deny_count=10, allow_count=0,
        )
        results = compute_flow_behaviors(db_session, use_cache=False)
        e = next(x for x in results if x["source_ip"] == "10.0.0.6")
        assert e["confidence"] <= 0.95

    def test_min_confidence_filter(self, db_session):
        """API endpoint filters by min_confidence."""
        # Normal flows → low confidence
        _seed_corr_flows(db_session, "10.0.0.10", n=6, dsts=2, ports=1)
        # Scanning flows → high confidence
        _seed_corr_flows(
            db_session, "10.0.0.11",
            n=15, dsts=12, ports=20,
            state="denied", flow_type="scanning",
            deny_count=5, allow_count=0,
        )
        uid = _seed_user(db_session, "beh_user")
        client = _make_client(db_session, uid)
        r = client.get("/api/live-flows/behaviors?min_confidence=0.7")
        assert r.status_code == 200
        entries = r.json()
        assert all(e["confidence"] >= 0.7 for e in entries)
        # The scanning IP should be there, the normal one should not
        ips = [e["source_ip"] for e in entries]
        assert "10.0.0.11" in ips

    def test_below_min_flows_excluded(self, db_session):
        """Source IPs with < 5 flows are excluded."""
        _seed_corr_flows(db_session, "10.0.0.20", n=3, dsts=1, ports=1)
        results = compute_flow_behaviors(db_session, use_cache=False)
        ips = [e["source_ip"] for e in results]
        assert "10.0.0.20" not in ips


# ══════════════════════════════════════════════════════════════════════════════
# Behavior-to-incident conversion
# ══════════════════════════════════════════════════════════════════════════════

def _seed_admin(db):
    from database import UserModel
    if not db.query(UserModel).filter(UserModel.id == 1).first():
        u = UserModel(username="admin", hashed_password="x")
        db.add(u); db.flush(); db.commit()


def _behavior(src="10.0.0.1", btype="scanning", confidence=0.8,
              flow_count=15, drivers=None):
    return {
        "source_ip": src,
        "behavior_type": btype,
        "confidence": confidence,
        "flow_count": flow_count,
        "distinct_destinations": 10,
        "distinct_ports": 20,
        "reset_ratio": 0.0,
        "deny_ratio": 0.5,
        "time_window_minutes": 10,
        "drivers": drivers or ["wide_port_spread"],
    }


class TestIncidentUpsert:

    def test_new_behavior_creates_incident(self, db_session):
        _seed_admin(db_session)
        result = upsert_incidents_from_behaviors(
            db_session, [_behavior(src="10.0.0.1", btype="scanning")],
        )
        assert result["created"] == 1
        assert result["updated"] == 0
        inc = db_session.query(LiveIncidentModel).first()
        assert inc is not None
        assert inc.source_ip == "10.0.0.1"
        assert inc.behavior_type == "scanning"
        assert inc.status == "open"
        assert inc.event_count == 1

    def test_repeated_behavior_updates_same_incident(self, db_session):
        _seed_admin(db_session)
        b = _behavior(src="10.0.0.2", btype="suspicious", confidence=0.75)
        upsert_incidents_from_behaviors(db_session, [b])
        upsert_incidents_from_behaviors(db_session, [b])
        upsert_incidents_from_behaviors(db_session, [b])
        incidents = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.2"
        ).all()
        assert len(incidents) == 1
        assert incidents[0].event_count == 3

    def test_different_behavior_creates_separate_incidents(self, db_session):
        _seed_admin(db_session)
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.3", btype="scanning"),
            _behavior(src="10.0.0.3", btype="lateral_movement", confidence=0.7),
        ])
        count = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.3"
        ).count()
        assert count == 2

    def test_severity_escalation(self, db_session):
        _seed_admin(db_session)
        # First: confidence 0.7 → medium
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.4", btype="scanning", confidence=0.7),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.4"
        ).first()
        assert inc.severity == "medium"

        # Second: confidence 0.85 → high (escalation)
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.4", btype="scanning", confidence=0.85),
        ])
        db_session.expire_all()
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.4"
        ).first()
        assert inc.severity == "high"
        assert inc.event_count == 2

    def test_severity_never_downgrades(self, db_session):
        _seed_admin(db_session)
        # Start high
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.5", btype="scanning", confidence=0.85),
        ])
        # Follow-up with lower confidence
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.5", btype="scanning", confidence=0.6),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.5"
        ).first()
        assert inc.severity == "high"  # did not downgrade

    def test_resolved_incident_not_reopened(self, db_session):
        _seed_admin(db_session)
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.6", btype="scanning"),
        ])
        # Resolve it
        inc = db_session.query(LiveIncidentModel).first()
        inc.status = "resolved"
        db_session.commit()
        # New detection should create a NEW incident, not reopen
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.6", btype="scanning"),
        ])
        incidents = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.6"
        ).all()
        assert len(incidents) == 2
        statuses = {i.status for i in incidents}
        assert "resolved" in statuses
        assert "open" in statuses

    def test_normal_behavior_ignored(self, db_session):
        _seed_admin(db_session)
        result = upsert_incidents_from_behaviors(
            db_session, [_behavior(btype="normal")],
        )
        assert result["created"] == 0
        assert db_session.query(LiveIncidentModel).count() == 0

    def test_notification_on_medium_creation(self, db_session):
        _seed_admin(db_session)
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.7", btype="scanning", confidence=0.75),
        ])
        notif = db_session.query(NotificationModel).filter(
            NotificationModel.message.contains("[INCIDENT]")
        ).first()
        assert notif is not None
        assert "10.0.0.7" in notif.message

    def test_escalation_notifies(self, db_session):
        _seed_admin(db_session)
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.8", btype="scanning", confidence=0.7),
        ])
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.8", btype="scanning", confidence=0.85),
        ])
        notifs = db_session.query(NotificationModel).filter(
            NotificationModel.message.contains("escalated")
        ).all()
        assert len(notifs) >= 1


class TestIncidentEnrichment:

    def test_enrichment_fields_populated(self, db_session):
        _seed_admin(db_session)
        # Seed flows for the source IP so enrichment has data
        now = datetime.utcnow()
        for i in range(5):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.1",
                destination_ip=f"10.0.{i}.1",
                source_port=50000 + i, destination_port=443 + i,
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=5, total_bytes_in=500, total_bytes_out=100,
                total_packets_in=5, total_packets_out=3,
                allow_count=0, deny_count=5, drop_count=0,
                reset_count=0, alert_count=0,
                state="denied", flow_type="scanning",
                raw_event_count=5, duration_ms=200,
            ))
        db_session.commit()

        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.1", btype="scanning"),
        ])
        inc = db_session.query(LiveIncidentModel).first()
        assert inc is not None
        assert inc.top_destination_ips is not None
        assert inc.top_ports is not None
        assert inc.total_distinct_destinations == 5
        assert inc.total_distinct_ports == 5
        assert inc.sample_flows is not None
        assert inc.last_activity_summary is not None

    def test_top_ports_correct(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        # 3 flows to port 443, 2 to port 80, 1 to port 22
        for port, count in [(443, 3), (80, 2), (22, 1)]:
            for _ in range(count):
                db_session.add(LiveFlowModel(
                    source_id="fw", device_type="firewall", parser_id="test",
                    source_ip="10.0.0.2", destination_ip="10.0.0.100",
                    destination_port=port, protocol="TCP",
                    first_seen=now - timedelta(minutes=5),
                    last_seen=now - timedelta(minutes=2),
                    event_count=1, total_bytes_in=100, total_bytes_out=50,
                    total_packets_in=1, total_packets_out=1,
                    allow_count=0, deny_count=1, drop_count=0,
                    reset_count=0, alert_count=0,
                    state="denied", raw_event_count=1,
                ))
        db_session.commit()

        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.2", btype="scanning"),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.2"
        ).first()
        import json
        ports = json.loads(inc.top_ports)
        assert ports[0] == 443  # most frequent first
        assert 80 in ports
        assert 22 in ports

    def test_top_destinations_correct(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        # 4 flows to 10.0.0.100, 2 to 10.0.0.200
        for dst, count in [("10.0.0.100", 4), ("10.0.0.200", 2)]:
            for _ in range(count):
                db_session.add(LiveFlowModel(
                    source_id="fw", device_type="firewall", parser_id="test",
                    source_ip="10.0.0.3", destination_ip=dst,
                    destination_port=443, protocol="TCP",
                    first_seen=now - timedelta(minutes=5),
                    last_seen=now - timedelta(minutes=2),
                    event_count=1, total_bytes_in=100, total_bytes_out=50,
                    total_packets_in=1, total_packets_out=1,
                    allow_count=0, deny_count=1, drop_count=0,
                    reset_count=0, alert_count=0,
                    state="denied", raw_event_count=1,
                ))
        db_session.commit()

        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.3", btype="suspicious"),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.3"
        ).first()
        import json
        dsts = json.loads(inc.top_destination_ips)
        assert dsts[0] == "10.0.0.100"
        assert "10.0.0.200" in dsts

    def test_sample_flows_max_3(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        for i in range(10):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.4", destination_ip=f"10.0.{i}.1",
                destination_port=443, protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2, seconds=i),
                event_count=1, total_bytes_in=100, total_bytes_out=50,
                total_packets_in=1, total_packets_out=1,
                allow_count=1, deny_count=0, drop_count=0,
                reset_count=0, alert_count=0,
                state="completed", raw_event_count=1, duration_ms=500,
            ))
        db_session.commit()

        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.4", btype="lateral_movement", confidence=0.7),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.4"
        ).first()
        import json
        samples = json.loads(inc.sample_flows)
        assert len(samples) <= 3
        assert all("src" in s and "dst" in s and "state" in s for s in samples)

    def test_summary_includes_enrichment(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        for i in range(5):
            db_session.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip="10.0.0.5", destination_ip=f"10.0.{i}.1",
                destination_port=3389 if i < 3 else 445,
                protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=1, total_bytes_in=100, total_bytes_out=50,
                total_packets_in=1, total_packets_out=1,
                allow_count=0, deny_count=1, drop_count=0,
                reset_count=0, alert_count=0,
                state="denied", raw_event_count=1,
            ))
        db_session.commit()

        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.5", btype="scanning"),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.5"
        ).first()
        assert "10.0.0.5" in inc.summary
        assert "scanning" in inc.summary
        assert "host" in inc.summary
        assert "port" in inc.summary


class TestAssetImpact:

    def _seed_assets(self, db, assets_data):
        for a in assets_data:
            db.add(AssetModel(**a))
        db.commit()

    def _seed_flows_for(self, db, src, dst_ips):
        now = datetime.utcnow()
        for dst in dst_ips:
            db.add(LiveFlowModel(
                source_id="fw", device_type="firewall", parser_id="test",
                source_ip=src, destination_ip=dst,
                destination_port=443, protocol="TCP",
                first_seen=now - timedelta(minutes=5),
                last_seen=now - timedelta(minutes=2),
                event_count=5, total_bytes_in=500, total_bytes_out=100,
                total_packets_in=5, total_packets_out=3,
                allow_count=0, deny_count=5, drop_count=0,
                reset_count=0, alert_count=0,
                state="denied", flow_type="scanning",
                raw_event_count=5,
            ))
        db.commit()

    def test_critical_asset_increases_severity(self, db_session):
        _seed_admin(db_session)
        self._seed_assets(db_session, [
            {"ip_address": "10.0.0.100", "hostname": "DC01",
             "asset_type": "server", "criticality": "critical", "environment": "prod"},
        ])
        self._seed_flows_for(db_session, "10.0.0.1", ["10.0.0.100"])
        # scanning + confidence 0.7 → base severity = medium
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.1", btype="scanning", confidence=0.7),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.1"
        ).first()
        assert inc is not None
        # critical target → +2 tiers: medium → critical
        assert inc.severity == "critical"
        assert inc.highest_target_criticality == "critical"
        assert inc.impacted_assets_count == 1
        assert "DC01" in (inc.summary or "")

    def test_high_asset_increases_severity_by_one(self, db_session):
        _seed_admin(db_session)
        self._seed_assets(db_session, [
            {"ip_address": "10.0.0.200", "hostname": "WebApp",
             "asset_type": "server", "criticality": "high", "environment": "prod"},
        ])
        self._seed_flows_for(db_session, "10.0.0.2", ["10.0.0.200"])
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.2", btype="scanning", confidence=0.7),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.2"
        ).first()
        # medium + high target → +1 = high
        assert inc.severity == "high"

    def test_multiple_assets_counted(self, db_session):
        _seed_admin(db_session)
        self._seed_assets(db_session, [
            {"ip_address": "10.0.0.10", "asset_type": "server", "criticality": "critical"},
            {"ip_address": "10.0.0.11", "asset_type": "workstation", "criticality": "medium"},
            {"ip_address": "10.0.0.12", "asset_type": "server", "criticality": "high"},
        ])
        self._seed_flows_for(db_session, "10.0.0.3", ["10.0.0.10", "10.0.0.11", "10.0.0.12"])
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.3", btype="scanning", confidence=0.7),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.3"
        ).first()
        assert inc.impacted_assets_count == 3
        assert inc.highest_target_criticality == "critical"
        assert inc.target_summary is not None
        assert "critical" in inc.target_summary

    def test_no_asset_match_no_change(self, db_session):
        _seed_admin(db_session)
        # No assets seeded
        self._seed_flows_for(db_session, "10.0.0.4", ["10.0.0.50"])
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.4", btype="scanning", confidence=0.7),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.4"
        ).first()
        assert inc.impacted_assets_count == 0
        assert inc.highest_target_criticality is None
        # Severity stays at base (medium for scanning/0.7)
        assert inc.severity == "medium"


class TestIncidentPriority:

    def _make_incident(self, **kw):
        defaults = dict(
            source_ip="10.0.0.1", behavior_type="scanning",
            severity="medium", status="open",
            first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
            last_activity_at=datetime.utcnow(),
            event_count=1, linked_flow_count=10,
            latest_confidence=0.7,
            highest_target_criticality=None,
            impacted_assets_count=0,
        )
        defaults.update(kw)
        return LiveIncidentModel(**defaults)

    def test_severity_increases_priority(self):
        now = datetime.utcnow()
        low = self._make_incident(severity="low", last_activity_at=now)
        med = self._make_incident(severity="medium", last_activity_at=now)
        high = self._make_incident(severity="high", last_activity_at=now)
        crit = self._make_incident(severity="critical", last_activity_at=now)
        assert compute_priority(low, now=now) < compute_priority(med, now=now)
        assert compute_priority(med, now=now) < compute_priority(high, now=now)
        assert compute_priority(high, now=now) < compute_priority(crit, now=now)

    def test_critical_asset_boosts_priority(self):
        now = datetime.utcnow()
        without = self._make_incident(severity="medium", last_activity_at=now)
        with_crit = self._make_incident(
            severity="medium", last_activity_at=now,
            highest_target_criticality="critical",
        )
        assert compute_priority(with_crit, now=now) > compute_priority(without, now=now)

    def test_repetition_boosts_priority(self):
        now = datetime.utcnow()
        one = self._make_incident(event_count=1, last_activity_at=now)
        five = self._make_incident(event_count=5, last_activity_at=now)
        assert compute_priority(five, now=now) > compute_priority(one, now=now)

    def test_priority_decays_over_time(self):
        now = datetime.utcnow()
        fresh = self._make_incident(last_activity_at=now)
        stale_30 = self._make_incident(
            last_activity_at=now - timedelta(minutes=35),
        )
        stale_60 = self._make_incident(
            last_activity_at=now - timedelta(minutes=65),
        )
        p_fresh = compute_priority(fresh, now=now)
        p_30 = compute_priority(stale_30, now=now)
        p_60 = compute_priority(stale_60, now=now)
        assert p_fresh > p_30 > p_60

    def test_priority_never_below_zero(self):
        now = datetime.utcnow()
        very_stale = self._make_incident(
            severity="low", event_count=1,
            last_activity_at=now - timedelta(hours=3),
        )
        assert compute_priority(very_stale, now=now) >= 0

    def test_priority_set_on_create(self, db_session):
        _seed_admin(db_session)
        now = datetime.utcnow()
        db_session.add(LiveFlowModel(
            source_id="fw", device_type="firewall", parser_id="test",
            source_ip="10.0.0.99", destination_ip="10.0.0.1",
            protocol="TCP",
            first_seen=now - timedelta(minutes=5),
            last_seen=now - timedelta(minutes=2),
            event_count=5, total_bytes_in=100, total_bytes_out=50,
            total_packets_in=0, total_packets_out=0,
            allow_count=0, deny_count=5, drop_count=0,
            reset_count=0, alert_count=0,
            state="denied", raw_event_count=5,
        ))
        db_session.commit()
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.99", btype="scanning", confidence=0.8),
        ])
        inc = db_session.query(LiveIncidentModel).filter(
            LiveIncidentModel.source_ip == "10.0.0.99"
        ).first()
        assert inc.priority_score is not None
        assert inc.priority_score > 0
        assert inc.last_activity_at is not None

    def test_sorting_by_priority(self, db_session):
        _seed_admin(db_session)
        uid = _seed_user(db_session, "sort_user")
        now = datetime.utcnow()
        # Create a low-priority incident
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.10", btype="unstable", confidence=0.5),
        ])
        # Create a high-priority incident
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.11", btype="scanning", confidence=0.85),
        ])
        client = _make_client(db_session, uid)
        r = client.get("/api/live-incidents")
        incs = r.json()["incidents"]
        assert len(incs) >= 2
        # First should have higher priority
        assert incs[0]["priority_score"] >= incs[1]["priority_score"]


class TestIncidentAPI:

    def test_list_incidents(self, db_session):
        _seed_admin(db_session)
        uid = _seed_user(db_session, "inc_user")
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.1", btype="scanning"),
            _behavior(src="10.0.0.2", btype="suspicious"),
        ])
        client = _make_client(db_session, uid)
        r = client.get("/api/live-incidents")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 2
        assert len(body["incidents"]) == 2

    def test_filter_by_status(self, db_session):
        _seed_admin(db_session)
        uid = _seed_user(db_session, "inc_user2")
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.1", btype="scanning"),
        ])
        inc = db_session.query(LiveIncidentModel).first()
        inc.status = "resolved"
        db_session.commit()
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.2", btype="suspicious"),
        ])
        client = _make_client(db_session, uid)
        r = client.get("/api/live-incidents?status=open")
        assert r.json()["total"] == 1

    def test_update_status(self, db_session):
        _seed_admin(db_session)
        uid = _seed_user(db_session, "inc_user3")
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.1", btype="scanning"),
        ])
        inc = db_session.query(LiveIncidentModel).first()
        client = _make_client(db_session, uid)
        r = client.put(
            f"/api/live-incidents/{inc.id}/status",
            json={"status": "investigating"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "investigating"

    def test_get_incident_detail(self, db_session):
        _seed_admin(db_session)
        uid = _seed_user(db_session, "inc_user4")
        upsert_incidents_from_behaviors(db_session, [
            _behavior(src="10.0.0.1", btype="scanning"),
        ])
        inc = db_session.query(LiveIncidentModel).first()
        client = _make_client(db_session, uid)
        r = client.get(f"/api/live-incidents/{inc.id}")
        assert r.status_code == 200
        body = r.json()
        assert body["source_ip"] == "10.0.0.1"
        assert body["behavior_type"] == "scanning"
