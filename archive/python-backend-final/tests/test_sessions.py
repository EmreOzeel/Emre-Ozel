"""
Tests for the attack session correlation layer.

Covers:
  - Multiple incidents grouped into a session
  - Different behavior_types merged
  - Priority aggregation with bonuses
  - Session status transitions (active → idle → closed)
  - REST API: list + detail
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
from database import (
    AssetModel,
    AttackSessionModel,
    Base,
    LiveIncidentModel,
    UserModel,
)
from main import app, get_db
from collector.sessions import (
    correlate_sessions,
    session_dict,
    IDLE_AFTER_MINUTES,
    CLOSE_AFTER_MINUTES,
)


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


def _incident(db, src="10.0.0.1", btype="scanning", severity="high",
              priority=70.0, now=None, status="open",
              target_criticality=None,
              top_destination_ips=None, top_ports=None,
              total_distinct_destinations=5, total_distinct_ports=10,
              linked_flow_count=10, event_count=1):
    now = now or datetime.utcnow()
    inc = LiveIncidentModel(
        source_ip=src,
        behavior_type=btype,
        severity=severity,
        status=status,
        first_seen=now,
        last_seen=now,
        event_count=event_count,
        linked_flow_count=linked_flow_count,
        latest_confidence=0.8,
        priority_score=priority,
        last_activity_at=now,
        total_distinct_destinations=total_distinct_destinations,
        total_distinct_ports=total_distinct_ports,
        highest_target_criticality=target_criticality,
        top_destination_ips=json.dumps(top_destination_ips) if top_destination_ips else None,
        top_ports=json.dumps(top_ports) if top_ports else None,
        created_at=now,
        updated_at=now,
    )
    db.add(inc)
    db.flush()
    return inc


# ── Grouping tests ──────────────────────────────────────────────────────────

class TestSessionGrouping:

    def test_multiple_incidents_grouped(self, db_session):
        """Two incidents from the same IP should be grouped into one session."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious", now=now)

        result = correlate_sessions(db_session, now=now)
        assert result["created"] == 1
        assert result["updated"] == 0

        sessions = db_session.query(AttackSessionModel).all()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.source_ip == "10.0.0.1"
        assert s.total_incidents == 2
        assert len(json.loads(s.incident_ids)) == 2

    def test_different_ips_separate_sessions(self, db_session):
        """Incidents from different IPs create separate sessions."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.2", btype="scanning", now=now)

        result = correlate_sessions(db_session, now=now)
        assert result["created"] == 2

        sessions = db_session.query(AttackSessionModel).all()
        assert len(sessions) == 2

    def test_resolved_incidents_excluded(self, db_session):
        """Resolved incidents should not be grouped."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  status="resolved", now=now)

        result = correlate_sessions(db_session, now=now)
        assert result["created"] == 0

    def test_session_updated_with_new_incidents(self, db_session):
        """New incidents should be added to an existing active session."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        correlate_sessions(db_session, now=now)

        # Add another incident 5 min later
        later = now + timedelta(minutes=5)
        _incident(db_session, src="10.0.0.1", btype="suspicious", now=later)
        result = correlate_sessions(db_session, now=later)
        assert result["updated"] == 1
        assert result["created"] == 0

        sessions = db_session.query(AttackSessionModel).all()
        assert len(sessions) == 1
        assert sessions[0].total_incidents == 2


# ── Behavior merging ────────────────────────────────────────────────────────

class TestBehaviorMerging:

    def test_different_behaviors_merged(self, db_session):
        """Different behavior_types should be merged into one session."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable", now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious", now=now)

        correlate_sessions(db_session, now=now)

        s = db_session.query(AttackSessionModel).first()
        behaviors = json.loads(s.behaviors)
        assert set(behaviors) == {"scanning", "unstable", "suspicious"}

    def test_behaviors_accumulate(self, db_session):
        """New behavior_types from later correlations should accumulate."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        correlate_sessions(db_session, now=now)

        later = now + timedelta(minutes=5)
        _incident(db_session, src="10.0.0.1", btype="lateral_movement", now=later)
        correlate_sessions(db_session, now=later)

        s = db_session.query(AttackSessionModel).first()
        behaviors = json.loads(s.behaviors)
        assert set(behaviors) == {"scanning", "lateral_movement"}


# ── Priority aggregation ────────────────────────────────────────────────────

class TestSessionPriority:

    def test_base_is_max_incident_priority(self, db_session):
        """Session priority base should be the max incident priority."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  priority=70.0, now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  priority=40.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # base 70 + 10 (multiple behaviors) = 80
        assert s.priority_score == 80.0

    def test_multi_behavior_bonus(self, db_session):
        """Multiple behavior_types should add +10 bonus."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  priority=50.0, now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  priority=50.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.priority_score >= 60.0  # 50 + 10

    def test_many_incidents_bonus(self, db_session):
        """More than 2 incidents should add +10 bonus."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  priority=50.0, now=now)
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  priority=50.0, now=now)
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  priority=50.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # base 50 + 10 (>2 incidents) = 60
        assert s.priority_score >= 60.0

    def test_critical_asset_bonus(self, db_session):
        """Critical-asset incidents should add +10 bonus."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  priority=50.0, target_criticality="critical", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # base 50 + 10 (critical asset) = 60
        assert s.priority_score == 60.0

    def test_priority_capped_at_100(self, db_session):
        """Priority should never exceed 100."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  priority=95.0, target_criticality="critical", now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  priority=95.0, now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  priority=90.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.priority_score <= 100.0

    def test_severity_is_max(self, db_session):
        """Session severity = highest incident severity."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  severity="medium", priority=40.0, now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  severity="critical", priority=90.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.severity == "critical"


# ── Status transitions ──────────────────────────────────────────────────────

class TestSessionStatus:

    def test_new_session_is_active(self, db_session):
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", now=now)
        correlate_sessions(db_session, now=now)

        s = db_session.query(AttackSessionModel).first()
        assert s.status == "active"

    def test_idle_after_30_min(self, db_session):
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", now=now)
        correlate_sessions(db_session, now=now)

        # Advance time past idle threshold
        later = now + timedelta(minutes=IDLE_AFTER_MINUTES + 1)
        correlate_sessions(db_session, now=later)

        s = db_session.query(AttackSessionModel).first()
        assert s.status == "idle"

    def test_closed_after_60_min(self, db_session):
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", now=now)
        correlate_sessions(db_session, now=now)

        # Advance time past close threshold
        later = now + timedelta(minutes=CLOSE_AFTER_MINUTES + 1)
        correlate_sessions(db_session, now=later)

        s = db_session.query(AttackSessionModel).first()
        assert s.status == "closed"

    def test_activity_resets_idle_to_active(self, db_session):
        """New incident activity should reset an idle session to active."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        correlate_sessions(db_session, now=now)

        # Go idle
        idle_time = now + timedelta(minutes=IDLE_AFTER_MINUTES + 1)
        correlate_sessions(db_session, now=idle_time)
        s = db_session.query(AttackSessionModel).first()
        assert s.status == "idle"

        # New incident within merge window brings session back
        active_time = idle_time + timedelta(minutes=1)
        _incident(db_session, src="10.0.0.1", btype="suspicious", now=active_time)
        correlate_sessions(db_session, now=active_time)

        s = db_session.query(AttackSessionModel).first()
        assert s.status == "active"


# ── API tests ───────────────────────────────────────────────────────────────

class TestSessionAPI:

    def test_list_sessions(self, db_session):
        uid = _seed_user(db_session)
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", now=now)
        correlate_sessions(db_session, now=now)

        client = _make_client(db_session, uid)
        resp = client.get("/api/attack-sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["source_ip"] == "10.0.0.1"
        assert data[0]["status"] == "active"
        assert "incident_ids" in data[0]

    def test_get_session_detail(self, db_session):
        uid = _seed_user(db_session)
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", now=now)
        correlate_sessions(db_session, now=now)

        s = db_session.query(AttackSessionModel).first()

        client = _make_client(db_session, uid)
        resp = client.get(f"/api/attack-sessions/{s.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == s.id
        assert data["source_ip"] == "10.0.0.1"

    def test_get_session_not_found(self, db_session):
        uid = _seed_user(db_session)
        client = _make_client(db_session, uid)
        resp = client.get("/api/attack-sessions/9999")
        assert resp.status_code == 404

    def test_filter_by_status(self, db_session):
        uid = _seed_user(db_session)
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", now=now)
        correlate_sessions(db_session, now=now)

        client = _make_client(db_session, uid)
        resp = client.get("/api/attack-sessions?status=active")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        resp = client.get("/api/attack-sessions?status=closed")
        assert resp.status_code == 200
        assert len(resp.json()) == 0


# ── Enrichment tests ────────────────────────────────────────────────────────

class TestSessionEnrichment:

    def test_top_destination_ips_aggregated(self, db_session):
        """Top destination IPs should be aggregated from linked incidents."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  top_destination_ips=["192.168.1.1", "192.168.1.2", "192.168.1.3"],
                  now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  top_destination_ips=["192.168.1.1", "192.168.1.4"],
                  now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        top_dests = json.loads(s.top_destination_ips)

        # 192.168.1.1 appears in both incidents so should be first
        assert top_dests[0] == "192.168.1.1"
        assert set(top_dests) == {"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"}

    def test_top_destination_ips_capped_at_5(self, db_session):
        """Top destinations should be capped at 5."""
        now = datetime.utcnow()
        ips = [f"192.168.1.{i}" for i in range(10)]
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  top_destination_ips=ips, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert len(json.loads(s.top_destination_ips)) == 5

    def test_top_ports_aggregated(self, db_session):
        """Top ports should be aggregated from linked incidents."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  top_ports=[22, 80, 443], now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  top_ports=[80, 8080], now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        top_ports = json.loads(s.top_ports)

        # port 80 appears in both incidents so should be first
        assert top_ports[0] == 80
        assert set(top_ports) == {22, 80, 443, 8080}

    def test_top_ports_capped_at_5(self, db_session):
        """Top ports should be capped at 5."""
        now = datetime.utcnow()
        ports = list(range(100, 110))
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  top_ports=ports, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert len(json.loads(s.top_ports)) == 5

    def test_highest_target_criticality_propagated(self, db_session):
        """Session should inherit the highest target criticality."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  target_criticality="medium", now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  target_criticality="critical", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.highest_target_criticality == "critical"

    def test_highest_target_criticality_none_when_absent(self, db_session):
        """No criticality set when no incidents have it."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.highest_target_criticality is None

    def test_target_summary_with_assets(self, db_session):
        """Target summary should describe asset composition."""
        now = datetime.utcnow()
        # Create known assets
        db_session.add(AssetModel(
            ip_address="192.168.1.1", hostname="db-prod",
            asset_type="server", criticality="critical",
        ))
        db_session.add(AssetModel(
            ip_address="192.168.1.2", hostname="ws-01",
            asset_type="workstation", criticality="low",
        ))
        db_session.flush()

        _incident(db_session, src="10.0.0.1", btype="scanning",
                  top_destination_ips=["192.168.1.1", "192.168.1.2", "10.10.10.10"],
                  now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()

        assert "critical" in s.target_summary
        assert "server" in s.target_summary
        assert "workstation" in s.target_summary
        assert "unknown" in s.target_summary

    def test_target_summary_no_destinations(self, db_session):
        """Target summary should handle no destinations gracefully."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.target_summary == "No targets identified"

    def test_session_summary_generated(self, db_session):
        """Session summary should be a readable description."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.5", btype="scanning",
                  total_distinct_destinations=15,
                  total_distinct_ports=22, now=now)
        _incident(db_session, src="10.0.0.5", btype="unstable",
                  total_distinct_destinations=3,
                  total_distinct_ports=5, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()

        assert "10.0.0.5" in s.session_summary
        assert "scanning" in s.session_summary
        assert "unstable" in s.session_summary

    def test_recommended_next_step_scanning(self, db_session):
        """Scanning-dominant sessions recommend reviewing ports."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert "port" in s.recommended_next_step.lower()

    def test_recommended_next_step_unstable(self, db_session):
        """Unstable-dominant sessions recommend inspecting resets."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="unstable", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert "reset" in s.recommended_next_step.lower()

    def test_recommended_next_step_suspicious(self, db_session):
        """Suspicious-dominant sessions recommend inspecting denied patterns."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="suspicious", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert "denied" in s.recommended_next_step.lower()

    def test_recommended_next_step_lateral_movement(self, db_session):
        """Lateral movement sessions recommend inspecting internal targets."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="lateral_movement", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert "internal" in s.recommended_next_step.lower()

    def test_recommended_next_step_lateral_dominates(self, db_session):
        """Lateral movement should dominate over scanning in next step."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="lateral_movement", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # Intent-aware: scanning → lateral_movement triggers intent-based step
        assert "authentication" in s.recommended_next_step.lower()

    def test_enrichment_fields_in_api(self, db_session):
        """API responses should include all enrichment fields."""
        uid = _seed_user(db_session)
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  top_destination_ips=["192.168.1.1"],
                  top_ports=[80], now=now)
        correlate_sessions(db_session, now=now)

        client = _make_client(db_session, uid)
        resp = client.get("/api/attack-sessions")
        assert resp.status_code == 200
        data = resp.json()[0]

        assert "top_destination_ips" in data
        assert "top_ports" in data
        assert "target_summary" in data
        assert "highest_target_criticality" in data
        assert "session_summary" in data
        assert "recommended_next_step" in data
        assert "behavior_sequence" in data
        assert "behavior_timeline" in data
        assert "attack_intent" in data


# ── Timeline & intent tests ─────────────────────────────────────────────────

class TestTimelineAndIntent:

    def test_timeline_ordered_by_time(self, db_session):
        """Behavior timeline should be ordered by incident first_seen."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=5))
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  now=now + timedelta(minutes=10))

        correlate_sessions(db_session, now=now + timedelta(minutes=10))
        s = db_session.query(AttackSessionModel).first()
        timeline = json.loads(s.behavior_timeline)

        assert len(timeline) == 3
        assert timeline[0]["behavior"] == "scanning"
        assert timeline[1]["behavior"] == "unstable"
        assert timeline[2]["behavior"] == "suspicious"

    def test_sequence_compressed(self, db_session):
        """Consecutive duplicate behaviors should be compressed."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  now=now + timedelta(minutes=2))
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=5))
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  now=now + timedelta(minutes=10))

        correlate_sessions(db_session, now=now + timedelta(minutes=10))
        s = db_session.query(AttackSessionModel).first()
        assert s.behavior_sequence == "scanning → unstable → suspicious"

    def test_sequence_single_behavior(self, db_session):
        """Single behavior should produce a simple sequence."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.behavior_sequence == "scanning"

    def test_intent_exploitation_attempt(self, db_session):
        """scanning → unstable → suspicious = possible exploitation attempt."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=5))
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  now=now + timedelta(minutes=10))

        correlate_sessions(db_session, now=now + timedelta(minutes=10))
        s = db_session.query(AttackSessionModel).first()
        assert s.attack_intent == "possible exploitation attempt"

    def test_intent_exploitation_scanning_unstable(self, db_session):
        """scanning → unstable = possible exploitation attempt."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()
        assert s.attack_intent == "possible exploitation attempt"

    def test_intent_lateral_movement_preparation(self, db_session):
        """scanning → lateral_movement = lateral movement preparation."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="lateral_movement",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()
        assert s.attack_intent == "lateral movement preparation"

    def test_intent_probing(self, db_session):
        """Repeated suspicious only = probing / policy violation."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="suspicious", now=now)
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()
        assert s.attack_intent == "probing / policy violation"

    def test_intent_service_instability(self, db_session):
        """Unstable-dominant = service instability / potential DoS."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="unstable", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.attack_intent == "service instability / potential DoS"

    def test_intent_none_for_single_scanning(self, db_session):
        """A single scanning incident has no specific intent pattern."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.attack_intent is None

    def test_summary_includes_intent(self, db_session):
        """Session summary should include intent when available."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.5", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.5", btype="unstable",
                  now=now + timedelta(minutes=5))
        _incident(db_session, src="10.0.0.5", btype="suspicious",
                  now=now + timedelta(minutes=10))

        correlate_sessions(db_session, now=now + timedelta(minutes=10))
        s = db_session.query(AttackSessionModel).first()
        assert "possible exploitation attempt" in s.session_summary
        assert "10.0.0.5" in s.session_summary

    def test_summary_includes_critical_assets(self, db_session):
        """Session summary should mention critical assets when present."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  target_criticality="critical", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert "critical" in s.session_summary.lower()

    def test_next_step_intent_aware_exploitation(self, db_session):
        """Intent-based next step for exploitation attempt."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()
        assert "compromise" in s.recommended_next_step.lower()

    def test_next_step_intent_aware_lateral(self, db_session):
        """Intent-based next step for lateral movement."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="lateral_movement",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()
        assert "authentication" in s.recommended_next_step.lower()

    def test_next_step_falls_back_without_intent(self, db_session):
        """Without intent, next step falls back to behavior-based."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # No intent → falls back to scanning generic step
        assert "port" in s.recommended_next_step.lower()


# ── Confidence & decision tests ─────────────────────────────────────────────

from collector.sessions import BURST_THRESHOLD


class TestIntentConfidence:

    def test_base_confidence(self, db_session):
        """Single matching behavior should give base + one match."""
        now = datetime.utcnow()
        # Low flow count to avoid burst boost
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  linked_flow_count=2, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # base 0.5 + 0.1 (unstable matches) = 0.6
        assert s.intent_confidence == 0.6
        assert s.burst_flag is False

    def test_confidence_increases_with_more_matches(self, db_session):
        """More matching behaviors should increase confidence."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  linked_flow_count=2, now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  linked_flow_count=2,
                  now=now + timedelta(minutes=5))
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  linked_flow_count=2,
                  now=now + timedelta(minutes=10))

        correlate_sessions(db_session, now=now + timedelta(minutes=10))
        s = db_session.query(AttackSessionModel).first()
        # base 0.5 + 0.3 (3 matches) + 0.1 (3 incidents) = 0.9
        assert s.intent_confidence >= 0.8

    def test_confidence_boost_critical_assets(self, db_session):
        """Critical assets should boost confidence by +0.1."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  target_criticality="critical", linked_flow_count=2,
                  now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # base 0.5 + 0.1 (match) + 0.1 (critical) = 0.7
        assert s.intent_confidence == 0.7

    def test_confidence_boost_high_repetition(self, db_session):
        """3+ incidents should boost confidence by +0.1."""
        now = datetime.utcnow()
        for i in range(3):
            _incident(db_session, src="10.0.0.1", btype="suspicious",
                      now=now + timedelta(minutes=i))

        correlate_sessions(db_session, now=now + timedelta(minutes=2))
        s = db_session.query(AttackSessionModel).first()
        # base 0.5 + 0.1 (match) + 0.1 (repetition) = 0.7
        assert s.intent_confidence >= 0.7

    def test_confidence_penalty_gaps(self, db_session):
        """Gaps in the behavior sequence should reduce confidence."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        # Gap: lateral_movement between scanning and unstable
        _incident(db_session, src="10.0.0.1", btype="lateral_movement",
                  now=now + timedelta(minutes=3))
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()

        intents = json.loads(s.attack_intents)
        # Find the exploitation attempt intent
        exploit = [i for i in intents if i["intent"] == "possible exploitation attempt"]
        assert len(exploit) == 1
        # Gap penalty applied: conf should be lower than without gap
        # base 0.5 + 0.2 (2 matches) + 0.1 (3 incidents) - 0.1 (gap) = 0.7
        assert exploit[0]["confidence"] <= 0.7

    def test_confidence_capped_at_095(self, db_session):
        """Confidence should never exceed 0.95."""
        now = datetime.utcnow()
        for i in range(5):
            _incident(db_session, src="10.0.0.1", btype="scanning",
                      target_criticality="critical",
                      linked_flow_count=100,
                      now=now + timedelta(minutes=i))
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  target_criticality="critical",
                  linked_flow_count=100,
                  now=now + timedelta(minutes=6))
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  target_criticality="critical",
                  linked_flow_count=100,
                  now=now + timedelta(minutes=7))

        correlate_sessions(db_session, now=now + timedelta(minutes=7))
        s = db_session.query(AttackSessionModel).first()
        assert s.intent_confidence <= 0.95

    def test_no_confidence_without_intent(self, db_session):
        """No intent means no confidence value."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.attack_intent is None
        assert s.intent_confidence is None


class TestMultiIntent:

    def test_multiple_intents_returned(self, db_session):
        """Session matching multiple patterns should return all intents."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=3))
        _incident(db_session, src="10.0.0.1", btype="lateral_movement",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()

        intents = json.loads(s.attack_intents)
        intent_names = [i["intent"] for i in intents]
        assert "possible exploitation attempt" in intent_names
        assert "lateral movement preparation" in intent_names

    def test_primary_intent_is_highest_confidence(self, db_session):
        """attack_intent should be the highest-confidence intent."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning", now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  now=now + timedelta(minutes=3))
        _incident(db_session, src="10.0.0.1", btype="lateral_movement",
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()

        intents = json.loads(s.attack_intents)
        assert intents[0]["confidence"] >= intents[-1]["confidence"]
        assert s.attack_intent == intents[0]["intent"]

    def test_single_intent_list(self, db_session):
        """Single intent should still be returned as a list."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="unstable", now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()

        intents = json.loads(s.attack_intents)
        assert len(intents) == 1
        assert intents[0]["intent"] == "service instability / potential DoS"


class TestTempoAnalysis:

    def test_activity_rate_calculated(self, db_session):
        """Activity rate should reflect flows per minute."""
        now = datetime.utcnow()
        # 2 incidents over 10 minutes, 50 flows each = 100 flows / 10 min = 10 f/m
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  linked_flow_count=50, now=now)
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  linked_flow_count=50,
                  now=now + timedelta(minutes=10))

        correlate_sessions(db_session, now=now + timedelta(minutes=10))
        s = db_session.query(AttackSessionModel).first()
        assert s.activity_rate == 10.0

    def test_burst_flag_set(self, db_session):
        """Burst flag should be set when rate exceeds threshold."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  linked_flow_count=100, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # 100 flows / 1 min (minimum) = 100 f/m > threshold
        assert s.burst_flag is True

    def test_no_burst_at_low_rate(self, db_session):
        """Burst flag should be false for low activity rates."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  linked_flow_count=2, now=now)
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  linked_flow_count=2,
                  now=now + timedelta(minutes=10))

        correlate_sessions(db_session, now=now + timedelta(minutes=10))
        s = db_session.query(AttackSessionModel).first()
        # 4 flows / 10 min = 0.4 f/m
        assert s.burst_flag is False

    def test_burst_boosts_confidence(self, db_session):
        """Burst should add +0.1 to intent confidence."""
        now = datetime.utcnow()
        # High flow count to trigger burst, unstable for intent
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  linked_flow_count=200, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # base 0.5 + 0.1 (match) + 0.1 (burst) = 0.7
        assert s.intent_confidence == 0.7
        assert s.burst_flag is True


class TestDecisionEngine:

    def test_action_block(self, db_session):
        """Critical severity + high confidence → block."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  severity="critical", priority=90.0, now=now)
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  severity="critical", priority=90.0,
                  target_criticality="critical",
                  now=now + timedelta(minutes=3))
        _incident(db_session, src="10.0.0.1", btype="suspicious",
                  severity="critical", priority=90.0,
                  now=now + timedelta(minutes=5))

        correlate_sessions(db_session, now=now + timedelta(minutes=5))
        s = db_session.query(AttackSessionModel).first()
        assert s.recommended_action == "block"

    def test_action_contain(self, db_session):
        """High severity + medium confidence → contain."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="unstable",
                  severity="high", priority=70.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        # severity=high, confidence=0.6 → contain
        assert s.recommended_action == "contain"

    def test_action_investigate(self, db_session):
        """Medium severity → investigate."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  severity="medium", priority=40.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.recommended_action == "investigate"

    def test_action_monitor(self, db_session):
        """Low severity → monitor."""
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="scanning",
                  severity="low", priority=20.0, now=now)

        correlate_sessions(db_session, now=now)
        s = db_session.query(AttackSessionModel).first()
        assert s.recommended_action == "monitor"

    def test_api_exposes_new_fields(self, db_session):
        """API should expose confidence, rate, and action fields."""
        uid = _seed_user(db_session)
        now = datetime.utcnow()
        _incident(db_session, src="10.0.0.1", btype="unstable", now=now)
        correlate_sessions(db_session, now=now)

        client = _make_client(db_session, uid)
        resp = client.get("/api/attack-sessions")
        assert resp.status_code == 200
        data = resp.json()[0]

        assert "intent_confidence" in data
        assert "activity_rate" in data
        assert "burst_flag" in data
        assert "recommended_action" in data
        assert "attack_intents" in data
