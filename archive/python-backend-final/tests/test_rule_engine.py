"""
Tests for the user-defined correlation rules engine.

Covers:
  1.  Rule evaluation — count condition triggers correctly
  2.  Rule evaluation — distinct_count triggers correctly
  3.  Rule evaluation — threshold NOT met → no incident
  4.  Cooldown respected — second evaluation within cooldown → skip
  5.  Cooldown expired — creates new incident
  6.  Built-in rule "Repeated denied" fires on 10+ denied flows
  7.  Built-in rule "Port sweep" fires on 15+ distinct ports
  8.  API list returns rules
  9.  API create rule works
  10. API toggle enable/disable works
  11. condition_operator "in" works (list match)
  12. target_entity src_dst_pair groups correctly
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import (
    Base,
    CorrelationRuleModel,
    LiveFlowModel,
    LiveIncidentModel,
    UserModel,
)
from main import app, get_db
from collector.rule_engine import (
    evaluate_rules,
    seed_default_rules,
    DEFAULT_RULES,
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


def _seed_user(db, username="admin", is_admin=True):
    u = UserModel(username=username, hashed_password="x", is_admin=is_admin)
    db.add(u)
    db.flush()
    uid = u.id
    db.commit()
    return uid


def _make_client(db_session, uid, is_admin=True):
    def _override_db():
        yield db_session

    def _override_user():
        return UserModel(id=uid, username="test", hashed_password="x", is_admin=is_admin)

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app)


def _make_flow(db, **kwargs):
    """Create a LiveFlowModel with sensible defaults."""
    now = kwargs.pop("now", datetime.utcnow())
    defaults = {
        "source_id": "test",
        "device_type": "firewall",
        "parser_id": "test",
        "source_ip": "10.0.0.1",
        "destination_ip": "192.168.1.1",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "TCP",
        "first_seen": now - timedelta(minutes=5),
        "last_seen": now,
        "state": "completed",
        "event_count": 1,
        "total_bytes_in": 100,
        "total_bytes_out": 200,
        "total_packets_in": 5,
        "total_packets_out": 10,
        "allow_count": 1,
        "deny_count": 0,
        "drop_count": 0,
        "reset_count": 0,
        "alert_count": 0,
        "raw_event_count": 1,
        "flow_type": "normal",
        "suppressed": False,
    }
    defaults.update(kwargs)
    f = LiveFlowModel(**defaults)
    db.add(f)
    db.flush()
    return f


def _make_rule(db, **kwargs):
    """Create a CorrelationRuleModel with sensible defaults."""
    defaults = {
        "name": "Test Rule",
        "enabled": True,
        "scope": "global",
        "condition_field": "action",
        "condition_operator": "eq",
        "condition_value": "deny",
        "aggregation_type": "count",
        "aggregation_field": None,
        "threshold": 5,
        "time_window_minutes": 10,
        "target_entity": "source_ip",
        "severity": "medium",
        "incident_behavior_type": "blocked",
        "cooldown_minutes": 30,
    }
    defaults.update(kwargs)
    r = CorrelationRuleModel(**defaults)
    db.add(r)
    db.flush()
    return r


# ── Test 1: count condition triggers ────────────────────────────────────────

def test_count_condition_triggers(db_session):
    """Rule with count >= 5 on denied flows fires when 6 matching flows exist."""
    now = datetime.utcnow()
    rule = _make_rule(db_session, threshold=5)

    # Create 6 denied flows
    for i in range(6):
        _make_flow(
            db_session, now=now,
            source_ip="10.0.0.1",
            destination_ip=f"192.168.1.{i}",
            allow_count=0, deny_count=1,
        )
    db_session.commit()

    n = evaluate_rules(db_session, now=now)
    assert n == 1

    incidents = db_session.query(LiveIncidentModel).all()
    assert len(incidents) == 1
    assert incidents[0].source_ip == "10.0.0.1"
    assert incidents[0].behavior_type == "blocked"
    assert incidents[0].severity == "medium"


# ── Test 2: distinct_count triggers ─────────────────────────────────────────

def test_distinct_count_triggers(db_session):
    """Rule with distinct_count(destination_port) >= 10 fires correctly."""
    now = datetime.utcnow()
    rule = _make_rule(
        db_session,
        name="Port scan",
        condition_field="flow_type",
        condition_operator="in",
        condition_value=json.dumps(["scanning", "blocked"]),
        aggregation_type="distinct_count",
        aggregation_field="destination_port",
        threshold=10,
        incident_behavior_type="scanning",
        severity="high",
    )

    # Create 12 flows with distinct ports, flow_type=scanning
    for i in range(12):
        _make_flow(
            db_session, now=now,
            source_ip="10.0.0.2",
            destination_port=8000 + i,
            flow_type="scanning",
        )
    db_session.commit()

    n = evaluate_rules(db_session, now=now)
    assert n == 1

    incident = db_session.query(LiveIncidentModel).first()
    assert incident.behavior_type == "scanning"
    assert incident.severity == "high"


# ── Test 3: threshold NOT met → no incident ─────────────────────────────────

def test_threshold_not_met(db_session):
    """No incident created when aggregation result is below threshold."""
    now = datetime.utcnow()
    rule = _make_rule(db_session, threshold=10)

    # Only 3 denied flows (below threshold of 10)
    for i in range(3):
        _make_flow(
            db_session, now=now,
            source_ip="10.0.0.1",
            allow_count=0, deny_count=1,
        )
    db_session.commit()

    n = evaluate_rules(db_session, now=now)
    assert n == 0
    assert db_session.query(LiveIncidentModel).count() == 0


# ── Test 4: cooldown respected ──────────────────────────────────────────────

def test_cooldown_respected(db_session):
    """Second evaluation within cooldown window does not create duplicate."""
    now = datetime.utcnow()
    rule = _make_rule(db_session, threshold=3, cooldown_minutes=30)

    for i in range(5):
        _make_flow(
            db_session, now=now,
            source_ip="10.0.0.1",
            allow_count=0, deny_count=1,
        )
    db_session.commit()

    # First evaluation creates incident
    n1 = evaluate_rules(db_session, now=now)
    assert n1 == 1
    assert db_session.query(LiveIncidentModel).count() == 1

    # Second evaluation within cooldown — should skip
    now2 = now + timedelta(minutes=5)
    n2 = evaluate_rules(db_session, now=now2)
    assert n2 == 0
    assert db_session.query(LiveIncidentModel).count() == 1


# ── Test 5: cooldown expired → new incident ─────────────────────────────────

def test_cooldown_expired_creates_new(db_session):
    """After cooldown expires, a new incident is created."""
    now = datetime.utcnow()
    rule = _make_rule(db_session, threshold=3, cooldown_minutes=10)

    for i in range(5):
        _make_flow(
            db_session, now=now,
            source_ip="10.0.0.1",
            allow_count=0, deny_count=1,
        )
    db_session.commit()

    # First evaluation
    n1 = evaluate_rules(db_session, now=now)
    assert n1 == 1

    # After cooldown (15 min later), add more flows
    now2 = now + timedelta(minutes=15)
    for i in range(5):
        _make_flow(
            db_session, now=now2,
            source_ip="10.0.0.1",
            allow_count=0, deny_count=1,
        )
    db_session.commit()

    n2 = evaluate_rules(db_session, now=now2)
    assert n2 == 1
    assert db_session.query(LiveIncidentModel).count() == 2


# ── Test 6: built-in "Repeated denied" fires on 10+ denied ──────────────────

def test_builtin_repeated_denied(db_session):
    """Default 'Repeated denied connections' rule fires on 10+ denied flows."""
    now = datetime.utcnow()
    seed_default_rules(db_session)

    # Create 12 denied flows
    for i in range(12):
        _make_flow(
            db_session, now=now,
            source_ip="10.1.1.1",
            destination_ip=f"192.168.1.{i}",
            allow_count=0, deny_count=1,
        )
    db_session.commit()

    n = evaluate_rules(db_session, now=now)
    assert n >= 1

    incidents = db_session.query(LiveIncidentModel).filter(
        LiveIncidentModel.behavior_type == "blocked"
    ).all()
    assert len(incidents) >= 1


# ── Test 7: built-in "Port sweep" fires on 15+ distinct ports ───────────────

def test_builtin_port_sweep(db_session):
    """Default 'Port sweep detection' rule fires on 15+ distinct ports."""
    now = datetime.utcnow()
    seed_default_rules(db_session)

    # Create 18 flows with distinct ports, flow_type=scanning
    for i in range(18):
        _make_flow(
            db_session, now=now,
            source_ip="10.2.2.2",
            destination_port=1000 + i,
            flow_type="scanning",
        )
    db_session.commit()

    n = evaluate_rules(db_session, now=now)
    assert n >= 1

    incidents = db_session.query(LiveIncidentModel).filter(
        LiveIncidentModel.behavior_type == "scanning"
    ).all()
    assert len(incidents) >= 1


# ── Test 8: API list returns rules ──────────────────────────────────────────

def test_api_list_rules(db_session):
    uid = _seed_user(db_session)
    _make_rule(db_session, name="Rule A", created_by=uid)
    _make_rule(db_session, name="Rule B", created_by=uid)
    db_session.commit()

    client = _make_client(db_session, uid)
    resp = client.get("/api/correlation-rules")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    names = {r["name"] for r in data}
    assert "Rule A" in names
    assert "Rule B" in names


# ── Test 9: API create rule ─────────────────────────────────────────────────

def test_api_create_rule(db_session):
    uid = _seed_user(db_session)
    client = _make_client(db_session, uid)

    resp = client.post("/api/correlation-rules", json={
        "name": "My Custom Rule",
        "condition_field": "action",
        "condition_operator": "eq",
        "condition_value": "deny",
        "aggregation_type": "count",
        "threshold": 20,
        "target_entity": "source_ip",
        "incident_behavior_type": "blocked",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "My Custom Rule"
    assert data["enabled"] is True
    assert data["threshold"] == 20
    assert data["created_by"] == uid


# ── Test 10: API toggle enable/disable ──────────────────────────────────────

def test_api_toggle_rule(db_session):
    uid = _seed_user(db_session)
    rule = _make_rule(db_session, name="Toggle Me", created_by=uid, enabled=True)
    db_session.commit()
    rule_id = rule.id

    client = _make_client(db_session, uid)

    # Toggle off
    resp = client.patch(f"/api/correlation-rules/{rule_id}/toggle")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

    # Toggle on
    resp = client.patch(f"/api/correlation-rules/{rule_id}/toggle")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


# ── Test 11: condition_operator "in" works ──────────────────────────────────

def test_condition_operator_in(db_session):
    """The 'in' operator correctly matches flows with listed values."""
    now = datetime.utcnow()
    rule = _make_rule(
        db_session,
        condition_field="flow_type",
        condition_operator="in",
        condition_value=json.dumps(["suspicious", "scanning"]),
        threshold=3,
        incident_behavior_type="suspicious",
    )

    # 2 scanning + 2 suspicious = 4 matching (above threshold of 3)
    for i in range(2):
        _make_flow(db_session, now=now, source_ip="10.3.3.3", flow_type="scanning")
    for i in range(2):
        _make_flow(db_session, now=now, source_ip="10.3.3.3", flow_type="suspicious")
    # 1 normal — should not match
    _make_flow(db_session, now=now, source_ip="10.3.3.3", flow_type="normal")
    db_session.commit()

    n = evaluate_rules(db_session, now=now)
    assert n == 1

    incident = db_session.query(LiveIncidentModel).first()
    assert incident.source_ip == "10.3.3.3"
    assert incident.behavior_type == "suspicious"


# ── Test 12: target_entity src_dst_pair groups correctly ────────────────────

def test_src_dst_pair_grouping(db_session):
    """src_dst_pair target groups flows by source+destination IP pair."""
    now = datetime.utcnow()
    rule = _make_rule(
        db_session,
        condition_field="flow_type",
        condition_operator="eq",
        condition_value="unstable",
        aggregation_type="count",
        threshold=3,
        target_entity="src_dst_pair",
        incident_behavior_type="unstable",
    )

    # Pair A: 10.0.0.1 → 192.168.1.1 — 4 flows (above threshold)
    for i in range(4):
        _make_flow(
            db_session, now=now,
            source_ip="10.0.0.1", destination_ip="192.168.1.1",
            flow_type="unstable",
        )
    # Pair B: 10.0.0.1 → 192.168.1.2 — 2 flows (below threshold)
    for i in range(2):
        _make_flow(
            db_session, now=now,
            source_ip="10.0.0.1", destination_ip="192.168.1.2",
            flow_type="unstable",
        )
    db_session.commit()

    n = evaluate_rules(db_session, now=now)
    assert n == 1  # only pair A triggers

    incident = db_session.query(LiveIncidentModel).first()
    assert incident.source_ip == "10.0.0.1"
    assert incident.behavior_type == "unstable"
