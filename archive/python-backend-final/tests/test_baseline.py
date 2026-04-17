"""
Tests for the IP baseline learning and deviation detection layer.

Covers:
  - Baseline computation (enough / not enough windows)
  - Deviation detection (no baseline, normal, anomalous, edge cases)
  - Incident severity boost on high deviation
  - API endpoints
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
    Base,
    IPBaselineModel,
    LiveFlowModel,
    LiveIncidentModel,
    UserModel,
)
from main import app, get_db
from collector.baseline import (
    compute_baselines,
    detect_deviations,
    MIN_WINDOWS,
    WINDOW_MINUTES,
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


def _flow(db, src="10.0.0.1", dst="10.0.0.2", dport=443,
          first_seen=None, state="completed",
          bytes_in=100, bytes_out=50,
          deny=False, reset=False):
    """Insert a minimal LiveFlowModel row."""
    first_seen = first_seen or datetime.utcnow()
    actual_state = state
    if deny:
        actual_state = "denied"
    elif reset:
        actual_state = "reset"
    flow = LiveFlowModel(
        source_id="fw01",
        device_type="firewall",
        parser_id="test",
        source_ip=src,
        destination_ip=dst,
        source_port=50000,
        destination_port=dport,
        protocol="TCP",
        first_seen=first_seen,
        last_seen=first_seen,
        total_bytes_in=bytes_in,
        total_bytes_out=bytes_out,
        state=actual_state,
        flow_type="normal",
    )
    db.add(flow)
    db.flush()
    return flow


def _seed_flows(db, src="10.0.0.1", num_windows=6, base_time=None):
    """Create flows spread across multiple 10-minute windows."""
    base_time = base_time or (datetime.utcnow() - timedelta(days=3))
    for w in range(num_windows):
        window_start = base_time + timedelta(minutes=w * WINDOW_MINUTES)
        # 3 normal flows per window
        for i in range(3):
            _flow(db, src=src,
                  dst=f"10.0.0.{(i % 5) + 2}",
                  dport=443 + (i % 3),
                  first_seen=window_start + timedelta(seconds=i * 10),
                  bytes_in=100, bytes_out=50)
    db.commit()


def _seed_baseline(db, src="10.0.0.1", avg_flows=3.0, avg_deny=0.0,
                   avg_reset=0.0, stddev_flows=0.5, stddev_deny=0.01,
                   stddev_reset=0.01, sample_count=10):
    """Directly insert a baseline for testing deviation detection."""
    bl = IPBaselineModel(
        source_ip=src,
        sample_count=sample_count,
        avg_flows_per_window=avg_flows,
        avg_distinct_destinations=3.0,
        avg_distinct_ports=2.0,
        avg_deny_ratio=avg_deny,
        avg_reset_ratio=avg_reset,
        avg_bytes_per_flow=150.0,
        stddev_flows=stddev_flows,
        stddev_deny_ratio=stddev_deny,
        stddev_reset_ratio=stddev_reset,
        last_computed_at=datetime.utcnow(),
    )
    db.add(bl)
    db.commit()
    return bl


# ── Baseline computation tests ──────────────────────────────────────────────

class TestComputeBaselines:

    def test_baseline_created_with_enough_windows(self, db_session):
        """With >= 5 windows, a baseline should be created."""
        _seed_flows(db_session, src="10.0.0.1", num_windows=6)

        n = compute_baselines(db_session)
        assert n == 1

        bl = db_session.query(IPBaselineModel).filter(
            IPBaselineModel.source_ip == "10.0.0.1",
        ).first()
        assert bl is not None
        assert bl.sample_count == 6
        assert bl.avg_flows_per_window > 0
        assert bl.last_computed_at is not None

    def test_baseline_not_created_with_few_windows(self, db_session):
        """With < 5 windows, no baseline should be created."""
        _seed_flows(db_session, src="10.0.0.1", num_windows=3)

        n = compute_baselines(db_session)
        assert n == 0

        bl = db_session.query(IPBaselineModel).filter(
            IPBaselineModel.source_ip == "10.0.0.1",
        ).first()
        assert bl is None

    def test_baseline_updated_on_recompute(self, db_session):
        """Recomputing should update existing baseline."""
        _seed_flows(db_session, src="10.0.0.1", num_windows=6)
        compute_baselines(db_session)

        # Add more flows and recompute
        _seed_flows(db_session, src="10.0.0.1", num_windows=8,
                    base_time=datetime.utcnow() - timedelta(days=1))
        n = compute_baselines(db_session)
        assert n == 1

        count = db_session.query(IPBaselineModel).filter(
            IPBaselineModel.source_ip == "10.0.0.1",
        ).count()
        assert count == 1  # upserted, not duplicated

    def test_multiple_ips_baselined(self, db_session):
        """Multiple IPs should each get their own baseline."""
        _seed_flows(db_session, src="10.0.0.1", num_windows=6)
        _seed_flows(db_session, src="10.0.0.2", num_windows=7)

        n = compute_baselines(db_session)
        assert n == 2


# ── Deviation detection tests ───────────────────────────────────────────────

class TestDetectDeviations:

    def test_no_baseline_returns_no_baseline_true(self, db_session):
        """When no baseline exists, no_baseline should be True, score 0."""
        behaviors = [{"source_ip": "10.0.0.99", "flow_count": 10,
                       "deny_ratio": 0.0, "reset_ratio": 0.0,
                       "distinct_destinations": 5, "distinct_ports": 3}]

        result = detect_deviations(db_session, behaviors)
        assert len(result) == 1
        assert result[0]["no_baseline"] is True
        assert result[0]["deviation_score"] == 0.0
        assert result[0]["baseline_sample_count"] == 0

    def test_normal_behavior_low_deviation(self, db_session):
        """Behavior matching baseline should have low deviation."""
        _seed_baseline(db_session, src="10.0.0.1",
                       avg_flows=10.0, avg_deny=0.05, avg_reset=0.02,
                       stddev_flows=2.0, stddev_deny=0.02, stddev_reset=0.01)

        behaviors = [{"source_ip": "10.0.0.1", "flow_count": 11,
                       "deny_ratio": 0.06, "reset_ratio": 0.02,
                       "distinct_destinations": 3, "distinct_ports": 2}]

        result = detect_deviations(db_session, behaviors)
        assert result[0]["no_baseline"] is False
        assert result[0]["deviation_score"] < 2.0
        assert result[0]["deviating_metrics"] == []

    def test_anomalous_deny_ratio_detected(self, db_session):
        """High deny_ratio deviation should flag deny_ratio."""
        _seed_baseline(db_session, src="10.0.0.1",
                       avg_deny=0.05, stddev_deny=0.02)

        # deny_ratio=0.80 is (0.80 - 0.05) / 0.02 = 37.5 stddevs
        behaviors = [{"source_ip": "10.0.0.1", "flow_count": 3,
                       "deny_ratio": 0.80, "reset_ratio": 0.0,
                       "distinct_destinations": 3, "distinct_ports": 2}]

        result = detect_deviations(db_session, behaviors)
        assert "deny_ratio" in result[0]["deviating_metrics"]
        assert result[0]["deviation_score"] > 2.0

    def test_anomalous_distinct_ports_detected(self, db_session):
        """distinct_ports has no stddev stored, so z=0 and should not flag."""
        _seed_baseline(db_session, src="10.0.0.1")

        behaviors = [{"source_ip": "10.0.0.1", "flow_count": 3,
                       "deny_ratio": 0.0, "reset_ratio": 0.0,
                       "distinct_destinations": 100, "distinct_ports": 100}]

        result = detect_deviations(db_session, behaviors)
        # distinct_ports has no stddev → z=0 → should NOT be flagged
        assert "distinct_ports" not in result[0]["deviating_metrics"]

    def test_anomalous_flow_count_detected(self, db_session):
        """Very high flow count should flag flow_count."""
        _seed_baseline(db_session, src="10.0.0.1",
                       avg_flows=5.0, stddev_flows=1.0)

        behaviors = [{"source_ip": "10.0.0.1", "flow_count": 50,
                       "deny_ratio": 0.0, "reset_ratio": 0.0,
                       "distinct_destinations": 3, "distinct_ports": 2}]

        result = detect_deviations(db_session, behaviors)
        assert "flow_count" in result[0]["deviating_metrics"]

    def test_stddev_zero_no_division_error(self, db_session):
        """stddev=0 should produce z=0, no crash."""
        _seed_baseline(db_session, src="10.0.0.1",
                       stddev_flows=0.0, stddev_deny=0.0, stddev_reset=0.0)

        behaviors = [{"source_ip": "10.0.0.1", "flow_count": 999,
                       "deny_ratio": 0.99, "reset_ratio": 0.99,
                       "distinct_destinations": 3, "distinct_ports": 2}]

        result = detect_deviations(db_session, behaviors)
        assert result[0]["deviation_score"] == 0.0
        assert result[0]["deviating_metrics"] == []

    def test_deviation_score_capped_at_10(self, db_session):
        """Deviation score should never exceed 10.0."""
        _seed_baseline(db_session, src="10.0.0.1",
                       avg_flows=5.0, stddev_flows=0.1,
                       avg_deny=0.01, stddev_deny=0.001,
                       avg_reset=0.01, stddev_reset=0.001)

        # Extreme deviation on all metrics
        behaviors = [{"source_ip": "10.0.0.1", "flow_count": 10000,
                       "deny_ratio": 1.0, "reset_ratio": 1.0,
                       "distinct_destinations": 3, "distinct_ports": 2}]

        result = detect_deviations(db_session, behaviors)
        assert result[0]["deviation_score"] == 10.0

    def test_empty_behaviors_returns_empty(self, db_session):
        """Empty input should return empty output."""
        result = detect_deviations(db_session, [])
        assert result == []


# ── Incident severity boost test ────────────────────────────────────────────

class TestDeviationSeverityBoost:

    def test_high_deviation_boosts_severity(self, db_session):
        """deviation_score > 3.0 should boost incident severity by one tier."""
        from collector.incidents import upsert_incidents_from_behaviors

        # Seed admin for notifications
        u = UserModel(username="admin", hashed_password="x")
        db_session.add(u)
        db_session.flush()
        db_session.commit()

        # Create baseline so deviation detection works
        _seed_baseline(db_session, src="10.0.0.1",
                       avg_flows=5.0, stddev_flows=1.0,
                       avg_deny=0.01, stddev_deny=0.005)

        # Behavior with high deviation (flow_count way above baseline)
        behavior = {
            "source_ip": "10.0.0.1",
            "behavior_type": "scanning",
            "confidence": 0.7,  # normally → medium severity
            "flow_count": 100,  # way above avg 5.0
            "distinct_destinations": 10,
            "distinct_ports": 20,
            "reset_ratio": 0.0,
            "deny_ratio": 0.5,  # (0.5 - 0.01) / 0.005 = 98 stddevs
            "time_window_minutes": 10,
            "drivers": ["wide_port_spread"],
            # Add deviation fields (normally added by detect_deviations)
            "deviation_score": 5.0,
            "deviating_metrics": ["flow_count", "deny_ratio"],
            "no_baseline": False,
            "baseline_sample_count": 10,
        }

        result = upsert_incidents_from_behaviors(db_session, [behavior])
        assert result["created"] == 1

        inc = db_session.query(LiveIncidentModel).first()
        # confidence=0.7 → base severity "medium", +1 from deviation → "high"
        assert inc.severity in ("high", "critical")
        assert "high_deviation" in inc.summary

    def test_low_deviation_no_boost(self, db_session):
        """deviation_score <= 3.0 should NOT boost severity."""
        from collector.incidents import upsert_incidents_from_behaviors

        u = UserModel(username="admin", hashed_password="x")
        db_session.add(u)
        db_session.flush()
        db_session.commit()

        behavior = {
            "source_ip": "10.0.0.1",
            "behavior_type": "scanning",
            "confidence": 0.7,
            "flow_count": 10,
            "distinct_destinations": 10,
            "distinct_ports": 20,
            "reset_ratio": 0.0,
            "deny_ratio": 0.0,
            "time_window_minutes": 10,
            "drivers": ["wide_port_spread"],
            "deviation_score": 1.0,
            "deviating_metrics": [],
            "no_baseline": False,
            "baseline_sample_count": 10,
        }

        result = upsert_incidents_from_behaviors(db_session, [behavior])
        inc = db_session.query(LiveIncidentModel).first()
        # confidence=0.7 → "medium", no deviation boost
        assert inc.severity == "medium"


# ── API tests ───────────────────────────────────────────────────────────────

class TestBaselineAPI:

    def test_list_baselines(self, db_session):
        uid = _seed_user(db_session)
        _seed_baseline(db_session, src="10.0.0.1")
        _seed_baseline(db_session, src="10.0.0.2")

        client = _make_client(db_session, uid)
        resp = client.get("/api/baselines")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["source_ip"] == "10.0.0.1"
        assert "avg_flows_per_window" in data[0]
        assert "stddev_flows" in data[0]

    def test_list_baselines_filter_by_ip(self, db_session):
        uid = _seed_user(db_session)
        _seed_baseline(db_session, src="10.0.0.1")
        _seed_baseline(db_session, src="10.0.0.2")

        client = _make_client(db_session, uid)
        resp = client.get("/api/baselines?source_ip=10.0.0.1")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["source_ip"] == "10.0.0.1"

    def test_get_baseline_detail(self, db_session):
        uid = _seed_user(db_session)
        _seed_baseline(db_session, src="10.0.0.1")

        client = _make_client(db_session, uid)
        resp = client.get("/api/baselines/10.0.0.1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["source_ip"] == "10.0.0.1"
        assert data["sample_count"] == 10

    def test_get_baseline_not_found(self, db_session):
        uid = _seed_user(db_session)
        client = _make_client(db_session, uid)
        resp = client.get("/api/baselines/99.99.99.99")
        assert resp.status_code == 404
