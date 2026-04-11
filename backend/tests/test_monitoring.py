"""
Tests for scheduled path monitoring + drift detection.

Covers:

- ``monitoring.detect_drift`` (pure unit tests, no DB):
    * first run / no baseline
    * outcome regression → critical/warning
    * primary impairment change → warning
    * new impairments → warning
    * resolved-only impairments → info
    * confidence drop ≥ threshold → info
    * timing regression on backend_response_delay → warning
    * sub-threshold confidence delta → none
    * is_due() schedule helper

- The full backend monitoring lifecycle through the FastAPI test client:
    * create / list / get / update / delete monitor endpoints
    * monitor ownership isolation
    * manual run baseline (first run records snapshot, no drift)
    * manual run drift (second run with a regressed result fires
      drift_detected notification + auto needs_review transition)
    * resolved/dismissed analyses are NOT pulled back to needs_review
    * cascade delete: deleting a saved query removes its monitors
    * cascade delete: deleting an analysis removes its monitors
    * run_due_monitors honours the interval timer

The path-analysis engine + PCAP normaliser are mocked the same way
test_path_analysis_cache.py mocks them, so the tests run with no real PCAP.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import (
    AnalysisModel,
    Base,
    MonitoredPathModel,
    NotificationModel,
    PathAnalysisSavedQueryModel,
    UserModel,
)
from main import app, get_db, run_due_monitors
from monitoring import detect_drift, is_due


# ══════════════════════════════════════════════════════════════════════════════
# Pure unit tests for detect_drift
# ══════════════════════════════════════════════════════════════════════════════

def _result(
    *,
    outcome="success",
    primary=None,
    impairments=None,
    confidence=90,
    timing=None,
):
    return {
        "connection_outcome":    outcome,
        "primary_impairment":    primary,
        "path_impairments":      list(impairments or []),
        "path_confidence_score": confidence,
        "timing_breakdown":      dict(timing or {}),
    }


class TestDetectDriftUnit:

    def test_first_run_returns_no_drift(self):
        rep = detect_drift(None, _result())
        assert rep["drift_detected"] is False
        assert rep["severity"] == "none"
        assert rep["action_required"] is False
        assert rep["previous_summary"] is None
        # Snapshot still includes the current state so callers can persist it
        assert rep["current_summary"]["connection_outcome"] == "success"

    def test_identical_results_no_drift(self):
        a = _result()
        rep = detect_drift(a, _result())
        assert rep["drift_detected"] is False
        assert rep["severity"] == "none"
        assert rep["changes"] == []

    def test_outcome_regression_to_failure_is_critical(self):
        rep = detect_drift(_result(), _result(outcome="failure"))
        assert rep["severity"] == "critical"
        assert rep["action_required"] is True
        assert rep["changed_fields"]["connection_outcome"]["regression"] is True
        assert any("regressed" in c for c in rep["changes"])

    def test_outcome_change_to_partial_is_warning(self):
        rep = detect_drift(_result(), _result(outcome="partial_success"))
        assert rep["severity"] == "warning"
        assert rep["action_required"] is True

    def test_outcome_improvement_is_warning_not_none(self):
        # An outcome change is always notable even when it's an improvement.
        rep = detect_drift(_result(outcome="failure"), _result(outcome="success"))
        assert rep["severity"] == "warning"
        assert rep["changed_fields"]["connection_outcome"]["regression"] is False

    def test_primary_impairment_appears_warning(self):
        rep = detect_drift(
            _result(),
            _result(primary="backend_response_delay"),
        )
        assert rep["severity"] == "warning"
        assert rep["changed_fields"]["primary_impairment"] == {
            "previous": None,
            "current":  "backend_response_delay",
        }

    def test_primary_impairment_connection_refused_is_critical(self):
        rep = detect_drift(
            _result(),
            _result(primary="connection_refused"),
        )
        assert rep["severity"] == "critical"

    def test_new_impairment_warning(self):
        rep = detect_drift(
            _result(impairments=["packet_loss"]),
            _result(impairments=["packet_loss", "tls_failure"]),
        )
        assert rep["severity"] == "warning"
        assert rep["changed_fields"]["impairments"]["new"] == ["tls_failure"]
        assert rep["changed_fields"]["impairments"]["resolved"] == []

    def test_only_resolved_impairments_is_info(self):
        rep = detect_drift(
            _result(impairments=["packet_loss"]),
            _result(impairments=[]),
        )
        assert rep["severity"] == "info"
        assert rep["action_required"] is False
        assert rep["changed_fields"]["impairments"]["resolved"] == ["packet_loss"]

    def test_confidence_drop_above_threshold_info(self):
        rep = detect_drift(
            _result(confidence=90),
            _result(confidence=70),
        )
        assert rep["severity"] == "info"
        assert rep["changed_fields"]["confidence"]["delta"] == -20

    def test_confidence_drop_below_threshold_no_drift(self):
        rep = detect_drift(
            _result(confidence=90),
            _result(confidence=85),
        )
        assert rep["severity"] == "none"
        assert "confidence" not in rep["changed_fields"]

    def test_backend_delay_regression_is_warning(self):
        rep = detect_drift(
            _result(timing={"backend_response_delay": 20.0}),
            _result(timing={"backend_response_delay": 200.0}),
        )
        assert rep["severity"] == "warning"
        assert "timing" in rep["changed_fields"]
        assert rep["changed_fields"]["timing"]["backend_response_delay"]["regressed"] is True

    def test_small_backend_delay_increase_no_drift(self):
        # +5 ms is well below the 50 ms absolute threshold and not a 1.5×
        # ratio, so it should not register.
        rep = detect_drift(
            _result(timing={"backend_response_delay": 100.0}),
            _result(timing={"backend_response_delay": 105.0}),
        )
        assert rep["severity"] == "none"

    def test_non_monitored_timing_key_does_not_trigger(self):
        rep = detect_drift(
            _result(timing={"unrelated_metric": 10.0}),
            _result(timing={"unrelated_metric": 9999.0}),
        )
        assert rep["severity"] == "none"

    def test_worst_severity_wins(self):
        # Confidence drop alone would be info, but a new impairment makes it
        # warning, and an outcome regression to failure makes it critical.
        rep = detect_drift(
            _result(confidence=90, impairments=["packet_loss"]),
            _result(
                outcome="failure",
                confidence=50,
                impairments=["packet_loss", "tls_failure"],
            ),
        )
        assert rep["severity"] == "critical"
        assert rep["action_required"] is True


class TestIsDue:

    def test_first_run_is_due(self):
        assert is_due(None, 60, datetime.utcnow()) is True

    def test_recent_run_is_not_due(self):
        now = datetime.utcnow()
        assert is_due(now - timedelta(minutes=10), 60, now) is False

    def test_elapsed_run_is_due(self):
        now = datetime.utcnow()
        assert is_due(now - timedelta(minutes=61), 60, now) is True

    def test_exactly_at_interval_is_due(self):
        now = datetime.utcnow()
        assert is_due(now - timedelta(minutes=60), 60, now) is True


# ══════════════════════════════════════════════════════════════════════════════
# Backend lifecycle tests (full FastAPI client + mocked engine)
# ══════════════════════════════════════════════════════════════════════════════

# ── Mock engine plumbing — same pattern as test_path_analysis_cache.py ───────

_NORMALIZE = "normalizer.pipeline.normalize"
_ENGINE    = "core.causal_path.CausalPathEngine"


def _mock_normalize():
    ctx = MagicMock()
    ctx.packets  = []
    ctx.flows    = {}
    ctx.findings = []
    return ctx


def _mock_engine_returning(result_dict: dict):
    """Return a patched CausalPathEngine class whose analyze() returns result_dict."""
    mock_result = MagicMock()
    mock_result.to_dict.return_value = result_dict
    mock_cls = MagicMock()
    mock_cls.return_value.analyze.return_value = mock_result
    return mock_cls


def _baseline_result_dict() -> dict:
    """Healthy baseline payload for the mocked engine."""
    return {
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.1",
        "destination_port": 443,
        "protocol": "TCP",
        "connection_state": "application_level_interaction",
        "path_summary": "Connection succeeded.",
        "path_steps": [],
        "hop_sequence": [],
        "firewall_observation":      {"role": "firewall", "ip": "", "observed": False, "note": ""},
        "load_balancer_observation": {"role": "load_balancer", "ip": "", "observed": False, "note": ""},
        "backend_observation":       {"role": "backend", "ip": "", "observed": False, "note": ""},
        "timing_breakdown": {"backend_response_delay": 20.0},
        "timing_interpretation": "",
        "return_path_observation": "",
        "connection_outcome": "success",
        "primary_impairment": None,
        "path_impairments": [],
        "likely_failure_point": "",
        "alternative_hypotheses": [],
        "confidence_score": 90,
        "confidence_reasoning": "",
        "path_confidence_score": 90,
        "confidence_reasons": [],
        "evidence_packets": [],
        "evidence_flows": [],
        "evidence_items": [],
        "missing_visibility_notes": [],
    }


def _regressed_result_dict() -> dict:
    """Same payload but with an outcome regression + new impairment."""
    d = _baseline_result_dict()
    d["connection_outcome"] = "failure"
    d["primary_impairment"] = "no_response"
    d["path_impairments"] = ["no_response"]
    d["path_confidence_score"] = 60
    d["timing_breakdown"] = {"backend_response_delay": 250.0}
    return d


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


@pytest.fixture(scope="function")
def tmp_pcap(tmp_path):
    f = tmp_path / "test.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return str(f)


def _seed_user(db, username: str, is_admin: bool = False) -> int:
    u = UserModel(username=username, hashed_password="x", is_admin=is_admin)
    db.add(u)
    db.flush()
    uid: int = u.id
    db.commit()
    return uid


def _seed_analysis(db, uid: int, *, file_path: str, aid: str = "ana-1") -> str:
    db.add(AnalysisModel(
        id=aid,
        user_id=uid,
        filename="test.pcap",
        file_path=file_path,
        status="completed",
    ))
    db.commit()
    return aid


def _seed_saved_query(db, uid: int) -> int:
    q = PathAnalysisSavedQueryModel(
        owner_user_id=uid,
        name="watch-prod",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.1",
        destination_port=443,
        firewall_ips=json.dumps([]),
        load_balancer_vips=json.dumps([]),
        backend_ips=json.dumps([]),
        backend_subnets=json.dumps([]),
        scope="private",
        created_by=uid,
        updated_by=uid,
    )
    db.add(q)
    db.commit()
    return q.id


def _make_client(db_session, uid: int, *, is_admin: bool = False) -> TestClient:
    def _override_db():
        yield db_session

    def _override_user():
        return SimpleNamespace(id=uid, is_admin=is_admin, team_id=None)

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def world(db_session, tmp_pcap):
    """A user + completed analysis + saved query + active client."""
    uid = _seed_user(db_session, "alice")
    aid = _seed_analysis(db_session, uid, file_path=tmp_pcap)
    qid = _seed_saved_query(db_session, uid)
    client = _make_client(db_session, uid)
    return SimpleNamespace(
        db=db_session, uid=uid, aid=aid, qid=qid, client=client,
    )


# ══════════════════════════════════════════════════════════════════════════════
# CRUD endpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestMonitorCRUD:

    def test_create_returns_201_and_payload(self, world):
        r = world.client.post(
            "/api/path-monitors",
            json={
                "saved_query_id": world.qid,
                "analysis_id":    world.aid,
                "schedule_interval_minutes": 30,
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["saved_query_id"] == world.qid
        assert body["analysis_id"]    == world.aid
        assert body["schedule_interval_minutes"] == 30
        assert body["enabled"] is True
        assert body["last_run_at"] is None
        assert body["has_baseline"] is False
        assert body["saved_query_name"]   == "watch-prod"
        assert body["analysis_filename"]  == "test.pcap"

    def test_create_rejects_unknown_saved_query(self, world):
        r = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": 99999, "analysis_id": world.aid},
        )
        assert r.status_code in (403, 404)

    def test_create_rejects_unknown_analysis(self, world):
        r = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": "missing"},
        )
        assert r.status_code == 404

    def test_list_only_returns_own_monitors(self, db_session, tmp_pcap):
        alice = _seed_user(db_session, "alice")
        bob   = _seed_user(db_session, "bob")
        aid   = _seed_analysis(db_session, alice, file_path=tmp_pcap, aid="ana-a")
        qid   = _seed_saved_query(db_session, alice)

        c_alice = _make_client(db_session, alice)
        c_alice.post(
            "/api/path-monitors",
            json={"saved_query_id": qid, "analysis_id": aid},
        )
        # Bob has no monitors (overrides are app-global, so we re-bind for
        # each user before issuing requests)
        c_bob = _make_client(db_session, bob)
        assert c_bob.get("/api/path-monitors").json() == []
        c_alice = _make_client(db_session, alice)
        assert len(c_alice.get("/api/path-monitors").json()) == 1

    def test_get_unknown_returns_404(self, world):
        assert world.client.get("/api/path-monitors/999").status_code == 404

    def test_get_other_users_monitor_404(self, db_session, tmp_pcap):
        alice = _seed_user(db_session, "alice")
        bob   = _seed_user(db_session, "bob")
        aid   = _seed_analysis(db_session, alice, file_path=tmp_pcap, aid="ana-a")
        qid   = _seed_saved_query(db_session, alice)

        c_alice = _make_client(db_session, alice)
        mid = c_alice.post(
            "/api/path-monitors",
            json={"saved_query_id": qid, "analysis_id": aid},
        ).json()["id"]
        c_bob = _make_client(db_session, bob)
        assert c_bob.get(f"/api/path-monitors/{mid}").status_code == 404

    def test_update_toggles_enabled(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        r = world.client.put(
            f"/api/path-monitors/{mid}",
            json={"enabled": False, "schedule_interval_minutes": 5},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is False
        assert body["schedule_interval_minutes"] == 5

    def test_delete_removes_monitor(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        assert world.client.delete(f"/api/path-monitors/{mid}").status_code == 204
        assert world.client.get(f"/api/path-monitors/{mid}").status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Manual run + drift
# ══════════════════════════════════════════════════════════════════════════════

class TestManualRun:

    def _create_monitor(self, world) -> int:
        return world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]

    def test_first_run_records_baseline_no_drift(self, world):
        mid = self._create_monitor(world)
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            r = world.client.post(f"/api/path-monitors/{mid}/run")
        assert r.status_code == 200
        body = r.json()
        assert body["report"]["drift_detected"] is False
        assert body["report"]["severity"] == "none"
        assert body["monitor"]["has_baseline"] is True
        assert body["monitor"]["last_run_at"] is not None

    def test_second_run_with_regression_fires_drift(self, world):
        mid = self._create_monitor(world)
        # First run = baseline
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        # Wipe the cache so the engine re-runs with the regressed payload
        from database import PathAnalysisCacheModel
        world.db.query(PathAnalysisCacheModel).delete()
        world.db.commit()

        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_regressed_result_dict())):
            r = world.client.post(f"/api/path-monitors/{mid}/run")
        assert r.status_code == 200
        body = r.json()
        assert body["report"]["drift_detected"] is True
        assert body["report"]["severity"] == "critical"
        assert body["report"]["action_required"] is True
        assert body["monitor"]["last_drift_severity"] == "critical"
        assert body["monitor"]["last_change_at"] is not None
        assert body["monitor"]["last_change_summary"]["severity"] == "critical"

    def test_drift_creates_notification(self, world):
        mid = self._create_monitor(world)
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        from database import PathAnalysisCacheModel
        world.db.query(PathAnalysisCacheModel).delete()
        world.db.commit()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_regressed_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        notifs = (
            world.db.query(NotificationModel)
            .filter(NotificationModel.user_id == world.uid)
            .all()
        )
        types = [n.type for n in notifs]
        assert "drift_detected" in types
        drift = next(n for n in notifs if n.type == "drift_detected")
        assert drift.analysis_id == world.aid
        assert "10.0.0.5" in drift.message

    def test_drift_transitions_workflow_to_needs_review(self, world):
        mid = self._create_monitor(world)
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        from database import PathAnalysisCacheModel
        world.db.query(PathAnalysisCacheModel).delete()
        world.db.commit()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_regressed_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        # Refresh the analysis row from the same session
        world.db.expire_all()
        a = world.db.query(AnalysisModel).filter(
            AnalysisModel.id == world.aid
        ).first()
        assert a.workflow_state == "needs_review"

    def test_resolved_analysis_is_not_pulled_back(self, world):
        # Mark the analysis resolved up front
        world.db.query(AnalysisModel).filter(
            AnalysisModel.id == world.aid
        ).update({"workflow_state": "resolved"})
        world.db.commit()

        mid = self._create_monitor(world)
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        from database import PathAnalysisCacheModel
        world.db.query(PathAnalysisCacheModel).delete()
        world.db.commit()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_regressed_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        world.db.expire_all()
        a = world.db.query(AnalysisModel).filter(
            AnalysisModel.id == world.aid
        ).first()
        # Stays resolved — analyst's verdict is sticky
        assert a.workflow_state == "resolved"

    def test_no_drift_creates_no_notifications(self, world):
        mid = self._create_monitor(world)
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
            world.client.post(f"/api/path-monitors/{mid}/run")
        notifs = (
            world.db.query(NotificationModel)
            .filter(NotificationModel.user_id == world.uid)
            .all()
        )
        assert all(n.type != "drift_detected" for n in notifs)


# ══════════════════════════════════════════════════════════════════════════════
# run_due_monitors interval gating + cascade deletes
# ══════════════════════════════════════════════════════════════════════════════

class TestRunDueAndCascade:

    def test_run_due_skips_recent_runs(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={
                "saved_query_id": world.qid,
                "analysis_id":    world.aid,
                "schedule_interval_minutes": 60,
            },
        ).json()["id"]

        # Pretend it ran 10 minutes ago
        m = world.db.query(MonitoredPathModel).filter(
            MonitoredPathModel.id == mid
        ).first()
        m.last_run_at = datetime.utcnow() - timedelta(minutes=10)
        world.db.commit()

        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            ran = run_due_monitors(world.db)
        assert ran == 0

    def test_run_due_processes_overdue_monitor(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={
                "saved_query_id": world.qid,
                "analysis_id":    world.aid,
                "schedule_interval_minutes": 60,
            },
        ).json()["id"]

        m = world.db.query(MonitoredPathModel).filter(
            MonitoredPathModel.id == mid
        ).first()
        m.last_run_at = datetime.utcnow() - timedelta(hours=2)
        world.db.commit()

        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            ran = run_due_monitors(world.db)
        assert ran == 1
        world.db.expire_all()
        m2 = world.db.query(MonitoredPathModel).filter(
            MonitoredPathModel.id == mid
        ).first()
        assert m2.last_run_at is not None
        assert m2.has_baseline if hasattr(m2, "has_baseline") else True

    def test_run_due_skips_disabled(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={
                "saved_query_id": world.qid,
                "analysis_id":    world.aid,
            },
        ).json()["id"]
        world.client.put(f"/api/path-monitors/{mid}", json={"enabled": False})

        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            ran = run_due_monitors(world.db)
        assert ran == 0

    def test_deleting_saved_query_cascades(self, world):
        world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        )
        assert world.db.query(MonitoredPathModel).count() == 1
        r = world.client.delete(
            f"/api/path-analysis/saved-queries/{world.qid}"
        )
        assert r.status_code == 204
        assert world.db.query(MonitoredPathModel).count() == 0

    def test_deleting_analysis_cascades(self, world):
        world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        )
        assert world.db.query(MonitoredPathModel).count() == 1
        r = world.client.delete(f"/api/analyses/{world.aid}")
        assert r.status_code == 204
        assert world.db.query(MonitoredPathModel).count() == 0


# ══════════════════════════════════════════════════════════════════════════════
# Tick endpoint admin gate
# ══════════════════════════════════════════════════════════════════════════════

class TestTickEndpoint:

    def test_non_admin_rejected(self, world):
        r = world.client.post("/api/path-monitors/tick")
        assert r.status_code == 403

    def test_admin_can_tick(self, db_session, tmp_pcap):
        admin = _seed_user(db_session, "root", is_admin=True)
        c = _make_client(db_session, admin, is_admin=True)
        r = c.post("/api/path-monitors/tick")
        assert r.status_code == 200
        assert r.json() == {"ran": 0}
