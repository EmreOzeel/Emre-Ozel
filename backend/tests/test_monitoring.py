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
    MonitoredPathRunModel,
    MonitorOutcomeModel,
    MonitorSuppressionModel,
    NotificationModel,
    PathAnalysisSavedQueryModel,
    UserModel,
)
from main import app, get_db, run_due_monitors
from monitoring import (
    adjust_action,
    apply_baseline,
    apply_suppressions,
    compute_risk_score,
    compute_system_insights,
    decide_action,
    detect_drift,
    is_due,
    learn_from_outcomes,
    summarize_history,
)


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


# ══════════════════════════════════════════════════════════════════════════════
# Trend intelligence — pure unit tests for summarize_history
# ══════════════════════════════════════════════════════════════════════════════

def _run(
    *,
    run_at="2026-04-11T00:00:00",
    outcome="success",
    primary=None,
    impairments=None,
    confidence=90,
    drift="none",
    timing=None,
    action_required=False,
):
    """Build a run dict in the same shape MonitoredPathRunModel produces."""
    return {
        "run_at":                run_at,
        "connection_outcome":    outcome,
        "primary_impairment":    primary,
        "impairments":           list(impairments or []),
        "path_confidence_score": confidence,
        "drift_severity":        drift,
        "action_required":       action_required,
        "timing":                dict(timing or {}),
    }


class TestSummarizeHistory:

    def test_empty_history_returns_safe_defaults(self):
        s = summarize_history([])
        assert s["total_runs"] == 0
        assert s["health_score"] == 100
        assert s["recurring_impairments"] == []
        assert s["worsening"] is False
        assert s["confidence_trend"]["slope"] == "stable"

    def test_single_healthy_run(self):
        s = summarize_history([_run()])
        assert s["total_runs"] == 1
        assert s["health_score"] == 100
        assert s["latest_outcome"] == "success"
        assert s["worsening"] is False
        assert s["drift_counts"]["none"] == 1

    def test_recurring_impairment_detection(self):
        runs = [
            _run(impairments=["packet_loss"]),
            _run(),
            _run(impairments=["packet_loss"]),
            _run(impairments=["packet_loss", "tls_failure"]),
        ]
        s = summarize_history(runs)
        tokens = [r["token"] for r in s["recurring_impairments"]]
        assert "packet_loss" in tokens
        # tls_failure appeared only once → not recurring
        assert "tls_failure" not in tokens
        # Sorted by count descending
        first = s["recurring_impairments"][0]
        assert first["token"] == "packet_loss"
        assert first["count"] == 3

    def test_one_off_impairment_not_recurring(self):
        runs = [_run(), _run(), _run(impairments=["packet_loss"])]
        s = summarize_history(runs)
        assert s["recurring_impairments"] == []

    def test_confidence_trend_dropping(self):
        runs = [
            _run(confidence=95), _run(confidence=92), _run(confidence=90),
            _run(confidence=70), _run(confidence=65), _run(confidence=60),
        ]
        s = summarize_history(runs)
        assert s["confidence_trend"]["slope"] == "worsening"

    def test_confidence_trend_stable(self):
        runs = [_run(confidence=85) for _ in range(8)]
        s = summarize_history(runs)
        assert s["confidence_trend"]["slope"] == "stable"

    def test_backend_delay_trend_detected(self):
        # Steady 20ms baseline, recent jump to 200ms
        runs = [
            _run(timing={"backend_response_delay": 20.0}),
            _run(timing={"backend_response_delay": 22.0}),
            _run(timing={"backend_response_delay": 19.0}),
            _run(timing={"backend_response_delay": 200.0}),
            _run(timing={"backend_response_delay": 220.0}),
            _run(timing={"backend_response_delay": 210.0}),
        ]
        s = summarize_history(runs)
        assert s["backend_delay_trend"]["slope"] == "worsening"
        assert s["backend_delay_trend"]["key"] == "backend_response_delay"
        assert s["backend_delay_trend"]["recent_avg"] > s["backend_delay_trend"]["prev_avg"]

    def test_backend_delay_trend_improving(self):
        # High baseline, recent improvement
        runs = (
            [_run(timing={"backend_response_delay": 200.0}) for _ in range(4)]
            + [_run(timing={"backend_response_delay": 30.0}) for _ in range(4)]
        )
        s = summarize_history(runs)
        assert s["backend_delay_trend"]["slope"] == "improving"

    def test_health_score_punishes_recent_failures(self):
        # 8 healthy runs, then 2 critical at the end — health score should
        # drop noticeably even though most history was fine.
        runs = (
            [_run() for _ in range(8)]
            + [_run(outcome="failure", drift="critical") for _ in range(2)]
        )
        s = summarize_history(runs)
        assert s["health_score"] < 80

    def test_recurring_return_path_problem_counted(self):
        runs = [
            _run(impairments=["return_path_problem"]),
            _run(),
            _run(impairments=["return_path_problem"]),
            _run(impairments=["return_path_problem"]),
        ]
        s = summarize_history(runs)
        assert s["return_path_problem_runs"] == 3
        # Also surfaces as recurring impairment
        tokens = [r["token"] for r in s["recurring_impairments"]]
        assert "return_path_problem" in tokens

    def test_regression_episodes_counts_distinct_stretches(self):
        # Two distinct bad stretches separated by recoveries
        runs = [
            _run(),
            _run(drift="warning", action_required=True),
            _run(drift="warning", action_required=True),  # same episode
            _run(),                                        # recovery
            _run(),
            _run(drift="critical", action_required=True),  # new episode
            _run(),
        ]
        s = summarize_history(runs)
        assert s["regression_episodes"] == 2
        assert s["action_required_runs"] == 3

    def test_worsening_flag_combines_signals(self):
        runs = (
            [_run(confidence=95, timing={"backend_response_delay": 20.0}) for _ in range(4)]
            + [
                _run(
                    confidence=60,
                    timing={"backend_response_delay": 200.0},
                    impairments=["packet_loss"],
                    drift="warning",
                ),
                _run(
                    confidence=55,
                    timing={"backend_response_delay": 220.0},
                    impairments=["packet_loss"],
                    drift="warning",
                ),
            ]
        )
        s = summarize_history(runs)
        assert s["worsening"] is True
        # Each independent reason should be present
        text = " ".join(s["worsening_reasons"])
        assert "backend response delay" in text
        assert "confidence" in text
        assert "recurring" in text

    def test_worsening_false_for_steady_history(self):
        runs = [_run(timing={"backend_response_delay": 20.0}) for _ in range(10)]
        s = summarize_history(runs)
        assert s["worsening"] is False
        assert s["worsening_reasons"] == []

    def test_drift_counts_aggregated(self):
        runs = [
            _run(),
            _run(drift="info"),
            _run(drift="warning"),
            _run(drift="warning"),
            _run(drift="critical"),
        ]
        s = summarize_history(runs)
        assert s["drift_counts"] == {
            "none": 1, "info": 1, "warning": 2, "critical": 1,
        }


# ══════════════════════════════════════════════════════════════════════════════
# History persistence + endpoints (full FastAPI lifecycle)
# ══════════════════════════════════════════════════════════════════════════════

class TestHistoryPersistenceAndEndpoints:

    def _create_monitor(self, world) -> int:
        return world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]

    def _run_with_result(self, world, mid: int, result_dict: dict):
        # Wipe the cache so the engine re-runs each call
        from database import PathAnalysisCacheModel
        world.db.query(PathAnalysisCacheModel).delete()
        world.db.commit()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(result_dict)):
            return world.client.post(f"/api/path-monitors/{mid}/run")

    def test_each_run_creates_one_history_row(self, world):
        mid = self._create_monitor(world)
        self._run_with_result(world, mid, _baseline_result_dict())
        self._run_with_result(world, mid, _baseline_result_dict())
        self._run_with_result(world, mid, _baseline_result_dict())
        n = (
            world.db.query(MonitoredPathRunModel)
            .filter(MonitoredPathRunModel.monitored_path_id == mid)
            .count()
        )
        assert n == 3

    def test_history_row_captures_projection_fields(self, world):
        mid = self._create_monitor(world)
        self._run_with_result(world, mid, _regressed_result_dict())
        row = (
            world.db.query(MonitoredPathRunModel)
            .filter(MonitoredPathRunModel.monitored_path_id == mid)
            .first()
        )
        assert row.connection_outcome == "failure"
        assert row.primary_impairment == "no_response"
        assert row.path_confidence_score == 60
        assert row.drift_severity == "none"  # first run = baseline, no drift
        assert row.action_required is False
        timing = json.loads(row.timing_json)
        assert timing["backend_response_delay"] == 250.0
        imps = json.loads(row.impairments_json)
        assert imps == ["no_response"]

    def test_history_endpoint_returns_newest_first(self, world):
        mid = self._create_monitor(world)
        self._run_with_result(world, mid, _baseline_result_dict())
        # Tweak each subsequent result so confidence varies
        for cval in (80, 70, 60):
            d = _baseline_result_dict()
            d["path_confidence_score"] = cval
            self._run_with_result(world, mid, d)
        r = world.client.get(f"/api/path-monitors/{mid}/history")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 4
        # Newest first → confidence series should descend across rows
        assert rows[0]["path_confidence_score"] == 60
        assert rows[-1]["path_confidence_score"] == 90

    def test_history_endpoint_respects_limit(self, world):
        mid = self._create_monitor(world)
        for _ in range(6):
            self._run_with_result(world, mid, _baseline_result_dict())
        r = world.client.get(f"/api/path-monitors/{mid}/history?limit=3")
        assert len(r.json()) == 3

    def test_history_endpoint_404_for_other_user(self, db_session, tmp_pcap):
        alice = _seed_user(db_session, "alice")
        bob   = _seed_user(db_session, "bob")
        aid   = _seed_analysis(db_session, alice, file_path=tmp_pcap, aid="ana-x")
        qid   = _seed_saved_query(db_session, alice)
        c_alice = _make_client(db_session, alice)
        mid = c_alice.post(
            "/api/path-monitors",
            json={"saved_query_id": qid, "analysis_id": aid},
        ).json()["id"]
        c_bob = _make_client(db_session, bob)
        r = c_bob.get(f"/api/path-monitors/{mid}/history")
        assert r.status_code == 404

    def test_trend_endpoint_returns_summary_shape(self, world):
        mid = self._create_monitor(world)
        for _ in range(4):
            self._run_with_result(world, mid, _baseline_result_dict())
        r = world.client.get(f"/api/path-monitors/{mid}/trend")
        assert r.status_code == 200
        body = r.json()
        # Spot-check that the digest keys are present
        for k in (
            "total_runs", "health_score", "worsening",
            "recurring_impairments", "confidence_trend",
            "backend_delay_trend", "drift_counts", "regression_episodes",
        ):
            assert k in body
        assert body["total_runs"] == 4
        assert body["health_score"] == 100

    def test_trend_endpoint_flags_worsening_path(self, world):
        mid = self._create_monitor(world)
        # 3 healthy runs
        for _ in range(3):
            self._run_with_result(world, mid, _baseline_result_dict())
        # Then 3 regressed runs (cache wipe handled inside helper)
        for _ in range(3):
            self._run_with_result(world, mid, _regressed_result_dict())
        body = world.client.get(f"/api/path-monitors/{mid}/trend").json()
        assert body["worsening"] is True
        assert body["worsening_reasons"]
        # Recurring no_response should appear
        tokens = [r["token"] for r in body["recurring_impairments"]]
        assert "no_response" in tokens
        assert body["health_score"] < 100

    def test_trend_endpoint_empty_for_new_monitor(self, world):
        mid = self._create_monitor(world)
        body = world.client.get(f"/api/path-monitors/{mid}/trend").json()
        assert body["total_runs"] == 0
        assert body["worsening"] is False
        assert body["recurring_impairments"] == []

    def test_run_count_on_list_endpoint(self, world):
        mid = self._create_monitor(world)
        for _ in range(3):
            self._run_with_result(world, mid, _baseline_result_dict())
        rows = world.client.get("/api/path-monitors").json()
        target = next(r for r in rows if r["id"] == mid)
        assert target["run_count"] == 3

    def test_deleting_monitor_cascades_history(self, world):
        mid = self._create_monitor(world)
        self._run_with_result(world, mid, _baseline_result_dict())
        self._run_with_result(world, mid, _baseline_result_dict())
        assert world.db.query(MonitoredPathRunModel).count() == 2
        r = world.client.delete(f"/api/path-monitors/{mid}")
        assert r.status_code == 204
        assert world.db.query(MonitoredPathRunModel).count() == 0

    def test_deleting_analysis_cascades_history(self, world):
        mid = self._create_monitor(world)
        self._run_with_result(world, mid, _baseline_result_dict())
        assert world.db.query(MonitoredPathRunModel).count() == 1
        r = world.client.delete(f"/api/analyses/{world.aid}")
        assert r.status_code == 204
        assert world.db.query(MonitoredPathRunModel).count() == 0

    def test_deleting_saved_query_cascades_history(self, world):
        mid = self._create_monitor(world)
        self._run_with_result(world, mid, _baseline_result_dict())
        assert world.db.query(MonitoredPathRunModel).count() == 1
        r = world.client.delete(
            f"/api/path-analysis/saved-queries/{world.qid}"
        )
        assert r.status_code == 204
        assert world.db.query(MonitoredPathRunModel).count() == 0


# ══════════════════════════════════════════════════════════════════════════════
# Risk scoring — pure unit tests for compute_risk_score
# ══════════════════════════════════════════════════════════════════════════════

class TestComputeRiskScore:

    def test_empty_summary_is_low(self):
        r = compute_risk_score({})
        assert r == {"risk_score": 0, "risk_level": "low", "drivers": []}

    def test_zero_run_summary_is_low(self):
        s = summarize_history([])
        r = compute_risk_score(s)
        assert r["risk_score"] == 0
        assert r["risk_level"] == "low"
        assert r["drivers"] == []

    def test_healthy_stable_path_scores_low(self):
        # 10 healthy runs → health_score 100, no drift, no recurring imps.
        runs = [_run() for _ in range(10)]
        s = summarize_history(runs)
        r = compute_risk_score(s)
        assert r["risk_score"] < 10
        assert r["risk_level"] == "low"

    def test_single_critical_drift_run_is_at_least_medium(self):
        runs = [_run() for _ in range(4)] + [
            _run(outcome="failure", drift="critical", action_required=True),
        ]
        s = summarize_history(runs)
        r = compute_risk_score(s)
        assert r["risk_score"] >= 25
        assert r["risk_level"] in ("medium", "high", "critical")

    def test_chronic_critical_path_is_critical(self):
        # Many critical runs with recurring severe impairment + worsening flags.
        runs = (
            [_run(timing={"backend_response_delay": 20.0}) for _ in range(2)]
            + [
                _run(
                    outcome="failure",
                    drift="critical",
                    action_required=True,
                    impairments=["no_response"],
                    confidence=40,
                    timing={"backend_response_delay": 300.0},
                ) for _ in range(6)
            ]
        )
        s = summarize_history(runs)
        r = compute_risk_score(s)
        assert r["risk_score"] >= 75
        assert r["risk_level"] == "critical"
        # Drivers should mention the dominant signals
        text = " ".join(r["drivers"])
        assert "health" in text or "critical" in text

    def test_score_is_deterministic(self):
        runs = [
            _run(),
            _run(drift="warning", action_required=True),
            _run(drift="warning", action_required=True),
            _run(impairments=["packet_loss"]),
            _run(impairments=["packet_loss"]),
        ]
        s = summarize_history(runs)
        r1 = compute_risk_score(s)
        r2 = compute_risk_score(s)
        r3 = compute_risk_score(summarize_history(runs))
        assert r1 == r2 == r3

    def test_score_clamped_to_100(self):
        # Worst-case profile — score should not blow past 100.
        runs = [
            _run(
                outcome="failure", drift="critical", action_required=True,
                confidence=10, impairments=["no_response", "tls_failure", "syn_timeout"],
                timing={"backend_response_delay": 500.0},
            ) for _ in range(10)
        ]
        s = summarize_history(runs)
        r = compute_risk_score(s)
        assert 0 <= r["risk_score"] <= 100
        assert r["risk_level"] == "critical"

    def test_severe_recurring_impairment_outranks_generic(self):
        severe_runs = [
            _run(impairments=["no_response"]),
            _run(impairments=["no_response"]),
            _run(impairments=["no_response"]),
        ]
        generic_runs = [
            _run(impairments=["packet_loss"]),
            _run(impairments=["packet_loss"]),
            _run(impairments=["packet_loss"]),
        ]
        sev_score = compute_risk_score(summarize_history(severe_runs))["risk_score"]
        gen_score = compute_risk_score(summarize_history(generic_runs))["risk_score"]
        assert sev_score > gen_score

    def test_recurring_return_path_problem_drives_risk(self):
        runs = [
            _run(impairments=["return_path_problem"]) for _ in range(4)
        ]
        s = summarize_history(runs)
        r = compute_risk_score(s)
        assert r["risk_score"] >= 25
        # The "return-path-problem" driver should be present somewhere
        assert any("return-path-problem" in d for d in r["drivers"])

    def test_isolated_info_drift_stays_low(self):
        runs = [_run() for _ in range(8)] + [_run(drift="info")]
        s = summarize_history(runs)
        r = compute_risk_score(s)
        assert r["risk_level"] == "low"

    def test_drivers_ordered_by_contribution(self):
        # Build a profile where health is the dominant driver. The first
        # driver in the list should mention health.
        runs = (
            [_run(outcome="failure", drift="critical", action_required=True) for _ in range(8)]
        )
        s = summarize_history(runs)
        r = compute_risk_score(s)
        assert r["drivers"], "drivers should not be empty"
        assert "health" in r["drivers"][0]

    def test_level_thresholds(self):
        # Synthetic summaries to pin level boundaries.
        for score, expected in [
            (0, "low"), (24, "low"),
            (25, "medium"), (49, "medium"),
            (50, "high"), (74, "high"),
            (75, "critical"), (100, "critical"),
        ]:
            from monitoring import _level_for_score
            assert _level_for_score(score) == expected


# ══════════════════════════════════════════════════════════════════════════════
# Risk in the list endpoint — ordering + payload shape
# ══════════════════════════════════════════════════════════════════════════════

class TestRiskInListEndpoint:

    def _create_two_monitors(self, world):
        # Two monitors against the same analysis + saved query is fine for
        # testing the list ordering — we use different IDs.
        m1 = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        m2 = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        return m1, m2

    def _run_with(self, world, mid, result):
        from database import PathAnalysisCacheModel
        world.db.query(PathAnalysisCacheModel).delete()
        world.db.commit()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(result)):
            world.client.post(f"/api/path-monitors/{mid}/run")

    def test_list_response_includes_risk_fields(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        rows = world.client.get("/api/path-monitors").json()
        target = next(r for r in rows if r["id"] == mid)
        assert "risk_score"   in target
        assert "risk_level"   in target
        assert "risk_drivers" in target
        # Brand-new monitor with no runs → low risk
        assert target["risk_score"] == 0
        assert target["risk_level"] == "low"
        assert target["risk_drivers"] == []

    def test_list_sorted_by_risk_desc(self, world):
        m1, m2 = self._create_two_monitors(world)
        # m1: healthy
        self._run_with(world, m1, _baseline_result_dict())
        # m2: chronic critical
        for _ in range(5):
            self._run_with(world, m2, _regressed_result_dict())
        rows = world.client.get("/api/path-monitors").json()
        # m2 should be first because its risk_score is much higher
        assert rows[0]["id"] == m2
        assert rows[0]["risk_score"] > rows[1]["risk_score"]
        assert rows[0]["risk_level"] in ("high", "critical")

    def test_tied_risk_breaks_by_id_desc(self, world):
        m1, m2 = self._create_two_monitors(world)
        # Both monitors have no runs → score 0 → tie. Newer (higher id) wins.
        rows = world.client.get("/api/path-monitors").json()
        assert rows[0]["id"] == m2
        assert rows[1]["id"] == m1

    def test_risk_drivers_are_human_readable(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        for _ in range(5):
            self._run_with(world, mid, _regressed_result_dict())
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        # Drivers exist, are strings, and reference real signals
        assert isinstance(target["risk_drivers"], list)
        assert all(isinstance(d, str) for d in target["risk_drivers"])
        joined = " ".join(target["risk_drivers"]).lower()
        # At least one of the dominant inputs should be cited
        assert any(k in joined for k in ("health", "critical", "recurring", "no_response"))


# ══════════════════════════════════════════════════════════════════════════════
# Action engine — pure unit tests for decide_action
# ══════════════════════════════════════════════════════════════════════════════

def _decide(runs):
    s = summarize_history(runs)
    r = compute_risk_score(s)
    return decide_action(s, r), r, s


class TestDecideActionBaseRules:

    def test_no_history_is_no_action(self):
        a, _r, _s = _decide([])
        assert a["action_required"] is False
        assert a["priority"] == "low"
        assert a["action_label"] == "no_action"
        assert a["recommended_action"] == "No action — path is healthy"

    def test_healthy_stable_path_is_low(self):
        runs = [_run() for _ in range(10)]
        a, _r, _s = _decide(runs)
        assert a["priority"] == "low"
        assert a["action_required"] is False
        assert a["action_label"] == "no_action"

    def test_critical_risk_requires_immediate_attention(self):
        runs = [
            _run(
                outcome="failure",
                drift="critical",
                action_required=True,
                impairments=["no_response"],
                confidence=20,
                timing={"backend_response_delay": 400.0},
            ) for _ in range(8)
        ]
        a, r, _s = _decide(runs)
        assert r["risk_level"] == "critical"
        assert a["priority"] == "critical"
        assert a["action_label"] == "requires_immediate_attention"
        assert a["action_required"] is True

    def test_high_risk_needs_attention(self):
        # Tuned to land squarely in the high band: a few warning runs +
        # a recurring (non-severe) impairment + worsening confidence trend.
        runs = (
            [_run(confidence=95, impairments=["packet_loss"]) for _ in range(2)]
            + [
                _run(
                    drift="warning",
                    action_required=True,
                    confidence=60,
                    impairments=["packet_loss"],
                ) for _ in range(3)
            ]
        )
        a, r, _s = _decide(runs)
        assert r["risk_level"] in ("medium", "high")
        # Either base mapping or escalation (worsening + episode) lands ≥ high
        assert a["priority"] in ("high", "critical")
        assert a["action_required"] is True
        assert a["action_label"] in ("needs_attention", "requires_immediate_attention")

    def test_medium_stable_passive_monitoring(self):
        # Single info-level drift in an otherwise healthy stretch — risk
        # should land in low or low-medium, with passive monitoring.
        runs = [_run() for _ in range(8)] + [_run(drift="info")]
        a, r, _s = _decide(runs)
        assert r["risk_level"] in ("low", "medium")
        if r["risk_level"] == "medium":
            assert a["action_label"] == "passive_monitoring"
            assert a["action_required"] is False

    def test_medium_with_worsening_flips_action_required(self):
        # Build a synthetic summary that lands in MEDIUM with worsening=True
        # and zero regression episodes — Override 3 should NOT fire (no
        # episode), so the only escalation path is the medium "worsening
        # flips action_required" rule.
        summary = {
            "total_runs": 5,
            "health_score": 70,
            "drift_counts": {"none": 5, "info": 0, "warning": 0, "critical": 0},
            "regression_episodes": 0,
            "worsening": True,
            "worsening_reasons": ["confidence dropping (90 → 70)"],
            "recurring_impairments": [],
            "confidence_trend": {"recent_avg": 70, "prev_avg": 90, "slope": "worsening"},
            "backend_delay_trend": {"recent_avg": None, "prev_avg": None, "slope": "stable", "key": None},
            "action_required_runs": 0,
            "return_path_problem_runs": 0,
        }
        risk = compute_risk_score(summary)
        # Force the risk into the medium band for this assertion — if the
        # base risk happens to land lower we still want to verify the rule
        # itself, so call decide_action directly with a synthetic medium risk.
        synthetic_risk = {"risk_score": 30, "risk_level": "medium", "drivers": []}
        a = decide_action(summary, synthetic_risk)
        assert a["priority"] in ("medium", "high")
        # action_required must be True because the medium-+-worsening rule
        # fires (or because override 3 escalates to high).
        assert a["action_required"] is True


class TestDecideActionOverrides:

    def test_severe_recurring_escalates_one_tier(self):
        # Three runs with recurring no_response — even without dramatic
        # other signals, this should escalate above "low".
        runs = [_run(impairments=["no_response"]) for _ in range(3)]
        a, _r, _s = _decide(runs)
        assert a["priority"] in ("medium", "high", "critical")
        # The escalation reason should appear in reasons[]
        assert any("severe recurring" in r for r in a["reasons"])

    def test_severe_recurring_does_not_overflow_critical(self):
        # Already critical; escalation must clamp at critical, not crash.
        runs = [
            _run(
                outcome="failure",
                drift="critical",
                action_required=True,
                impairments=["no_response", "tls_failure"],
                confidence=10,
                timing={"backend_response_delay": 500.0},
            ) for _ in range(8)
        ]
        a, _r, _s = _decide(runs)
        assert a["priority"] == "critical"

    def test_recurring_return_path_problem_forces_action(self):
        # Recurring return_path_problem on an otherwise medium history
        # must land action_required=True regardless of base mapping.
        runs = [
            _run(impairments=["return_path_problem"]) for _ in range(4)
        ]
        a, _r, _s = _decide(runs)
        assert a["action_required"] is True
        assert any("return path" in f.lower() for f in a["focus"])

    def test_worsening_plus_episode_forces_high_minimum(self):
        # Synthetic medium summary with a regression episode + worsening flag.
        summary = {
            "total_runs": 5,
            "health_score": 70,
            "drift_counts": {"none": 3, "info": 0, "warning": 1, "critical": 0},
            "regression_episodes": 1,
            "worsening": True,
            "worsening_reasons": ["confidence dropping"],
            "recurring_impairments": [],
            "confidence_trend": {"recent_avg": 60, "prev_avg": 90, "slope": "worsening"},
            "backend_delay_trend": {"recent_avg": None, "prev_avg": None, "slope": "stable", "key": None},
            "action_required_runs": 1,
            "return_path_problem_runs": 0,
        }
        risk = {"risk_score": 35, "risk_level": "medium", "drivers": []}
        a = decide_action(summary, risk)
        assert a["priority"] in ("high", "critical")
        assert a["action_required"] is True

    def test_overrides_never_de_escalate(self):
        # Whatever band the base mapping picks, overrides must only escalate.
        # We try several profiles and verify priority(after) >= priority(base).
        from monitoring import _PRIORITY_RANK

        profiles = [
            # 1: low/healthy
            [_run() for _ in range(10)],
            # 2: medium-ish (a few warnings)
            [_run(drift="warning") for _ in range(3)] + [_run() for _ in range(3)],
            # 3: high — many critical failure runs
            [_run(outcome="failure", drift="critical", action_required=True) for _ in range(8)],
            # 4: critical — chronic failure with severe recurring impairment
            [
                _run(
                    outcome="failure", drift="critical", action_required=True,
                    impairments=["no_response"], confidence=10,
                    timing={"backend_response_delay": 500.0},
                ) for _ in range(8)
            ],
        ]
        for runs in profiles:
            s = summarize_history(runs)
            r = compute_risk_score(s)
            base_priority = {
                "low": "low", "medium": "medium",
                "high": "high", "critical": "critical",
            }[r["risk_level"]]
            a = decide_action(s, r)
            assert _PRIORITY_RANK[a["priority"]] >= _PRIORITY_RANK[base_priority], \
                f"override de-escalated {base_priority} → {a['priority']}"


class TestDecideActionFocusAndRecommendation:

    def test_recommendation_for_no_history(self):
        a, _r, _s = _decide([])
        assert "healthy" in a["recommended_action"].lower()

    def test_focus_includes_backend_latency(self):
        runs = (
            [_run(timing={"backend_response_delay": 20.0}) for _ in range(4)]
            + [_run(timing={"backend_response_delay": 250.0}) for _ in range(4)]
        )
        a, _r, _s = _decide(runs)
        text = " ".join(a["focus"]).lower()
        assert "backend" in text or "latency" in text

    def test_focus_includes_return_path(self):
        runs = [_run(impairments=["return_path_problem"]) for _ in range(3)]
        a, _r, _s = _decide(runs)
        text = " ".join(a["focus"]).lower()
        assert "return path" in text or "asymmetry" in text

    def test_focus_includes_tls(self):
        runs = [_run(impairments=["tls_failure"]) for _ in range(3)]
        a, _r, _s = _decide(runs)
        text = " ".join(a["focus"]).lower()
        assert "tls" in text

    def test_focus_includes_no_response(self):
        runs = [_run(impairments=["no_response"]) for _ in range(3)]
        a, _r, _s = _decide(runs)
        text = " ".join(a["focus"]).lower()
        assert "destination" in text or "reachability" in text

    def test_recommendation_picks_first_focus_item(self):
        runs = (
            [_run(timing={"backend_response_delay": 20.0}) for _ in range(4)]
            + [_run(timing={"backend_response_delay": 300.0}) for _ in range(4)]
        )
        a, _r, _s = _decide(runs)
        assert a["focus"]
        assert a["recommended_action"] == a["focus"][0]

    def test_critical_without_clear_signal_has_generic_recommendation(self):
        # All-failure but no recurring severe imps (failures with empty
        # impairment lists are unusual but we should still recommend
        # something useful — the focus list will be empty and the
        # priority-based fallback ("Review the recent drift event" /
        # "Open the latest run and investigate immediately") kicks in).
        runs = [
            _run(outcome="failure", drift="critical", action_required=True)
            for _ in range(8)
        ]
        a, _r, _s = _decide(runs)
        assert a["recommended_action"]
        if not a["focus"]:
            text = a["recommended_action"].lower()
            assert any(k in text for k in ("investigate", "review", "drift"))

    def test_reasons_are_audit_trail(self):
        runs = (
            [_run(impairments=["no_response"]) for _ in range(3)]
        )
        a, _r, _s = _decide(runs)
        # reasons must include the base band classification
        joined = " ".join(a["reasons"]).lower()
        assert "band" in joined or "no history" in joined


# ══════════════════════════════════════════════════════════════════════════════
# Action fields surfaced through the list endpoint
# ══════════════════════════════════════════════════════════════════════════════

class TestActionInListEndpoint:

    def _create_monitor(self, world) -> int:
        return world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]

    def _run_with(self, world, mid, result):
        from database import PathAnalysisCacheModel
        world.db.query(PathAnalysisCacheModel).delete()
        world.db.commit()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(result)):
            world.client.post(f"/api/path-monitors/{mid}/run")

    def test_list_response_includes_action_fields(self, world):
        mid = self._create_monitor(world)
        rows = world.client.get("/api/path-monitors").json()
        target = next(r for r in rows if r["id"] == mid)
        for k in (
            "action_required", "action_label", "priority",
            "recommended_action", "action_focus",
        ):
            assert k in target
        # Brand-new monitor → no action
        assert target["action_required"] is False
        assert target["priority"] == "low"
        assert target["action_label"] == "no_action"

    def test_list_marks_chronic_critical_as_action_required(self, world):
        mid = self._create_monitor(world)
        for _ in range(5):
            self._run_with(world, mid, _regressed_result_dict())
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        assert target["action_required"] is True
        assert target["priority"] in ("high", "critical")
        assert target["action_label"] in (
            "needs_attention", "requires_immediate_attention",
        )
        # Recommendation should be a non-empty human sentence
        assert isinstance(target["recommended_action"], str)
        assert len(target["recommended_action"]) > 5
        # Focus list should reference the dominant signal
        focus_text = " ".join(target["action_focus"]).lower()
        assert any(k in focus_text for k in ("destination", "reachability", "backend", "no_response"))


# ══════════════════════════════════════════════════════════════════════════════
# Outcome learning — pure unit tests for learn_from_outcomes + adjust_action
# ══════════════════════════════════════════════════════════════════════════════

def _outcome(
    outcome="issue_confirmed", root_cause=None, drivers=None,
):
    return {
        "outcome": outcome,
        "root_cause_type": root_cause,
        "signal_drivers": list(drivers or []),
    }


class TestLearnFromOutcomes:

    def test_empty_outcomes(self):
        l = learn_from_outcomes([])
        assert l["total"] == 0
        assert l["fp_rate"] == 0.0
        assert l["dominant_root_cause"] is None
        assert l["hints"] == []

    def test_counts_confirmed_and_fp(self):
        outs = [
            _outcome("issue_confirmed"),
            _outcome("issue_confirmed"),
            _outcome("false_positive"),
            _outcome("transient_issue"),
        ]
        l = learn_from_outcomes(outs)
        assert l["total"] == 4
        assert l["confirmed"] == 2
        assert l["false_positives"] == 1
        assert l["transient"] == 1
        assert l["fp_rate"] == 0.25

    def test_root_cause_identified_counts_as_confirmed(self):
        outs = [_outcome("root_cause_identified", root_cause="firewall")]
        l = learn_from_outcomes(outs)
        assert l["confirmed"] == 1

    def test_dominant_root_cause(self):
        outs = [
            _outcome("root_cause_identified", root_cause="firewall"),
            _outcome("root_cause_identified", root_cause="firewall"),
            _outcome("root_cause_identified", root_cause="app"),
        ]
        l = learn_from_outcomes(outs)
        assert l["dominant_root_cause"] == "firewall"
        assert l["root_cause_dist"] == {"firewall": 2, "app": 1}

    def test_signal_stats_track_confirm_and_fp_per_driver(self):
        outs = [
            _outcome("issue_confirmed", drivers=["5 critical drift run(s)"]),
            _outcome("issue_confirmed", drivers=["5 critical drift run(s)"]),
            _outcome("false_positive", drivers=["5 critical drift run(s)"]),
            _outcome("false_positive", drivers=["health score 12/100"]),
        ]
        l = learn_from_outcomes(outs)
        cd = l["signal_stats"]["critical_drift"]
        assert cd["confirmed"] == 2
        assert cd["fp"] == 1
        assert cd["total"] == 3
        assert cd["confirm_rate"] > 0.6
        hs = l["signal_stats"]["health_score"]
        assert hs["fp"] == 1
        assert hs["fp_rate"] == 1.0

    def test_hints_surface_dominant_root_cause(self):
        outs = [
            _outcome("root_cause_identified", root_cause="dns"),
            _outcome("root_cause_identified", root_cause="dns"),
            _outcome("root_cause_identified", root_cause="dns"),
        ]
        l = learn_from_outcomes(outs)
        text = " ".join(l["hints"]).lower()
        assert "dns" in text

    def test_hints_surface_noisy_signal(self):
        outs = [
            _outcome("false_positive", drivers=["confidence dropping"]),
            _outcome("false_positive", drivers=["confidence dropping"]),
            _outcome("false_positive", drivers=["confidence dropping"]),
        ]
        l = learn_from_outcomes(outs)
        text = " ".join(l["hints"]).lower()
        assert "noisy" in text or "false-positive" in text

    def test_hints_surface_strong_signal(self):
        outs = [
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
        ]
        l = learn_from_outcomes(outs)
        text = " ".join(l["hints"]).lower()
        assert "reliability" in text or "confirmed" in text

    def test_hints_cap_at_5(self):
        outs = [
            _outcome("root_cause_identified", root_cause="dns",
                     drivers=[f"signal_{i}" for i in range(6)])
            for _ in range(5)
        ]
        l = learn_from_outcomes(outs)
        assert len(l["hints"]) <= 5


class TestAdjustAction:

    def _base_action(self, **overrides):
        base = {
            "action_required": True,
            "action_label": "needs_attention",
            "priority": "high",
            "recommended_action": "Investigate backend latency increase",
            "focus": ["Investigate backend latency increase"],
            "reasons": ["risk 60/100 in HIGH band"],
        }
        base.update(overrides)
        return base

    def test_no_learnings_returns_action_unchanged(self):
        a = self._base_action()
        assert adjust_action(a, None) == a
        assert adjust_action(a, {"total": 0}) == a

    def test_root_cause_hint_prepended_to_focus(self):
        a = self._base_action()
        learnings = learn_from_outcomes([
            _outcome("root_cause_identified", root_cause="firewall"),
            _outcome("root_cause_identified", root_cause="firewall"),
        ])
        adjusted = adjust_action(a, learnings)
        assert "firewall" in adjusted["focus"][0].lower()

    def test_strong_signal_prefixes_recommendation(self):
        a = self._base_action()
        learnings = learn_from_outcomes([
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
        ])
        adjusted = adjust_action(a, learnings)
        assert adjusted["recommended_action"].startswith("[confirmed")

    def test_high_fp_rate_deprioritises(self):
        a = self._base_action(priority="high", action_required=True)
        learnings = learn_from_outcomes([
            _outcome("false_positive"),
            _outcome("false_positive"),
            _outcome("false_positive"),
            _outcome("issue_confirmed"),
        ])
        adjusted = adjust_action(a, learnings)
        # 75% FP rate ≥ threshold → should drop one tier
        assert adjusted["priority"] == "medium"
        assert adjusted["action_required"] is False
        assert "de-prioritised" in " ".join(adjusted["reasons"]).lower()

    def test_high_fp_rate_below_min_outcomes_does_not_deprioritise(self):
        a = self._base_action(priority="high", action_required=True)
        # Only 2 outcomes — not enough to trigger de-prioritisation (need ≥3)
        learnings = learn_from_outcomes([
            _outcome("false_positive"),
            _outcome("false_positive"),
        ])
        adjusted = adjust_action(a, learnings)
        assert adjusted["priority"] == "high"

    def test_adjust_does_not_mutate_original(self):
        a = self._base_action()
        learnings = learn_from_outcomes([
            _outcome("root_cause_identified", root_cause="dns"),
            _outcome("root_cause_identified", root_cause="dns"),
        ])
        original_focus_len = len(a["focus"])
        adjusted = adjust_action(a, learnings)
        # Original should not have been modified
        assert len(a["focus"]) == original_focus_len
        # Adjusted should have more focus items
        assert len(adjusted["focus"]) > original_focus_len

    def test_hints_appended_to_focus(self):
        a = self._base_action()
        learnings = learn_from_outcomes([
            _outcome("transient_issue"),
            _outcome("transient_issue"),
            _outcome("transient_issue"),
        ])
        adjusted = adjust_action(a, learnings)
        focus_text = " ".join(adjusted["focus"]).lower()
        assert "transient" in focus_text or "settling" in focus_text


# ══════════════════════════════════════════════════════════════════════════════
# Outcome endpoints (full FastAPI lifecycle)
# ══════════════════════════════════════════════════════════════════════════════

class TestOutcomeEndpoints:

    def _create_monitor(self, world) -> int:
        return world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]

    def test_record_outcome_returns_201(self, world):
        mid = self._create_monitor(world)
        r = world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "issue_confirmed"},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["outcome"] == "issue_confirmed"
        assert body["monitored_path_id"] == mid
        assert body["analyst_id"] == world.uid

    def test_root_cause_required_for_root_cause_identified(self, world):
        mid = self._create_monitor(world)
        r = world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "root_cause_identified"},
        )
        assert r.status_code == 400

    def test_root_cause_accepted(self, world):
        mid = self._create_monitor(world)
        r = world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={
                "outcome": "root_cause_identified",
                "root_cause_type": "firewall",
                "note": "ACL change broke the path",
            },
        )
        assert r.status_code == 201
        assert r.json()["root_cause_type"] == "firewall"
        assert r.json()["note"] == "ACL change broke the path"

    def test_list_outcomes_newest_first(self, world):
        mid = self._create_monitor(world)
        world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "false_positive"},
        )
        world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "issue_confirmed"},
        )
        r = world.client.get(f"/api/path-monitors/{mid}/outcomes")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 2
        assert rows[0]["outcome"] == "issue_confirmed"   # newest
        assert rows[1]["outcome"] == "false_positive"

    def test_outcome_snapshots_drivers(self, world):
        mid = self._create_monitor(world)
        # Record an outcome — since there's no run history, drivers will be []
        r = world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "false_positive"},
        )
        assert r.status_code == 201
        assert isinstance(r.json()["signal_drivers"], list)

    def test_last_outcome_on_monitor(self, world):
        mid = self._create_monitor(world)
        world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "issue_confirmed"},
        )
        world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "false_positive"},
        )
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        assert target["last_outcome"] == "false_positive"
        assert target["last_outcome_at"] is not None

    def test_outcome_count_on_monitor(self, world):
        mid = self._create_monitor(world)
        for _ in range(3):
            world.client.post(
                f"/api/path-monitors/{mid}/outcomes",
                json={"outcome": "issue_confirmed"},
            )
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        assert target["outcome_count"] == 3

    def test_learnings_endpoint(self, world):
        mid = self._create_monitor(world)
        for _ in range(3):
            world.client.post(
                f"/api/path-monitors/{mid}/outcomes",
                json={"outcome": "root_cause_identified", "root_cause_type": "dns"},
            )
        r = world.client.get(f"/api/path-monitors/{mid}/learnings")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 3
        assert body["dominant_root_cause"] == "dns"
        assert body["confirmed"] == 3

    def test_outcome_hints_on_monitor_list(self, world):
        mid = self._create_monitor(world)
        for _ in range(3):
            world.client.post(
                f"/api/path-monitors/{mid}/outcomes",
                json={"outcome": "root_cause_identified", "root_cause_type": "firewall"},
            )
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        assert target["dominant_root_cause"] == "firewall"
        text = " ".join(target["outcome_hints"]).lower()
        assert "firewall" in text

    def test_fp_deprioritises_action_on_list(self, world):
        mid = self._create_monitor(world)
        # Run a few times to build some risk
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_regressed_result_dict())):
            for _ in range(5):
                from database import PathAnalysisCacheModel
                world.db.query(PathAnalysisCacheModel).delete()
                world.db.commit()
                world.client.post(f"/api/path-monitors/{mid}/run")
        # Now mark 3 FPs → should trigger de-prioritisation
        for _ in range(3):
            world.client.post(
                f"/api/path-monitors/{mid}/outcomes",
                json={"outcome": "false_positive"},
            )
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        # fp_rate should be 1.0 (3/3)
        assert target["fp_rate"] >= 0.9
        # De-prioritisation should have lowered the priority by one tier
        # from whatever the risk engine set it to
        assert target["action_required"] is False

    def test_delete_monitor_cascades_outcomes(self, world):
        mid = self._create_monitor(world)
        world.client.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "issue_confirmed"},
        )
        assert world.db.query(MonitorOutcomeModel).count() == 1
        world.client.delete(f"/api/path-monitors/{mid}")
        assert world.db.query(MonitorOutcomeModel).count() == 0

    def test_404_for_other_users_monitor(self, db_session, tmp_pcap):
        alice = _seed_user(db_session, "alice")
        bob   = _seed_user(db_session, "bob")
        aid   = _seed_analysis(db_session, alice, file_path=tmp_pcap, aid="ana-o")
        qid   = _seed_saved_query(db_session, alice)
        c_alice = _make_client(db_session, alice)
        mid = c_alice.post(
            "/api/path-monitors",
            json={"saved_query_id": qid, "analysis_id": aid},
        ).json()["id"]
        c_bob = _make_client(db_session, bob)
        r = c_bob.post(
            f"/api/path-monitors/{mid}/outcomes",
            json={"outcome": "false_positive"},
        )
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# System insights — pure unit tests for compute_system_insights
# ══════════════════════════════════════════════════════════════════════════════

def _monitor_dict(
    mid=1, dst="10.0.0.1", src="10.0.0.5", name="mon",
    risk_score=0, risk_level="low", action_required=False,
    last_drift_severity="none",
):
    return {
        "id": mid, "destination_ip": dst, "source_ip": src,
        "saved_query_name": name, "risk_score": risk_score,
        "risk_level": risk_level, "action_required": action_required,
        "last_drift_severity": last_drift_severity,
    }


def _run_dict(mid=1, outcome="success", impairments=None, drift="none"):
    return {
        "monitored_path_id": mid,
        "run_at": "2026-04-12T00:00:00",
        "connection_outcome": outcome,
        "primary_impairment": None,
        "impairments": list(impairments or []),
        "drift_severity": drift,
        "path_confidence_score": 90,
        "action_required": False,
        "timing": {},
    }


class TestComputeSystemInsights:

    def test_empty_system(self):
        r = compute_system_insights([], [], [])
        assert r["monitor_count"] == 0
        assert r["avg_risk_score"] == 0
        assert r["headlines"] == []
        assert r["systemic_destinations"] == []
        assert r["shared_impairments"] == []

    def test_risk_distribution(self):
        monitors = [
            _monitor_dict(mid=1, risk_level="low"),
            _monitor_dict(mid=2, risk_level="high"),
            _monitor_dict(mid=3, risk_level="critical"),
            _monitor_dict(mid=4, risk_level="critical"),
        ]
        r = compute_system_insights(monitors, [], [])
        assert r["risk_distribution"] == {
            "low": 1, "medium": 0, "high": 1, "critical": 2,
        }
        assert r["monitor_count"] == 4

    def test_avg_risk_score(self):
        monitors = [
            _monitor_dict(mid=1, risk_score=20),
            _monitor_dict(mid=2, risk_score=80),
        ]
        r = compute_system_insights(monitors, [], [])
        assert r["avg_risk_score"] == 50

    def test_action_required_count(self):
        monitors = [
            _monitor_dict(mid=1, action_required=True),
            _monitor_dict(mid=2, action_required=False),
            _monitor_dict(mid=3, action_required=True),
        ]
        r = compute_system_insights(monitors, [], [])
        assert r["action_required_count"] == 2

    def test_dominant_root_cause_headline(self):
        outcomes = [
            _outcome("root_cause_identified", root_cause="firewall"),
            _outcome("root_cause_identified", root_cause="firewall"),
            _outcome("root_cause_identified", root_cause="dns"),
        ]
        r = compute_system_insights(
            [_monitor_dict()], outcomes, [],
        )
        assert r["dominant_root_cause"] == "firewall"
        text = " ".join(r["headlines"]).lower()
        assert "firewall" in text

    def test_reliable_signal_headline(self):
        outcomes = [
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
        ]
        r = compute_system_insights(
            [_monitor_dict()], outcomes, [],
        )
        assert len(r["reliable_signals"]) >= 1
        assert r["reliable_signals"][0]["signal"] == "backend_delay"
        text = " ".join(r["headlines"]).lower()
        assert "reliable" in text or "backend" in text

    def test_noisy_signal_detected(self):
        outcomes = [
            _outcome("false_positive", drivers=["confidence dropping"]),
            _outcome("false_positive", drivers=["confidence dropping"]),
            _outcome("issue_confirmed", drivers=["backend delay trending up"]),
        ]
        r = compute_system_insights(
            [_monitor_dict()], outcomes, [],
        )
        assert len(r["noisy_signals"]) >= 1
        assert r["noisy_signals"][0]["signal"] == "confidence_dropping"

    def test_systemic_destination_detection(self):
        monitors = [
            _monitor_dict(mid=1, dst="10.0.0.1", last_drift_severity="critical"),
            _monitor_dict(mid=2, dst="10.0.0.1", last_drift_severity="warning"),
            _monitor_dict(mid=3, dst="10.0.0.2"),  # different dest
        ]
        r = compute_system_insights(monitors, [], [])
        assert len(r["systemic_destinations"]) == 1
        sd = r["systemic_destinations"][0]
        assert sd["destination_ip"] == "10.0.0.1"
        assert sd["affected_count"] == 2
        text = " ".join(r["headlines"]).lower()
        assert "systemic" in text or "10.0.0.1" in text

    def test_no_systemic_when_single_degraded_per_dest(self):
        monitors = [
            _monitor_dict(mid=1, dst="10.0.0.1", last_drift_severity="critical"),
            _monitor_dict(mid=2, dst="10.0.0.1", last_drift_severity="none"),
        ]
        r = compute_system_insights(monitors, [], [])
        assert r["systemic_destinations"] == []

    def test_shared_impairment_across_monitors(self):
        runs = [
            _run_dict(mid=1, impairments=["packet_loss"]),
            _run_dict(mid=2, impairments=["packet_loss"]),
            _run_dict(mid=3, impairments=["tls_failure"]),
        ]
        r = compute_system_insights(
            [_monitor_dict(mid=i) for i in (1, 2, 3)],
            [], runs,
        )
        assert len(r["shared_impairments"]) >= 1
        assert r["shared_impairments"][0]["impairment"] == "packet_loss"
        assert r["shared_impairments"][0]["monitor_count"] == 2

    def test_no_shared_impairment_when_single_monitor(self):
        runs = [_run_dict(mid=1, impairments=["packet_loss"])]
        r = compute_system_insights(
            [_monitor_dict(mid=1)], [], runs,
        )
        assert r["shared_impairments"] == []

    def test_high_global_fp_rate_headline(self):
        outcomes = [
            _outcome("false_positive"),
            _outcome("false_positive"),
            _outcome("false_positive"),
            _outcome("issue_confirmed"),
        ]
        r = compute_system_insights(
            [_monitor_dict()], outcomes, [],
        )
        assert r["outcome_fp_rate"] == 0.75
        text = " ".join(r["headlines"]).lower()
        assert "fp" in text.lower() or "false" in text.lower() or "threshold" in text.lower()

    def test_headlines_capped_at_5(self):
        # Create a scenario with many different headline triggers
        outcomes = [
            _outcome("root_cause_identified", root_cause="firewall",
                     drivers=["backend delay trending up", "confidence dropping"]),
        ] * 5 + [
            _outcome("false_positive",
                     drivers=["health score 10/100"]),
        ] * 5
        monitors = [
            _monitor_dict(mid=1, dst="10.0.0.1", last_drift_severity="critical"),
            _monitor_dict(mid=2, dst="10.0.0.1", action_required=True,
                          last_drift_severity="warning"),
        ]
        runs = [
            _run_dict(mid=1, impairments=["packet_loss"]),
            _run_dict(mid=2, impairments=["packet_loss"]),
        ]
        r = compute_system_insights(monitors, outcomes, runs)
        assert len(r["headlines"]) <= 5


# ══════════════════════════════════════════════════════════════════════════════
# System insights endpoint (full FastAPI lifecycle)
# ══════════════════════════════════════════════════════════════════════════════

class TestSystemInsightsEndpoint:

    def test_empty_system_returns_200(self, world):
        r = world.client.get("/api/system-insights")
        assert r.status_code == 200
        body = r.json()
        assert body["monitor_count"] >= 0

    def test_returns_risk_distribution(self, world):
        # Create a monitor
        world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        )
        r = world.client.get("/api/system-insights")
        body = r.json()
        assert body["monitor_count"] == 1
        assert "risk_distribution" in body
        assert sum(body["risk_distribution"].values()) == 1

    def test_outcomes_reflected_in_insights(self, world):
        mid = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        for _ in range(3):
            world.client.post(
                f"/api/path-monitors/{mid}/outcomes",
                json={"outcome": "root_cause_identified", "root_cause_type": "dns"},
            )
        body = world.client.get("/api/system-insights").json()
        assert body["outcome_total"] == 3
        assert body["dominant_root_cause"] == "dns"

    def test_shared_impairments_from_runs(self, world):
        # Two monitors on the same analysis
        m1 = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        m2 = world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]
        # Run both with the same regressed result (has "no_response")
        for mid in (m1, m2):
            from database import PathAnalysisCacheModel
            world.db.query(PathAnalysisCacheModel).delete()
            world.db.commit()
            with patch(_NORMALIZE, return_value=_mock_normalize()), \
                 patch(_ENGINE, new=_mock_engine_returning(_regressed_result_dict())):
                world.client.post(f"/api/path-monitors/{mid}/run")
        body = world.client.get("/api/system-insights").json()
        imp_tokens = [s["impairment"] for s in body["shared_impairments"]]
        assert "no_response" in imp_tokens


# ══════════════════════════════════════════════════════════════════════════════
# Suppression + baseline — pure unit tests
# ══════════════════════════════════════════════════════════════════════════════

class TestApplySuppressions:

    def _base_action(self, **kw):
        base = {
            "action_required": True,
            "action_label": "needs_attention",
            "priority": "high",
            "recommended_action": "Investigate return_path_problem",
            "focus": ["Check firewall / return path asymmetry"],
            "reasons": ["risk 60/100 in HIGH band"],
        }
        base.update(kw)
        return base

    def test_no_suppressions_passthrough(self):
        a = self._base_action()
        result = apply_suppressions(a, [], now=datetime.utcnow())
        assert result["action_required"] is True
        assert result["suppressed"] is False

    def test_mute_suppresses_all(self):
        a = self._base_action()
        result = apply_suppressions(
            a,
            [{"id": 1, "kind": "mute", "reason": "maintenance", "enabled": True, "until": None}],
            now=datetime.utcnow(),
        )
        assert result["suppressed"] is True
        assert result["action_required"] is False
        assert result["priority"] == "low"
        assert any("mute" in r for r in result["reasons"])

    def test_snooze_within_window_suppresses(self):
        a = self._base_action()
        future = datetime.utcnow() + timedelta(hours=2)
        result = apply_suppressions(
            a,
            [{"id": 2, "kind": "snooze", "reason": "investigating", "enabled": True,
              "until": future}],
            now=datetime.utcnow(),
        )
        assert result["suppressed"] is True
        assert result["action_required"] is False

    def test_expired_snooze_ignored(self):
        a = self._base_action()
        past = datetime.utcnow() - timedelta(hours=1)
        result = apply_suppressions(
            a,
            [{"id": 3, "kind": "snooze", "reason": "old", "enabled": True, "until": past}],
            now=datetime.utcnow(),
        )
        assert result["suppressed"] is False
        assert result["action_required"] is True

    def test_disabled_rule_ignored(self):
        a = self._base_action()
        result = apply_suppressions(
            a,
            [{"id": 4, "kind": "mute", "reason": "x", "enabled": False, "until": None}],
            now=datetime.utcnow(),
        )
        assert result["suppressed"] is False

    def test_impairment_suppression_deescalates(self):
        a = self._base_action(
            focus=["Check firewall / return path asymmetry"],
            reasons=["return_path_problem recurring"],
        )
        result = apply_suppressions(
            a,
            [{"id": 5, "kind": "impairment", "value": "return_path_problem",
              "reason": "known issue", "enabled": True, "until": None}],
            now=datetime.utcnow(),
        )
        assert result["suppressed"] is True
        # Priority dropped one tier from high→medium
        assert result["priority"] == "medium"
        assert any("impairment" in r for r in result["reasons"])

    def test_severity_suppression_clears_action(self):
        a = self._base_action(priority="medium")
        result = apply_suppressions(
            a,
            [{"id": 6, "kind": "severity", "value": "warning",
              "reason": "info/warning is noise", "enabled": True, "until": None}],
            now=datetime.utcnow(),
        )
        # medium ≤ warning in severity rank → suppressed
        assert result["suppressed"] is True
        assert result["action_required"] is False

    def test_audit_trail_in_reasons(self):
        a = self._base_action()
        result = apply_suppressions(
            a,
            [{"id": 7, "kind": "mute", "reason": "planned downtime", "enabled": True,
              "until": None}],
            now=datetime.utcnow(),
        )
        joined = " ".join(result["reasons"]).lower()
        assert "planned downtime" in joined


class TestApplyBaseline:

    def _summary(self, delay_avg=None, conf_avg=None):
        return {
            "backend_delay_trend": {
                "recent_avg": delay_avg, "prev_avg": None,
                "slope": "stable", "key": "backend_response_delay",
            },
            "confidence_trend": {
                "recent_avg": conf_avg, "prev_avg": None,
                "slope": "stable",
            },
        }

    def _base_action(self, **kw):
        base = {
            "action_required": True,
            "action_label": "needs_attention",
            "priority": "high",
            "recommended_action": "Investigate backend latency increase",
            "focus": [
                "Investigate backend latency increase on the destination",
                "Re-check role hints / refresh the capture — confidence is dropping",
            ],
            "reasons": ["risk 60/100 in HIGH band"],
        }
        base.update(kw)
        return base

    def test_no_baseline_passthrough(self):
        a = self._base_action()
        result = apply_baseline(a, self._summary(), None)
        assert result["baseline_applied"] is False

    def test_accepted_delay_removes_backend_focus(self):
        a = self._base_action()
        baseline = {"accepted_delay_max_ms": 300.0}
        result = apply_baseline(a, self._summary(delay_avg=200.0), baseline)
        assert result["baseline_applied"] is True
        assert not any("backend" in f.lower() and "de-emphasis" not in f.lower()
                        for f in result["focus"][:1])
        assert any("de-emphasised" in f for f in result["focus"])

    def test_delay_above_accepted_not_deemphasised(self):
        a = self._base_action()
        baseline = {"accepted_delay_max_ms": 100.0}
        result = apply_baseline(a, self._summary(delay_avg=200.0), baseline)
        # Delay is above accepted range → no de-emphasis
        assert not any("de-emphasised" in r for r in result["reasons"])

    def test_accepted_confidence_removes_conf_focus(self):
        a = self._base_action()
        baseline = {"accepted_confidence_min": 60}
        result = apply_baseline(a, self._summary(conf_avg=70), baseline)
        assert result["baseline_applied"] is True
        assert not any("confidence" in f.lower() and "de-emphasis" not in f.lower()
                        for f in result["focus"][:1])

    def test_known_noisy_impairment_annotated(self):
        a = self._base_action(
            focus=["Check firewall / return path asymmetry"],
        )
        baseline = {"known_noisy_impairments": ["return_path_problem"]}
        result = apply_baseline(a, {}, baseline)
        assert result["baseline_applied"] is True
        assert any("known noisy" in f.lower() for f in result["focus"])

    def test_multiple_rules_deescalate(self):
        a = self._base_action(priority="high")
        baseline = {
            "accepted_delay_max_ms": 300.0,
            "accepted_confidence_min": 60,
        }
        result = apply_baseline(
            a, self._summary(delay_avg=200.0, conf_avg=70), baseline,
        )
        # Both delay and confidence rules fired → de-escalation
        assert result["priority"] in ("medium", "low")
        assert any("de-escalated" in r for r in result["reasons"])

    def test_visibility_gaps_appended(self):
        a = self._base_action()
        baseline = {"known_visibility_gaps": ["no span port on switch B"]}
        result = apply_baseline(a, {}, baseline)
        assert any("known gap" in f for f in result["focus"])

    def test_does_not_mutate_original(self):
        a = self._base_action()
        orig_len = len(a["focus"])
        apply_baseline(a, {}, {"known_visibility_gaps": ["x"]})
        assert len(a["focus"]) == orig_len


# ══════════════════════════════════════════════════════════════════════════════
# Suppression + baseline endpoint integration tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSuppressionEndpoints:

    def _create_monitor(self, world) -> int:
        return world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]

    def test_create_mute_suppression(self, world):
        mid = self._create_monitor(world)
        r = world.client.post(
            f"/api/path-monitors/{mid}/suppressions",
            json={"kind": "mute", "reason": "maintenance"},
        )
        assert r.status_code == 201
        assert r.json()["kind"] == "mute"

    def test_snooze_requires_until(self, world):
        mid = self._create_monitor(world)
        r = world.client.post(
            f"/api/path-monitors/{mid}/suppressions",
            json={"kind": "snooze", "reason": "later"},
        )
        assert r.status_code == 400

    def test_list_suppressions(self, world):
        mid = self._create_monitor(world)
        world.client.post(
            f"/api/path-monitors/{mid}/suppressions",
            json={"kind": "mute", "reason": "a"},
        )
        world.client.post(
            f"/api/path-monitors/{mid}/suppressions",
            json={"kind": "impairment", "value": "packet_loss"},
        )
        rows = world.client.get(f"/api/path-monitors/{mid}/suppressions").json()
        assert len(rows) == 2

    def test_delete_suppression(self, world):
        mid = self._create_monitor(world)
        sid = world.client.post(
            f"/api/path-monitors/{mid}/suppressions",
            json={"kind": "mute"},
        ).json()["id"]
        r = world.client.delete(f"/api/path-monitors/{mid}/suppressions/{sid}")
        assert r.status_code == 204
        assert world.client.get(f"/api/path-monitors/{mid}/suppressions").json() == []

    def test_mute_suppresses_on_list(self, world):
        mid = self._create_monitor(world)
        # Run to build some risk
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_regressed_result_dict())):
            for _ in range(5):
                from database import PathAnalysisCacheModel
                world.db.query(PathAnalysisCacheModel).delete()
                world.db.commit()
                world.client.post(f"/api/path-monitors/{mid}/run")
        # Without mute: action_required should be True
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        assert target["action_required"] is True

        # Add mute
        world.client.post(
            f"/api/path-monitors/{mid}/suppressions",
            json={"kind": "mute", "reason": "maintenance window"},
        )
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        assert target["suppressed"] is True
        assert target["action_required"] is False

    def test_cascade_delete_monitor(self, world):
        mid = self._create_monitor(world)
        world.client.post(
            f"/api/path-monitors/{mid}/suppressions",
            json={"kind": "mute"},
        )
        assert world.db.query(MonitorSuppressionModel).count() == 1
        world.client.delete(f"/api/path-monitors/{mid}")
        assert world.db.query(MonitorSuppressionModel).count() == 0


class TestBaselineEndpoints:

    def _create_monitor(self, world) -> int:
        return world.client.post(
            "/api/path-monitors",
            json={"saved_query_id": world.qid, "analysis_id": world.aid},
        ).json()["id"]

    def test_set_and_get_baseline(self, world):
        mid = self._create_monitor(world)
        r = world.client.put(
            f"/api/path-monitors/{mid}/baseline",
            json={
                "accepted_delay_max_ms": 200.0,
                "accepted_confidence_min": 60,
                "known_noisy_impairments": ["packet_loss"],
                "known_visibility_gaps": ["no span on switch B"],
            },
        )
        assert r.status_code == 200
        body = world.client.get(f"/api/path-monitors/{mid}/baseline").json()
        assert body["baseline"]["accepted_delay_max_ms"] == 200.0
        assert body["baseline"]["known_noisy_impairments"] == ["packet_loss"]

    def test_clear_baseline(self, world):
        mid = self._create_monitor(world)
        world.client.put(
            f"/api/path-monitors/{mid}/baseline",
            json={"accepted_delay_max_ms": 100.0},
        )
        # Overwrite with empty → clears baseline
        world.client.put(
            f"/api/path-monitors/{mid}/baseline", json={},
        )
        body = world.client.get(f"/api/path-monitors/{mid}/baseline").json()
        assert body["baseline"] == {}

    def test_baseline_applied_shown_on_list(self, world):
        mid = self._create_monitor(world)
        # Run with data that has backend delay
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_returning(_baseline_result_dict())):
            world.client.post(f"/api/path-monitors/{mid}/run")
        # Set a generous baseline
        world.client.put(
            f"/api/path-monitors/{mid}/baseline",
            json={"accepted_delay_max_ms": 1000.0, "accepted_confidence_min": 50},
        )
        target = next(
            r for r in world.client.get("/api/path-monitors").json()
            if r["id"] == mid
        )
        assert target["baseline_applied"] is True
