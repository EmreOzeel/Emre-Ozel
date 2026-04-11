"""
Regression tests for POST /api/path-analysis/compare.

Four compare scenarios are covered:
  1. Healthy baseline vs backend-slow incident
  2. Healthy baseline vs no-response incident
  3. Healthy baseline vs return-path-problem incident
  4. Healthy baseline vs LB-backend-issue incident

Each test:
  - Seeds two completed analyses in an in-memory SQLite DB.
  - Mocks PCAP normalisation + CausalPathEngine so no real capture file is
    needed.
  - Asserts on the structured compare response.

All tests use StaticPool so FastAPI worker threads share the same in-memory DB.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import AnalysisModel, Base, UserModel
from main import app, get_db


# ── Patch targets ─────────────────────────────────────────────────────────────

_NORMALIZE = "normalizer.pipeline.normalize"
_ENGINE    = "core.causal_path.CausalPathEngine"


# ── Fake result builders ──────────────────────────────────────────────────────

def _healthy_result() -> dict:
    return {
        "source_ip":          "10.0.0.5",
        "destination_ip":     "10.0.0.1",
        "destination_port":   443,
        "protocol":           "TCP",
        "connection_state":   "application_level_interaction",
        "path_summary":       "Connection succeeded with no impairments.",
        "path_steps":         ["SYN sent", "SYN-ACK received", "Data exchanged"],
        "hop_sequence":       [],
        "firewall_observation":      {"role": "firewall",      "ip": "", "observed": False, "note": ""},
        "load_balancer_observation": {"role": "load_balancer", "ip": "", "observed": False, "note": ""},
        "backend_observation":       {"role": "backend",       "ip": "", "observed": False, "note": ""},
        "timing_breakdown":          {"connection_setup_ms": 12.0, "backend_response_ms": 20.0},
        "timing_interpretation":     "Fast.",
        "return_path_observation":   "",
        "connection_outcome":        "success",
        "primary_impairment":        None,
        "path_impairments":          [],
        "likely_failure_point":      "",
        "alternative_hypotheses":    [],
        "confidence_score":          90,
        "confidence_reasoning":      "",
        "path_confidence_score":     90,
        "confidence_reasons":        [],
        "evidence_packets":          [],
        "evidence_flows":            [],
        "evidence_items":            [],
        "missing_visibility_notes":  [],
    }


def _backend_slow_result() -> dict:
    r = _healthy_result()
    r["connection_outcome"]    = "success"
    r["primary_impairment"]    = "backend_response_delay"
    r["path_impairments"]      = ["backend_response_delay"]
    r["path_summary"]          = "Connection succeeded but backend response was slow."
    r["timing_breakdown"]      = {"connection_setup_ms": 12.0, "backend_response_ms": 950.0}
    r["path_confidence_score"] = 80
    return r


def _no_response_result() -> dict:
    r = _healthy_result()
    r["connection_outcome"]    = "failure"
    r["primary_impairment"]    = "no_response"
    r["path_impairments"]      = ["no_response"]
    r["path_summary"]          = "No response received from destination."
    r["timing_breakdown"]      = {"connection_setup_ms": 12.0, "backend_response_ms": 0.0}
    r["path_confidence_score"] = 65
    return r


def _return_path_result() -> dict:
    r = _healthy_result()
    r["connection_outcome"]    = "partial_success"
    r["primary_impairment"]    = "return_path_problem"
    r["path_impairments"]      = ["return_path_problem"]
    r["path_summary"]          = "Outbound path ok but return path has issues."
    r["timing_breakdown"]      = {"connection_setup_ms": 12.0, "backend_response_ms": 35.0}
    r["path_confidence_score"] = 70
    return r


def _lb_backend_result() -> dict:
    r = _healthy_result()
    r["connection_outcome"]    = "failure"
    r["primary_impairment"]    = "lb_backend_issue"
    r["path_impairments"]      = ["lb_backend_issue"]
    r["path_summary"]          = "Load balancer cannot reach any healthy backend."
    r["timing_breakdown"]      = {"connection_setup_ms": 12.0, "backend_response_ms": 0.0}
    r["path_confidence_score"] = 75
    return r


# ── Mock helpers ──────────────────────────────────────────────────────────────

def _mock_normalize():
    ctx = MagicMock()
    ctx.packets = []
    ctx.flows   = {}
    ctx.findings = []
    return ctx


def _mock_engine_pair(first_result_dict: dict, second_result_dict: dict):
    """Return a mock CausalPathEngine class whose analyze() side-effects two calls."""
    first_res  = MagicMock()
    first_res.to_dict.return_value  = first_result_dict

    second_res = MagicMock()
    second_res.to_dict.return_value = second_result_dict

    mock_eng = MagicMock()
    mock_eng.return_value.analyze.side_effect = [first_res, second_res]
    return mock_eng


# ── Fixtures ──────────────────────────────────────────────────────────────────

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


@pytest.fixture(scope="function")
def tmp_pcap(tmp_path):
    f = tmp_path / "test.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return str(f)


@pytest.fixture(scope="function", autouse=True)
def clear_overrides():
    yield
    app.dependency_overrides.clear()


def _seed_analysis(db, user_id: int, pcap_path: str, analysis_id: str) -> None:
    row = AnalysisModel(
        id=analysis_id,
        user_id=user_id,
        filename="test.pcap",
        file_path=pcap_path,
        status="completed",
        result_json=json.dumps({"summary": "ok"}),
    )
    db.add(row)
    db.commit()


def _make_client(db_session, user_id: int) -> TestClient:
    def _override_db():
        yield db_session

    def _override_user():
        fake = MagicMock()
        fake.id = user_id
        return fake

    app.dependency_overrides[get_db]           = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True)


def _seed_user(db_session) -> int:
    u = UserModel(username="tester", hashed_password="x")
    db_session.add(u)
    db_session.flush()
    uid: int = u.id
    db_session.commit()
    return uid


_URL = "/api/path-analysis/compare"

_BASE_PAYLOAD = {
    "source_ip":      "10.0.0.5",
    "destination_ip": "10.0.0.1",
    "destination_port": 443,
}


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 1 — healthy vs backend slow
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthyVsBackendSlow:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "baseline-1")
        _seed_analysis(db_session, self.uid, tmp_pcap, "incident-1")
        self.client = _make_client(db_session, self.uid)

    def _post(self) -> dict:
        mock_eng = _mock_engine_pair(_healthy_result(), _backend_slow_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_URL, json={
                **_BASE_PAYLOAD,
                "baseline_analysis_id": "baseline-1",
                "incident_analysis_id": "incident-1",
            })
        assert r.status_code == 200, r.text
        return r.json()

    def test_returns_200(self):
        self._post()

    def test_outcome_unchanged(self):
        d = self._post()
        assert d["outcome_changed"] is False

    def test_no_outcome_regression(self):
        d = self._post()
        assert d["outcome_regression"] is False

    def test_new_impairment_detected(self):
        d = self._post()
        assert "backend_response_delay" in d["impairment_changes"]["new"]

    def test_regression_point_mentions_backend(self):
        d = self._post()
        assert d["most_likely_regression_point"] is not None
        assert "backend" in d["most_likely_regression_point"].lower()

    def test_key_differences_non_empty(self):
        d = self._post()
        assert len(d["key_differences"]) > 0

    def test_timing_backend_response_worsened(self):
        d = self._post()
        td = d["timing_differences"]
        assert "backend_response_ms" in td
        assert td["backend_response_ms"]["worsened"] is True
        assert td["backend_response_ms"]["delta"] > 0

    def test_confidence_dropped(self):
        d = self._post()
        cc = d["confidence_changes"]
        assert cc["baseline"] == 90
        assert cc["incident"] == 80
        assert cc["worsened"] is True

    def test_summaries_present(self):
        d = self._post()
        assert d["baseline_summary"]["connection_outcome"] == "success"
        assert d["incident_summary"]["primary_impairment"] == "backend_response_delay"

    def test_analysis_ids_echoed(self):
        d = self._post()
        assert d["baseline_analysis_id"] == "baseline-1"
        assert d["incident_analysis_id"] == "incident-1"


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 2 — healthy vs no response
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthyVsNoResponse:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "baseline-2")
        _seed_analysis(db_session, self.uid, tmp_pcap, "incident-2")
        self.client = _make_client(db_session, self.uid)

    def _post(self) -> dict:
        mock_eng = _mock_engine_pair(_healthy_result(), _no_response_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_URL, json={
                **_BASE_PAYLOAD,
                "baseline_analysis_id": "baseline-2",
                "incident_analysis_id": "incident-2",
            })
        assert r.status_code == 200, r.text
        return r.json()

    def test_outcome_changed(self):
        d = self._post()
        assert d["outcome_changed"] is True

    def test_outcome_regression(self):
        d = self._post()
        assert d["outcome_regression"] is True

    def test_new_impairment_no_response(self):
        d = self._post()
        assert "no_response" in d["impairment_changes"]["new"]

    def test_incident_outcome_is_failure(self):
        d = self._post()
        assert d["incident_summary"]["connection_outcome"] == "failure"

    def test_regression_point_set(self):
        d = self._post()
        assert d["most_likely_regression_point"] is not None

    def test_key_differences_mentions_outcome(self):
        d = self._post()
        texts = " ".join(d["key_differences"]).lower()
        assert "outcome" in texts or "failure" in texts

    def test_confidence_worsened(self):
        d = self._post()
        assert d["confidence_changes"]["worsened"] is True


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — healthy vs return path problem
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthyVsReturnPath:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "baseline-3")
        _seed_analysis(db_session, self.uid, tmp_pcap, "incident-3")
        self.client = _make_client(db_session, self.uid)

    def _post(self) -> dict:
        mock_eng = _mock_engine_pair(_healthy_result(), _return_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_URL, json={
                **_BASE_PAYLOAD,
                "baseline_analysis_id": "baseline-3",
                "incident_analysis_id": "incident-3",
            })
        assert r.status_code == 200, r.text
        return r.json()

    def test_outcome_regression_partial(self):
        """success → partial_success is a regression."""
        d = self._post()
        assert d["outcome_regression"] is True

    def test_new_impairment_return_path(self):
        d = self._post()
        assert "return_path_problem" in d["impairment_changes"]["new"]

    def test_regression_point_return_path(self):
        d = self._post()
        rp = d["most_likely_regression_point"] or ""
        assert "return" in rp.lower() or "asymmetric" in rp.lower()

    def test_incident_outcome_partial(self):
        d = self._post()
        assert d["incident_summary"]["connection_outcome"] == "partial_success"

    def test_baseline_outcome_success(self):
        d = self._post()
        assert d["baseline_summary"]["connection_outcome"] == "success"


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 4 — healthy vs LB backend issue
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthyVsLbBackend:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "baseline-4")
        _seed_analysis(db_session, self.uid, tmp_pcap, "incident-4")
        self.client = _make_client(db_session, self.uid)

    def _post(self) -> dict:
        mock_eng = _mock_engine_pair(_healthy_result(), _lb_backend_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_URL, json={
                **_BASE_PAYLOAD,
                "baseline_analysis_id": "baseline-4",
                "incident_analysis_id": "incident-4",
            })
        assert r.status_code == 200, r.text
        return r.json()

    def test_outcome_regression_failure(self):
        d = self._post()
        assert d["outcome_regression"] is True
        assert d["incident_summary"]["connection_outcome"] == "failure"

    def test_new_impairment_lb_backend(self):
        d = self._post()
        assert "lb_backend_issue" in d["impairment_changes"]["new"]

    def test_regression_point_lb(self):
        d = self._post()
        rp = d["most_likely_regression_point"] or ""
        assert "load balancer" in rp.lower() or "backend" in rp.lower()

    def test_no_resolved_impairments(self):
        """Healthy baseline had no impairments to resolve."""
        d = self._post()
        assert d["impairment_changes"]["resolved"] == []

    def test_no_persisting_impairments(self):
        d = self._post()
        assert d["impairment_changes"]["persisting"] == []


# ══════════════════════════════════════════════════════════════════════════════
# Edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestCompareEdgeCases:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "base-e")
        _seed_analysis(db_session, self.uid, tmp_pcap, "inc-e")
        self.client = _make_client(db_session, self.uid)

    def test_same_result_no_regression(self):
        """Identical baseline and incident should yield no regression."""
        mock_eng = _mock_engine_pair(_healthy_result(), _healthy_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_URL, json={
                **_BASE_PAYLOAD,
                "baseline_analysis_id": "base-e",
                "incident_analysis_id": "inc-e",
            })
        d = r.json()
        assert d["outcome_regression"] is False
        assert d["impairment_changes"]["new"] == []
        assert d["most_likely_regression_point"] is None

    def test_missing_analysis_404(self, db_session):
        r = self.client.post(_URL, json={
            **_BASE_PAYLOAD,
            "baseline_analysis_id": "does-not-exist",
            "incident_analysis_id": "inc-e",
        })
        assert r.status_code == 404

    def test_missing_source_ip_422(self):
        r = self.client.post(_URL, json={
            "baseline_analysis_id": "base-e",
            "incident_analysis_id": "inc-e",
            "destination_ip": "10.0.0.1",
        })
        assert r.status_code == 422

    def test_missing_destination_ip_422(self):
        r = self.client.post(_URL, json={
            "baseline_analysis_id": "base-e",
            "incident_analysis_id": "inc-e",
            "source_ip": "10.0.0.5",
        })
        assert r.status_code == 422

    def test_improvement_not_flagged_as_regression(self):
        """Incident better than baseline should not be marked as regression."""
        mock_eng = _mock_engine_pair(_no_response_result(), _healthy_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_URL, json={
                **_BASE_PAYLOAD,
                "baseline_analysis_id": "base-e",
                "incident_analysis_id": "inc-e",
            })
        d = r.json()
        assert d["outcome_regression"] is False
        assert d["outcome_changed"] is True
