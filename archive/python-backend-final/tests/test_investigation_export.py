"""
Tests for POST /api/path-analysis/export/json
         POST /api/path-analysis/export/html

Four scenarios:
  1. Path analysis only — no compare, no feedback
  2. With compare data — include_compare=True, two analysis IDs
  3. With analyst feedback — feedback seeded in DB, appears in package
  4. Missing optional sections handled gracefully — absent sections are null

All tests use StaticPool + mock engine so no real PCAP is needed.
"""
from __future__ import annotations

import json as _json
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
from database import AnalysisModel, Base, PathAnalysisFeedbackModel, UserModel
from main import app, get_db

# ── Patch targets ─────────────────────────────────────────────────────────────

_NORMALIZE = "normalizer.pipeline.normalize"
_ENGINE    = "core.causal_path.CausalPathEngine"

# ── Fake result ───────────────────────────────────────────────────────────────

def _fake_path_result(outcome: str = "success", impairment: str | None = None) -> dict:
    return {
        "source_ip":          "10.0.0.5",
        "destination_ip":     "10.0.0.1",
        "destination_port":   443,
        "protocol":           "TCP",
        "connection_state":   "application_level_interaction",
        "path_summary":       f"Connection {outcome}.",
        "path_steps":         ["SYN sent", "SYN-ACK received", "Data exchanged"],
        "hop_sequence":       [],
        "firewall_observation":      {"role": "firewall",      "ip": "", "observed": False, "note": ""},
        "load_balancer_observation": {"role": "load_balancer", "ip": "", "observed": False, "note": ""},
        "backend_observation":       {"role": "backend",       "ip": "", "observed": False, "note": ""},
        "timing_breakdown":          {"connection_setup_ms": 12.0, "backend_response_ms": 25.0},
        "timing_interpretation":     "Normal.",
        "return_path_observation":   "",
        "connection_outcome":        outcome,
        "primary_impairment":        impairment,
        "path_impairments":          [impairment] if impairment else [],
        "likely_failure_point":      "",
        "alternative_hypotheses":    ["Could be transient congestion"],
        "confidence_score":          85,
        "confidence_reasoning":      "",
        "path_confidence_score":     85,
        "confidence_reasons":        ["SYN-ACK observed", "data exchange confirmed"],
        "evidence_packets":          [],
        "evidence_flows":            [],
        "evidence_items": [
            {"type": "tcp_handshake", "signal_strength": "high",
             "summary": "Full handshake observed", "flow_id": "f1", "packet_refs": [1, 2, 3]},
        ],
        "missing_visibility_notes":  ["No firewall capture available"],
    }


def _mock_normalize():
    ctx = MagicMock()
    ctx.packets = []
    ctx.flows   = {}
    ctx.findings = []
    return ctx


def _mock_engine_for(result_dict: dict):
    mock_res = MagicMock()
    mock_res.to_dict.return_value = result_dict
    mock_eng = MagicMock()
    mock_eng.return_value.analyze.return_value = mock_res
    return mock_eng


def _mock_engine_pair(first: dict, second: dict):
    r1 = MagicMock(); r1.to_dict.return_value = first
    r2 = MagicMock(); r2.to_dict.return_value = second
    mock_eng = MagicMock()
    mock_eng.return_value.analyze.side_effect = [r1, r2]
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


def _seed_user(db) -> int:
    u = UserModel(username="tester", hashed_password="x")
    db.add(u); db.flush()
    uid: int = u.id; db.commit()
    return uid


def _seed_analysis(db, uid: int, pcap: str, aid: str) -> None:
    db.add(AnalysisModel(
        id=aid, user_id=uid, filename="t.pcap", file_path=pcap,
        status="completed", result_json=_json.dumps({}),
    ))
    db.commit()


def _seed_feedback(db, uid: int, aid: str) -> None:
    db.add(PathAnalysisFeedbackModel(
        analysis_id=aid,
        source_ip="10.0.0.5", destination_ip="10.0.0.1", destination_port=443,
        predicted_outcome="success", predicted_impairment=None, predicted_confidence=85,
        verdict="correct",
        analyst_note="Confirmed — handshake logs match.",
        actual_root_cause=None, misleading_step=None,
        analyst_id=uid,
    ))
    db.commit()


def _make_client(db_session, uid: int) -> TestClient:
    def _db():  yield db_session
    def _user():
        m = MagicMock(); m.id = uid; return m
    app.dependency_overrides[get_db]           = _db
    app.dependency_overrides[get_current_user] = _user
    return TestClient(app, raise_server_exceptions=True)


_BASE = {
    "analysis_id":      "aid-1",
    "source_ip":        "10.0.0.5",
    "destination_ip":   "10.0.0.1",
    "destination_port": 443,
}

_JSON_URL = "/api/path-analysis/export/json"
_HTML_URL = "/api/path-analysis/export/html"


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 1 — path analysis only (no compare, no feedback)
# ══════════════════════════════════════════════════════════════════════════════

class TestExportPathOnly:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid    = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "aid-1")
        self.client = _make_client(db_session, self.uid)

    def _post_json(self) -> dict:
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json=_BASE)
        assert r.status_code == 200, r.text
        return _json.loads(r.content)

    def test_returns_200(self):
        self._post_json()

    def test_content_disposition_json(self):
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json=_BASE)
        assert "attachment" in r.headers.get("content-disposition", "")
        assert ".json" in r.headers.get("content-disposition", "")

    def test_package_has_path_analysis(self):
        pkg = self._post_json()
        pa  = pkg["path_analysis"]
        assert pa["connection_outcome"] == "success"
        assert pa["path_confidence_score"] == 85
        assert len(pa["path_steps"]) > 0
        assert len(pa["evidence_items"]) > 0

    def test_compare_result_is_null(self):
        pkg = self._post_json()
        assert pkg["compare_result"] is None

    def test_feedback_is_null(self):
        pkg = self._post_json()
        assert pkg["analyst_feedback"] is None

    def test_export_metadata_present(self):
        pkg = self._post_json()
        assert "generated_at" in pkg["export_metadata"]
        assert "engine_version" in pkg["export_metadata"]

    def test_query_section_echoed(self):
        pkg = self._post_json()
        assert pkg["query"]["analysis_id"]      == "aid-1"
        assert pkg["query"]["source_ip"]        == "10.0.0.5"
        assert pkg["query"]["destination_ip"]   == "10.0.0.1"
        assert pkg["query"]["destination_port"] == 443

    def test_html_endpoint_returns_200(self):
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_HTML_URL, json=_BASE)
        assert r.status_code == 200
        assert b"<!DOCTYPE html>" in r.content

    def test_html_contains_what_happened(self):
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_HTML_URL, json=_BASE)
        assert b"What Happened" in r.content

    def test_html_contains_path_narrative(self):
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_HTML_URL, json=_BASE)
        assert b"Path Narrative" in r.content


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 2 — with compare data
# ══════════════════════════════════════════════════════════════════════════════

class TestExportWithCompare:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid    = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "aid-1")
        _seed_analysis(db_session, self.uid, tmp_pcap, "base-1")
        _seed_analysis(db_session, self.uid, tmp_pcap, "inc-1")
        self.client = _make_client(db_session, self.uid)

    def _post_json(self) -> dict:
        # analysis_id run = one call; baseline + incident = two more calls (three total)
        healthy  = _fake_path_result("success")
        baseline = _fake_path_result("success")
        incident = _fake_path_result("failure", "backend_response_delay")

        r1 = MagicMock(); r1.to_dict.return_value = healthy
        r2 = MagicMock(); r2.to_dict.return_value = baseline
        r3 = MagicMock(); r3.to_dict.return_value = incident
        mock_eng = MagicMock()
        mock_eng.return_value.analyze.side_effect = [r1, r2, r3]

        payload = {
            **_BASE,
            "include_compare":        True,
            "baseline_analysis_id":   "base-1",
            "incident_analysis_id":   "inc-1",
        }
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json=payload)
        assert r.status_code == 200, r.text
        return _json.loads(r.content)

    def test_compare_result_present(self):
        pkg = self._post_json()
        assert pkg["compare_result"] is not None

    def test_compare_has_key_differences(self):
        pkg = self._post_json()
        cr  = pkg["compare_result"]
        assert len(cr["key_differences"]) > 0

    def test_compare_has_regression_flag(self):
        pkg = self._post_json()
        assert pkg["compare_result"]["outcome_regression"] is True

    def test_compare_has_impairment_changes(self):
        pkg = self._post_json()
        imp = pkg["compare_result"]["impairment_changes"]
        assert "backend_response_delay" in imp["new"]

    def test_compare_has_regression_point(self):
        pkg = self._post_json()
        assert pkg["compare_result"]["most_likely_regression_point"] is not None

    def test_html_contains_what_changed(self):
        r1 = MagicMock(); r1.to_dict.return_value = _fake_path_result("success")
        r2 = MagicMock(); r2.to_dict.return_value = _fake_path_result("success")
        r3 = MagicMock(); r3.to_dict.return_value = _fake_path_result("failure", "no_response")
        mock_eng = MagicMock()
        mock_eng.return_value.analyze.side_effect = [r1, r2, r3]
        payload = {
            **_BASE,
            "include_compare":        True,
            "baseline_analysis_id":   "base-1",
            "incident_analysis_id":   "inc-1",
        }
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_HTML_URL, json=payload)
        assert b"What Changed" in r.content


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — with analyst feedback
# ══════════════════════════════════════════════════════════════════════════════

class TestExportWithFeedback:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid    = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "aid-1")
        _seed_feedback(db_session, self.uid, "aid-1")
        self.client = _make_client(db_session, self.uid)

    def _post_json(self) -> dict:
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json=_BASE)
        assert r.status_code == 200, r.text
        return _json.loads(r.content)

    def test_feedback_present(self):
        pkg = self._post_json()
        assert pkg["analyst_feedback"] is not None

    def test_feedback_verdict(self):
        pkg = self._post_json()
        assert pkg["analyst_feedback"]["verdict"] == "correct"

    def test_feedback_note(self):
        pkg = self._post_json()
        assert pkg["analyst_feedback"]["analyst_note"] == "Confirmed — handshake logs match."

    def test_html_contains_analyst_conclusion(self):
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_HTML_URL, json=_BASE)
        assert b"Analyst Conclusion" in r.content


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 4 — missing optional sections handled gracefully
# ══════════════════════════════════════════════════════════════════════════════

class TestExportMissingOptionals:

    @pytest.fixture(autouse=True)
    def setup(self, db_session, tmp_pcap):
        self.uid    = _seed_user(db_session)
        _seed_analysis(db_session, self.uid, tmp_pcap, "aid-1")
        # No feedback seeded, no compare requested
        self.client = _make_client(db_session, self.uid)

    def test_no_compare_requested_is_null(self):
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json={**_BASE, "include_compare": False})
        pkg = _json.loads(r.content)
        assert pkg["compare_result"] is None

    def test_no_feedback_seeded_is_null(self):
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json=_BASE)
        pkg = _json.loads(r.content)
        assert pkg["analyst_feedback"] is None

    def test_include_compare_without_ids_returns_null(self):
        """include_compare=True but no baseline/incident IDs → compare is skipped."""
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json={
                **_BASE,
                "include_compare": True,
                # baseline_analysis_id and incident_analysis_id omitted
            })
        assert r.status_code == 200
        pkg = _json.loads(r.content)
        assert pkg["compare_result"] is None

    def test_path_analysis_fields_all_present(self):
        """Even without optional sections, all required path fields must be in the package."""
        mock_eng = _mock_engine_for(_fake_path_result())
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r = self.client.post(_JSON_URL, json=_BASE)
        pa = _json.loads(r.content)["path_analysis"]
        for field in (
            "connection_outcome", "primary_impairment", "path_impairments",
            "path_confidence_score", "confidence_reasons", "path_summary",
            "path_steps", "evidence_items", "alternative_hypotheses",
            "missing_visibility_notes",
        ):
            assert field in pa, f"Missing field: {field}"

    def test_analysis_not_found_returns_404(self):
        r = self.client.post(_JSON_URL, json={**_BASE, "analysis_id": "no-such-id"})
        assert r.status_code == 404

    def test_missing_source_ip_returns_422(self):
        r = self.client.post(_JSON_URL, json={
            "analysis_id": "aid-1",
            "destination_ip": "10.0.0.1",
        })
        assert r.status_code == 422
