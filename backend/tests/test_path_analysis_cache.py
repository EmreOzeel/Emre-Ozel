"""
Cache tests for POST /api/analyses/{id}/path-analysis.

Validates that:
  1. The first call computes a fresh result and returns from_cache=False.
  2. An identical second call returns from_cache=True without re-running the engine.
  3. Changing roles causes a cache miss (different cache key → fresh compute).
  4. Bumping engine_version causes a cache miss.
  5. Changing destination_port causes a cache miss.

All tests use an in-memory SQLite database and mock both the PCAP normaliser
and CausalPathEngine so no real capture file is needed.
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
from database import AnalysisModel, Base, PathAnalysisCacheModel, UserModel
from main import app, get_db


# ── Fake engine result ────────────────────────────────────────────────────────

def _fake_result_dict() -> dict:
    """Minimal PathAnalysisResult.to_dict() payload returned by the mock engine."""
    return {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "destination_port": 80,
        "protocol": "TCP",
        "connection_state": "application_level_interaction",
        "path_summary": "Connection succeeded.",
        "path_steps": ["SYN observed", "SYN-ACK received", "Data exchanged"],
        "hop_sequence": [],
        "firewall_observation":      {"role": "firewall",       "ip": "", "observed": False, "note": ""},
        "load_balancer_observation": {"role": "load_balancer",  "ip": "", "observed": False, "note": ""},
        "backend_observation":       {"role": "backend",        "ip": "", "observed": False, "note": ""},
        "timing_breakdown": {},
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


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def db_session():
    """Fresh in-memory SQLite session for each test.

    StaticPool is required so that all SQLAlchemy operations — including those
    issued from FastAPI's worker threads — share the exact same underlying
    sqlite3 connection (and therefore the same in-memory database).
    """
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
    """A real file on disk so that Path.exists() returns True."""
    f = tmp_path / "test.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return str(f)


@pytest.fixture(scope="function")
def seeded_db(db_session, tmp_pcap):
    """DB session pre-populated with a user and a completed analysis.

    Returns (db_session, user_id) where user_id is a plain int so closures
    can reference it without triggering SQLAlchemy lazy-loading across threads.
    """
    user = UserModel(username="testuser", hashed_password="x")
    db_session.add(user)
    db_session.flush()          # assigns user.id inside this session
    user_id: int = user.id      # capture as plain int before commit expires it

    row = AnalysisModel(
        id="analysis-001",
        user_id=user_id,
        filename="test.pcap",
        file_path=tmp_pcap,
        status="completed",
    )
    db_session.add(row)
    db_session.commit()
    return db_session, user_id


@pytest.fixture(scope="function")
def client(seeded_db):
    """TestClient with DB and auth dependencies overridden."""
    db_session, user_id = seeded_db

    def _override_db():
        yield db_session

    def _override_user():
        fake = MagicMock()
        fake.id = user_id       # plain int — no lazy-loading required
        return fake

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    app.dependency_overrides.clear()


# ── Shared patch targets ──────────────────────────────────────────────────────

_NORMALIZE = "normalizer.pipeline.normalize"
_ENGINE    = "core.causal_path.CausalPathEngine"


def _mock_normalize():
    """Return a mock CaptureContext with the attributes CausalPathEngine expects."""
    ctx = MagicMock()
    ctx.packets  = []
    ctx.flows    = {}
    ctx.findings = []
    return ctx


def _mock_engine_class():
    """Return a mock CausalPathEngine class whose analyze() returns a fake result."""
    mock_result = MagicMock()
    mock_result.to_dict.return_value = _fake_result_dict()

    mock_cls = MagicMock()
    mock_cls.return_value.analyze.return_value = mock_result
    return mock_cls


# ── Base request ──────────────────────────────────────────────────────────────

_BASE_REQ = {
    "source_ip":       "10.0.0.1",
    "destination_ip":  "10.0.0.2",
    "destination_port": 80,
    "roles": None,
}

_URL = "/api/analyses/analysis-001/path-analysis"


# ══════════════════════════════════════════════════════════════════════════════
# 1 — First call: fresh compute, from_cache=False; result stored in DB
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheFirstCall:
    """The first request must run the engine and return from_cache=False."""

    def test_from_cache_is_false(self, client, seeded_db):
        db = seeded_db[0]  # noqa: F841
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_class()):
            r = client.post(_URL, json=_BASE_REQ)

        assert r.status_code == 200
        assert r.json()["from_cache"] is False

    def test_cache_row_created(self, client, seeded_db):
        db = seeded_db[0]   # db_session
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=_mock_engine_class()):
            client.post(_URL, json=_BASE_REQ)

        count = db.query(PathAnalysisCacheModel).count()
        assert count == 1, f"expected 1 cache row, got {count}"


# ══════════════════════════════════════════════════════════════════════════════
# 2 — Second identical call: from_cache=True, engine not invoked again
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheSecondCall:
    """An identical follow-up request must be served from the cache."""

    def test_from_cache_is_true_on_second_call(self, client, seeded_db):
        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            client.post(_URL, json=_BASE_REQ)           # first — populates cache
            r2 = client.post(_URL, json=_BASE_REQ)      # second — should hit cache

        assert r2.status_code == 200
        assert r2.json()["from_cache"] is True

    def test_engine_called_only_once(self, client, seeded_db):
        """Engine.analyze() must be invoked exactly once across two identical calls."""
        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            client.post(_URL, json=_BASE_REQ)
            client.post(_URL, json=_BASE_REQ)

        assert mock_eng.return_value.analyze.call_count == 1

    def test_result_content_matches(self, client, seeded_db):
        """Cached response must contain the same domain fields as the fresh one."""
        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r1 = client.post(_URL, json=_BASE_REQ)
            r2 = client.post(_URL, json=_BASE_REQ)

        # Strip the from_cache flag before comparing domain content
        d1 = {k: v for k, v in r1.json().items() if k != "from_cache"}
        d2 = {k: v for k, v in r2.json().items() if k != "from_cache"}
        assert d1 == d2


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Changed roles: cache miss, engine re-invoked
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheMissOnRolesChange:
    """Different roles must produce a separate cache entry (different key)."""

    def test_changed_roles_causes_miss(self, client, seeded_db):
        req_a = {**_BASE_REQ, "roles": {"firewall_ips": ["192.168.1.1"]}}
        req_b = {**_BASE_REQ, "roles": {"firewall_ips": ["192.168.1.2"]}}

        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r_a = client.post(_URL, json=req_a)
            r_b = client.post(_URL, json=req_b)

        assert r_a.json()["from_cache"] is False
        assert r_b.json()["from_cache"] is False, (
            "Different roles must produce a cache miss"
        )

    def test_changed_roles_calls_engine_twice(self, client, seeded_db):
        req_a = {**_BASE_REQ, "roles": {"firewall_ips": ["192.168.1.1"]}}
        req_b = {**_BASE_REQ, "roles": {"firewall_ips": ["192.168.1.2"]}}

        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            client.post(_URL, json=req_a)
            client.post(_URL, json=req_b)

        assert mock_eng.return_value.analyze.call_count == 2

    def test_list_order_does_not_cause_false_miss(self, client, seeded_db):
        """Same IPs supplied in a different order must hit the cache."""
        req_a = {**_BASE_REQ, "roles": {"firewall_ips": ["10.0.0.1", "10.0.0.2"]}}
        req_b = {**_BASE_REQ, "roles": {"firewall_ips": ["10.0.0.2", "10.0.0.1"]}}

        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            client.post(_URL, json=req_a)
            r_b = client.post(_URL, json=req_b)

        assert r_b.json()["from_cache"] is True, (
            "Roles list order must not produce a spurious cache miss"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4 — Changed engine_version: cache miss
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheMissOnEngineVersionChange:
    """A bumped CACHE_ENGINE_VERSION must invalidate all existing cache entries."""

    def test_changed_engine_version_causes_miss(self, client, seeded_db):
        mock_eng = _mock_engine_class()

        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng), \
             patch("core.causal_path.CACHE_ENGINE_VERSION", "1"):
            r1 = client.post(_URL, json=_BASE_REQ)

        assert r1.json()["from_cache"] is False

        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng), \
             patch("core.causal_path.CACHE_ENGINE_VERSION", "2"):
            r2 = client.post(_URL, json=_BASE_REQ)

        assert r2.json()["from_cache"] is False, (
            "Bumped engine_version must produce a cache miss"
        )

    def test_same_engine_version_still_hits(self, client, seeded_db):
        mock_eng = _mock_engine_class()

        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng), \
             patch("core.causal_path.CACHE_ENGINE_VERSION", "1"):
            client.post(_URL, json=_BASE_REQ)
            r2 = client.post(_URL, json=_BASE_REQ)

        assert r2.json()["from_cache"] is True


# ══════════════════════════════════════════════════════════════════════════════
# 5 — Changed destination_port: cache miss
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheMissOnPortChange:
    """Different destination_port values must produce separate cache entries."""

    def test_changed_port_causes_miss(self, client, seeded_db):
        req_80  = {**_BASE_REQ, "destination_port": 80}
        req_443 = {**_BASE_REQ, "destination_port": 443}

        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            r1 = client.post(_URL, json=req_80)
            r2 = client.post(_URL, json=req_443)

        assert r1.json()["from_cache"] is False
        assert r2.json()["from_cache"] is False, (
            "Different destination_port must produce a cache miss"
        )

    def test_same_port_still_hits(self, client, seeded_db):
        req_443 = {**_BASE_REQ, "destination_port": 443}

        mock_eng = _mock_engine_class()
        with patch(_NORMALIZE, return_value=_mock_normalize()), \
             patch(_ENGINE, new=mock_eng):
            client.post(_URL, json=req_443)
            r2 = client.post(_URL, json=req_443)

        assert r2.json()["from_cache"] is True
