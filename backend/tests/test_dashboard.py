"""
Tests for GET /api/dashboard/summary.

Validates:
  - Response shape (all top-level keys present)
  - work_queue counts match actual analysis workflow states
  - analyses.pending count matches pending/running analyses
"""
from __future__ import annotations

import os
import sys
import uuid
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import AnalysisModel, Base, UserModel
from main import app, get_db


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


def _seed_user(db, username="admin", is_admin=False):
    u = UserModel(username=username, hashed_password="x", is_admin=is_admin)
    db.add(u)
    db.flush()
    uid = u.id
    db.commit()
    return uid


def _make_client(db_session, uid, is_admin=False):
    def _override_db():
        yield db_session

    def _override_user():
        return SimpleNamespace(id=uid, is_admin=is_admin, team_id=None)

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True)


def _seed_analysis(db, uid, *, status="completed", workflow_state="new",
                    aid=None):
    aid = aid or str(uuid.uuid4())
    db.add(AnalysisModel(
        id=aid, user_id=uid, filename="test.pcap",
        status=status, workflow_state=workflow_state,
    ))
    db.commit()
    return aid


# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestDashboardSummary:

    def test_shape_all_keys_present(self, db_session):
        uid = _seed_user(db_session, "alice")
        client = _make_client(db_session, uid)
        r = client.get("/api/dashboard/summary")
        assert r.status_code == 200
        body = r.json()
        for key in (
            "collector", "live_events", "risk_scores",
            "auto_detections", "work_queue", "analyses",
        ):
            assert key in body, f"missing top-level key: {key}"
        # Collector sub-keys
        assert "running" in body["collector"]
        # Live events sub-keys
        for k in ("total_last_5min", "allow_last_5min", "deny_last_5min",
                   "drop_last_5min", "top_risk_ip", "top_risk_score"):
            assert k in body["live_events"]
        # Work queue
        for k in ("total_open", "needs_review", "new_analyses"):
            assert k in body["work_queue"]
        # Analyses
        for k in ("total", "completed_today", "failed_today", "pending"):
            assert k in body["analyses"]

    def test_work_queue_counts_match(self, db_session):
        uid = _seed_user(db_session, "bob")
        # Create analyses in various workflow states
        _seed_analysis(db_session, uid, status="completed", workflow_state="new")
        _seed_analysis(db_session, uid, status="completed", workflow_state="new")
        _seed_analysis(db_session, uid, status="completed", workflow_state="needs_review")
        _seed_analysis(db_session, uid, status="completed", workflow_state="in_progress")
        _seed_analysis(db_session, uid, status="completed", workflow_state="resolved")
        # pending status → not in work queue (engine not done)
        _seed_analysis(db_session, uid, status="pending", workflow_state="new")

        client = _make_client(db_session, uid)
        body = client.get("/api/dashboard/summary").json()
        wq = body["work_queue"]
        # total_open = new(2) + in_progress(1) + needs_review(1) = 4
        assert wq["total_open"] == 4
        assert wq["needs_review"] == 1
        assert wq["new_analyses"] == 2

    def test_analyses_pending_count(self, db_session):
        uid = _seed_user(db_session, "carol")
        _seed_analysis(db_session, uid, status="pending")
        _seed_analysis(db_session, uid, status="running")
        _seed_analysis(db_session, uid, status="completed")
        _seed_analysis(db_session, uid, status="failed")

        client = _make_client(db_session, uid)
        body = client.get("/api/dashboard/summary").json()
        a = body["analyses"]
        assert a["pending"] == 2    # pending + running
        assert a["total"] == 4
