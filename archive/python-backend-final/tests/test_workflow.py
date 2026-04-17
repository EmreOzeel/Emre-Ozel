"""
Tests for the investigation workflow layer:

- Workflow state transitions (GET / PUT /workflow/state)
- Assignee management (PUT /workflow/assignee) — owner / admin only
- Visibility rules (owner, assignee, admin vs. stranger) for detail + status
- Feedback auto-transition (incorrect → needs_review, correct → resolved)
- /api/users endpoint (team + admin scoping)
- list_analyses assigned_to_me and workflow_state filters

Uses the same ``SimpleNamespace`` + ``_UserHolder`` pattern as test_sharing.py
so that ``is_admin`` and ``team_id`` never spuriously truthy via MagicMock
auto-vivification.
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
from database import (
    AnalysisModel,
    Base,
    PathAnalysisFeedbackModel,
    TeamModel,
    UserModel,
)
from main import app, get_db


# ── Shared infrastructure ────────────────────────────────────────────────────

class _UserHolder:
    def __init__(self, uid: int, team_id: int | None = None, is_admin: bool = False):
        self.uid = uid
        self.team_id = team_id
        self.is_admin = is_admin


def _make_client(db_session, holder: _UserHolder) -> TestClient:
    def _override_db():
        yield db_session

    def _override_user():
        return SimpleNamespace(
            id=holder.uid,
            is_admin=holder.is_admin,
            team_id=holder.team_id,
        )

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True)


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


# ── Seed helpers ─────────────────────────────────────────────────────────────

def _seed_team(db, name: str) -> int:
    t = TeamModel(name=name)
    db.add(t)
    db.flush()
    tid: int = t.id
    db.commit()
    return tid


def _seed_user(db, username: str, team_id: int | None = None) -> int:
    u = UserModel(
        username=username, hashed_password="x", team_id=team_id,
    )
    db.add(u)
    db.flush()
    uid: int = u.id
    db.commit()
    return uid


def _seed_analysis(
    db,
    user_id: int,
    *,
    workflow_state: str = "new",
    assigned_user_id: int | None = None,
) -> str:
    aid = str(uuid.uuid4())
    db.add(AnalysisModel(
        id=aid,
        user_id=user_id,
        filename="t.pcap",
        status="completed",
        workflow_state=workflow_state,
        assigned_user_id=assigned_user_id,
    ))
    db.commit()
    return aid


def _holder(uid, team_id=None, is_admin=False) -> _UserHolder:
    return _UserHolder(uid=uid, team_id=team_id, is_admin=is_admin)


@pytest.fixture
def team_alpha(db_session) -> int:
    return _seed_team(db_session, "alpha")


@pytest.fixture
def alice_id(db_session) -> int:
    return _seed_user(db_session, "alice")


@pytest.fixture
def bob_id(db_session) -> int:
    return _seed_user(db_session, "bob")


@pytest.fixture
def carol_id(db_session) -> int:
    return _seed_user(db_session, "carol")


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/analyses/{id}/workflow
# ══════════════════════════════════════════════════════════════════════════════

class TestWorkflowGet:

    def test_new_analysis_defaults_to_new_state(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.get(f"/api/analyses/{aid}/workflow")
        assert r.status_code == 200
        body = r.json()
        assert body["analysis_id"]      == aid
        assert body["workflow_state"]   == "new"
        assert body["assigned_user_id"] is None
        assert body["owner_user_id"]    == alice_id
        assert body["can_edit_state"]   is True
        assert body["can_assign"]       is True

    def test_stranger_cannot_read_workflow(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(bob_id))
        r = c.get(f"/api/analyses/{aid}/workflow")
        assert r.status_code == 404

    def test_assignee_can_read_workflow(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = c.get(f"/api/analyses/{aid}/workflow")
        assert r.status_code == 200
        body = r.json()
        assert body["assigned_user_id"] == bob_id
        # Assignee can change state but NOT reassign
        assert body["can_edit_state"]   is True
        assert body["can_assign"]       is False

    def test_admin_can_read_any_workflow(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        admin_uid = _seed_user(db_session, "root")
        c = _make_client(db_session, _holder(admin_uid, is_admin=True))
        r = c.get(f"/api/analyses/{aid}/workflow")
        assert r.status_code == 200
        body = r.json()
        assert body["can_edit_state"] is True
        assert body["can_assign"]     is True


# ══════════════════════════════════════════════════════════════════════════════
# PUT /api/analyses/{id}/workflow/state
# ══════════════════════════════════════════════════════════════════════════════

class TestWorkflowStateTransitions:

    def test_owner_can_advance_to_in_progress(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "in_progress"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["workflow_state"]       == "in_progress"
        assert body["workflow_updated_by"]  == alice_id
        assert body["workflow_updated_at"]  is not None

    def test_owner_can_resolve(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "resolved"},
        )
        assert r.status_code == 200
        assert r.json()["workflow_state"] == "resolved"

    def test_assignee_can_change_state(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "needs_review"},
        )
        assert r.status_code == 200
        assert r.json()["workflow_state"] == "needs_review"

    def test_stranger_cannot_change_state(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(bob_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "resolved"},
        )
        # 404 — we do not leak existence to strangers
        assert r.status_code == 404

    def test_admin_can_change_any_state(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        admin_uid = _seed_user(db_session, "root")
        c = _make_client(db_session, _holder(admin_uid, is_admin=True))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "dismissed"},
        )
        assert r.status_code == 200
        assert r.json()["workflow_state"] == "dismissed"

    def test_invalid_state_rejected(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "bogus"},
        )
        assert r.status_code == 422  # Pydantic pattern rejection

    def test_state_update_is_persisted(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "in_progress"},
        )
        row = db_session.query(AnalysisModel).filter_by(id=aid).first()
        assert row.workflow_state == "in_progress"
        assert row.workflow_updated_by == alice_id


# ══════════════════════════════════════════════════════════════════════════════
# PUT /api/analyses/{id}/workflow/assignee
# ══════════════════════════════════════════════════════════════════════════════

class TestWorkflowAssignee:

    def test_owner_can_assign(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["assigned_user_id"]  == bob_id
        assert body["assignee_username"] == "bob"

    def test_owner_can_unassign(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": None},
        )
        assert r.status_code == 200
        assert r.json()["assigned_user_id"] is None

    def test_assignee_cannot_reassign(self, db_session, alice_id, bob_id, carol_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": carol_id},
        )
        assert r.status_code == 403

    def test_stranger_cannot_assign(self, db_session, alice_id, bob_id, carol_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(carol_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        assert r.status_code == 404

    def test_admin_can_assign(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id)
        admin_uid = _seed_user(db_session, "root")
        c = _make_client(db_session, _holder(admin_uid, is_admin=True))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        assert r.status_code == 200
        assert r.json()["assigned_user_id"] == bob_id

    def test_unknown_user_rejected(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": 999_999},
        )
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Feedback auto-transition
# ══════════════════════════════════════════════════════════════════════════════

_FEEDBACK_BODY = {
    "source_ip": "10.0.0.5",
    "destination_ip": "10.0.0.1",
    "destination_port": 443,
    "predicted_outcome": "success",
    "predicted_impairment": None,
    "predicted_confidence": 90,
    "verdict": "correct",
    "analyst_note": "Looks right",
    "actual_root_cause": None,
    "misleading_step": None,
    "scope": "private",
}


class TestFeedbackAutoTransition:

    def _post_feedback(self, client, aid, **overrides):
        body = {**_FEEDBACK_BODY, **overrides}
        return client.post(
            f"/api/analyses/{aid}/path-analysis/feedback", json=body
        )

    def test_correct_verdict_moves_new_to_resolved(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id, workflow_state="new")
        c = _make_client(db_session, _holder(alice_id))
        r = self._post_feedback(c, aid, verdict="correct")
        assert r.status_code == 200
        row = db_session.query(AnalysisModel).filter_by(id=aid).first()
        db_session.refresh(row)
        assert row.workflow_state == "resolved"

    def test_partially_correct_also_moves_to_resolved(self, db_session, alice_id):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="in_progress",
        )
        c = _make_client(db_session, _holder(alice_id))
        r = self._post_feedback(c, aid, verdict="partially_correct")
        assert r.status_code == 200
        row = db_session.query(AnalysisModel).filter_by(id=aid).first()
        db_session.refresh(row)
        assert row.workflow_state == "resolved"

    def test_incorrect_verdict_moves_to_needs_review(self, db_session, alice_id):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="in_progress",
        )
        c = _make_client(db_session, _holder(alice_id))
        r = self._post_feedback(c, aid, verdict="incorrect")
        assert r.status_code == 200
        row = db_session.query(AnalysisModel).filter_by(id=aid).first()
        db_session.refresh(row)
        assert row.workflow_state == "needs_review"

    def test_does_not_override_resolved(self, db_session, alice_id):
        """An already-resolved investigation should NOT be reopened by a new verdict."""
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="resolved",
        )
        c = _make_client(db_session, _holder(alice_id))
        r = self._post_feedback(c, aid, verdict="incorrect")
        assert r.status_code == 200
        row = db_session.query(AnalysisModel).filter_by(id=aid).first()
        db_session.refresh(row)
        assert row.workflow_state == "resolved"

    def test_does_not_override_dismissed(self, db_session, alice_id):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="dismissed",
        )
        c = _make_client(db_session, _holder(alice_id))
        r = self._post_feedback(c, aid, verdict="correct")
        assert r.status_code == 200
        row = db_session.query(AnalysisModel).filter_by(id=aid).first()
        db_session.refresh(row)
        assert row.workflow_state == "dismissed"

    def test_assignee_can_submit_feedback(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = self._post_feedback(c, aid, verdict="correct")
        assert r.status_code == 200
        row = db_session.query(AnalysisModel).filter_by(id=aid).first()
        db_session.refresh(row)
        assert row.workflow_state == "resolved"

    def test_stranger_cannot_submit_feedback(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(bob_id))
        r = self._post_feedback(c, aid, verdict="correct")
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# /api/users (assignee picker)
# ══════════════════════════════════════════════════════════════════════════════

class TestUserPicker:

    def test_private_user_sees_only_self(self, db_session, alice_id, bob_id):
        c = _make_client(db_session, _holder(alice_id))
        r = c.get("/api/users")
        assert r.status_code == 200
        ids = {u["id"] for u in r.json()}
        assert alice_id in ids
        assert bob_id not in ids

    def test_team_member_sees_team(self, db_session, team_alpha):
        alice = _seed_user(db_session, "alice", team_id=team_alpha)
        bob   = _seed_user(db_session, "bob",   team_id=team_alpha)
        carol = _seed_user(db_session, "carol")  # different / no team
        c = _make_client(db_session, _holder(alice, team_id=team_alpha))
        r = c.get("/api/users")
        assert r.status_code == 200
        ids = {u["id"] for u in r.json()}
        assert alice in ids
        assert bob   in ids
        assert carol not in ids

    def test_admin_sees_all_users(self, db_session, alice_id, bob_id):
        admin_uid = _seed_user(db_session, "root")
        c = _make_client(db_session, _holder(admin_uid, is_admin=True))
        r = c.get("/api/users")
        assert r.status_code == 200
        ids = {u["id"] for u in r.json()}
        assert alice_id in ids
        assert bob_id   in ids
        assert admin_uid in ids


# ══════════════════════════════════════════════════════════════════════════════
# list_analyses with workflow filters
# ══════════════════════════════════════════════════════════════════════════════

class TestListAnalysesWorkflow:

    def test_summary_includes_workflow_fields(self, db_session, alice_id):
        _seed_analysis(db_session, alice_id, workflow_state="in_progress")
        c = _make_client(db_session, _holder(alice_id))
        r = c.get("/api/analyses")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        row = rows[0]
        assert row["workflow_state"] == "in_progress"
        assert row["owner_user_id"]  == alice_id

    def test_assigned_to_me_includes_analyses_not_owned(
        self, db_session, alice_id, bob_id,
    ):
        # Alice owns two, one of which is assigned to Bob
        _seed_analysis(db_session, alice_id)
        _seed_analysis(db_session, alice_id, assigned_user_id=bob_id)
        # Bob owns one of his own
        own_bob = _seed_analysis(db_session, bob_id)

        c = _make_client(db_session, _holder(bob_id))

        # Without assigned_to_me, Bob only sees his own
        r = c.get("/api/analyses")
        assert r.status_code == 200
        ids = {row["id"] for row in r.json()}
        assert ids == {own_bob}

        # With assigned_to_me, he also sees Alice's assigned one
        r = c.get("/api/analyses?assigned_to_me=true")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_workflow_state_filter(self, db_session, alice_id):
        _seed_analysis(db_session, alice_id, workflow_state="new")
        _seed_analysis(db_session, alice_id, workflow_state="resolved")
        _seed_analysis(db_session, alice_id, workflow_state="resolved")
        c = _make_client(db_session, _holder(alice_id))
        r = c.get("/api/analyses?workflow_state=resolved")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 2
        assert all(row["workflow_state"] == "resolved" for row in rows)

    def test_invalid_workflow_state_rejected(self, db_session, alice_id):
        _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.get("/api/analyses?workflow_state=bogus")
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# Access via GET /api/analyses/{id}
# ══════════════════════════════════════════════════════════════════════════════

class TestAnalysisDetailAccess:

    def test_owner_can_view(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.get(f"/api/analyses/{aid}")
        assert r.status_code == 200

    def test_assignee_can_view(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = c.get(f"/api/analyses/{aid}")
        assert r.status_code == 200
        body = r.json()
        assert body["assigned_user_id"]  == bob_id
        assert body["assignee_username"] == "bob"

    def test_stranger_cannot_view(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(bob_id))
        r = c.get(f"/api/analyses/{aid}")
        assert r.status_code == 404

    def test_admin_can_view_any(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        admin_uid = _seed_user(db_session, "root")
        c = _make_client(db_session, _holder(admin_uid, is_admin=True))
        r = c.get(f"/api/analyses/{aid}")
        assert r.status_code == 200
