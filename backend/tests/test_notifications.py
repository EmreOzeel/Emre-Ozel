"""
Tests for the in-app notification system:

- Creation triggers (assignment, state change to needs_review / resolved,
  incorrect feedback, feedback auto-transition)
- Self-notifications are suppressed
- Per-user visibility (one user never sees another user's notifications)
- GET /api/notifications (list, unread_only, ordering)
- GET /api/notifications/unread-count
- POST /api/notifications/mark-read (ids list + all=true + no-op when already read)
- Cascade delete when an analysis is deleted

Follows the same SimpleNamespace + _UserHolder pattern as test_sharing.py
and test_workflow.py so that ``is_admin`` and ``team_id`` stay strictly
explicit.
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
    NotificationModel,
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

def _seed_user(db, username: str) -> int:
    u = UserModel(username=username, hashed_password="x")
    db.add(u)
    db.flush()
    uid: int = u.id
    db.commit()
    return uid


def _seed_analysis(
    db,
    user_id: int,
    *,
    filename: str = "capture.pcap",
    workflow_state: str = "new",
    assigned_user_id: int | None = None,
) -> str:
    aid = str(uuid.uuid4())
    db.add(AnalysisModel(
        id=aid,
        user_id=user_id,
        filename=filename,
        status="completed",
        workflow_state=workflow_state,
        assigned_user_id=assigned_user_id,
    ))
    db.commit()
    return aid


def _holder(uid, team_id=None, is_admin=False) -> _UserHolder:
    return _UserHolder(uid=uid, team_id=team_id, is_admin=is_admin)


@pytest.fixture
def alice_id(db_session) -> int:
    return _seed_user(db_session, "alice")


@pytest.fixture
def bob_id(db_session) -> int:
    return _seed_user(db_session, "bob")


@pytest.fixture
def carol_id(db_session) -> int:
    return _seed_user(db_session, "carol")


def _notifs_for(db, user_id):
    return (
        db.query(NotificationModel)
        .filter(NotificationModel.user_id == user_id)
        .order_by(NotificationModel.id.asc())
        .all()
    )


# ══════════════════════════════════════════════════════════════════════════════
# Assignment trigger
# ══════════════════════════════════════════════════════════════════════════════

class TestAssignmentTrigger:

    def test_new_assignee_gets_notification(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id, filename="case.pcap")
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        assert r.status_code == 200
        notifs = _notifs_for(db_session, bob_id)
        assert len(notifs) == 1
        n = notifs[0]
        assert n.type          == "assignment"
        assert n.analysis_id   == aid
        assert n.actor_user_id == alice_id
        assert "case.pcap" in n.message
        assert n.read_at is None

    def test_self_assign_does_not_notify(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": alice_id},
        )
        assert r.status_code == 200
        assert _notifs_for(db_session, alice_id) == []

    def test_unassign_does_not_notify(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        # Clear Bob's existing notifications to isolate this case
        db_session.query(NotificationModel).delete()
        db_session.commit()

        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": None},
        )
        assert r.status_code == 200
        assert _notifs_for(db_session, bob_id) == []

    def test_reassign_same_user_is_noop(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        # Clear any from the seed phase (seed doesn't trigger notifications
        # but we want a clean slate)
        db_session.query(NotificationModel).delete()
        db_session.commit()

        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        assert r.status_code == 200
        # No new notification because the assignee did not change.
        assert _notifs_for(db_session, bob_id) == []


# ══════════════════════════════════════════════════════════════════════════════
# State change triggers (explicit PUT)
# ══════════════════════════════════════════════════════════════════════════════

class TestStateChangeNotifications:

    def test_needs_review_notifies_owner(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        # Bob (assignee) transitions it to needs_review
        c = _make_client(db_session, _holder(bob_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "needs_review"},
        )
        assert r.status_code == 200
        owner_notifs = _notifs_for(db_session, alice_id)
        assert len(owner_notifs) == 1
        assert owner_notifs[0].type == "review_required"
        # Bob (the actor + assignee) does not notify himself
        assert _notifs_for(db_session, bob_id) == []

    def test_needs_review_notifies_assignee_when_actor_is_owner(
        self, db_session, alice_id, bob_id,
    ):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        # Owner triggers the transition
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "needs_review"},
        )
        assert r.status_code == 200
        # Bob (assignee) is notified; Alice (owner+actor) is not
        assert len(_notifs_for(db_session, bob_id)) == 1
        assert _notifs_for(db_session, bob_id)[0].type == "review_required"
        assert _notifs_for(db_session, alice_id) == []

    def test_resolved_notifies_owner(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "resolved"},
        )
        assert r.status_code == 200
        owner = _notifs_for(db_session, alice_id)
        assert len(owner) == 1
        assert owner[0].type == "resolved"

    def test_resolved_by_owner_is_silent(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "resolved"},
        )
        assert r.status_code == 200
        # Self-notify is suppressed
        assert _notifs_for(db_session, alice_id) == []

    def test_dismissed_emits_nothing(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "dismissed"},
        )
        assert r.status_code == 200
        assert _notifs_for(db_session, alice_id) == []
        assert _notifs_for(db_session, bob_id) == []

    def test_no_state_change_no_notification(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="needs_review",
            assigned_user_id=bob_id,
        )
        # Transition needs_review -> needs_review (same state)
        c = _make_client(db_session, _holder(bob_id))
        r = c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "needs_review"},
        )
        assert r.status_code == 200
        assert _notifs_for(db_session, alice_id) == []


# ══════════════════════════════════════════════════════════════════════════════
# Feedback triggers
# ══════════════════════════════════════════════════════════════════════════════

_FEEDBACK_BASE = {
    "source_ip": "10.0.0.5",
    "destination_ip": "10.0.0.1",
    "destination_port": 443,
    "predicted_outcome": "success",
    "predicted_impairment": None,
    "predicted_confidence": 90,
    "verdict": "correct",
    "analyst_note": None,
    "actual_root_cause": None,
    "misleading_step": None,
    "scope": "private",
}


def _feedback_body(**overrides):
    return {**_FEEDBACK_BASE, **overrides}


class TestFeedbackNotifications:

    def test_incorrect_verdict_alerts_owner(
        self, db_session, alice_id, bob_id,
    ):
        aid = _seed_analysis(db_session, alice_id, assigned_user_id=bob_id)
        # Bob (assignee) submits an incorrect verdict
        c = _make_client(db_session, _holder(bob_id))
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json=_feedback_body(verdict="incorrect"),
        )
        assert r.status_code == 200
        owner = _notifs_for(db_session, alice_id)
        # Owner gets BOTH feedback_alert AND review_required (auto-transition)
        types = {n.type for n in owner}
        assert "feedback_alert" in types
        assert "review_required" in types
        # Bob (assignee + actor) does NOT self-notify
        assert _notifs_for(db_session, bob_id) == []

    def test_incorrect_alerts_owner_and_assignee_distinct(
        self, db_session, alice_id, bob_id, carol_id,
    ):
        # Alice owns, Bob is assignee, Carol submits the feedback
        aid = _seed_analysis(db_session, alice_id, assigned_user_id=bob_id)
        c = _make_client(db_session, _holder(carol_id))
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json=_feedback_body(verdict="incorrect"),
        )
        # Carol is a stranger — the route requires owner/assignee/admin.
        # So this should 404 (by design). Verify that strangers cannot emit
        # notifications.
        assert r.status_code == 404
        assert _notifs_for(db_session, alice_id) == []
        assert _notifs_for(db_session, bob_id) == []

    def test_admin_incorrect_alerts_owner_and_assignee(
        self, db_session, alice_id, bob_id,
    ):
        admin_uid = _seed_user(db_session, "root")
        aid = _seed_analysis(db_session, alice_id, assigned_user_id=bob_id)
        c = _make_client(db_session, _holder(admin_uid, is_admin=True))
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json=_feedback_body(verdict="incorrect"),
        )
        assert r.status_code == 200
        # Both owner and assignee are alerted
        assert any(
            n.type == "feedback_alert" for n in _notifs_for(db_session, alice_id)
        )
        assert any(
            n.type == "feedback_alert" for n in _notifs_for(db_session, bob_id)
        )

    def test_correct_verdict_triggers_resolved_notification(
        self, db_session, alice_id, bob_id,
    ):
        aid = _seed_analysis(
            db_session, alice_id, assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json=_feedback_body(verdict="correct"),
        )
        assert r.status_code == 200
        owner = _notifs_for(db_session, alice_id)
        assert len(owner) == 1
        assert owner[0].type == "resolved"

    def test_correct_by_owner_creates_no_notifications(
        self, db_session, alice_id,
    ):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json=_feedback_body(verdict="correct"),
        )
        assert r.status_code == 200
        assert _notifs_for(db_session, alice_id) == []


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/notifications  +  unread-count
# ══════════════════════════════════════════════════════════════════════════════

class TestListNotifications:

    def test_user_only_sees_own_notifications(
        self, db_session, alice_id, bob_id,
    ):
        # Bob is assigned by Alice — Bob gets one notification
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )

        # Alice sees no notifications (she was the actor)
        r = c.get("/api/notifications")
        assert r.status_code == 200
        assert r.json() == []

        # Bob sees his
        c2 = _make_client(db_session, _holder(bob_id))
        r = c2.get("/api/notifications")
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["type"]              == "assignment"
        assert body[0]["analysis_id"]       == aid
        assert body[0]["actor_user_id"]     == alice_id
        assert body[0]["actor_username"]    == "alice"
        assert body[0]["analysis_filename"] == "capture.pcap"
        assert body[0]["read_at"] is None

    def test_notifications_sorted_newest_first(
        self, db_session, alice_id, bob_id,
    ):
        a1 = _seed_analysis(db_session, alice_id, filename="first.pcap")
        a2 = _seed_analysis(db_session, alice_id, filename="second.pcap")
        c = _make_client(db_session, _holder(alice_id))
        c.put(
            f"/api/analyses/{a1}/workflow/assignee",
            json={"user_id": bob_id},
        )
        c.put(
            f"/api/analyses/{a2}/workflow/assignee",
            json={"user_id": bob_id},
        )

        c2 = _make_client(db_session, _holder(bob_id))
        rows = c2.get("/api/notifications").json()
        assert len(rows) == 2
        # Newest first: the second assignment is the newest
        assert rows[0]["analysis_id"] == a2
        assert rows[1]["analysis_id"] == a1

    def test_unread_only_filter(self, db_session, alice_id, bob_id):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        # Mark Bob's notification as read directly in the DB
        n = _notifs_for(db_session, bob_id)[0]
        from datetime import datetime as _dt
        n.read_at = _dt.utcnow()
        db_session.commit()

        c2 = _make_client(db_session, _holder(bob_id))
        all_rows = c2.get("/api/notifications").json()
        assert len(all_rows) == 1
        unread_rows = c2.get("/api/notifications?unread_only=true").json()
        assert unread_rows == []

    def test_unread_count_endpoint(self, db_session, alice_id, bob_id):
        a1 = _seed_analysis(db_session, alice_id, filename="one.pcap")
        a2 = _seed_analysis(db_session, alice_id, filename="two.pcap")
        c = _make_client(db_session, _holder(alice_id))
        c.put(f"/api/analyses/{a1}/workflow/assignee", json={"user_id": bob_id})
        c.put(f"/api/analyses/{a2}/workflow/assignee", json={"user_id": bob_id})

        c2 = _make_client(db_session, _holder(bob_id))
        r = c2.get("/api/notifications/unread-count")
        assert r.status_code == 200
        assert r.json() == {"unread": 2}

    def test_unread_count_is_zero_for_user_with_no_notifications(
        self, db_session, alice_id,
    ):
        c = _make_client(db_session, _holder(alice_id))
        r = c.get("/api/notifications/unread-count")
        assert r.status_code == 200
        assert r.json() == {"unread": 0}


# ══════════════════════════════════════════════════════════════════════════════
# Mark-read endpoint
# ══════════════════════════════════════════════════════════════════════════════

class TestMarkRead:

    def _prepare_two_notifications(self, db_session, alice_id, bob_id):
        a1 = _seed_analysis(db_session, alice_id, filename="a.pcap")
        a2 = _seed_analysis(db_session, alice_id, filename="b.pcap")
        c = _make_client(db_session, _holder(alice_id))
        c.put(f"/api/analyses/{a1}/workflow/assignee", json={"user_id": bob_id})
        c.put(f"/api/analyses/{a2}/workflow/assignee", json={"user_id": bob_id})
        app.dependency_overrides.clear()
        return _notifs_for(db_session, bob_id)

    def test_mark_specific_ids_read(self, db_session, alice_id, bob_id):
        notifs = self._prepare_two_notifications(db_session, alice_id, bob_id)
        first_id = notifs[0].id
        c = _make_client(db_session, _holder(bob_id))
        r = c.post(
            "/api/notifications/mark-read",
            json={"ids": [first_id]},
        )
        assert r.status_code == 200
        assert r.json() == {"marked": 1}
        fresh = _notifs_for(db_session, bob_id)
        assert fresh[0].read_at is not None
        assert fresh[1].read_at is None

    def test_mark_all_true(self, db_session, alice_id, bob_id):
        self._prepare_two_notifications(db_session, alice_id, bob_id)
        c = _make_client(db_session, _holder(bob_id))
        r = c.post("/api/notifications/mark-read", json={"all": True})
        assert r.status_code == 200
        assert r.json() == {"marked": 2}
        fresh = _notifs_for(db_session, bob_id)
        assert all(n.read_at is not None for n in fresh)

    def test_mark_read_ignores_other_users_ids(
        self, db_session, alice_id, bob_id, carol_id,
    ):
        notifs = self._prepare_two_notifications(db_session, alice_id, bob_id)
        bob_notif_id = notifs[0].id
        # Carol tries to mark Bob's notification as read
        c = _make_client(db_session, _holder(carol_id))
        r = c.post(
            "/api/notifications/mark-read",
            json={"ids": [bob_notif_id]},
        )
        assert r.status_code == 200
        assert r.json() == {"marked": 0}
        # Bob's notification remains unread
        assert _notifs_for(db_session, bob_id)[0].read_at is None

    def test_mark_read_requires_ids_or_all(self, db_session, bob_id):
        c = _make_client(db_session, _holder(bob_id))
        r = c.post("/api/notifications/mark-read", json={})
        assert r.status_code == 400

    def test_mark_read_is_idempotent(self, db_session, alice_id, bob_id):
        self._prepare_two_notifications(db_session, alice_id, bob_id)
        c = _make_client(db_session, _holder(bob_id))
        r1 = c.post("/api/notifications/mark-read", json={"all": True})
        assert r1.json() == {"marked": 2}
        # Second call should mark nothing new
        r2 = c.post("/api/notifications/mark-read", json={"all": True})
        assert r2.json() == {"marked": 0}


# ══════════════════════════════════════════════════════════════════════════════
# Cascade delete
# ══════════════════════════════════════════════════════════════════════════════

class TestCascadeDelete:

    def test_deleting_analysis_removes_notifications(
        self, db_session, alice_id, bob_id,
    ):
        aid = _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        assert len(_notifs_for(db_session, bob_id)) == 1
        r = c.delete(f"/api/analyses/{aid}")
        assert r.status_code == 204
        assert _notifs_for(db_session, bob_id) == []
