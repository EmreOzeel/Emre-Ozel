"""
Tests for GET /api/work-queue — the "My Work" dashboard endpoint.

Covers:
- Section grouping (disjoint by priority)
- Prioritization order
- Visibility rules (owner/assignee/admin)
- Feedback alert surfacing (incorrect verdicts)
- Feedback-derived enrichment (primary_impairment, path_confidence_score)
- Notification enrichment
- Only completed analyses appear
- Recent-resolved tail cap
- Empty-state shape
- total_open excludes recent_resolved

Mirrors the SimpleNamespace + _UserHolder pattern used elsewhere.
"""
from __future__ import annotations

import os
import sys
import uuid
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
    AnalysisModel,
    Base,
    NotificationModel,
    PathAnalysisFeedbackModel,
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
    status: str = "completed",
    workflow_state: str = "new",
    assigned_user_id: int | None = None,
    workflow_updated_at: datetime | None = None,
    issue_count: int = 0,
    critical_count: int = 0,
) -> str:
    aid = str(uuid.uuid4())
    db.add(AnalysisModel(
        id=aid,
        user_id=user_id,
        filename=filename,
        status=status,
        workflow_state=workflow_state,
        assigned_user_id=assigned_user_id,
        workflow_updated_at=workflow_updated_at,
        issue_count=issue_count,
        critical_count=critical_count,
    ))
    db.commit()
    return aid


def _seed_feedback(
    db,
    *,
    analysis_id: str,
    analyst_id: int,
    verdict: str = "correct",
    predicted_impairment: str | None = "packet_loss",
    predicted_confidence: int = 72,
    source_ip: str = "10.0.0.5",
    destination_ip: str = "10.0.0.1",
    destination_port: int | None = 443,
    updated_at: datetime | None = None,
) -> int:
    row = PathAnalysisFeedbackModel(
        analysis_id=analysis_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        predicted_outcome="success",
        predicted_impairment=predicted_impairment,
        predicted_confidence=predicted_confidence,
        verdict=verdict,
        analyst_id=analyst_id,
        scope="private",
    )
    if updated_at is not None:
        row.updated_at = updated_at
    db.add(row)
    db.commit()
    return row.id


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


def _fetch_queue(client) -> dict:
    r = client.get("/api/work-queue")
    assert r.status_code == 200, r.text
    return r.json()


def _section(body: dict, key: str) -> dict:
    for s in body["sections"]:
        if s["key"] == key:
            return s
    raise AssertionError(f"section {key!r} missing from {[s['key'] for s in body['sections']]}")


# ══════════════════════════════════════════════════════════════════════════════
# Empty state / shape
# ══════════════════════════════════════════════════════════════════════════════

class TestEmptyState:

    def test_empty_user_gets_all_sections(self, db_session, alice_id):
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        keys = [s["key"] for s in body["sections"]]
        assert keys == [
            "needs_review",
            "recent_feedback_alerts",
            "assigned_to_me",
            "new_analyses",
            "unresolved_owned",
            "recent_resolved",
        ]
        # Each section is empty but present
        for s in body["sections"]:
            assert s["count"] == 0
            assert s["items"] == []
        assert body["total_open"] == 0
        assert body["counts"] == {
            "needs_review": 0,
            "recent_feedback_alerts": 0,
            "assigned_to_me": 0,
            "new_analyses": 0,
            "unresolved_owned": 0,
            "recent_resolved": 0,
        }

    def test_sections_are_priority_ordered(self, db_session, alice_id):
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        priorities = [s["priority"] for s in body["sections"]]
        assert priorities == sorted(priorities)
        # Explicit ordering contract
        assert priorities == [1, 2, 3, 4, 5, 6]


# ══════════════════════════════════════════════════════════════════════════════
# Grouping
# ══════════════════════════════════════════════════════════════════════════════

class TestSectionGrouping:

    def test_new_owned_analysis_lands_in_new_section(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id, filename="fresh.pcap")
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        new = _section(body, "new_analyses")
        assert new["count"] == 1
        assert new["items"][0]["analysis_id"] == aid
        assert new["items"][0]["filename"] == "fresh.pcap"
        # Must NOT also appear in unresolved_owned
        assert _section(body, "unresolved_owned")["count"] == 0

    def test_in_progress_owned_lands_in_unresolved(self, db_session, alice_id):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="in_progress",
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        assert _section(body, "unresolved_owned")["count"] == 1
        assert _section(body, "unresolved_owned")["items"][0]["analysis_id"] == aid
        assert _section(body, "new_analyses")["count"] == 0

    def test_needs_review_takes_priority_over_new(self, db_session, alice_id):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="needs_review",
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        nr = _section(body, "needs_review")
        assert nr["count"] == 1
        assert nr["items"][0]["analysis_id"] == aid
        # Should NOT cascade into new_analyses
        assert _section(body, "new_analyses")["count"] == 0
        assert _section(body, "unresolved_owned")["count"] == 0

    def test_assigned_to_me_excludes_needs_review(
        self, db_session, alice_id, bob_id,
    ):
        # Alice owns, Bob is assigned; workflow is needs_review
        aid = _seed_analysis(
            db_session, alice_id,
            workflow_state="needs_review",
            assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        body = _fetch_queue(c)
        # Needs_review wins
        assert _section(body, "needs_review")["count"] == 1
        assert _section(body, "needs_review")["items"][0]["analysis_id"] == aid
        # Not duplicated in assigned_to_me
        assert _section(body, "assigned_to_me")["count"] == 0

    def test_assigned_to_me_picks_up_in_progress(
        self, db_session, alice_id, bob_id,
    ):
        aid = _seed_analysis(
            db_session, alice_id,
            workflow_state="in_progress",
            assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        body = _fetch_queue(c)
        assert _section(body, "assigned_to_me")["count"] == 1
        item = _section(body, "assigned_to_me")["items"][0]
        assert item["analysis_id"] == aid
        assert item["assigned_user_id"] == bob_id
        assert item["assignee_username"] == "bob"
        assert item["owner_user_id"] == alice_id
        assert item["owner_username"] == "alice"

    def test_resolved_goes_into_recent_resolved(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id, workflow_state="resolved")
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        rr = _section(body, "recent_resolved")
        assert rr["count"] == 1
        assert rr["items"][0]["analysis_id"] == aid
        # Does NOT leak into new_analyses/unresolved_owned
        assert _section(body, "new_analyses")["count"] == 0
        assert _section(body, "unresolved_owned")["count"] == 0

    def test_dismissed_also_shown_as_recent_resolved(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id, workflow_state="dismissed")
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        rr = _section(body, "recent_resolved")
        assert rr["count"] == 1
        assert rr["items"][0]["analysis_id"] == aid

    def test_recent_resolved_respects_limit(self, db_session, alice_id):
        for i in range(7):
            _seed_analysis(
                db_session, alice_id,
                filename=f"r{i}.pcap",
                workflow_state="resolved",
            )
        c = _make_client(db_session, _holder(alice_id))
        r = c.get("/api/work-queue?recent_resolved_limit=3")
        assert r.status_code == 200
        body = r.json()
        assert _section(body, "recent_resolved")["count"] == 3

    def test_only_completed_analyses_appear(self, db_session, alice_id):
        # Pending / running / failed analyses must not leak into the queue
        _seed_analysis(db_session, alice_id, status="pending")
        _seed_analysis(db_session, alice_id, status="running")
        _seed_analysis(db_session, alice_id, status="failed")
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        assert body["total_open"] == 0
        for s in body["sections"]:
            assert s["count"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# Visibility
# ══════════════════════════════════════════════════════════════════════════════

class TestVisibility:

    def test_stranger_sees_nothing(
        self, db_session, alice_id, bob_id, carol_id,
    ):
        # Alice owns, Bob is assigned. Carol is unrelated.
        _seed_analysis(
            db_session, alice_id,
            workflow_state="in_progress",
            assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(carol_id))
        body = _fetch_queue(c)
        assert body["total_open"] == 0

    def test_owner_sees_own_analysis(self, db_session, alice_id):
        _seed_analysis(db_session, alice_id)
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        assert _section(body, "new_analyses")["count"] == 1

    def test_assignee_sees_assigned_analysis(
        self, db_session, alice_id, bob_id,
    ):
        _seed_analysis(
            db_session, alice_id,
            workflow_state="in_progress",
            assigned_user_id=bob_id,
        )
        c = _make_client(db_session, _holder(bob_id))
        body = _fetch_queue(c)
        assert _section(body, "assigned_to_me")["count"] == 1

    def test_admin_queue_is_self_centric(
        self, db_session, alice_id,
    ):
        """Admin users get their own queue, not a global queue."""
        admin_uid = _seed_user(db_session, "root")
        _seed_analysis(db_session, alice_id)  # Alice owns, admin is unrelated
        c = _make_client(db_session, _holder(admin_uid, is_admin=True))
        body = _fetch_queue(c)
        assert body["total_open"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# Feedback enrichment
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedbackEnrichment:

    def test_latest_feedback_fields_populated(self, db_session, alice_id):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="in_progress",
        )
        _seed_feedback(
            db_session,
            analysis_id=aid,
            analyst_id=alice_id,
            verdict="correct",
            predicted_impairment="congestion",
            predicted_confidence=88,
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        item = _section(body, "unresolved_owned")["items"][0]
        assert item["primary_impairment"] == "congestion"
        assert item["path_confidence_score"] == 88
        assert item["latest_feedback_verdict"] == "correct"

    def test_multiple_feedbacks_use_latest(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        old = datetime.utcnow() - timedelta(hours=2)
        newer = datetime.utcnow()
        _seed_feedback(
            db_session, analysis_id=aid, analyst_id=alice_id,
            source_ip="1.1.1.1", destination_ip="2.2.2.2",
            predicted_impairment="jitter", predicted_confidence=40,
            updated_at=old,
        )
        _seed_feedback(
            db_session, analysis_id=aid, analyst_id=alice_id,
            source_ip="3.3.3.3", destination_ip="4.4.4.4",
            predicted_impairment="loss", predicted_confidence=95,
            updated_at=newer,
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        item = _section(body, "new_analyses")["items"][0]
        assert item["primary_impairment"] == "loss"
        assert item["path_confidence_score"] == 95


# ══════════════════════════════════════════════════════════════════════════════
# Feedback alert section
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedbackAlerts:

    def test_incorrect_feedback_surfaces_as_alert(
        self, db_session, alice_id,
    ):
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="in_progress",
        )
        _seed_feedback(
            db_session,
            analysis_id=aid, analyst_id=alice_id,
            verdict="incorrect",
            predicted_impairment="drop", predicted_confidence=60,
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        alerts = _section(body, "recent_feedback_alerts")
        assert alerts["count"] == 1
        assert alerts["items"][0]["analysis_id"] == aid
        assert alerts["items"][0]["latest_feedback_verdict"] == "incorrect"
        # Should be excluded from unresolved_owned (higher priority claimed it)
        assert _section(body, "unresolved_owned")["count"] == 0

    def test_correct_feedback_does_not_appear_in_alerts(
        self, db_session, alice_id,
    ):
        aid = _seed_analysis(db_session, alice_id)
        _seed_feedback(
            db_session, analysis_id=aid, analyst_id=alice_id,
            verdict="correct",
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        assert _section(body, "recent_feedback_alerts")["count"] == 0
        # Still in new_analyses
        assert _section(body, "new_analyses")["count"] == 1

    def test_needs_review_takes_priority_over_feedback_alert(
        self, db_session, alice_id,
    ):
        # needs_review should win over recent_feedback_alerts
        aid = _seed_analysis(
            db_session, alice_id, workflow_state="needs_review",
        )
        _seed_feedback(
            db_session, analysis_id=aid, analyst_id=alice_id,
            verdict="incorrect",
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        assert _section(body, "needs_review")["count"] == 1
        assert _section(body, "recent_feedback_alerts")["count"] == 0

    def test_feedback_alert_limit(self, db_session, alice_id):
        # Seed 6 incorrect feedback rows; request only 2
        for i in range(6):
            aid = _seed_analysis(
                db_session, alice_id, filename=f"f{i}.pcap",
            )
            _seed_feedback(
                db_session, analysis_id=aid, analyst_id=alice_id,
                verdict="incorrect",
                source_ip=f"10.0.0.{i}", destination_ip="1.1.1.1",
            )
        c = _make_client(db_session, _holder(alice_id))
        r = c.get("/api/work-queue?recent_feedback_limit=2")
        body = r.json()
        assert _section(body, "recent_feedback_alerts")["count"] == 2

    def test_feedback_alert_requires_visibility(
        self, db_session, alice_id, bob_id,
    ):
        # Feedback on an analysis NOT visible to Bob must not appear for Bob
        aid = _seed_analysis(db_session, alice_id)
        _seed_feedback(
            db_session, analysis_id=aid, analyst_id=alice_id,
            verdict="incorrect",
        )
        c = _make_client(db_session, _holder(bob_id))
        body = _fetch_queue(c)
        assert _section(body, "recent_feedback_alerts")["count"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# Notification enrichment
# ══════════════════════════════════════════════════════════════════════════════

class TestNotificationEnrichment:

    def test_latest_notification_surfaced_on_item(
        self, db_session, alice_id, bob_id,
    ):
        aid = _seed_analysis(db_session, alice_id)
        # Alice assigns Bob -> Bob gets an 'assignment' notification
        c = _make_client(db_session, _holder(alice_id))
        c.put(
            f"/api/analyses/{aid}/workflow/assignee",
            json={"user_id": bob_id},
        )
        # Bob's queue should surface that notification on the matching item
        c2 = _make_client(db_session, _holder(bob_id))
        body = _fetch_queue(c2)
        items = _section(body, "new_analyses")["items"]
        # Note: 'new_analyses' is owner-only; Bob is assignee, not owner.
        # Bob has no owned-new items. Instead check assigned_to_me section.
        # Wait — state is still "new" and Bob is assignee, so he's excluded
        # from assigned_to_me (new is not in assigned-eligible). There's no
        # section for "assigned to me but still new". For this test we only
        # care that the field is populated where appropriate, so re-drive
        # the state to in_progress so Bob's queue lights up.
        assert items == []
        # Switch state to in_progress from Alice
        c.put(
            f"/api/analyses/{aid}/workflow/state",
            json={"state": "in_progress"},
        )
        body = _fetch_queue(c2)
        items = _section(body, "assigned_to_me")["items"]
        assert len(items) == 1
        assert items[0]["latest_notification_type"] == "assignment"
        assert items[0]["latest_notification_at"] is not None


# ══════════════════════════════════════════════════════════════════════════════
# total_open semantics
# ══════════════════════════════════════════════════════════════════════════════

class TestTotalOpen:

    def test_total_open_excludes_recent_resolved(self, db_session, alice_id):
        _seed_analysis(db_session, alice_id, workflow_state="new")
        _seed_analysis(db_session, alice_id, workflow_state="in_progress")
        _seed_analysis(db_session, alice_id, workflow_state="resolved")
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        assert _section(body, "new_analyses")["count"]      == 1
        assert _section(body, "unresolved_owned")["count"]  == 1
        assert _section(body, "recent_resolved")["count"]   == 1
        # Resolved does NOT count as "open"
        assert body["total_open"] == 2

    def test_total_open_counts_disjoint_sections(
        self, db_session, alice_id, bob_id,
    ):
        # needs_review + new + in_progress all land in disjoint sections
        _seed_analysis(
            db_session, alice_id, workflow_state="needs_review",
        )
        _seed_analysis(
            db_session, alice_id, workflow_state="new",
        )
        _seed_analysis(
            db_session, alice_id, workflow_state="in_progress",
        )
        c = _make_client(db_session, _holder(alice_id))
        body = _fetch_queue(c)
        assert body["total_open"] == 3
