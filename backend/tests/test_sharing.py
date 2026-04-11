"""
Tests for the team-sharing workflow:

- Visibility rules (``private`` / ``team`` / ``global``) for role presets and
  saved queries.
- Edit / delete permission rules (author-only, even for team-visible items).
- Scope isolation across teams.
- Create-permission rules for each scope (team requires membership, global
  requires admin).
- Scope promotion / demotion on existing rows.
- Investigation note sharing (create + author-only edits).

The overrides use ``SimpleNamespace`` rather than ``MagicMock`` because
MagicMock auto-vivifies attributes, which would make ``is_admin`` and
``team_id`` spuriously truthy and break the visibility filter.
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
    InvestigationNoteModel,
    TeamModel,
    UserModel,
)
from main import app, get_db


# ── Shared infrastructure ────────────────────────────────────────────────────

class _UserHolder:
    """Mutable container that lets a single client impersonate different users."""

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


def _seed_team(db, name: str) -> int:
    t = TeamModel(name=name)
    db.add(t)
    db.flush()
    tid: int = t.id
    db.commit()
    return tid


def _seed_user(db, username: str) -> int:
    u = UserModel(username=username, hashed_password="x")
    db.add(u)
    db.flush()
    uid: int = u.id
    db.commit()
    return uid


@pytest.fixture
def team_alpha(db_session) -> int:
    return _seed_team(db_session, "alpha")


@pytest.fixture
def team_beta(db_session) -> int:
    return _seed_team(db_session, "beta")


@pytest.fixture
def alice_id(db_session) -> int:
    """Alice — private user (no team)."""
    return _seed_user(db_session, "alice")


@pytest.fixture
def bob_id(db_session) -> int:
    """Bob — private user (no team)."""
    return _seed_user(db_session, "bob")


# Helpers that assemble a holder for each canonical role the tests need.
def _holder(uid, team_id=None, is_admin=False) -> _UserHolder:
    return _UserHolder(uid=uid, team_id=team_id, is_admin=is_admin)


# ── Constants ────────────────────────────────────────────────────────────────

_PRESET_URL = "/api/path-analysis/presets"
_QUERY_URL  = "/api/path-analysis/saved-queries"

_PRESET_BODY = {
    "name": "Prod cluster",
    "firewall_ips": ["10.0.0.254"],
    "backend_ips":  ["10.0.2.20"],
}

_QUERY_BODY = {
    "name": "Client → LB",
    "source_ip": "10.0.0.5",
    "destination_ip": "10.0.0.1",
    "destination_port": 443,
}


# ══════════════════════════════════════════════════════════════════════════════
# Role preset — visibility
# ══════════════════════════════════════════════════════════════════════════════

class TestPresetVisibility:
    """Who can *see* a preset depending on its scope."""

    def test_private_preset_only_owner_sees_it(self, db_session, alice_id, bob_id):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        pid = c.post(_PRESET_URL, json=_PRESET_BODY).json()["id"]

        # Bob (different user, no team) sees nothing
        holder.uid = bob_id
        assert c.get(_PRESET_URL).json() == []
        assert c.get(f"{_PRESET_URL}/{pid}").status_code == 403

    def test_team_preset_visible_to_teammate(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]

        # Bob joins the same team → he sees the preset (read-only)
        holder.uid = bob_id
        holder.team_id = team_alpha
        listed = c.get(_PRESET_URL).json()
        assert [p["id"] for p in listed] == [pid]
        assert listed[0]["scope"]    == "team"
        assert listed[0]["can_edit"] is False

        # Direct GET also works
        assert c.get(f"{_PRESET_URL}/{pid}").status_code == 200

    def test_team_preset_invisible_to_other_team(
        self, db_session, alice_id, bob_id, team_alpha, team_beta,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]

        # Bob on a different team cannot see Alice's team preset
        holder.uid = bob_id
        holder.team_id = team_beta
        assert c.get(_PRESET_URL).json() == []
        assert c.get(f"{_PRESET_URL}/{pid}").status_code == 403

    def test_team_preset_invisible_to_teamless_user(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]

        # Bob with no team sees nothing
        holder.uid = bob_id
        holder.team_id = None
        assert c.get(_PRESET_URL).json() == []
        assert c.get(f"{_PRESET_URL}/{pid}").status_code == 403

    def test_global_preset_visible_to_everyone(
        self, db_session, alice_id, bob_id,
    ):
        # Admin creates a global preset
        admin_uid = _seed_user(db_session, "root")
        holder = _holder(admin_uid, is_admin=True)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "global"}
        ).json()["id"]

        # Alice (no team, not admin) still sees it
        holder.uid = alice_id
        holder.is_admin = False
        assert [p["id"] for p in c.get(_PRESET_URL).json()] == [pid]
        listed = c.get(f"{_PRESET_URL}/{pid}").json()
        assert listed["scope"]    == "global"
        assert listed["can_edit"] is False  # read-only for non-admin

    def test_admin_sees_all_presets(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        # Seed: alice private, bob private, alice team
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        c.post(_PRESET_URL, json={**_PRESET_BODY, "name": "AP1"})
        c.post(_PRESET_URL, json={**_PRESET_BODY, "name": "AT1", "scope": "team"})

        holder.uid = bob_id
        holder.team_id = None
        c.post(_PRESET_URL, json={**_PRESET_BODY, "name": "BP1"})

        # Admin sees everything
        admin_uid = _seed_user(db_session, "root")
        holder.uid = admin_uid
        holder.team_id = None
        holder.is_admin = True
        names = {p["name"] for p in c.get(_PRESET_URL).json()}
        assert names == {"AP1", "AT1", "BP1"}


# ══════════════════════════════════════════════════════════════════════════════
# Role preset — edit/delete permissions
# ══════════════════════════════════════════════════════════════════════════════

class TestPresetEditPermissions:
    """Viewing and editing are gated separately."""

    def test_owner_can_edit_own_team_preset(
        self, db_session, alice_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]
        r = c.put(f"{_PRESET_URL}/{pid}", json={"name": "Renamed"})
        assert r.status_code == 200
        assert r.json()["name"] == "Renamed"

    def test_teammate_cannot_edit_team_preset(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]

        holder.uid = bob_id  # still team_alpha
        r = c.put(f"{_PRESET_URL}/{pid}", json={"name": "Hijacked"})
        assert r.status_code == 403

    def test_teammate_cannot_delete_team_preset(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]

        holder.uid = bob_id
        assert c.delete(f"{_PRESET_URL}/{pid}").status_code == 403

        # And the preset still exists for Alice
        holder.uid = alice_id
        assert c.get(f"{_PRESET_URL}/{pid}").status_code == 200

    def test_non_admin_cannot_edit_global_preset(
        self, db_session, alice_id,
    ):
        admin_uid = _seed_user(db_session, "root")
        holder = _holder(admin_uid, is_admin=True)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "global"}
        ).json()["id"]

        # Alice (non-admin) cannot edit/delete
        holder.uid = alice_id
        holder.is_admin = False
        assert c.put(f"{_PRESET_URL}/{pid}", json={"name": "X"}).status_code == 403
        assert c.delete(f"{_PRESET_URL}/{pid}").status_code == 403

    def test_admin_can_edit_any_preset(
        self, db_session, alice_id,
    ):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        pid = c.post(_PRESET_URL, json=_PRESET_BODY).json()["id"]

        admin_uid = _seed_user(db_session, "root")
        holder.uid = admin_uid
        holder.is_admin = True
        r = c.put(f"{_PRESET_URL}/{pid}", json={"name": "Admin edited"})
        assert r.status_code == 200
        assert r.json()["name"] == "Admin edited"


# ══════════════════════════════════════════════════════════════════════════════
# Role preset — create-scope permissions
# ══════════════════════════════════════════════════════════════════════════════

class TestPresetCreatePermissions:
    """Who can create what scope."""

    def test_teamless_cannot_create_team_preset(self, db_session, alice_id):
        holder = _holder(alice_id, team_id=None)
        c = _make_client(db_session, holder)
        r = c.post(_PRESET_URL, json={**_PRESET_BODY, "scope": "team"})
        assert r.status_code == 403

    def test_team_member_can_create_team_preset(
        self, db_session, alice_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.post(_PRESET_URL, json={**_PRESET_BODY, "scope": "team"})
        assert r.status_code == 201
        body = r.json()
        assert body["scope"]    == "team"
        assert body["team_id"]  == team_alpha
        assert body["can_edit"] is True

    def test_non_admin_cannot_create_global_preset(self, db_session, alice_id):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(_PRESET_URL, json={**_PRESET_BODY, "scope": "global"})
        assert r.status_code == 403

    def test_admin_can_create_global_preset(self, db_session):
        admin_uid = _seed_user(db_session, "root")
        holder = _holder(admin_uid, is_admin=True)
        c = _make_client(db_session, holder)
        r = c.post(_PRESET_URL, json={**_PRESET_BODY, "scope": "global"})
        assert r.status_code == 201
        assert r.json()["scope"] == "global"

    def test_invalid_scope_rejected(self, db_session, alice_id):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(_PRESET_URL, json={**_PRESET_BODY, "scope": "company"})
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# Role preset — scope transitions
# ══════════════════════════════════════════════════════════════════════════════

class TestPresetScopeTransitions:
    """Changing scope on an existing preset goes through the same check."""

    def test_owner_promotes_private_to_team(
        self, db_session, alice_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(_PRESET_URL, json=_PRESET_BODY).json()["id"]
        r = c.put(f"{_PRESET_URL}/{pid}", json={"scope": "team"})
        assert r.status_code == 200
        body = r.json()
        assert body["scope"]   == "team"
        assert body["team_id"] == team_alpha

    def test_cannot_promote_to_team_without_team(
        self, db_session, alice_id,
    ):
        holder = _holder(alice_id, team_id=None)
        c = _make_client(db_session, holder)
        pid = c.post(_PRESET_URL, json=_PRESET_BODY).json()["id"]
        r = c.put(f"{_PRESET_URL}/{pid}", json={"scope": "team"})
        assert r.status_code == 403

    def test_cannot_promote_to_global_without_admin(
        self, db_session, alice_id,
    ):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        pid = c.post(_PRESET_URL, json=_PRESET_BODY).json()["id"]
        r = c.put(f"{_PRESET_URL}/{pid}", json={"scope": "global"})
        assert r.status_code == 403

    def test_demote_team_to_private_clears_team_id(
        self, db_session, alice_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]
        r = c.put(f"{_PRESET_URL}/{pid}", json={"scope": "private"})
        body = r.json()
        assert body["scope"]   == "private"
        assert body["team_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# Saved queries — mirror of preset visibility / permission tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSavedQueryVisibility:

    def test_private_only_owner_sees(self, db_session, alice_id, bob_id):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        qid = c.post(_QUERY_URL, json=_QUERY_BODY).json()["id"]

        holder.uid = bob_id
        assert c.get(_QUERY_URL).json() == []
        assert c.get(f"{_QUERY_URL}/{qid}").status_code == 403

    def test_team_visible_to_teammate_readonly(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        qid = c.post(
            _QUERY_URL, json={**_QUERY_BODY, "scope": "team"}
        ).json()["id"]

        holder.uid = bob_id
        holder.team_id = team_alpha
        listed = c.get(_QUERY_URL).json()
        assert [q["id"] for q in listed] == [qid]
        assert listed[0]["can_edit"] is False

    def test_team_invisible_to_other_team(
        self, db_session, alice_id, bob_id, team_alpha, team_beta,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        qid = c.post(
            _QUERY_URL, json={**_QUERY_BODY, "scope": "team"}
        ).json()["id"]

        holder.uid = bob_id
        holder.team_id = team_beta
        assert c.get(_QUERY_URL).json() == []
        assert c.get(f"{_QUERY_URL}/{qid}").status_code == 403

    def test_global_visible_to_all(self, db_session, alice_id):
        admin_uid = _seed_user(db_session, "root")
        holder = _holder(admin_uid, is_admin=True)
        c = _make_client(db_session, holder)
        qid = c.post(
            _QUERY_URL, json={**_QUERY_BODY, "scope": "global"}
        ).json()["id"]

        holder.uid = alice_id
        holder.is_admin = False
        assert [q["id"] for q in c.get(_QUERY_URL).json()] == [qid]


class TestSavedQueryEditPermissions:

    def test_teammate_cannot_edit_team_query(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        qid = c.post(
            _QUERY_URL, json={**_QUERY_BODY, "scope": "team"}
        ).json()["id"]

        holder.uid = bob_id
        assert c.put(
            f"{_QUERY_URL}/{qid}", json={"name": "Hijacked"}
        ).status_code == 403
        assert c.delete(f"{_QUERY_URL}/{qid}").status_code == 403

    def test_non_admin_cannot_edit_global_query(self, db_session, alice_id):
        admin_uid = _seed_user(db_session, "root")
        holder = _holder(admin_uid, is_admin=True)
        c = _make_client(db_session, holder)
        qid = c.post(
            _QUERY_URL, json={**_QUERY_BODY, "scope": "global"}
        ).json()["id"]

        holder.uid = alice_id
        holder.is_admin = False
        assert c.put(
            f"{_QUERY_URL}/{qid}", json={"name": "X"}
        ).status_code == 403

    def test_admin_can_edit_any_query(self, db_session, alice_id):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        qid = c.post(_QUERY_URL, json=_QUERY_BODY).json()["id"]

        admin_uid = _seed_user(db_session, "root")
        holder.uid = admin_uid
        holder.is_admin = True
        r = c.put(f"{_QUERY_URL}/{qid}", json={"name": "Admin"})
        assert r.status_code == 200


class TestSavedQueryCreatePermissions:

    def test_teamless_cannot_create_team_query(self, db_session, alice_id):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(_QUERY_URL, json={**_QUERY_BODY, "scope": "team"})
        assert r.status_code == 403

    def test_non_admin_cannot_create_global_query(self, db_session, alice_id):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(_QUERY_URL, json={**_QUERY_BODY, "scope": "global"})
        assert r.status_code == 403

    def test_team_member_creates_team_query(
        self, db_session, alice_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.post(_QUERY_URL, json={**_QUERY_BODY, "scope": "team"})
        assert r.status_code == 201
        body = r.json()
        assert body["scope"]   == "team"
        assert body["team_id"] == team_alpha


# ══════════════════════════════════════════════════════════════════════════════
# Cross-resource referential integrity
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossResource:
    """A saved query may reference a preset; the preset must be visible."""

    def test_query_may_reference_team_preset_if_teammate(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        pid = c.post(
            _PRESET_URL, json={**_PRESET_BODY, "scope": "team"}
        ).json()["id"]

        # Bob (same team) may build a private query that references Alice's
        # team-shared preset because it is visible to him.
        holder.uid = bob_id
        r = c.post(
            _QUERY_URL, json={**_QUERY_BODY, "role_preset_id": pid},
        )
        assert r.status_code == 201
        assert r.json()["role_preset_id"] == pid

    def test_query_cannot_reference_invisible_private_preset(
        self, db_session, alice_id, bob_id,
    ):
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        pid = c.post(_PRESET_URL, json=_PRESET_BODY).json()["id"]

        holder.uid = bob_id
        r = c.post(
            _QUERY_URL, json={**_QUERY_BODY, "role_preset_id": pid},
        )
        assert r.status_code in (403, 404)


# ══════════════════════════════════════════════════════════════════════════════
# Investigation notes
# ══════════════════════════════════════════════════════════════════════════════

def _seed_analysis(db, user_id: int) -> str:
    aid = str(uuid.uuid4())
    db.add(AnalysisModel(
        id=aid, user_id=user_id, filename="t.pcap", status="completed",
    ))
    db.commit()
    return aid


_NOTE_BODY = {
    "source_ip": "10.0.0.5",
    "destination_ip": "10.0.0.1",
    "destination_port": 443,
    "body": "Initial investigation note.",
}


class TestInvestigationNoteCreate:

    def test_owner_can_create_private_note(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(f"/api/analyses/{aid}/investigation-notes", json=_NOTE_BODY)
        assert r.status_code == 201
        body = r.json()
        assert body["scope"]    == "private"
        assert body["team_id"]  is None
        assert body["can_edit"] is True

    def test_owner_can_create_team_note(
        self, db_session, alice_id, team_alpha,
    ):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.post(
            f"/api/analyses/{aid}/investigation-notes",
            json={**_NOTE_BODY, "scope": "team"},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["scope"]   == "team"
        assert body["team_id"] == team_alpha

    def test_teamless_user_cannot_create_team_note(
        self, db_session, alice_id,
    ):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id, team_id=None)
        c = _make_client(db_session, holder)
        r = c.post(
            f"/api/analyses/{aid}/investigation-notes",
            json={**_NOTE_BODY, "scope": "team"},
        )
        assert r.status_code == 403

    def test_global_scope_rejected_by_schema(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(
            f"/api/analyses/{aid}/investigation-notes",
            json={**_NOTE_BODY, "scope": "global"},
        )
        assert r.status_code == 422


class TestInvestigationNoteEditPermissions:
    """The update/delete endpoints look up by note id (they don't go through
    the analysis ownership check), so they are the correct surface to test
    author-only semantics for team-visible notes."""

    def _seed_team_note(self, db_session, alice_id, team_alpha) -> tuple[str, int]:
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        nid = c.post(
            f"/api/analyses/{aid}/investigation-notes",
            json={**_NOTE_BODY, "scope": "team"},
        ).json()["id"]
        return aid, nid

    def test_author_can_edit_own_team_note(
        self, db_session, alice_id, team_alpha,
    ):
        aid, nid = self._seed_team_note(db_session, alice_id, team_alpha)
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.put(
            f"/api/analyses/{aid}/investigation-notes/{nid}",
            json={"body": "Updated"},
        )
        assert r.status_code == 200
        assert r.json()["body"] == "Updated"

    def test_teammate_non_author_gets_403(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        aid, nid = self._seed_team_note(db_session, alice_id, team_alpha)

        # Bob, same team, non-author
        holder = _holder(bob_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.put(
            f"/api/analyses/{aid}/investigation-notes/{nid}",
            json={"body": "Hijacked"},
        )
        assert r.status_code == 403

    def test_non_teammate_gets_403(
        self, db_session, alice_id, bob_id, team_alpha, team_beta,
    ):
        aid, nid = self._seed_team_note(db_session, alice_id, team_alpha)

        # Bob on a different team — no visibility at all
        holder = _holder(bob_id, team_id=team_beta)
        c = _make_client(db_session, holder)
        r = c.put(
            f"/api/analyses/{aid}/investigation-notes/{nid}",
            json={"body": "Hijacked"},
        )
        assert r.status_code == 403

    def test_teammate_cannot_delete_team_note(
        self, db_session, alice_id, bob_id, team_alpha,
    ):
        aid, nid = self._seed_team_note(db_session, alice_id, team_alpha)
        holder = _holder(bob_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.delete(f"/api/analyses/{aid}/investigation-notes/{nid}")
        assert r.status_code == 403

    def test_author_can_delete_own_note(
        self, db_session, alice_id, team_alpha,
    ):
        aid, nid = self._seed_team_note(db_session, alice_id, team_alpha)
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.delete(f"/api/analyses/{aid}/investigation-notes/{nid}")
        assert r.status_code == 204
        # Gone afterwards
        assert db_session.query(InvestigationNoteModel).filter_by(id=nid).first() is None


# ══════════════════════════════════════════════════════════════════════════════
# Path-analysis feedback (scope)
# ══════════════════════════════════════════════════════════════════════════════

_FEEDBACK_BODY = {
    "source_ip":             "10.0.0.5",
    "destination_ip":        "10.0.0.1",
    "destination_port":      443,
    "predicted_outcome":     "failure",
    "predicted_impairment":  "tls_handshake_failure",
    "predicted_confidence":  80,
    "verdict":               "correct",
}


class TestFeedbackScope:

    def test_private_feedback_default(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json=_FEEDBACK_BODY,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["scope"]    == "private"
        assert body["team_id"]  is None
        assert body["can_edit"] is True

    def test_team_feedback_requires_team(
        self, db_session, alice_id,
    ):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id, team_id=None)
        c = _make_client(db_session, holder)
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json={**_FEEDBACK_BODY, "scope": "team"},
        )
        assert r.status_code == 403

    def test_team_feedback_records_team_id(
        self, db_session, alice_id, team_alpha,
    ):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id, team_id=team_alpha)
        c = _make_client(db_session, holder)
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json={**_FEEDBACK_BODY, "scope": "team"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["scope"]   == "team"
        assert body["team_id"] == team_alpha

    def test_global_scope_rejected_by_schema(self, db_session, alice_id):
        aid = _seed_analysis(db_session, alice_id)
        holder = _holder(alice_id)
        c = _make_client(db_session, holder)
        r = c.post(
            f"/api/analyses/{aid}/path-analysis/feedback",
            json={**_FEEDBACK_BODY, "scope": "global"},
        )
        assert r.status_code == 422
