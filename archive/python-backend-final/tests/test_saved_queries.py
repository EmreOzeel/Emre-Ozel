"""
CRUD and ownership-isolation tests for path-analysis saved queries.

Endpoints under test:
  POST   /api/path-analysis/saved-queries
  GET    /api/path-analysis/saved-queries
  GET    /api/path-analysis/saved-queries/{id}
  PUT    /api/path-analysis/saved-queries/{id}
  DELETE /api/path-analysis/saved-queries/{id}
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import Base, PathAnalysisRolePresetModel, UserModel
from main import app, get_db


# ── Shared infra (mirrors test_role_presets.py pattern) ──────────────────────

class _UserHolder:
    def __init__(self, uid: int):
        self.uid = uid


def _make_client(db_session, user_id: int) -> tuple[TestClient, _UserHolder]:
    holder = _UserHolder(user_id)

    def _override_db():
        yield db_session

    def _override_user():
        return SimpleNamespace(id=holder.uid, is_admin=False, team_id=None)

    app.dependency_overrides[get_db]           = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True), holder


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


def _seed_user(db_session, username: str) -> int:
    u = UserModel(username=username, hashed_password="x")
    db_session.add(u)
    db_session.flush()
    uid: int = u.id
    db_session.commit()
    return uid


@pytest.fixture(scope="function")
def alice_id(db_session):
    return _seed_user(db_session, "alice")


@pytest.fixture(scope="function")
def bob_id(db_session):
    return _seed_user(db_session, "bob")


@pytest.fixture(scope="function", autouse=True)
def clear_overrides():
    yield
    app.dependency_overrides.clear()


# ── Fixtures / helpers ────────────────────────────────────────────────────────

_BASE_QUERY = {
    "name":            "Health check",
    "source_ip":       "10.0.0.5",
    "destination_ip":  "10.0.0.1",
    "destination_port": 443,
    "firewall_ips":    ["10.0.0.254"],
    "backend_ips":     ["10.0.2.20", "10.0.2.21"],
}

_URL = "/api/path-analysis/saved-queries"


# ══════════════════════════════════════════════════════════════════════════════
# Create
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateSavedQuery:

    def test_create_returns_201(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.post(_URL, json=_BASE_QUERY)
        assert r.status_code == 201

    def test_response_shape(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        d = c.post(_URL, json=_BASE_QUERY).json()
        assert d["name"]            == "Health check"
        assert d["source_ip"]       == "10.0.0.5"
        assert d["destination_ip"]  == "10.0.0.1"
        assert d["destination_port"] == 443
        assert "id" in d
        assert "created_at" in d

    def test_backend_ips_stored_sorted(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        d = c.post(_URL, json={**_BASE_QUERY, "backend_ips": ["10.0.2.21", "10.0.2.20"]}).json()
        assert d["backend_ips"] == ["10.0.2.20", "10.0.2.21"]

    def test_missing_name_rejected(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.post(_URL, json={"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2"})
        assert r.status_code == 422

    def test_empty_name_rejected(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.post(_URL, json={**_BASE_QUERY, "name": ""})
        assert r.status_code == 422

    def test_no_port_stored_as_null(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        body = {k: v for k, v in _BASE_QUERY.items() if k != "destination_port"}
        d = c.post(_URL, json=body).json()
        assert d["destination_port"] is None

    def test_with_note(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        d = c.post(_URL, json={**_BASE_QUERY, "note": "Nightly probe"}).json()
        assert d["note"] == "Nightly probe"

    def test_with_valid_preset_reference(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        preset_id = c.post(
            "/api/path-analysis/presets",
            json={"name": "P", "firewall_ips": ["1.2.3.4"]},
        ).json()["id"]
        d = c.post(_URL, json={**_BASE_QUERY, "role_preset_id": preset_id}).json()
        assert d["role_preset_id"] == preset_id

    def test_foreign_preset_reference_rejected(self, db_session, alice_id, bob_id):
        """Saving a query that references a preset owned by someone else must fail."""
        c, holder = _make_client(db_session, alice_id)

        holder.uid = bob_id
        bob_preset = c.post(
            "/api/path-analysis/presets",
            json={"name": "Bob's preset"},
        ).json()["id"]

        holder.uid = alice_id
        r = c.post(_URL, json={**_BASE_QUERY, "role_preset_id": bob_preset})
        assert r.status_code in (403, 404)


# ══════════════════════════════════════════════════════════════════════════════
# List
# ══════════════════════════════════════════════════════════════════════════════

class TestListSavedQueries:

    def test_empty_for_new_user(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        assert c.get(_URL).json() == []

    def test_returns_own_queries(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        c.post(_URL, json={**_BASE_QUERY, "name": "Q1"})
        c.post(_URL, json={**_BASE_QUERY, "name": "Q2"})
        names = {q["name"] for q in c.get(_URL).json()}
        assert names == {"Q1", "Q2"}

    def test_excludes_other_users_queries(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        c.post(_URL, json={**_BASE_QUERY, "name": "Alice query"})

        holder.uid = bob_id
        c.post(_URL, json={**_BASE_QUERY, "name": "Bob query"})

        holder.uid = alice_id
        result = c.get(_URL).json()
        assert len(result) == 1
        assert result[0]["name"] == "Alice query"


# ══════════════════════════════════════════════════════════════════════════════
# Get one
# ══════════════════════════════════════════════════════════════════════════════

class TestGetSavedQuery:

    def test_get_own(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        r   = c.get(f"{_URL}/{qid}")
        assert r.status_code == 200
        assert r.json()["id"] == qid

    def test_get_nonexistent_404(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        assert c.get(f"{_URL}/99999").status_code == 404

    def test_get_foreign_403(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]

        holder.uid = bob_id
        assert c.get(f"{_URL}/{qid}").status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# Update
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateSavedQuery:

    def test_update_name(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        r   = c.put(f"{_URL}/{qid}", json={"name": "Renamed"})
        assert r.status_code == 200
        assert r.json()["name"] == "Renamed"

    def test_update_ips(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        r   = c.put(f"{_URL}/{qid}", json={"source_ip": "192.168.1.1",
                                            "destination_ip": "192.168.1.2"})
        d = r.json()
        assert d["source_ip"]      == "192.168.1.1"
        assert d["destination_ip"] == "192.168.1.2"

    def test_clear_port(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        r   = c.put(f"{_URL}/{qid}", json={"clear_port": True})
        assert r.json()["destination_port"] is None

    def test_partial_update_preserves_other_fields(self, db_session, alice_id):
        """Updating only name must leave IPs and roles unchanged."""
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        c.put(f"{_URL}/{qid}", json={"name": "New name"})
        d = c.get(f"{_URL}/{qid}").json()
        assert d["source_ip"]      == _BASE_QUERY["source_ip"]
        assert d["destination_ip"] == _BASE_QUERY["destination_ip"]
        assert d["firewall_ips"]   == _BASE_QUERY["firewall_ips"]

    def test_update_normalises_list(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        r   = c.put(f"{_URL}/{qid}", json={"backend_ips": ["10.0.2.21", "10.0.2.20"]})
        assert r.json()["backend_ips"] == ["10.0.2.20", "10.0.2.21"]

    def test_update_foreign_403(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]

        holder.uid = bob_id
        assert c.put(f"{_URL}/{qid}", json={"name": "Hijacked"}).status_code == 403

    def test_update_nonexistent_404(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        assert c.put(f"{_URL}/99999", json={"name": "x"}).status_code == 404

    def test_link_preset(self, db_session, alice_id):
        """Updating role_preset_id to own preset must succeed."""
        c, _ = _make_client(db_session, alice_id)
        pid = c.post(
            "/api/path-analysis/presets", json={"name": "P"}
        ).json()["id"]
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        r   = c.put(f"{_URL}/{qid}", json={"role_preset_id": pid})
        assert r.json()["role_preset_id"] == pid

    def test_link_foreign_preset_rejected(self, db_session, alice_id, bob_id):
        """Linking a preset owned by another user must be rejected."""
        c, holder = _make_client(db_session, alice_id)

        holder.uid = bob_id
        bob_pid = c.post(
            "/api/path-analysis/presets", json={"name": "Bob preset"}
        ).json()["id"]

        holder.uid = alice_id
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        r   = c.put(f"{_URL}/{qid}", json={"role_preset_id": bob_pid})
        assert r.status_code in (403, 404)

    def test_clear_preset(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        pid = c.post(
            "/api/path-analysis/presets", json={"name": "P"}
        ).json()["id"]
        qid = c.post(_URL, json={**_BASE_QUERY, "role_preset_id": pid}).json()["id"]
        r   = c.put(f"{_URL}/{qid}", json={"clear_preset": True})
        assert r.json()["role_preset_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# Delete
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteSavedQuery:

    def test_delete_own_204(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        assert c.delete(f"{_URL}/{qid}").status_code == 204

    def test_deleted_not_in_list(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]
        c.delete(f"{_URL}/{qid}")
        ids = [q["id"] for q in c.get(_URL).json()]
        assert qid not in ids

    def test_delete_nonexistent_404(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        assert c.delete(f"{_URL}/99999").status_code == 404

    def test_delete_foreign_403(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]

        holder.uid = bob_id
        assert c.delete(f"{_URL}/{qid}").status_code == 403

    def test_original_survives_rejected_delete(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        qid = c.post(_URL, json=_BASE_QUERY).json()["id"]

        holder.uid = bob_id
        c.delete(f"{_URL}/{qid}")  # 403 — must have no effect

        holder.uid = alice_id
        assert c.get(f"{_URL}/{qid}").status_code == 200
