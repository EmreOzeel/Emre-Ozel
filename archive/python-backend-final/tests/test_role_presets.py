"""
CRUD and ownership-isolation tests for path-analysis role presets.

Endpoints under test:
  POST   /api/path-analysis/presets
  GET    /api/path-analysis/presets
  GET    /api/path-analysis/presets/{id}
  PUT    /api/path-analysis/presets/{id}
  DELETE /api/path-analysis/presets/{id}
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


def _seed_user(db_session, username: str) -> int:
    """Insert a user and return its integer id."""
    u = UserModel(username=username, hashed_password="x")
    db_session.add(u)
    db_session.flush()
    uid: int = u.id
    db_session.commit()
    return uid


class _UserHolder:
    """Mutable box so multi-user tests can switch callers without recreating the client."""
    def __init__(self, uid: int):
        self.uid = uid


def _make_client(db_session, user_id: int) -> tuple[TestClient, _UserHolder]:
    """
    Return a (TestClient, UserHolder) pair.

    All requests through the client run as holder.uid.  To impersonate a second
    user within the same test, set holder.uid before the next request — this
    avoids overwriting app.dependency_overrides a second time.
    """
    holder = _UserHolder(user_id)

    def _override_db():
        yield db_session

    def _override_user():
        return SimpleNamespace(id=holder.uid, is_admin=False, team_id=None)

    app.dependency_overrides[get_db]           = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True), holder


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


# ── Helpers ───────────────────────────────────────────────────────────────────

_PRESET_BODY = {
    "name": "Prod cluster",
    "firewall_ips":       ["10.0.0.254", "10.0.0.253"],
    "load_balancer_vips": ["10.0.1.10"],
    "backend_ips":        ["10.0.2.20", "10.0.2.21"],
    "backend_subnets":    ["10.0.2.0/24"],
}


# ══════════════════════════════════════════════════════════════════════════════
# Create
# ══════════════════════════════════════════════════════════════════════════════

class TestCreatePreset:

    def test_create_returns_201(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.post("/api/path-analysis/presets", json=_PRESET_BODY)
        assert r.status_code == 201

    def test_response_contains_id_and_name(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.post("/api/path-analysis/presets", json=_PRESET_BODY)
        d = r.json()
        assert "id" in d
        assert d["name"] == "Prod cluster"

    def test_list_values_are_sorted(self, db_session, alice_id):
        """Firewall IPs supplied in reverse order must be stored/returned sorted."""
        c, _ = _make_client(db_session, alice_id)
        r = c.post("/api/path-analysis/presets", json={
            "name": "sort-test",
            "firewall_ips": ["10.0.0.2", "10.0.0.1"],
        })
        assert r.json()["firewall_ips"] == ["10.0.0.1", "10.0.0.2"]

    def test_empty_name_rejected(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.post("/api/path-analysis/presets", json={"name": ""})
        assert r.status_code == 422

    def test_missing_name_rejected(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.post("/api/path-analysis/presets", json={"firewall_ips": ["1.2.3.4"]})
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# List
# ══════════════════════════════════════════════════════════════════════════════

class TestListPresets:

    def test_empty_list_for_new_user(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.get("/api/path-analysis/presets")
        assert r.status_code == 200
        assert r.json() == []

    def test_returns_own_presets(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        c.post("/api/path-analysis/presets", json={**_PRESET_BODY, "name": "A"})
        c.post("/api/path-analysis/presets", json={**_PRESET_BODY, "name": "B"})
        r = c.get("/api/path-analysis/presets")
        names = {p["name"] for p in r.json()}
        assert names == {"A", "B"}

    def test_does_not_return_other_users_presets(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        c.post("/api/path-analysis/presets", json={**_PRESET_BODY, "name": "Alice preset"})

        holder.uid = bob_id
        c.post("/api/path-analysis/presets", json={**_PRESET_BODY, "name": "Bob preset"})

        holder.uid = alice_id
        alice_list = c.get("/api/path-analysis/presets").json()
        assert all(p["name"] == "Alice preset" for p in alice_list)
        assert len(alice_list) == 1


# ══════════════════════════════════════════════════════════════════════════════
# Get one
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPreset:

    def test_get_own_preset(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]
        r   = c.get(f"/api/path-analysis/presets/{pid}")
        assert r.status_code == 200
        assert r.json()["id"] == pid

    def test_get_nonexistent_returns_404(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.get("/api/path-analysis/presets/99999")
        assert r.status_code == 404

    def test_get_other_users_preset_returns_403(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]

        holder.uid = bob_id
        r = c.get(f"/api/path-analysis/presets/{pid}")
        assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# Update
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdatePreset:

    def test_update_name(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]
        r   = c.put(f"/api/path-analysis/presets/{pid}", json={"name": "Renamed"})
        assert r.status_code == 200
        assert r.json()["name"] == "Renamed"

    def test_update_firewall_ips(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]
        r   = c.put(f"/api/path-analysis/presets/{pid}",
                    json={"firewall_ips": ["10.9.9.9"]})
        assert r.json()["firewall_ips"] == ["10.9.9.9"]

    def test_partial_update_preserves_other_fields(self, db_session, alice_id):
        """Updating only firewall_ips must leave backend_ips unchanged."""
        c, _ = _make_client(db_session, alice_id)
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]
        c.put(f"/api/path-analysis/presets/{pid}", json={"firewall_ips": ["1.2.3.4"]})
        updated = c.get(f"/api/path-analysis/presets/{pid}").json()
        assert updated["backend_ips"] == sorted(_PRESET_BODY["backend_ips"])

    def test_update_normalises_list_order(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]
        r   = c.put(f"/api/path-analysis/presets/{pid}",
                    json={"backend_ips": ["10.0.2.21", "10.0.2.20"]})
        assert r.json()["backend_ips"] == ["10.0.2.20", "10.0.2.21"]

    def test_update_other_users_preset_returns_403(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]

        holder.uid = bob_id
        r = c.put(f"/api/path-analysis/presets/{pid}", json={"name": "Hijacked"})
        assert r.status_code == 403

    def test_update_nonexistent_returns_404(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.put("/api/path-analysis/presets/99999", json={"name": "x"})
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Delete
# ══════════════════════════════════════════════════════════════════════════════

class TestDeletePreset:

    def test_delete_own_preset_returns_204(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]
        r   = c.delete(f"/api/path-analysis/presets/{pid}")
        assert r.status_code == 204

    def test_deleted_preset_no_longer_listed(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]
        c.delete(f"/api/path-analysis/presets/{pid}")
        ids = [p["id"] for p in c.get("/api/path-analysis/presets").json()]
        assert pid not in ids

    def test_delete_other_users_preset_returns_403(self, db_session, alice_id, bob_id):
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]

        holder.uid = bob_id
        r = c.delete(f"/api/path-analysis/presets/{pid}")
        assert r.status_code == 403

    def test_delete_nonexistent_returns_404(self, db_session, alice_id):
        c, _ = _make_client(db_session, alice_id)
        r = c.delete("/api/path-analysis/presets/99999")
        assert r.status_code == 404

    def test_original_owner_preset_survives_other_delete_attempt(
        self, db_session, alice_id, bob_id
    ):
        """After Bob's rejected attempt, Alice's preset must still exist."""
        c, holder = _make_client(db_session, alice_id)

        holder.uid = alice_id
        pid = c.post("/api/path-analysis/presets", json=_PRESET_BODY).json()["id"]

        holder.uid = bob_id
        c.delete(f"/api/path-analysis/presets/{pid}")   # 403, no effect

        holder.uid = alice_id
        r = c.get(f"/api/path-analysis/presets/{pid}")
        assert r.status_code == 200
