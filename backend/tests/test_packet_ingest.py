"""Tests for the /api/ingest/packet-events and /api/ingest/packet-alerts endpoints."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, LiveEventModel, LiveIncidentModel, NotificationModel, get_db
from main import app


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


@pytest.fixture(autouse=True)
def _override_deps(db_session, monkeypatch):
    app.dependency_overrides[get_db] = lambda: db_session
    monkeypatch.setenv("PACKET_ENGINE_TOKEN", "test-token-123")
    from config import Settings
    s = Settings()
    monkeypatch.setattr("config.settings", s)
    monkeypatch.setattr("main.settings", s)
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    return TestClient(app)


VALID_PAYLOAD = {
    "events": [
        {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 12345,
            "destination_port": 443,
            "protocol": "TCP",
            "first_seen": "2025-01-01T00:00:00",
            "last_seen": "2025-01-01T00:00:10",
            "duration_ms": 10000,
            "packet_count": 42,
            "bytes_in": 5000,
            "bytes_out": 3000,
            "action": "allow",
            "device_type": "packet_engine",
            "parser_id": "gopacket",
            "source_id": "test-host",
        }
    ]
}


def test_ingest_accepts_valid_events(client):
    resp = client.post(
        "/api/ingest/packet-events",
        json=VALID_PAYLOAD,
        headers={"Authorization": "Bearer test-token-123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted"] == 1


def test_ingest_rejects_invalid_token(client):
    resp = client.post(
        "/api/ingest/packet-events",
        json=VALID_PAYLOAD,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_ingest_rejects_missing_token(client):
    resp = client.post(
        "/api/ingest/packet-events",
        json=VALID_PAYLOAD,
    )
    assert resp.status_code == 401


def test_ingest_malformed_body(client):
    resp = client.post(
        "/api/ingest/packet-events",
        json={"not_events": []},
        headers={"Authorization": "Bearer test-token-123"},
    )
    assert resp.status_code == 422


def test_ingest_stores_as_live_event(client, db_session):
    resp = client.post(
        "/api/ingest/packet-events",
        json=VALID_PAYLOAD,
        headers={"Authorization": "Bearer test-token-123"},
    )
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 1

    row = (
        db_session.query(LiveEventModel)
        .filter(LiveEventModel.parser_id == "gopacket")
        .order_by(LiveEventModel.id.desc())
        .first()
    )
    assert row is not None
    assert row.source_ip == "10.0.0.1"
    assert row.destination_ip == "10.0.0.2"
    assert row.device_type == "packet_engine"
    assert row.packets_in == 42


# ── Packet Alerts ────────────────────────────────────────────────────────────

VALID_ALERT = {
    "timestamp": "2025-01-01T00:00:00",
    "src_ip": "10.0.0.5",
    "dst_ip": "10.0.0.1",
    "dst_port": 80,
    "protocol": "TCP",
    "alert_type": "threshold_exceeded",
    "message": "PPS 150.0 exceeds threshold 100.0 for 10.0.0.1:80",
    "value": 150.0,
    "threshold": 100.0,
}


def test_alert_creates_notification(client, db_session):
    # Seed admin user (id=1)
    from database import UserModel
    admin = UserModel(username="admin", hashed_password="x", is_admin=True)
    db_session.add(admin)
    db_session.commit()

    resp = client.post(
        "/api/ingest/packet-alerts",
        json=VALID_ALERT,
        headers={"Authorization": "Bearer test-token-123"},
    )
    assert resp.status_code == 200
    assert resp.json()["accepted"] is True

    notif = (
        db_session.query(NotificationModel)
        .filter(NotificationModel.user_id == admin.id)
        .first()
    )
    assert notif is not None
    assert notif.type == "drift_detected"
    assert "[STREAM ALERT] threshold_exceeded" in notif.message


def test_alert_updates_matching_incident(client, db_session):
    from database import UserModel
    from datetime import datetime

    admin = UserModel(username="admin", hashed_password="x", is_admin=True)
    db_session.add(admin)
    db_session.commit()

    # Create an open incident for the alert source IP
    incident = LiveIncidentModel(
        source_ip="10.0.0.5",
        behavior_type="scan",
        severity="medium",
        status="open",
        first_seen=datetime(2025, 1, 1),
        last_seen=datetime(2025, 1, 1),
    )
    db_session.add(incident)
    db_session.commit()
    incident_id = incident.id

    resp = client.post(
        "/api/ingest/packet-alerts",
        json=VALID_ALERT,
        headers={"Authorization": "Bearer test-token-123"},
    )
    assert resp.status_code == 200

    db_session.refresh(incident)
    assert incident.last_activity_summary is not None
    assert "threshold_exceeded" in incident.last_activity_summary


def test_alert_rejects_invalid_token(client):
    resp = client.post(
        "/api/ingest/packet-alerts",
        json=VALID_ALERT,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401
