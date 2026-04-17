"""
Tests for the targeted PCAP capture trigger.

Covers:
  1. trigger() creates subprocess with correct BPF filter
  2. trigger() with dst_port includes port in BPF filter
  3. Duplicate trigger for same key → returns None
  4. max_concurrent limit respected → returns None
  5. _on_capture_complete with empty file → no analysis created
  6. _on_capture_complete with valid file → AnalysisModel created
  7. stats() returns correct shape
  8. trigger() without interface configured → safe no-op
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import AnalysisModel, Base, LiveIncidentModel, UserModel
from collector.pcap_trigger import PcapTrigger, _link_to_incident

from auth import get_current_user
from main import app, get_db


@pytest.fixture
def capture_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def db_session():
    eng = sa_create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    db = Session()
    db.add(UserModel(id=1, username="admin", hashed_password="x", is_admin=True))
    db.commit()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(eng)


def _blocking_wait():
    """A wait() that blocks long enough to keep _active populated."""
    time.sleep(5)


# ── Test 1: correct BPF filter ─────────────────────────────────────────────

def test_trigger_correct_bpf(capture_dir):
    trigger = PcapTrigger(capture_dir=capture_dir, interface="eth0", duration_seconds=10)

    with patch("collector.pcap_trigger.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.wait = _blocking_wait
        mock_popen.return_value = mock_proc

        result = trigger.trigger("10.0.0.1", "192.168.1.1")
        assert result is not None
        assert result.endswith(".pcap")

        cmd = mock_popen.call_args[0][0]
        bpf = cmd[-1]
        assert "host 10.0.0.1" in bpf
        assert "host 192.168.1.1" in bpf
        assert "port" not in bpf


# ── Test 2: dst_port in BPF ────────────────────────────────────────────────

def test_trigger_with_port(capture_dir):
    trigger = PcapTrigger(capture_dir=capture_dir, interface="eth0")

    with patch("collector.pcap_trigger.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.wait = _blocking_wait
        mock_popen.return_value = mock_proc

        result = trigger.trigger("10.0.0.1", "192.168.1.1", dst_port=443)
        assert result is not None

        cmd = mock_popen.call_args[0][0]
        bpf = cmd[-1]
        assert "port 443" in bpf


# ── Test 3: duplicate returns None ──────────────────────────────────────────

def test_duplicate_trigger_returns_none(capture_dir):
    trigger = PcapTrigger(capture_dir=capture_dir, interface="eth0")

    with patch("collector.pcap_trigger.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.wait = _blocking_wait
        mock_popen.return_value = mock_proc

        r1 = trigger.trigger("10.0.0.1", "192.168.1.1")
        assert r1 is not None

        # Give monitor thread a moment to start (but wait blocks for 5s)
        time.sleep(0.1)

        r2 = trigger.trigger("10.0.0.1", "192.168.1.1")
        assert r2 is None


# ── Test 4: max_concurrent limit ────────────────────────────────────────────

def test_max_concurrent_limit(capture_dir):
    trigger = PcapTrigger(capture_dir=capture_dir, interface="eth0", max_concurrent=2)

    with patch("collector.pcap_trigger.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.wait = _blocking_wait
        mock_popen.return_value = mock_proc

        r1 = trigger.trigger("10.0.0.1", "192.168.1.1")
        r2 = trigger.trigger("10.0.0.2", "192.168.1.2")
        assert r1 is not None
        assert r2 is not None

        time.sleep(0.1)

        r3 = trigger.trigger("10.0.0.3", "192.168.1.3")
        assert r3 is None


# ── Test 5: empty file → no analysis ───────────────────────────────────────

def test_empty_capture_no_analysis(capture_dir):
    trigger = PcapTrigger(capture_dir=capture_dir, interface="eth0")

    filepath = os.path.join(capture_dir, "test_empty.pcap")
    with open(filepath, "w") as f:
        pass

    trigger._on_capture_complete(filepath, "10.0.0.1", "192.168.1.1", "test")
    assert not os.path.exists(filepath)


# ── Test 6: valid file → AnalysisModel created ─────────────────────────────

def test_valid_capture_creates_analysis(capture_dir, db_session):
    trigger = PcapTrigger(capture_dir=capture_dir, interface="eth0")

    filepath = os.path.join(capture_dir, "test_valid.pcap")
    with open(filepath, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

    with patch("database.SessionLocal", return_value=db_session):
        with patch("jobs.queue.enqueue") as mock_enqueue:
            trigger._on_capture_complete(filepath, "10.0.0.1", "192.168.1.1", "test")

    analyses = db_session.query(AnalysisModel).all()
    assert len(analyses) == 1
    assert analyses[0].filename == "test_valid.pcap"
    assert analyses[0].status == "pending"
    assert analyses[0].user_id == 1


# ── Test 7: stats shape ────────────────────────────────────────────────────

def test_stats_shape(capture_dir):
    trigger = PcapTrigger(
        capture_dir=capture_dir, interface="eth0",
        duration_seconds=30, max_concurrent=5,
    )

    s = trigger.stats()
    assert s["active_captures"] == 0
    assert s["max_concurrent"] == 5
    assert s["interface"] == "eth0"
    assert s["duration_seconds"] == 30


# ── Test 8: no interface → safe no-op ───────────────────────────────────────

def test_trigger_no_interface(capture_dir):
    trigger = PcapTrigger(capture_dir=capture_dir, interface="")
    result = trigger.trigger("10.0.0.1", "192.168.1.1")
    assert result is None


# ── Test 9: _link_to_incident links analysis to open incident ───────────────

def test_link_to_open_incident(db_session):
    """_link_to_incident should append analysis_id to open incident."""
    from datetime import datetime
    now = datetime.utcnow()

    incident = LiveIncidentModel(
        source_ip="10.0.0.1",
        behavior_type="scanning",
        severity="high",
        status="open",
        first_seen=now,
        last_seen=now,
        event_count=1,
        linked_flow_count=0,
        linked_pcap_analysis_ids="[]",
        pcap_trigger_count=0,
    )
    db_session.add(incident)
    db_session.commit()

    _link_to_incident(db_session, "analysis-123", "10.0.0.1")

    db_session.refresh(incident)
    import json
    ids = json.loads(incident.linked_pcap_analysis_ids)
    assert "analysis-123" in ids
    assert incident.pcap_trigger_count == 1
    assert "PCAP captured" in (incident.last_activity_summary or "")


# ── Test 10: _link_to_incident does NOT link to resolved incident ────────────

def test_no_link_to_resolved_incident(db_session):
    """_link_to_incident should skip resolved incidents."""
    from datetime import datetime
    now = datetime.utcnow()

    incident = LiveIncidentModel(
        source_ip="10.0.0.1",
        behavior_type="scanning",
        severity="high",
        status="resolved",
        first_seen=now,
        last_seen=now,
        event_count=1,
        linked_flow_count=0,
        linked_pcap_analysis_ids="[]",
        pcap_trigger_count=0,
    )
    db_session.add(incident)
    db_session.commit()

    _link_to_incident(db_session, "analysis-456", "10.0.0.1")

    db_session.refresh(incident)
    import json
    ids = json.loads(incident.linked_pcap_analysis_ids)
    assert ids == []
    assert incident.pcap_trigger_count == 0


# ── Test 11: pcap_trigger_count increments correctly ─────────────────────────

def test_pcap_trigger_count_increments(db_session):
    """Multiple links should increment pcap_trigger_count."""
    from datetime import datetime
    now = datetime.utcnow()

    incident = LiveIncidentModel(
        source_ip="10.0.0.1",
        behavior_type="scanning",
        severity="high",
        status="open",
        first_seen=now,
        last_seen=now,
        event_count=1,
        linked_flow_count=0,
        linked_pcap_analysis_ids="[]",
        pcap_trigger_count=0,
    )
    db_session.add(incident)
    db_session.commit()

    _link_to_incident(db_session, "a-1", "10.0.0.1")
    _link_to_incident(db_session, "a-2", "10.0.0.1")
    _link_to_incident(db_session, "a-3", "10.0.0.1")

    db_session.refresh(incident)
    assert incident.pcap_trigger_count == 3
    import json
    ids = json.loads(incident.linked_pcap_analysis_ids)
    assert len(ids) == 3


# ── Test 12: linked_pcap_analysis_ids appends without duplicates ─────────────

def test_linked_ids_no_duplicates(db_session):
    """Same analysis_id should not be appended twice."""
    from datetime import datetime
    now = datetime.utcnow()

    incident = LiveIncidentModel(
        source_ip="10.0.0.1",
        behavior_type="scanning",
        severity="high",
        status="open",
        first_seen=now,
        last_seen=now,
        event_count=1,
        linked_flow_count=0,
        linked_pcap_analysis_ids="[]",
        pcap_trigger_count=0,
    )
    db_session.add(incident)
    db_session.commit()

    _link_to_incident(db_session, "same-id", "10.0.0.1")
    _link_to_incident(db_session, "same-id", "10.0.0.1")

    db_session.refresh(incident)
    import json
    ids = json.loads(incident.linked_pcap_analysis_ids)
    assert ids.count("same-id") == 1
    # count still increments each call
    assert incident.pcap_trigger_count == 2


# ── Test 13: API GET /api/live-incidents/{id}/pcaps returns correct shape ────

def _make_api_client(db_session, uid):
    def _override_db():
        yield db_session
    def _override_user():
        return UserModel(id=uid, username="admin", hashed_password="x", is_admin=True)
    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    from fastapi.testclient import TestClient
    return TestClient(app)


def test_api_incident_pcaps(db_session):
    from datetime import datetime
    import json as _json
    now = datetime.utcnow()

    uid = 1  # already seeded in db_session fixture

    # Create analysis
    a = AnalysisModel(
        id="test-pcap-analysis",
        user_id=uid,
        filename="triggered_capture.pcap",
        status="completed",
        packet_count=42,
        issue_count=3,
    )
    db_session.add(a)

    # Create incident linked to analysis
    incident = LiveIncidentModel(
        source_ip="10.0.0.1",
        behavior_type="scanning",
        severity="high",
        status="open",
        first_seen=now,
        last_seen=now,
        event_count=1,
        linked_flow_count=0,
        linked_pcap_analysis_ids=_json.dumps(["test-pcap-analysis"]),
        pcap_trigger_count=1,
    )
    db_session.add(incident)
    db_session.commit()

    client = _make_api_client(db_session, uid)
    resp = client.get(f"/api/live-incidents/{incident.id}/pcaps")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["analysis_id"] == "test-pcap-analysis"
    assert data[0]["filename"] == "triggered_capture.pcap"
    assert data[0]["status"] == "completed"
    assert data[0]["packet_count"] == 42
    assert data[0]["issue_count"] == 3

    app.dependency_overrides.clear()


# ── Test 14: API GET /api/live-incidents/{id}/pcaps returns empty ────────────

def test_api_incident_pcaps_empty(db_session):
    from datetime import datetime
    now = datetime.utcnow()

    uid = 1

    incident = LiveIncidentModel(
        source_ip="10.0.0.2",
        behavior_type="unstable",
        severity="low",
        status="open",
        first_seen=now,
        last_seen=now,
        event_count=1,
        linked_flow_count=0,
        linked_pcap_analysis_ids="[]",
        pcap_trigger_count=0,
    )
    db_session.add(incident)
    db_session.commit()

    client = _make_api_client(db_session, uid)
    resp = client.get(f"/api/live-incidents/{incident.id}/pcaps")
    assert resp.status_code == 200
    assert resp.json() == []

    app.dependency_overrides.clear()
