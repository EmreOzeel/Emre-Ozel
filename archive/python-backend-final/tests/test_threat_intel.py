"""
Tests for the threat intelligence layer.

Covers:
  1.  fetch_feed parses plain IP list correctly
  2.  fetch_feed skips comment lines
  3.  fetch_feed upserts existing indicator (updates last_seen)
  4.  fetch_feed validates IP format (rejects invalid)
  5.  lookup_ip finds exact match
  6.  lookup_ip returns empty for unknown IP
  7.  lookup_ip skips expired indicators
  8.  is_threat_ip returns True for known IP
  9.  CIDR match works (10.0.0.5 matches 10.0.0.0/24)
  10. bridge notification gets [TI MATCH] prefix
  11. incident severity boosted to critical on TI match
  12. refresh_all_feeds skips feeds not yet due
  13. API lookup endpoint returns correct shape
  14. API list feeds returns all 4 built-in feeds
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import get_current_user
from database import (
    Base,
    LiveFlowModel,
    LiveIncidentModel,
    NotificationModel,
    ThreatFeedModel,
    ThreatIndicatorModel,
    UserModel,
)
from main import app, get_db
from collector.threat_feeds import (
    clear_cache,
    fetch_feed,
    is_threat_ip,
    lookup_ip,
    refresh_all_feeds,
    seed_default_feeds,
    DEFAULT_FEEDS,
)


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


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_cache()
    yield
    clear_cache()
    app.dependency_overrides.clear()


def _seed_user(db, username="admin", is_admin=True):
    u = UserModel(username=username, hashed_password="x", is_admin=is_admin)
    db.add(u)
    db.flush()
    uid = u.id
    db.commit()
    return uid


def _make_client(db_session, uid, is_admin=True):
    def _override_db():
        yield db_session
    def _override_user():
        return UserModel(id=uid, username="test", hashed_password="x", is_admin=is_admin)
    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app)


def _make_feed(db, **kwargs):
    defaults = {
        "name": "test_feed",
        "feed_type": "ip_list",
        "url": "http://example.com/ips.txt",
        "enabled": True,
        "format": "plain",
        "comment_char": "#",
        "ip_column": 0,
        "default_threat_type": "malware",
        "default_confidence": 0.8,
        "fetch_interval_hours": 24,
    }
    defaults.update(kwargs)
    f = ThreatFeedModel(**defaults)
    db.add(f)
    db.flush()
    return f


def _make_indicator(db, **kwargs):
    now = datetime.utcnow()
    defaults = {
        "indicator_type": "ip",
        "indicator_value": "1.2.3.4",
        "threat_type": "malware",
        "confidence": 0.8,
        "source_feed": "test_feed",
        "first_seen": now,
        "last_seen": now,
    }
    defaults.update(kwargs)
    ind = ThreatIndicatorModel(**defaults)
    db.add(ind)
    db.flush()
    return ind


def _fake_http_get(text):
    """Return a callable that returns fixed text."""
    def _get(url):
        return text
    return _get


# ── Test 1: fetch_feed parses plain IP list correctly ────────────────────────

def test_fetch_feed_plain_ip_list(db_session):
    feed = _make_feed(db_session)
    db_session.commit()

    text = "10.0.0.1\n10.0.0.2\n10.0.0.3\n"
    n = fetch_feed(db_session, feed, _http_get=_fake_http_get(text))

    assert n == 3
    indicators = db_session.query(ThreatIndicatorModel).all()
    assert len(indicators) == 3
    ips = {ind.indicator_value for ind in indicators}
    assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


# ── Test 2: fetch_feed skips comment lines ───────────────────────────────────

def test_fetch_feed_skips_comments(db_session):
    feed = _make_feed(db_session)
    db_session.commit()

    text = "# This is a comment\n10.0.0.1\n# Another comment\n10.0.0.2\n\n"
    n = fetch_feed(db_session, feed, _http_get=_fake_http_get(text))

    assert n == 2
    indicators = db_session.query(ThreatIndicatorModel).all()
    assert len(indicators) == 2


# ── Test 3: fetch_feed upserts existing indicator ────────────────────────────

def test_fetch_feed_upserts_existing(db_session):
    now = datetime.utcnow()
    feed = _make_feed(db_session)
    # Pre-create an indicator
    old_time = now - timedelta(days=7)
    _make_indicator(
        db_session,
        indicator_value="10.0.0.1",
        source_feed="test_feed",
        first_seen=old_time,
        last_seen=old_time,
    )
    db_session.commit()

    text = "10.0.0.1\n10.0.0.2\n"
    n = fetch_feed(db_session, feed, now=now, _http_get=_fake_http_get(text))

    assert n == 2
    # Should still be 2 total (1 updated + 1 new)
    indicators = db_session.query(ThreatIndicatorModel).all()
    assert len(indicators) == 2

    # Check the existing one was updated
    existing = db_session.query(ThreatIndicatorModel).filter(
        ThreatIndicatorModel.indicator_value == "10.0.0.1"
    ).first()
    assert existing.last_seen >= now - timedelta(seconds=2)
    assert existing.first_seen == old_time  # first_seen unchanged


# ── Test 4: fetch_feed validates IP format ───────────────────────────────────

def test_fetch_feed_rejects_invalid_ips(db_session):
    feed = _make_feed(db_session)
    db_session.commit()

    text = "10.0.0.1\nnot_an_ip\n999.999.999.999\n192.168.1.1\n"
    n = fetch_feed(db_session, feed, _http_get=_fake_http_get(text))

    # Only 2 valid IPs
    assert n == 2
    indicators = db_session.query(ThreatIndicatorModel).all()
    assert len(indicators) == 2
    ips = {ind.indicator_value for ind in indicators}
    assert ips == {"10.0.0.1", "192.168.1.1"}


# ── Test 5: lookup_ip finds exact match ──────────────────────────────────────

def test_lookup_ip_exact_match(db_session):
    _make_indicator(db_session, indicator_value="5.6.7.8", threat_type="c2")
    db_session.commit()

    results = lookup_ip(db_session, "5.6.7.8")
    assert len(results) == 1
    assert results[0]["indicator_value"] == "5.6.7.8"
    assert results[0]["threat_type"] == "c2"


# ── Test 6: lookup_ip returns empty for unknown ──────────────────────────────

def test_lookup_ip_unknown(db_session):
    _make_indicator(db_session, indicator_value="5.6.7.8")
    db_session.commit()

    results = lookup_ip(db_session, "1.1.1.1")
    assert results == []


# ── Test 7: lookup_ip skips expired indicators ───────────────────────────────

def test_lookup_ip_skips_expired(db_session):
    now = datetime.utcnow()
    _make_indicator(
        db_session,
        indicator_value="5.6.7.8",
        expiry=now - timedelta(hours=1),  # expired 1 hour ago
    )
    db_session.commit()

    results = lookup_ip(db_session, "5.6.7.8", now=now)
    assert results == []


# ── Test 8: is_threat_ip returns True for known IP ───────────────────────────

def test_is_threat_ip_true(db_session):
    _make_indicator(db_session, indicator_value="9.8.7.6")
    db_session.commit()

    assert is_threat_ip(db_session, "9.8.7.6") is True
    assert is_threat_ip(db_session, "1.1.1.1") is False


# ── Test 9: CIDR match works ────────────────────────────────────────────────

def test_cidr_match(db_session):
    _make_indicator(
        db_session,
        indicator_type="cidr",
        indicator_value="10.0.0.0/24",
    )
    db_session.commit()

    # IP within the CIDR
    results = lookup_ip(db_session, "10.0.0.5")
    assert len(results) == 1
    assert results[0]["indicator_value"] == "10.0.0.0/24"

    # Clear cache before next lookup
    clear_cache()

    # IP outside the CIDR
    results = lookup_ip(db_session, "10.0.1.5")
    assert results == []


# ── Test 10: bridge notification gets [TI MATCH] prefix ─────────────────────

def test_bridge_notification_ti_prefix(db_session):
    from collector.bridge import _scan_blocked_flow_spike, _emit, WINDOW_MINUTES

    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)

    # Seed a threat indicator for the source IP
    _make_indicator(db_session, indicator_value="10.99.99.99", threat_type="c2")

    # Create blocked flows from that IP
    for i in range(8):
        f = LiveFlowModel(
            source_id="test", device_type="fw", parser_id="test",
            source_ip="10.99.99.99",
            destination_ip=f"192.168.1.{i}",
            source_port=12345, destination_port=443,
            protocol="TCP",
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
            state="denied",
            event_count=1,
            total_bytes_in=0, total_bytes_out=0,
            total_packets_in=0, total_packets_out=0,
            allow_count=0, deny_count=1, drop_count=0,
            reset_count=0, alert_count=0,
            raw_event_count=1,
            flow_type="blocked",
            suppressed=False,
        )
        db_session.add(f)
    db_session.commit()

    n = _scan_blocked_flow_spike(db_session, cutoff, set())

    assert n == 1
    notif = db_session.query(NotificationModel).first()
    assert notif is not None
    assert notif.message.startswith("[TI MATCH] ")


# ── Test 11: incident severity boosted to critical on TI match ───────────────

def test_incident_severity_boost_on_ti_match(db_session):
    from collector.incidents import upsert_incidents_from_behaviors

    now = datetime.utcnow()

    # Seed a threat indicator
    _make_indicator(db_session, indicator_value="10.50.50.50", threat_type="malware")
    db_session.commit()

    behaviors = [
        {
            "source_ip": "10.50.50.50",
            "behavior_type": "scanning",
            "confidence": 0.7,
            "flow_count": 5,
            "distinct_destinations": 3,
            "distinct_ports": 10,
            "drivers": ["wide_port_spread"],
        }
    ]

    result = upsert_incidents_from_behaviors(db_session, behaviors, now=now)
    assert result["created"] == 1

    incident = db_session.query(LiveIncidentModel).first()
    assert incident is not None
    assert incident.severity == "critical"
    assert "threat_intel_match" in incident.summary


# ── Test 12: refresh_all_feeds skips feeds not yet due ───────────────────────

def test_refresh_all_skips_not_due(db_session):
    now = datetime.utcnow()
    feed = _make_feed(
        db_session,
        last_fetched_at=now - timedelta(hours=1),  # fetched 1h ago
        fetch_interval_hours=24,
    )
    db_session.commit()

    result = refresh_all_feeds(
        db_session,
        now=now,
        _http_get=_fake_http_get("1.2.3.4\n"),
    )

    # Feed was fetched 1h ago, interval is 24h, so it should be skipped
    assert result == {}
    assert db_session.query(ThreatIndicatorModel).count() == 0


# ── Test 13: API lookup endpoint returns correct shape ───────────────────────

def test_api_lookup_endpoint(db_session):
    uid = _seed_user(db_session)
    _make_indicator(db_session, indicator_value="44.55.66.77", threat_type="scanner")
    db_session.commit()

    client = _make_client(db_session, uid)
    resp = client.get("/api/threat-indicators/lookup", params={"ip": "44.55.66.77"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "44.55.66.77"
    assert data["is_threat"] is True
    assert len(data["matches"]) == 1
    assert data["matches"][0]["threat_type"] == "scanner"


# ── Test 14: API list feeds returns all 4 built-in feeds ────────────────────

def test_api_list_feeds_builtin(db_session):
    uid = _seed_user(db_session)
    seed_default_feeds(db_session)

    client = _make_client(db_session, uid)
    resp = client.get("/api/threat-feeds")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 4
    names = {f["name"] for f in data}
    assert names == {
        "emerging_threats_compromised",
        "feodo_tracker_c2",
        "cins_army_scanners",
        "tor_exit_nodes",
    }
