"""
Tests for the GeoIP enrichment layer.

Covers:
  1.  Private IP detection (10.x.x.x → is_private=True, no lookup)
  2.  Bogon IP detection
  3.  Cache hit returns cached result
  4.  Cache miss triggers lookup (mock ip-api response)
  5.  batch_lookup uses single DB query for cache
  6.  batch_lookup only calls API for misses
  7.  ip-api rate limiter prevents > 45 req/min
  8.  lookup stores result in GeoIPCacheModel
  9.  API /api/geo/lookup returns correct shape
  10. API batch-lookup validates max 50 IPs
  11. Incident summary includes country code
  12. Expired cache (> 7 days) triggers re-lookup
"""
from __future__ import annotations

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
    GeoIPCacheModel,
    LiveFlowModel,
    LiveIncidentModel,
    UserModel,
)
from main import app, get_db
from collector.geoip import (
    lookup_ip_geo,
    batch_lookup,
    _reset_rate_limiter,
    _rate_limit_ok,
    CACHE_TTL_DAYS,
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
def _cleanup():
    _reset_rate_limiter()
    yield
    _reset_rate_limiter()
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


def _fake_ipapi(data):
    """Return a callable that returns a fake ip-api response."""
    def _get(url):
        return data
    return _get


MOCK_IPAPI_RESPONSE = {
    "status": "success",
    "country": "Turkey",
    "countryCode": "TR",
    "city": "Istanbul",
    "lat": 41.0082,
    "lon": 28.9784,
    "as": "AS9121 Turk Telekom",
    "org": "Turk Telekom",
}


# ── Test 1: Private IP detection ────────────────────────────────────────────

def test_private_ip_detection(db_session):
    """Private IPs should return is_private=True without any lookup."""
    for ip in ["10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1"]:
        result = lookup_ip_geo(ip, db_session)
        assert result["is_private"] is True
        assert result["source"] == "private"
        assert result["country_code"] is None

    # No cache entries should be created for private IPs
    assert db_session.query(GeoIPCacheModel).count() == 0


# ── Test 2: Bogon IP detection ──────────────────────────────────────────────

def test_bogon_ip_detection(db_session):
    """Bogon IPs should return is_bogon=True without any lookup."""
    for ip in ["0.0.0.1", "100.64.0.1", "198.51.100.5", "240.0.0.1"]:
        result = lookup_ip_geo(ip, db_session)
        assert result["is_bogon"] is True
        assert result["source"] == "private"

    assert db_session.query(GeoIPCacheModel).count() == 0


# ── Test 3: Cache hit returns cached result ──────────────────────────────────

def test_cache_hit(db_session):
    """A cached result should be returned without external lookup."""
    now = datetime.utcnow()
    db_session.add(GeoIPCacheModel(
        ip="8.8.8.8",
        country_code="US",
        country_name="United States",
        city="Mountain View",
        latitude=37.386,
        longitude=-122.084,
        asn=15169,
        asn_org="Google LLC",
        is_private=False,
        is_bogon=False,
        source="ip-api",
        looked_up_at=now,
    ))
    db_session.commit()

    # Should NOT call external API
    api_called = []
    def _spy(url):
        api_called.append(url)
        return MOCK_IPAPI_RESPONSE

    result = lookup_ip_geo("8.8.8.8", db_session, now=now, _http_get=_spy)
    assert result["country_code"] == "US"
    assert result["asn_org"] == "Google LLC"
    assert len(api_called) == 0  # no external call


# ── Test 4: Cache miss triggers lookup ───────────────────────────────────────

def test_cache_miss_triggers_lookup(db_session):
    """A cache miss should trigger an ip-api lookup."""
    now = datetime.utcnow()

    result = lookup_ip_geo(
        "5.5.5.5", db_session,
        now=now,
        _http_get=_fake_ipapi(MOCK_IPAPI_RESPONSE),
    )

    assert result["country_code"] == "TR"
    assert result["country_name"] == "Turkey"
    assert result["city"] == "Istanbul"
    assert result["asn"] == 9121
    assert result["asn_org"] == "Turk Telekom"
    assert result["source"] == "ip-api"


# ── Test 5: batch_lookup uses single DB query for cache ──────────────────────

def test_batch_lookup_cache_query(db_session):
    """batch_lookup should load all cached results in one query."""
    now = datetime.utcnow()

    # Pre-cache 3 IPs
    for i in range(3):
        db_session.add(GeoIPCacheModel(
            ip=f"1.1.1.{i}",
            country_code="US",
            is_private=False,
            is_bogon=False,
            source="ip-api",
            looked_up_at=now,
        ))
    db_session.commit()

    api_calls = []
    def _spy(url):
        api_calls.append(url)
        return MOCK_IPAPI_RESPONSE

    results = batch_lookup(
        ["1.1.1.0", "1.1.1.1", "1.1.1.2"],
        db_session,
        now=now,
        _http_get=_spy,
    )

    assert len(results) == 3
    assert all(r["country_code"] == "US" for r in results.values())
    assert len(api_calls) == 0  # all from cache


# ── Test 6: batch_lookup only calls API for misses ───────────────────────────

def test_batch_lookup_api_for_misses(db_session):
    """batch_lookup should only call API for IPs not in cache."""
    now = datetime.utcnow()

    # Cache one IP
    db_session.add(GeoIPCacheModel(
        ip="1.1.1.1",
        country_code="AU",
        is_private=False,
        is_bogon=False,
        source="ip-api",
        looked_up_at=now,
    ))
    db_session.commit()

    api_calls = []
    def _spy(url):
        api_calls.append(url)
        return MOCK_IPAPI_RESPONSE

    results = batch_lookup(
        ["1.1.1.1", "2.2.2.2", "10.0.0.1"],  # cached, miss, private
        db_session,
        now=now,
        _http_get=_spy,
    )

    assert len(results) == 3
    assert results["1.1.1.1"]["country_code"] == "AU"  # from cache
    assert results["2.2.2.2"]["country_code"] == "TR"   # from API
    assert results["10.0.0.1"]["is_private"] is True     # private
    assert len(api_calls) == 1  # only for 2.2.2.2


# ── Test 7: ip-api rate limiter ──────────────────────────────────────────────

def test_ipapi_rate_limiter(db_session):
    """Rate limiter should prevent more than 45 requests per minute."""
    _reset_rate_limiter()

    # Exhaust the limit
    for _ in range(45):
        assert _rate_limit_ok() is True

    # 46th should be blocked
    assert _rate_limit_ok() is False


# ── Test 8: lookup stores result in cache ────────────────────────────────────

def test_lookup_stores_in_cache(db_session):
    """lookup_ip_geo should store the result in GeoIPCacheModel."""
    now = datetime.utcnow()

    lookup_ip_geo(
        "3.3.3.3", db_session,
        now=now,
        _http_get=_fake_ipapi(MOCK_IPAPI_RESPONSE),
    )

    cached = db_session.query(GeoIPCacheModel).filter(
        GeoIPCacheModel.ip == "3.3.3.3"
    ).first()
    assert cached is not None
    assert cached.country_code == "TR"
    assert cached.asn == 9121
    assert cached.source == "ip-api"


# ── Test 9: API /api/geo/lookup returns correct shape ────────────────────────

def test_api_geo_lookup(db_session):
    uid = _seed_user(db_session)
    client = _make_client(db_session, uid)

    # Private IP — should work without external call
    resp = client.get("/api/geo/lookup", params={"ip": "10.0.0.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "10.0.0.1"
    assert data["is_private"] is True
    assert data["country_code"] is None
    assert "source" in data


# ── Test 10: API batch-lookup validates max 50 IPs ──────────────────────────

def test_api_batch_lookup_max(db_session):
    uid = _seed_user(db_session)
    client = _make_client(db_session, uid)

    # More than 50 IPs should fail (422 from Pydantic validation)
    ips = [f"1.2.3.{i}" for i in range(51)]
    resp = client.post("/api/geo/batch-lookup", json={"ips": ips})
    assert resp.status_code in (400, 422)

    # Exactly 50 private IPs should work
    ips = [f"10.0.0.{i}" for i in range(50)]
    resp = client.post("/api/geo/batch-lookup", json={"ips": ips})
    assert resp.status_code == 200


# ── Test 11: Incident summary includes country code ─────────────────────────

def test_incident_summary_includes_country(db_session):
    """When geo data is cached, incident summary should include country."""
    from collector.incidents import upsert_incidents_from_behaviors

    now = datetime.utcnow()

    # Pre-cache geo for the source IP
    db_session.add(GeoIPCacheModel(
        ip="44.55.66.77",
        country_code="CN",
        country_name="China",
        asn=4134,
        asn_org="CHINANET",
        is_private=False,
        is_bogon=False,
        source="ip-api",
        looked_up_at=now,
    ))

    # Create some flows for enrichment
    for i in range(3):
        db_session.add(LiveFlowModel(
            source_id="test", device_type="fw", parser_id="test",
            source_ip="44.55.66.77",
            destination_ip=f"192.168.1.{i}",
            source_port=12345, destination_port=80 + i,
            protocol="TCP",
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
            state="completed",
            event_count=1,
            total_bytes_in=100, total_bytes_out=200,
            total_packets_in=5, total_packets_out=10,
            allow_count=1, deny_count=0, drop_count=0,
            reset_count=0, alert_count=0,
            raw_event_count=1,
            suppressed=False,
        ))
    db_session.commit()

    behaviors = [
        {
            "source_ip": "44.55.66.77",
            "behavior_type": "scanning",
            "confidence": 0.8,
            "flow_count": 10,
            "distinct_destinations": 5,
            "distinct_ports": 15,
            "drivers": ["wide_port_spread"],
        },
    ]

    result = upsert_incidents_from_behaviors(db_session, behaviors, now=now)
    assert result["created"] == 1

    incident = db_session.query(LiveIncidentModel).first()
    assert incident is not None
    # Summary should include country code
    assert "CN" in incident.summary


# ── Test 12: Expired cache triggers re-lookup ────────────────────────────────

def test_expired_cache_triggers_relookup(db_session):
    """Cache older than 7 days should trigger a fresh lookup."""
    now = datetime.utcnow()
    old_time = now - timedelta(days=CACHE_TTL_DAYS + 1)

    db_session.add(GeoIPCacheModel(
        ip="7.7.7.7",
        country_code="DE",
        country_name="Germany",
        is_private=False,
        is_bogon=False,
        source="ip-api",
        looked_up_at=old_time,
    ))
    db_session.commit()

    api_called = []
    def _spy(url):
        api_called.append(url)
        return MOCK_IPAPI_RESPONSE

    result = lookup_ip_geo("7.7.7.7", db_session, now=now, _http_get=_spy)

    # Should have called API (cache was stale)
    assert len(api_called) == 1
    # Result should be fresh from API (Turkey from mock), not stale Germany
    assert result["country_code"] == "TR"
