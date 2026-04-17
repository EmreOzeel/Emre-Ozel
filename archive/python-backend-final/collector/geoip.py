"""
GeoIP enrichment module.

Provides IP-to-location/ASN lookups with a multi-tier strategy:
  1. Private/bogon detection (instant, no external call)
  2. Database cache (GeoIPCacheModel, TTL 7 days)
  3. MaxMind GeoLite2 .mmdb files (if configured)
  4. ip-api.com free API fallback (rate-limited to 45 req/min)

All results are cached in the database so repeated lookups are fast.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from config import settings
from database import GeoIPCacheModel

logger = logging.getLogger("geoip")

# ── Constants ────────────────────────────────────────────────────────────────

CACHE_TTL_DAYS = 7

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def _is_private(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _PRIVATE_NETWORKS)


def _is_bogon(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _BOGON_NETWORKS)


# ── Rate limiter for ip-api.com ──────────────────────────────────────────────

_rate_lock = threading.Lock()
_rate_timestamps: List[float] = []
_RATE_LIMIT = 45  # requests per minute
_RATE_WINDOW = 60.0  # seconds


def _rate_limit_ok() -> bool:
    """Return True if we can make another ip-api request."""
    now = time.time()
    with _rate_lock:
        # Prune old timestamps
        cutoff = now - _RATE_WINDOW
        while _rate_timestamps and _rate_timestamps[0] < cutoff:
            _rate_timestamps.pop(0)
        if len(_rate_timestamps) >= _RATE_LIMIT:
            return False
        _rate_timestamps.append(now)
        return True


def _reset_rate_limiter() -> None:
    """Reset rate limiter (for testing)."""
    with _rate_lock:
        _rate_timestamps.clear()


# ── Empty geo dict ───────────────────────────────────────────────────────────

def _empty_geo(ip: str, *, is_private: bool = False, is_bogon: bool = False, source: str = "private") -> dict:
    return {
        "ip": ip,
        "country_code": None,
        "country_name": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "asn_org": None,
        "is_private": is_private,
        "is_bogon": is_bogon,
        "source": source,
    }


def _cache_to_dict(c: GeoIPCacheModel) -> dict:
    return {
        "ip": c.ip,
        "country_code": c.country_code,
        "country_name": c.country_name,
        "city": c.city,
        "latitude": c.latitude,
        "longitude": c.longitude,
        "asn": c.asn,
        "asn_org": c.asn_org,
        "is_private": c.is_private,
        "is_bogon": c.is_bogon,
        "source": c.source,
    }


# ── MaxMind lookup ───────────────────────────────────────────────────────────

_maxmind_city_reader = None
_maxmind_asn_reader = None
_maxmind_init_done = False


def _init_maxmind() -> None:
    """Lazy-initialize MaxMind readers."""
    global _maxmind_city_reader, _maxmind_asn_reader, _maxmind_init_done
    if _maxmind_init_done:
        return
    _maxmind_init_done = True

    try:
        import geoip2.database
    except ImportError:
        logger.debug("geoip2 not installed, MaxMind lookups disabled")
        return

    if settings.GEOIP_CITY_DB:
        try:
            _maxmind_city_reader = geoip2.database.Reader(settings.GEOIP_CITY_DB)
            logger.info("MaxMind City DB loaded: %s", settings.GEOIP_CITY_DB)
        except Exception as e:
            logger.warning("Failed to load MaxMind City DB: %s", e)

    if settings.GEOIP_ASN_DB:
        try:
            _maxmind_asn_reader = geoip2.database.Reader(settings.GEOIP_ASN_DB)
            logger.info("MaxMind ASN DB loaded: %s", settings.GEOIP_ASN_DB)
        except Exception as e:
            logger.warning("Failed to load MaxMind ASN DB: %s", e)


def _lookup_maxmind(ip: str) -> Optional[dict]:
    """Try MaxMind lookup. Returns geo dict or None if not available."""
    _init_maxmind()
    if not _maxmind_city_reader and not _maxmind_asn_reader:
        return None

    result = _empty_geo(ip, source="maxmind")
    found = False

    if _maxmind_city_reader:
        try:
            resp = _maxmind_city_reader.city(ip)
            result["country_code"] = resp.country.iso_code
            result["country_name"] = resp.country.name
            result["city"] = resp.city.name if resp.city else None
            result["latitude"] = resp.location.latitude if resp.location else None
            result["longitude"] = resp.location.longitude if resp.location else None
            found = True
        except Exception:
            pass

    if _maxmind_asn_reader:
        try:
            resp = _maxmind_asn_reader.asn(ip)
            result["asn"] = resp.autonomous_system_number
            result["asn_org"] = resp.autonomous_system_organization
            found = True
        except Exception:
            pass

    return result if found else None


# ── ip-api.com fallback ──────────────────────────────────────────────────────

def _lookup_ipapi(
    ip: str,
    *,
    _http_get: Optional[Callable] = None,
) -> Optional[dict]:
    """Lookup via ip-api.com free API. Returns geo dict or None."""
    if not settings.GEOIP_USE_IPAPI_FALLBACK:
        return None

    if not _rate_limit_ok():
        logger.debug("ip-api rate limit reached, skipping %s", ip)
        return None

    try:
        import requests
        http_get = _http_get or (lambda url: requests.get(url, timeout=10).json())
        data = http_get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,org"
        )
        if data.get("status") != "success":
            return None

        # Parse AS number from "AS1234 Org Name" format
        asn = None
        as_str = data.get("as", "")
        if as_str and as_str.startswith("AS"):
            try:
                asn = int(as_str.split()[0][2:])
            except (ValueError, IndexError):
                pass

        return {
            "ip": ip,
            "country_code": data.get("countryCode"),
            "country_name": data.get("country"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "asn": asn,
            "asn_org": data.get("org"),
            "is_private": False,
            "is_bogon": False,
            "source": "ip-api",
        }
    except Exception as e:
        logger.debug("ip-api lookup failed for %s: %s", ip, e)
        return None


# ── Main lookup function ────────────────────────────────────────────────────

def lookup_ip_geo(
    ip: str,
    db: Session,
    *,
    now: Optional[datetime] = None,
    _http_get: Optional[Callable] = None,
) -> dict:
    """Look up GeoIP data for a single IP.

    Strategy:
      1. Private/bogon → return immediately
      2. Check cache (TTL 7 days)
      3. Try MaxMind .mmdb
      4. Fallback to ip-api.com
      5. Cache and return result
    """
    now = now or datetime.utcnow()

    # 1. Private/bogon detection
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _empty_geo(ip, source="invalid")

    if _is_private(addr):
        return _empty_geo(ip, is_private=True, source="private")

    if _is_bogon(addr):
        return _empty_geo(ip, is_bogon=True, source="private")

    if not settings.GEOIP_ENABLED:
        return _empty_geo(ip, source="disabled")

    # 2. Check cache
    cached = (
        db.query(GeoIPCacheModel)
        .filter(GeoIPCacheModel.ip == ip)
        .first()
    )
    if cached and cached.looked_up_at and (now - cached.looked_up_at).days < CACHE_TTL_DAYS:
        return _cache_to_dict(cached)

    # 3. Try MaxMind
    result = _lookup_maxmind(ip)

    # 4. Fallback to ip-api
    if result is None:
        result = _lookup_ipapi(ip, _http_get=_http_get)

    # 5. If still nothing, return empty
    if result is None:
        result = _empty_geo(ip, source="unknown")

    # Upsert cache
    _upsert_cache(db, ip, result, now)

    return result


def _upsert_cache(
    db: Session,
    ip: str,
    result: dict,
    now: datetime,
) -> None:
    """Upsert a GeoIP cache entry."""
    existing = (
        db.query(GeoIPCacheModel)
        .filter(GeoIPCacheModel.ip == ip)
        .first()
    )
    if existing:
        existing.country_code = result.get("country_code")
        existing.country_name = result.get("country_name")
        existing.city = result.get("city")
        existing.latitude = result.get("latitude")
        existing.longitude = result.get("longitude")
        existing.asn = result.get("asn")
        existing.asn_org = result.get("asn_org")
        existing.is_private = result.get("is_private", False)
        existing.is_bogon = result.get("is_bogon", False)
        existing.source = result.get("source", "unknown")
        existing.looked_up_at = now
    else:
        db.add(GeoIPCacheModel(
            ip=ip,
            country_code=result.get("country_code"),
            country_name=result.get("country_name"),
            city=result.get("city"),
            latitude=result.get("latitude"),
            longitude=result.get("longitude"),
            asn=result.get("asn"),
            asn_org=result.get("asn_org"),
            is_private=result.get("is_private", False),
            is_bogon=result.get("is_bogon", False),
            source=result.get("source", "unknown"),
            looked_up_at=now,
        ))
    try:
        db.commit()
    except Exception:
        db.rollback()


# ── Batch lookup ─────────────────────────────────────────────────────────────

def batch_lookup(
    ips: List[str],
    db: Session,
    *,
    now: Optional[datetime] = None,
    _http_get: Optional[Callable] = None,
) -> Dict[str, dict]:
    """Look up multiple IPs efficiently.

    Checks cache for all IPs in one query, then calls external API
    only for cache misses.
    """
    now = now or datetime.utcnow()
    results: Dict[str, dict] = {}

    if not ips:
        return results

    # Separate private/bogon IPs first
    to_lookup = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            results[ip] = _empty_geo(ip, source="invalid")
            continue

        if _is_private(addr):
            results[ip] = _empty_geo(ip, is_private=True, source="private")
        elif _is_bogon(addr):
            results[ip] = _empty_geo(ip, is_bogon=True, source="private")
        else:
            to_lookup.append(ip)

    if not to_lookup or not settings.GEOIP_ENABLED:
        for ip in to_lookup:
            results[ip] = _empty_geo(ip, source="disabled")
        return results

    # Batch cache lookup
    cache_cutoff = now - timedelta(days=CACHE_TTL_DAYS)
    cached_rows = (
        db.query(GeoIPCacheModel)
        .filter(
            GeoIPCacheModel.ip.in_(to_lookup),
            GeoIPCacheModel.looked_up_at >= cache_cutoff,
        )
        .all()
    )
    cached_map = {c.ip: c for c in cached_rows}

    cache_misses = []
    for ip in to_lookup:
        if ip in cached_map:
            results[ip] = _cache_to_dict(cached_map[ip])
        else:
            cache_misses.append(ip)

    # Lookup cache misses
    for ip in cache_misses:
        results[ip] = lookup_ip_geo(ip, db, now=now, _http_get=_http_get)

    return results


# ── Helper for integration ───────────────────────────────────────────────────

def get_geo_summary(ip: str, db: Session) -> str:
    """Return a short geo summary for use in notification messages.

    Returns strings like "(CN, AS4134 CHINANET)" or "" if unavailable.
    """
    try:
        geo = lookup_ip_geo(ip, db)
    except Exception:
        return ""

    if geo.get("is_private") or geo.get("is_bogon"):
        return ""

    parts = []
    if geo.get("country_code"):
        parts.append(geo["country_code"])
    if geo.get("asn") and geo.get("asn_org"):
        parts.append(f"AS{geo['asn']} {geo['asn_org']}")
    elif geo.get("asn_org"):
        parts.append(geo["asn_org"])

    return f" ({', '.join(parts)})" if parts else ""


def get_cached_geo(ip: str, db: Session) -> Optional[dict]:
    """Return cached geo data if available, without triggering a lookup."""
    cached = (
        db.query(GeoIPCacheModel)
        .filter(GeoIPCacheModel.ip == ip)
        .first()
    )
    if cached:
        return _cache_to_dict(cached)
    return None
