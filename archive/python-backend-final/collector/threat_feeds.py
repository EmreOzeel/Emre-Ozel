"""
Threat intelligence feed ingestion and IP lookup.

Ingests known-malicious IP/domain lists from external feeds, stores them
as ``ThreatIndicatorModel`` records, and provides fast lookup functions
used by the bridge and incident layers to boost severity.

The module maintains an in-memory cache (TTL 5 minutes) so that the
hot-path ``is_threat_ip()`` call does not hit the database on every
invocation.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

import requests
from sqlalchemy.orm import Session

from database import ThreatFeedModel, ThreatIndicatorModel

logger = logging.getLogger("threat_feeds")

# ── In-memory lookup cache ───────────────────────────────────────────────────
# {ip_str: (timestamp_float, list_of_indicator_dicts)}
_cache: Dict[str, tuple] = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 300  # 5 minutes


def _cache_get(ip: str) -> Optional[List[dict]]:
    with _cache_lock:
        entry = _cache.get(ip)
        if entry and time.time() - entry[0] < _CACHE_TTL:
            return entry[1]
    return None


def _cache_set(ip: str, results: List[dict]) -> None:
    with _cache_lock:
        _cache[ip] = (time.time(), results)


def clear_cache() -> None:
    """Clear the entire lookup cache (useful for tests)."""
    with _cache_lock:
        _cache.clear()


# ── IP validation ────────────────────────────────────────────────────────────

def _is_valid_ip(value: str) -> bool:
    """Check if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_cidr(value: str) -> bool:
    """Check if value is a valid CIDR network."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


# ── Feed parsing ─────────────────────────────────────────────────────────────

def _parse_plain(text: str, comment_char: str) -> List[str]:
    """Parse a plain-text feed: one value per line, skip comments/blanks."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue
        # Some feeds have trailing comments: "1.2.3.4 # reason"
        value = line.split()[0]
        results.append(value)
    return results


def _parse_csv(text: str, comment_char: str, ip_column: int) -> List[str]:
    """Parse a CSV feed: extract field at ip_column index."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue
        parts = line.split(",")
        if len(parts) > ip_column:
            value = parts[ip_column].strip().strip('"')
            results.append(value)
    return results


def _parse_json(text: str) -> List[str]:
    """Parse a JSON feed: extract 'ip' or 'address' key from each object."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        data = [data]
    results = []
    for obj in data:
        if isinstance(obj, dict):
            val = obj.get("ip") or obj.get("address") or obj.get("indicator")
            if val:
                results.append(str(val))
        elif isinstance(obj, str):
            results.append(obj)
    return results


# ── Feed fetching ────────────────────────────────────────────────────────────

def fetch_feed(
    db: Session,
    feed: ThreatFeedModel,
    *,
    now: Optional[datetime] = None,
    _http_get: Optional[Callable] = None,
) -> int:
    """Fetch a single feed and upsert indicators.

    Args:
        db: Database session.
        feed: The feed to fetch.
        now: Override current time (for testing).
        _http_get: Override HTTP GET function (for testing).

    Returns:
        Count of indicators upserted.
    """
    now = now or datetime.utcnow()
    http_get = _http_get or _default_http_get

    if not feed.url:
        logger.warning("Feed %s has no URL, skipping", feed.name)
        return 0

    # Fetch content
    try:
        text = http_get(feed.url)
    except Exception as e:
        logger.error("Failed to fetch feed %s: %s", feed.name, e)
        return 0

    # Parse
    if feed.format == "csv":
        raw_values = _parse_csv(text, feed.comment_char, feed.ip_column)
    elif feed.format == "json":
        raw_values = _parse_json(text)
    else:  # plain
        raw_values = _parse_plain(text, feed.comment_char)

    if not raw_values:
        logger.info("Feed %s returned 0 values", feed.name)
        feed.last_fetched_at = now
        feed.last_indicator_count = 0
        db.commit()
        return 0

    # Determine indicator type from feed type
    if feed.feed_type == "cidr_list":
        ind_type = "cidr"
        validator = _is_valid_cidr
    elif feed.feed_type == "domain_list":
        ind_type = "domain"
        validator = lambda v: bool(v) and not _is_valid_ip(v)
    else:  # ip_list
        ind_type = "ip"
        validator = _is_valid_ip

    # Upsert indicators
    upserted = 0
    for value in raw_values:
        value = value.strip()
        if not value or not validator(value):
            continue

        existing = (
            db.query(ThreatIndicatorModel)
            .filter(
                ThreatIndicatorModel.indicator_value == value,
                ThreatIndicatorModel.source_feed == feed.name,
            )
            .first()
        )

        if existing:
            existing.last_seen = now
            existing.confidence = feed.default_confidence
            existing.updated_at = now
        else:
            db.add(ThreatIndicatorModel(
                indicator_type=ind_type,
                indicator_value=value,
                threat_type=feed.default_threat_type,
                confidence=feed.default_confidence,
                source_feed=feed.name,
                first_seen=now,
                last_seen=now,
            ))
        upserted += 1

    # Update feed metadata
    feed.last_fetched_at = now
    feed.last_indicator_count = upserted
    feed.updated_at = now
    db.commit()

    # Clear cache so new indicators are picked up
    clear_cache()

    logger.info("Feed %s: upserted %d indicators", feed.name, upserted)
    return upserted


def _default_http_get(url: str) -> str:
    """Default HTTP GET with 30s timeout."""
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


def refresh_all_feeds(
    db: Session,
    *,
    now: Optional[datetime] = None,
    _http_get: Optional[Callable] = None,
) -> Dict[str, int]:
    """Refresh all enabled feeds that are due.

    A feed is due if last_fetched_at is None OR
    now - last_fetched_at >= fetch_interval_hours.

    Returns {feed_name: indicator_count, ...}.
    """
    now = now or datetime.utcnow()

    feeds = (
        db.query(ThreatFeedModel)
        .filter(ThreatFeedModel.enabled.is_(True))
        .all()
    )

    results = {}
    for feed in feeds:
        if feed.last_fetched_at is not None:
            elapsed = (now - feed.last_fetched_at).total_seconds() / 3600
            if elapsed < feed.fetch_interval_hours:
                continue  # not yet due

        n = fetch_feed(db, feed, now=now, _http_get=_http_get)
        results[feed.name] = n

    return results


# ── IP lookup ────────────────────────────────────────────────────────────────

def lookup_ip(db: Session, ip: str, *, now: Optional[datetime] = None) -> List[dict]:
    """Look up an IP against all active threat indicators.

    Checks exact IP matches and CIDR membership.
    Filters out expired indicators.
    Results are cached for 5 minutes.
    """
    cached = _cache_get(ip)
    if cached is not None:
        return cached

    now = now or datetime.utcnow()
    results = []

    # Exact IP match
    exact = (
        db.query(ThreatIndicatorModel)
        .filter(
            ThreatIndicatorModel.indicator_type == "ip",
            ThreatIndicatorModel.indicator_value == ip,
        )
        .all()
    )
    for ind in exact:
        if ind.expiry and ind.expiry < now:
            continue
        results.append(_indicator_dict(ind))

    # CIDR match — load all CIDR indicators and check membership
    try:
        target_addr = ipaddress.ip_address(ip)
    except ValueError:
        _cache_set(ip, results)
        return results

    cidrs = (
        db.query(ThreatIndicatorModel)
        .filter(ThreatIndicatorModel.indicator_type == "cidr")
        .all()
    )
    for ind in cidrs:
        if ind.expiry and ind.expiry < now:
            continue
        try:
            network = ipaddress.ip_network(ind.indicator_value, strict=False)
            if target_addr in network:
                results.append(_indicator_dict(ind))
        except ValueError:
            continue

    _cache_set(ip, results)
    return results


def is_threat_ip(db: Session, ip: str, *, now: Optional[datetime] = None) -> bool:
    """Return True if the IP matches any active threat indicator."""
    return len(lookup_ip(db, ip, now=now)) > 0


def _indicator_dict(ind: ThreatIndicatorModel) -> dict:
    """Convert indicator model to dict."""
    return {
        "id": ind.id,
        "indicator_type": ind.indicator_type,
        "indicator_value": ind.indicator_value,
        "threat_type": ind.threat_type,
        "confidence": ind.confidence,
        "source_feed": ind.source_feed,
        "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
        "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
        "expiry": ind.expiry.isoformat() if ind.expiry else None,
        "tags": json.loads(ind.tags) if ind.tags else [],
    }


# ── Default feeds seed ───────────────────────────────────────────────────────

DEFAULT_FEEDS: List[Dict[str, Any]] = [
    {
        "name": "emerging_threats_compromised",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "feed_type": "ip_list",
        "format": "plain",
        "default_threat_type": "malware",
        "default_confidence": 0.8,
        "fetch_interval_hours": 24,
    },
    {
        "name": "feodo_tracker_c2",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "feed_type": "ip_list",
        "format": "plain",
        "default_threat_type": "c2",
        "default_confidence": 0.9,
        "fetch_interval_hours": 24,
    },
    {
        "name": "cins_army_scanners",
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "feed_type": "ip_list",
        "format": "plain",
        "default_threat_type": "scanner",
        "default_confidence": 0.7,
        "fetch_interval_hours": 24,
    },
    {
        "name": "tor_exit_nodes",
        "url": "https://check.torproject.org/torbulkexitlist",
        "feed_type": "ip_list",
        "format": "plain",
        "default_threat_type": "tor_exit",
        "default_confidence": 0.95,
        "fetch_interval_hours": 24,
    },
]


def seed_default_feeds(db: Session) -> int:
    """Seed built-in feeds if the table is empty. Returns count created."""
    count = db.query(ThreatFeedModel).count()
    if count > 0:
        return 0

    created = 0
    for feed_def in DEFAULT_FEEDS:
        feed = ThreatFeedModel(
            name=feed_def["name"],
            feed_type=feed_def["feed_type"],
            url=feed_def["url"],
            enabled=True,
            format=feed_def["format"],
            default_threat_type=feed_def["default_threat_type"],
            default_confidence=feed_def["default_confidence"],
            fetch_interval_hours=feed_def["fetch_interval_hours"],
        )
        db.add(feed)
        created += 1

    db.commit()
    logger.info("Seeded %d default threat feeds", created)
    return created
