"""
IP baseline learning and deviation detection.

Learns "normal" behavior per source_ip from historical flows by
sampling 10-minute windows over the last 7 days.  Deviations are
detected by comparing current behavior metrics against baseline
means using z-scores.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta
from statistics import mean, stdev
from typing import Any, Dict, List, Optional

from sqlalchemy import Integer, case, func as sqlfunc, type_coerce
from sqlalchemy.orm import Session

from database import IPBaselineModel, LiveFlowModel

# ── Tunables ──────────────────────────────────────────────────────────────────
OBSERVATION_DAYS = 7
WINDOW_MINUTES = 10
MIN_WINDOWS = 5          # need at least 5 sampled windows to build a baseline
DEVIATION_CAP = 10.0
Z_SCORE_THRESHOLD = 2.0  # flag metrics where |z| > 2.0


# ── Baseline computation ─────────────────────────────────────────────────────

def compute_baselines(
    db: Session,
    *,
    now: Optional[datetime] = None,
) -> int:
    """Compute/update IP baselines from historical flows.

    Returns count of baselines upserted.
    """
    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=OBSERVATION_DAYS)

    # Bucket each flow into a 10-minute window and aggregate per
    # (source_ip, window_bucket).
    #
    # SQLite doesn't have date_trunc, so we use strftime to bucket:
    #   window = strftime('%Y-%m-%d %H:', first_seen) || (cast(strftime('%M', first_seen) as int) / 10)
    # This gives buckets like "2026-04-14 10:3" for 10:30-10:39.

    # Bucket into 10-minute windows:  "YYYY-MM-DD HH:B" where B = minute // 10
    minute_int = type_coerce(sqlfunc.strftime("%M", LiveFlowModel.first_seen), Integer)
    window_expr = (
        sqlfunc.strftime("%Y-%m-%d %H:", LiveFlowModel.first_seen)
        + sqlfunc.cast(minute_int / WINDOW_MINUTES, Integer)
    )

    rows = (
        db.query(
            LiveFlowModel.source_ip,
            window_expr.label("window_bucket"),
            sqlfunc.count(LiveFlowModel.id).label("flow_count"),
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_ip)).label("distinct_dsts"),
            sqlfunc.count(sqlfunc.distinct(LiveFlowModel.destination_port)).label("distinct_ports"),
            sqlfunc.sum(case((LiveFlowModel.state.in_(("denied", "dropped")), 1), else_=0)).label("denied"),
            sqlfunc.sum(case((LiveFlowModel.state == "reset", 1), else_=0)).label("resets"),
            sqlfunc.sum(LiveFlowModel.total_bytes_in + LiveFlowModel.total_bytes_out).label("total_bytes"),
        )
        .filter(LiveFlowModel.first_seen >= cutoff)
        .group_by(LiveFlowModel.source_ip, "window_bucket")
        .all()
    )

    # Group window samples by source_ip
    by_ip: Dict[str, List[Dict[str, float]]] = {}
    for r in rows:
        flow_count = int(r.flow_count or 0)
        if flow_count == 0:
            continue
        sample = {
            "flow_count": float(flow_count),
            "distinct_destinations": float(r.distinct_dsts or 0),
            "distinct_ports": float(r.distinct_ports or 0),
            "deny_ratio": float(r.denied or 0) / flow_count,
            "reset_ratio": float(r.resets or 0) / flow_count,
            "bytes_per_flow": float(r.total_bytes or 0) / flow_count,
        }
        by_ip.setdefault(r.source_ip, []).append(sample)

    updated = 0
    for src_ip, samples in by_ip.items():
        if len(samples) < MIN_WINDOWS:
            continue

        flows = [s["flow_count"] for s in samples]
        deny_ratios = [s["deny_ratio"] for s in samples]
        reset_ratios = [s["reset_ratio"] for s in samples]
        dests = [s["distinct_destinations"] for s in samples]
        ports = [s["distinct_ports"] for s in samples]
        bpf = [s["bytes_per_flow"] for s in samples]

        baseline = db.query(IPBaselineModel).filter(
            IPBaselineModel.source_ip == src_ip,
        ).first()

        if not baseline:
            baseline = IPBaselineModel(source_ip=src_ip)
            db.add(baseline)

        baseline.observation_window_days = OBSERVATION_DAYS
        baseline.sample_count = len(samples)
        baseline.avg_flows_per_window = round(mean(flows), 2)
        baseline.avg_distinct_destinations = round(mean(dests), 2)
        baseline.avg_distinct_ports = round(mean(ports), 2)
        baseline.avg_deny_ratio = round(mean(deny_ratios), 4)
        baseline.avg_reset_ratio = round(mean(reset_ratios), 4)
        baseline.avg_bytes_per_flow = round(mean(bpf), 2)
        baseline.stddev_flows = round(stdev(flows), 2) if len(flows) > 1 else 0.0
        baseline.stddev_deny_ratio = round(stdev(deny_ratios), 4) if len(deny_ratios) > 1 else 0.0
        baseline.stddev_reset_ratio = round(stdev(reset_ratios), 4) if len(reset_ratios) > 1 else 0.0
        baseline.last_computed_at = now
        baseline.updated_at = now

        updated += 1

    if updated:
        db.commit()

    return updated


# ── Deviation detection ──────────────────────────────────────────────────────

def detect_deviations(
    db: Session,
    behaviors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Enrich behavior entries with deviation scores against IP baselines.

    Each entry gets:
      deviation_score (float, 0.0–10.0)
      deviating_metrics (list of metric names where |z| > 2.0)
      no_baseline (bool)
      baseline_sample_count (int)
    """
    if not behaviors:
        return behaviors

    # Bulk-load baselines for all source IPs in one query
    src_ips = list({b["source_ip"] for b in behaviors})
    baselines = (
        db.query(IPBaselineModel)
        .filter(IPBaselineModel.source_ip.in_(src_ips))
        .all()
    )
    baseline_map = {bl.source_ip: bl for bl in baselines}

    result = []
    for b in behaviors:
        entry = dict(b)  # shallow copy
        bl = baseline_map.get(b["source_ip"])

        if not bl:
            entry["deviation_score"] = 0.0
            entry["deviating_metrics"] = []
            entry["no_baseline"] = True
            entry["baseline_sample_count"] = 0
            result.append(entry)
            continue

        # Compute z-scores for each comparable metric
        metrics = _compute_z_scores(b, bl)
        total_z = sum(abs(z) for _, z in metrics)
        deviating = [name for name, z in metrics if abs(z) > Z_SCORE_THRESHOLD]

        entry["deviation_score"] = round(min(total_z, DEVIATION_CAP), 2)
        entry["deviating_metrics"] = deviating
        entry["no_baseline"] = False
        entry["baseline_sample_count"] = bl.sample_count
        result.append(entry)

    return result


def _compute_z_scores(
    behavior: Dict[str, Any],
    baseline: IPBaselineModel,
) -> List[tuple]:
    """Return [(metric_name, z_score), ...] for comparable metrics."""
    pairs = [
        ("flow_count", behavior.get("flow_count", 0),
         baseline.avg_flows_per_window, baseline.stddev_flows),
        ("deny_ratio", behavior.get("deny_ratio", 0),
         baseline.avg_deny_ratio, baseline.stddev_deny_ratio),
        ("reset_ratio", behavior.get("reset_ratio", 0),
         baseline.avg_reset_ratio, baseline.stddev_reset_ratio),
        ("distinct_destinations", behavior.get("distinct_destinations", 0),
         baseline.avg_distinct_destinations, 0),  # no stddev stored for dests
        ("distinct_ports", behavior.get("distinct_ports", 0),
         baseline.avg_distinct_ports, 0),  # no stddev stored for ports
    ]

    results = []
    for name, current, avg, sd in pairs:
        if sd and sd > 0:
            z = (current - avg) / sd
        else:
            z = 0.0
        results.append((name, round(z, 2)))

    return results


# ── Serialization ─────────────────────────────────────────────────────────────

def baseline_dict(b: IPBaselineModel) -> dict:
    return {
        "id": b.id,
        "source_ip": b.source_ip,
        "observation_window_days": b.observation_window_days,
        "sample_count": b.sample_count,
        "avg_flows_per_window": b.avg_flows_per_window,
        "avg_distinct_destinations": b.avg_distinct_destinations,
        "avg_distinct_ports": b.avg_distinct_ports,
        "avg_deny_ratio": b.avg_deny_ratio,
        "avg_reset_ratio": b.avg_reset_ratio,
        "avg_bytes_per_flow": b.avg_bytes_per_flow,
        "stddev_flows": b.stddev_flows,
        "stddev_deny_ratio": b.stddev_deny_ratio,
        "stddev_reset_ratio": b.stddev_reset_ratio,
        "last_computed_at": b.last_computed_at.isoformat() if b.last_computed_at else None,
        "created_at": b.created_at.isoformat() if b.created_at else None,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
    }
