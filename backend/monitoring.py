"""
Drift detection for scheduled path-monitoring.

This module is intentionally pure: it does not import the FastAPI app, the
database session, or any I/O.  It exists so the API layer in ``main.py`` can
re-use the same drift logic from both the periodic tick and the manual-run
endpoint, and so unit tests can drive ``detect_drift`` directly with plain
dicts.

The diff vocabulary mirrors ``_compare_path_results`` in main.py — we re-use
its outcome severity table and impairment hint table — but the *output* is
shaped for monitoring (single severity, summary bullets, action flag) rather
than for an interactive baseline-vs-incident UI.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# ── Tunable thresholds ────────────────────────────────────────────────────────
# These defaults can be overridden per call.  They are deliberately conservative
# so that an unrelated rounding wobble in timing or a one-point confidence
# nudge does not generate a notification.

DEFAULT_CONFIDENCE_DROP_THRESHOLD = 15            # percent points
DEFAULT_TIMING_REGRESSION_MS = 50.0               # absolute ms
DEFAULT_TIMING_REGRESSION_RATIO = 1.5             # relative multiplier

# Backend-delay-style timing keys whose increase counts as a regression.  Other
# numeric keys are still reported in ``timing_changes`` but do not by themselves
# trigger drift.
TIMING_REGRESSION_KEYS = (
    "backend_response_delay",
    "server_response_time",
    "first_byte_delay",
    "tcp_handshake_delay",
)

# Outcome severity ladder shared with the compare endpoint.
_OUTCOME_SEVERITY: Dict[str, int] = {
    "success": 0,
    "partial_success": 1,
    "failure": 2,
    "unknown": 3,
}

# Drift severity ladder (string + integer) so we can take the worst.
_DRIFT_SEVERITY_RANK: Dict[str, int] = {
    "none": 0,
    "info": 1,
    "warning": 2,
    "critical": 3,
}


def _worst(a: str, b: str) -> str:
    return a if _DRIFT_SEVERITY_RANK[a] >= _DRIFT_SEVERITY_RANK[b] else b


def _path_summary(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the comparable subset of a PathAnalysisResult dict."""
    return {
        "connection_outcome":    r.get("connection_outcome", "unknown"),
        "primary_impairment":    r.get("primary_impairment"),
        "path_impairments":      list(r.get("path_impairments") or []),
        "path_confidence_score": int(r.get("path_confidence_score") or 0),
        "timing_breakdown":      dict(r.get("timing_breakdown") or {}),
    }


def detect_drift(
    previous: Optional[Dict[str, Any]],
    current: Dict[str, Any],
    *,
    confidence_drop_threshold: int = DEFAULT_CONFIDENCE_DROP_THRESHOLD,
    timing_regression_ms: float = DEFAULT_TIMING_REGRESSION_MS,
    timing_regression_ratio: float = DEFAULT_TIMING_REGRESSION_RATIO,
) -> Dict[str, Any]:
    """
    Compare a fresh path-analysis result against the previous snapshot and
    return a drift report.

    Returns a dict with the following keys:

      drift_detected     bool   — True if any monitored signal regressed.
      severity           str    — none|info|warning|critical (worst signal).
      action_required    bool   — True for warning/critical.
      changes            list   — short human-readable bullets.
      changed_fields     dict   — structured per-signal detail.
      previous_summary   dict   — comparable subset of previous (or None).
      current_summary    dict   — comparable subset of current.

    Severity policy:
      critical — outcome regression toward "failure", or new connection_refused.
      warning  — outcome change of any kind, new impairment, primary_impairment
                 change, or timing regression on a backend-delay key.
      info     — confidence drop ≥ threshold without any of the above.
      none     — no drift.

    If ``previous`` is None this is treated as the first run; the result is
    drift_detected=False, severity=none, and the report still contains the
    current summary so callers can persist a baseline snapshot.
    """
    current_summary = _path_summary(current)
    if previous is None:
        return {
            "drift_detected":  False,
            "severity":        "none",
            "action_required": False,
            "changes":         [],
            "changed_fields":  {},
            "previous_summary": None,
            "current_summary": current_summary,
        }

    previous_summary = _path_summary(previous)

    severity = "none"
    changes: List[str] = []
    changed_fields: Dict[str, Any] = {}

    # ── Outcome drift ────────────────────────────────────────────────────────
    p_outcome = previous_summary["connection_outcome"]
    c_outcome = current_summary["connection_outcome"]
    if p_outcome != c_outcome:
        regression = (
            _OUTCOME_SEVERITY.get(c_outcome, 3)
            > _OUTCOME_SEVERITY.get(p_outcome, 3)
        )
        changed_fields["connection_outcome"] = {
            "previous":   p_outcome,
            "current":    c_outcome,
            "regression": regression,
        }
        if regression and c_outcome == "failure":
            severity = _worst(severity, "critical")
        else:
            severity = _worst(severity, "warning")
        verb = "regressed" if regression else "changed"
        changes.append(
            f"Connection outcome {verb}: "
            f"{p_outcome.replace('_', ' ')} → {c_outcome.replace('_', ' ')}"
        )

    # ── Primary impairment drift ─────────────────────────────────────────────
    p_imp = previous_summary["primary_impairment"]
    c_imp = current_summary["primary_impairment"]
    if p_imp != c_imp:
        changed_fields["primary_impairment"] = {
            "previous": p_imp,
            "current":  c_imp,
        }
        severity = _worst(severity, "warning")
        if p_imp is None:
            changes.append(
                f"Primary impairment appeared: {str(c_imp).replace('_', ' ')}"
            )
        elif c_imp is None:
            changes.append(
                f"Primary impairment cleared (was {str(p_imp).replace('_', ' ')})"
            )
        else:
            changes.append(
                f"Primary impairment changed: "
                f"{str(p_imp).replace('_', ' ')} → "
                f"{str(c_imp).replace('_', ' ')}"
            )
        if c_imp == "connection_refused":
            severity = _worst(severity, "critical")

    # ── New / resolved impairments ───────────────────────────────────────────
    prev_imps = set(previous_summary["path_impairments"])
    curr_imps = set(current_summary["path_impairments"])
    new_imps = sorted(curr_imps - prev_imps)
    resolved_imps = sorted(prev_imps - curr_imps)
    if new_imps or resolved_imps:
        changed_fields["impairments"] = {
            "new":      new_imps,
            "resolved": resolved_imps,
        }
        if new_imps:
            severity = _worst(severity, "warning")
            for imp in new_imps:
                changes.append(
                    f"New impairment: {imp.replace('_', ' ')}"
                )
        if resolved_imps and not new_imps:
            # Pure improvement still surfaces as info-level drift so the user
            # sees something happened, but is not "action required".
            severity = _worst(severity, "info")
            for imp in resolved_imps:
                changes.append(
                    f"Impairment resolved: {imp.replace('_', ' ')}"
                )

    # ── Confidence drop ──────────────────────────────────────────────────────
    p_conf = previous_summary["path_confidence_score"]
    c_conf = current_summary["path_confidence_score"]
    conf_delta = c_conf - p_conf
    if conf_delta <= -confidence_drop_threshold:
        changed_fields["confidence"] = {
            "previous": p_conf,
            "current":  c_conf,
            "delta":    conf_delta,
        }
        severity = _worst(severity, "info")
        changes.append(
            f"Path confidence dropped {abs(conf_delta)} points "
            f"({p_conf}% → {c_conf}%)"
        )

    # ── Timing regression on a backend-delay-style key ───────────────────────
    p_timing = previous_summary["timing_breakdown"]
    c_timing = current_summary["timing_breakdown"]
    timing_changes: Dict[str, Dict[str, Any]] = {}
    for key in sorted(set(p_timing) | set(c_timing)):
        pv = p_timing.get(key)
        cv = c_timing.get(key)
        if not (isinstance(pv, (int, float)) and isinstance(cv, (int, float))):
            continue
        delta = round(cv - pv, 3)
        regressed = (
            key in TIMING_REGRESSION_KEYS
            and delta >= timing_regression_ms
            and (pv == 0 or cv >= pv * timing_regression_ratio)
        )
        if regressed:
            timing_changes[key] = {
                "previous":  pv,
                "current":   cv,
                "delta":     delta,
                "regressed": True,
            }
            severity = _worst(severity, "warning")
            changes.append(
                f"{key.replace('_', ' ').title()} increased by "
                f"{delta} ms ({pv} → {cv})"
            )
    if timing_changes:
        changed_fields["timing"] = timing_changes

    drift_detected  = severity != "none"
    action_required = severity in ("warning", "critical")

    return {
        "drift_detected":   drift_detected,
        "severity":         severity,
        "action_required":  action_required,
        "changes":          changes,
        "changed_fields":   changed_fields,
        "previous_summary": previous_summary,
        "current_summary":  current_summary,
    }


def is_due(
    last_run_at, schedule_interval_minutes: int, now,
) -> bool:
    """Return True if a monitor with the given last_run_at is due to run.

    Pure helper kept here so the periodic tick in main.py and tests can share
    the same logic without coupling to ``datetime.utcnow``.
    """
    if last_run_at is None:
        return True
    delta_seconds = (now - last_run_at).total_seconds()
    return delta_seconds >= schedule_interval_minutes * 60
