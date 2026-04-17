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


# ── Trend analysis ───────────────────────────────────────────────────────────
#
# ``summarize_history`` consumes a list of run dicts (oldest → newest, the
# shape stored in ``MonitoredPathRunModel``) and produces a high-level health
# digest for the trend panel.  It is intentionally I/O free so the API layer
# in main.py and the unit tests can both call it with plain dicts.
#
# Each run dict is expected to have:
#   run_at                 (datetime or ISO string — only ordering matters)
#   connection_outcome     str
#   primary_impairment     Optional[str]
#   path_confidence_score  int
#   drift_severity         str
#   action_required        bool
#   timing                 dict[str, float]   (already-decoded timing_breakdown)
#   impairments            list[str]          (already-decoded path_impairments)

# Recurring threshold — an impairment seen in this many distinct runs is
# treated as "recurring" rather than a one-off blip.
RECURRING_MIN_OCCURRENCES = 2
# A 1.3× ratio between the recent-window backend delay and the historical
# baseline counts as a meaningful trend (less noisy than absolute deltas).
TREND_RATIO = 1.3
# How many tail runs we count as "recent" when comparing against the rest.
RECENT_WINDOW = 5


def _avg(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    if not xs:
        return None
    return round(sum(xs) / len(xs), 2)


def _slope_label(prev_avg, recent_avg) -> str:
    """Categorise a numeric trend as worsening / improving / stable.

    Defined here so the test suite can pin the exact thresholds and so the
    same labelling applies to confidence and to backend delay.
    """
    if prev_avg is None or recent_avg is None:
        return "stable"
    if prev_avg == 0:
        return "stable" if recent_avg == 0 else "worsening"
    ratio = recent_avg / prev_avg
    if ratio >= TREND_RATIO:
        return "worsening"
    if ratio <= 1 / TREND_RATIO:
        return "improving"
    return "stable"


def _confidence_slope(prev_avg, recent_avg) -> str:
    """Inverse of _slope_label: a higher confidence is better."""
    if prev_avg is None or recent_avg is None:
        return "stable"
    delta = recent_avg - prev_avg
    if delta <= -10:
        return "worsening"
    if delta >= 10:
        return "improving"
    return "stable"


def summarize_history(runs):
    """Compute a trend digest over a chronological list of run dicts.

    Returns a dict with the keys consumed by the frontend trend panel:

      total_runs               int
      first_run_at / last_run_at
      health_score             int 0–100  — share of healthy runs, weighted
                                            by recency.  Used by the
                                            "most unstable monitors" view.
      latest_outcome           str
      latest_drift_severity    str
      worsening                bool       — composite "is this getting worse"
      worsening_reasons        list[str]
      recurring_impairments    list of {token, count, last_seen}
      confidence_trend         dict (recent_avg, prev_avg, slope)
      backend_delay_trend      dict (recent_avg, prev_avg, slope, key)
      drift_counts             dict severity → int
      regression_episodes      int        — distinct stretches of
                                            warning/critical runs
      action_required_runs     int
      return_path_problem_runs int
    """
    if not runs:
        return {
            "total_runs":               0,
            "first_run_at":             None,
            "last_run_at":              None,
            "health_score":             100,
            "latest_outcome":           None,
            "latest_drift_severity":    "none",
            "worsening":                False,
            "worsening_reasons":        [],
            "recurring_impairments":    [],
            "confidence_trend":         {"recent_avg": None, "prev_avg": None, "slope": "stable"},
            "backend_delay_trend":      {"recent_avg": None, "prev_avg": None, "slope": "stable", "key": None},
            "drift_counts":             {"none": 0, "info": 0, "warning": 0, "critical": 0},
            "regression_episodes":      0,
            "action_required_runs":     0,
            "return_path_problem_runs": 0,
        }

    total = len(runs)
    latest = runs[-1]

    # ── Drift counts ─────────────────────────────────────────────────────────
    drift_counts = {"none": 0, "info": 0, "warning": 0, "critical": 0}
    for r in runs:
        sev = r.get("drift_severity") or "none"
        drift_counts[sev] = drift_counts.get(sev, 0) + 1

    action_required_runs = sum(1 for r in runs if r.get("action_required"))

    # ── Recurring impairments ────────────────────────────────────────────────
    counts: dict = {}
    last_seen: dict = {}
    return_path_problem_runs = 0
    for r in runs:
        imps = r.get("impairments") or []
        for imp in imps:
            counts[imp] = counts.get(imp, 0) + 1
            last_seen[imp] = r.get("run_at")
            if imp == "return_path_problem":
                return_path_problem_runs += 1
    recurring = sorted(
        (
            {"token": k, "count": v, "last_seen": last_seen[k]}
            for k, v in counts.items()
            if v >= RECURRING_MIN_OCCURRENCES
        ),
        key=lambda x: (-x["count"], x["token"]),
    )

    # ── Confidence trend (recent window vs. prior history) ───────────────────
    confidences = [r.get("path_confidence_score", 0) or 0 for r in runs]
    if total >= 2:
        recent = confidences[-min(RECENT_WINDOW, total):]
        prev   = confidences[: max(total - RECENT_WINDOW, 0)] or confidences[:-1]
        conf_recent_avg = _avg(recent)
        conf_prev_avg   = _avg(prev)
    else:
        conf_recent_avg = confidences[0]
        conf_prev_avg   = None
    confidence_trend = {
        "recent_avg": conf_recent_avg,
        "prev_avg":   conf_prev_avg,
        "slope":      _confidence_slope(conf_prev_avg, conf_recent_avg),
    }

    # ── Backend delay trend ──────────────────────────────────────────────────
    # Pick the first backend-delay-style key that actually has data so the
    # trend reflects whichever timing field the engine reported.
    delay_key = None
    for key in TIMING_REGRESSION_KEYS:
        if any(
            isinstance((r.get("timing") or {}).get(key), (int, float))
            for r in runs
        ):
            delay_key = key
            break
    backend_delay_trend = {
        "recent_avg": None, "prev_avg": None, "slope": "stable", "key": delay_key,
    }
    if delay_key is not None:
        delay_series = [
            (r.get("timing") or {}).get(delay_key) for r in runs
        ]
        if total >= 2:
            recent = delay_series[-min(RECENT_WINDOW, total):]
            prev   = delay_series[: max(total - RECENT_WINDOW, 0)] or delay_series[:-1]
        else:
            recent, prev = delay_series, []
        backend_delay_trend["recent_avg"] = _avg(recent)
        backend_delay_trend["prev_avg"]   = _avg(prev)
        backend_delay_trend["slope"]      = _slope_label(
            backend_delay_trend["prev_avg"],
            backend_delay_trend["recent_avg"],
        )

    # ── Regression episodes (distinct stretches of warning/critical) ─────────
    regression_episodes = 0
    in_episode = False
    for r in runs:
        sev = r.get("drift_severity") or "none"
        bad = sev in ("warning", "critical")
        if bad and not in_episode:
            regression_episodes += 1
            in_episode = True
        elif not bad:
            in_episode = False

    # ── Health score (recency-weighted share of healthy runs) ────────────────
    # Healthy = success outcome AND no warning/critical drift.
    weights = list(range(1, total + 1))   # newest run has the highest weight
    healthy_w = 0.0
    for r, w in zip(runs, weights):
        sev = r.get("drift_severity") or "none"
        if r.get("connection_outcome") == "success" and sev not in ("warning", "critical"):
            healthy_w += w
    health_score = round(100 * healthy_w / sum(weights)) if weights else 100

    # ── Composite worsening flag ─────────────────────────────────────────────
    worsening_reasons: list = []
    if backend_delay_trend["slope"] == "worsening":
        worsening_reasons.append(
            f"{(delay_key or 'backend delay').replace('_', ' ')} trending up"
            f" ({backend_delay_trend['prev_avg']} → {backend_delay_trend['recent_avg']} ms)"
        )
    if confidence_trend["slope"] == "worsening":
        worsening_reasons.append(
            f"confidence dropping ({confidence_trend['prev_avg']} → {confidence_trend['recent_avg']})"
        )
    if recurring:
        worsening_reasons.append(
            f"{len(recurring)} recurring impairment(s): "
            + ", ".join(r["token"] for r in recurring[:3])
        )
    if regression_episodes >= 2:
        worsening_reasons.append(
            f"{regression_episodes} distinct regression episodes"
        )
    worsening = bool(worsening_reasons)

    return {
        "total_runs":               total,
        "first_run_at":             runs[0].get("run_at"),
        "last_run_at":              latest.get("run_at"),
        "health_score":             health_score,
        "latest_outcome":           latest.get("connection_outcome"),
        "latest_drift_severity":    latest.get("drift_severity") or "none",
        "worsening":                worsening,
        "worsening_reasons":        worsening_reasons,
        "recurring_impairments":    recurring,
        "confidence_trend":         confidence_trend,
        "backend_delay_trend":      backend_delay_trend,
        "drift_counts":             drift_counts,
        "regression_episodes":      regression_episodes,
        "action_required_runs":     action_required_runs,
        "return_path_problem_runs": return_path_problem_runs,
    }


# ── Risk scoring ─────────────────────────────────────────────────────────────
#
# Deterministic operational risk score (0–100) computed from a trend digest
# (the dict ``summarize_history`` returns).  No ML, no historical baselines —
# every input has a fixed weight so the score is reproducible across runs and
# easy to debug from the drivers list.
#
# The score answers three questions for the analyst:
#   1. What should I look at first? → highest risk_score wins
#   2. What is degrading fastest?    → worsening flag + confidence slope
#   3. What is most likely to break? → recurring severe impairments + critical
#                                      drift count + return_path_problem freq

# Impairments that, when recurring, indicate a fragile path even if the most
# recent run is healthy — they push the score noticeably higher than a generic
# packet_loss recurrence would.
SEVERE_RECURRING_IMPAIRMENTS = {
    "no_response",
    "connection_refused",
    "tls_failure",
    "syn_timeout",
    "return_path_problem",
}

# Sub-score caps so a single noisy signal can't dominate the total.  These are
# tuned so a healthy stable monitor scores < 10 and a path that is critical,
# worsening, with recurring no_response easily clears 80.
_CAP_HEALTH        = 40   # (100 - health_score) * 0.4 max
_CAP_CRITICAL_RUNS = 20   # 4 pts × 5 runs
_CAP_WARNING_RUNS  = 10   # 2 pts × 5 runs
_CAP_INFO_RUNS     = 3    # 0.6 pts × 5 runs (rounded)
_CAP_EPISODES      = 15   # 3 pts × 5 episodes
_CAP_RECURRING     = 12   # 3 pts × 4 tokens

# Risk-level thresholds.  Picked so that:
#   - "low":      no concern, healthy
#   - "medium":   one or two soft signals (info drift, single recurrence)
#   - "high":     multiple signals or warning-level drift
#   - "critical": critical drift OR worsening + recurring severe
RISK_LEVELS = (
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0,  "low"),
)


def _level_for_score(score: int) -> str:
    for cutoff, label in RISK_LEVELS:
        if score >= cutoff:
            return label
    return "low"


def compute_risk_score(summary):
    """Return a deterministic risk dict for a trend summary.

    Output:
      {
        "risk_score":  int 0–100,
        "risk_level":  "low" | "medium" | "high" | "critical",
        "drivers":     list[str]   — short human-readable reasons,
                                     ordered by contribution.
      }

    A monitor with no runs returns score=0 / level="low" with an empty
    drivers list — there is no signal to score yet.
    """
    if not summary or summary.get("total_runs", 0) == 0:
        return {"risk_score": 0, "risk_level": "low", "drivers": []}

    # ── Sub-scores (each contribution recorded so we can rank drivers) ───────
    contributions: list = []  # (points, label)

    # 1) Inverse health — the strongest single driver because it already
    #    weights recent runs more heavily.
    health = int(summary.get("health_score") or 0)
    health_pts = round(min((100 - health) * 0.4, _CAP_HEALTH), 2)
    if health_pts > 0:
        contributions.append((health_pts, f"health score {health}/100"))

    # 2) Drift counts (cap each tier so a long noisy history can't pile up).
    drift = summary.get("drift_counts") or {}
    crit  = min(int(drift.get("critical") or 0), 5)
    warn  = min(int(drift.get("warning")  or 0), 5)
    info  = min(int(drift.get("info")     or 0), 5)
    crit_pts = min(crit * 4,   _CAP_CRITICAL_RUNS)
    warn_pts = min(warn * 2,   _CAP_WARNING_RUNS)
    info_pts = min(info * 0.6, _CAP_INFO_RUNS)
    if crit_pts: contributions.append((crit_pts, f"{crit} critical drift run(s)"))
    if warn_pts: contributions.append((warn_pts, f"{warn} warning drift run(s)"))
    if info_pts: contributions.append((info_pts, f"{info} info drift run(s)"))

    # 3) Distinct regression episodes — recurring failure pattern matters
    #    more than total bad runs in one stretch.
    episodes = int(summary.get("regression_episodes") or 0)
    ep_pts = min(episodes * 3, _CAP_EPISODES)
    if ep_pts:
        contributions.append((ep_pts, f"{episodes} regression episode(s)"))

    # 4) Worsening composite flag — fast signal that "the trend is wrong".
    if summary.get("worsening"):
        contributions.append((15, "trend marked as worsening"))

    # 5) Confidence slope — analytic disagreement is itself worth surfacing.
    conf_slope = (summary.get("confidence_trend") or {}).get("slope")
    if conf_slope == "worsening":
        contributions.append((10, "confidence trend dropping"))

    # 6) Backend delay slope — same idea on the timing axis.
    delay_slope = (summary.get("backend_delay_trend") or {}).get("slope")
    if delay_slope == "worsening":
        contributions.append((10, "backend delay trending up"))

    # 7) Recurring impairments, with a bonus for severe ones.
    recurring = summary.get("recurring_impairments") or []
    if recurring:
        rec_pts = min(len(recurring) * 3, _CAP_RECURRING)
        severe = [r for r in recurring if r.get("token") in SEVERE_RECURRING_IMPAIRMENTS]
        severe_pts = min(len(severe) * 5, 15)
        if rec_pts:
            contributions.append((
                rec_pts,
                f"{len(recurring)} recurring impairment(s)",
            ))
        if severe_pts:
            tokens = ", ".join(r["token"] for r in severe[:3])
            contributions.append((severe_pts, f"severe recurring: {tokens}"))

    # 8) Return-path-problem frequency — emphasised because it routinely
    #    indicates asymmetric routing or NAT problems that escalate.
    rpp = int(summary.get("return_path_problem_runs") or 0)
    if rpp >= 2:
        contributions.append((min(rpp * 2, 8), f"{rpp} return-path-problem run(s)"))

    # 9) At least one action_required run pulls the score up a notch even if
    #    other signals are mild — analyst attention was demanded.
    if int(summary.get("action_required_runs") or 0) > 0:
        contributions.append((5, "action required at least once"))

    raw_total = sum(pts for pts, _ in contributions)
    score = int(round(min(max(raw_total, 0), 100)))
    level = _level_for_score(score)

    # Top 5 drivers ordered by point contribution — what the user should read.
    drivers = [
        label for _pts, label in
        sorted(contributions, key=lambda x: x[0], reverse=True)[:5]
    ]

    return {
        "risk_score": score,
        "risk_level": level,
        "drivers":    drivers,
    }


# ── Action engine (deterministic, rule-based) ────────────────────────────────
#
# Turns the (summary, risk) pair into a concrete decision:
#
#   action_required     bool
#   action_label        no_action | passive_monitoring | needs_attention |
#                       requires_immediate_attention
#   priority            low | medium | high | critical
#   recommended_action  short human sentence ("what to do next")
#   focus               list of short investigation hints derived from the
#                       trend signals (used by the frontend bullet list)
#   reasons             flat list of short strings — why we took this path
#                       through the rules. Useful for debugging escalations.
#
# Pure module: no DB, no FastAPI imports, no datetime side effects, no I/O.
#
# Rules (base, before overrides):
#
#   risk >= 75 (critical):  requires_immediate_attention   priority=critical
#   risk 50–74  (high):     needs_attention                priority=high
#   risk 25–49  (medium):   passive_monitoring             priority=medium
#                                  ↳ action_required only if worsening
#   risk < 25   (low):      no_action                      priority=low
#
# Overrides (applied in order, each may escalate but never de-escalate):
#
#   1. severe recurring impairment   → escalate by one priority tier
#   2. recurring return_path_problem → always action_required = True
#   3. worsening flag + regressions  → force minimum priority = high

_PRIORITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_PRIORITY_BY_RANK = ["low", "medium", "high", "critical"]
_LABEL_BY_PRIORITY = {
    "critical": "requires_immediate_attention",
    "high":     "needs_attention",
    "medium":   "passive_monitoring",
    "low":      "no_action",
}


def _escalate(priority: str) -> str:
    """Bump a priority by one tier (critical stays critical)."""
    rank = _PRIORITY_RANK.get(priority, 0)
    rank = min(rank + 1, _PRIORITY_RANK["critical"])
    return _PRIORITY_BY_RANK[rank]


def _focus_from_signals(summary, recurring_severe, recurring_tokens) -> list:
    """Build the bullet-style investigation focus list.

    Each focus item is a short imperative sentence that the analyst can
    actually act on.  Items are deduplicated and ordered by impact so that
    the first bullet is the single most useful next step.
    """
    focus: list = []
    seen: set = set()

    def add(text):
        if text not in seen:
            focus.append(text)
            seen.add(text)

    # Backend latency increase
    if (summary.get("backend_delay_trend") or {}).get("slope") == "worsening":
        key = (summary.get("backend_delay_trend") or {}).get("key") or "backend latency"
        add(f"Investigate {key.replace('_', ' ')} increase on the destination")

    # Return path / asymmetric routing
    if (
        "return_path_problem" in recurring_tokens
        or int(summary.get("return_path_problem_runs") or 0) >= 2
    ):
        add("Check firewall / return path asymmetry")

    # No-response style failures
    if "no_response" in recurring_tokens or "syn_timeout" in recurring_tokens:
        add("Verify destination reachability and service health")

    # Connection refused
    if "connection_refused" in recurring_tokens:
        add("Confirm the listening port is up and not blocked")

    # TLS handshake
    if "tls_failure" in recurring_tokens:
        add("Inspect TLS handshake — cert chain, SNI, cipher mismatch")

    # Confidence trend
    if (summary.get("confidence_trend") or {}).get("slope") == "worsening":
        add("Re-check role hints / refresh the capture — confidence is dropping")

    # Generic recurring impairment fallback
    if not focus and recurring_severe:
        tokens = ", ".join(t for t in recurring_tokens[:2])
        add(f"Investigate recurring impairment(s): {tokens}")

    return focus


def _recommended_action(focus, priority, summary) -> str:
    """One-line recommendation for the card header.

    Falls back through several heuristics so the user always sees something
    useful, even on a fresh monitor with no history.
    """
    if focus:
        return focus[0]
    if priority == "critical":
        return "Open the latest run and investigate immediately"
    if priority == "high":
        return "Review the recent drift event"
    if priority == "medium":
        if summary.get("worsening"):
            return "Trend is degrading — keep an eye on the next run"
        return "Continue passive monitoring"
    return "No action — path is healthy"


def decide_action(summary, risk):
    """Deterministic rule engine that turns (summary, risk) into an action.

    ``summary`` is the dict from ``summarize_history`` and ``risk`` is the
    dict from ``compute_risk_score``. Both must already be computed; this
    function performs no I/O of its own.

    Returns a dict shaped for direct serialisation onto the monitor row.
    """
    risk_score = int((risk or {}).get("risk_score") or 0)
    risk_level = (risk or {}).get("risk_level") or "low"
    summary    = summary or {}

    recurring = summary.get("recurring_impairments") or []
    recurring_tokens = [r.get("token") for r in recurring if r.get("token")]
    recurring_severe = [
        r for r in recurring
        if r.get("token") in SEVERE_RECURRING_IMPAIRMENTS
    ]

    reasons: list = []

    # ── Base mapping from risk_level to priority ─────────────────────────────
    if risk_level == "critical":
        priority = "critical"
        action_required = True
        reasons.append(f"risk {risk_score}/100 in CRITICAL band")
    elif risk_level == "high":
        priority = "high"
        action_required = True
        reasons.append(f"risk {risk_score}/100 in HIGH band")
    elif risk_level == "medium":
        priority = "medium"
        action_required = bool(summary.get("worsening"))
        reasons.append(f"risk {risk_score}/100 in MEDIUM band")
        if action_required:
            reasons.append("medium risk + worsening flag → action required")
    else:
        priority = "low"
        action_required = False
        if summary.get("total_runs", 0) > 0:
            reasons.append(f"risk {risk_score}/100 in LOW band")
        else:
            reasons.append("no history yet")

    # ── Override 1: severe recurring impairment escalates one tier ───────────
    if recurring_severe:
        old = priority
        priority = _escalate(priority)
        action_required = action_required or (priority != "low")
        if priority != old:
            tokens = ", ".join(r["token"] for r in recurring_severe[:2])
            reasons.append(
                f"escalated {old}→{priority}: severe recurring ({tokens})"
            )

    # ── Override 2: recurring return_path_problem always demands action ──────
    if (
        "return_path_problem" in recurring_tokens
        or int(summary.get("return_path_problem_runs") or 0) >= 2
    ):
        if not action_required:
            action_required = True
            reasons.append("recurring return_path_problem → action required")

    # ── Override 3: worsening + regression episodes force ≥ HIGH ─────────────
    if (
        summary.get("worsening")
        and int(summary.get("regression_episodes") or 0) >= 1
        and _PRIORITY_RANK[priority] < _PRIORITY_RANK["high"]
    ):
        old = priority
        priority = "high"
        action_required = True
        reasons.append(
            f"escalated {old}→high: worsening trend + regression episode"
        )

    # ── Build the human-facing fields ───────────────────────────────────────
    focus = _focus_from_signals(summary, recurring_severe, recurring_tokens)
    label = _LABEL_BY_PRIORITY[priority]
    recommended = _recommended_action(focus, priority, summary)

    return {
        "action_required":    action_required,
        "action_label":       label,
        "priority":           priority,
        "recommended_action": recommended,
        "focus":              focus,
        "reasons":            reasons,
    }


# ── Outcome learning ─────────────────────────────────────────────────────────
#
# Pure heuristic module that:
#   1. ``learn_from_outcomes(outcomes)`` — aggregates outcome records into a
#      compact "learnings" dict (signal → outcome counters, dominant root
#      cause, false-positive rate).
#   2. ``adjust_action(action, learnings)`` — patches a decide_action result
#      so recommendations adapt to historical outcomes (strengthen confirmed
#      signals, soften noisy ones, surface dominant root cause).
#
# No ML.  The model is a flat counter table: for each signal (driver string
# normalised to a key), how many times was the outcome confirmed / FP /
# transient?  Plus an overall root-cause distribution.
#
# Both functions are pure (no DB, no I/O).

# Canonical outcome values
VALID_OUTCOMES = (
    "issue_confirmed",
    "false_positive",
    "transient_issue",
    "root_cause_identified",
)
VALID_ROOT_CAUSE_TYPES = ("network", "firewall", "app", "dns", "unknown")

# Positive-signal outcomes = "this alert was real or partially real".
_CONFIRMED_OUTCOMES = {"issue_confirmed", "root_cause_identified"}

# Threshold above which a signal's false-positive ratio is considered "noisy".
_FP_NOISY_THRESHOLD = 0.6   # ≥ 60% FP
# Threshold above which a signal's confirmation ratio strengthens the rec.
_CONFIRM_STRONG_THRESHOLD = 0.7  # ≥ 70% confirmed


def _driver_key(driver: str) -> str:
    """Normalise a risk-driver string to a stable counter key.

    The risk_drivers list contains sentences like:
        "5 critical drift run(s)"
        "health score 12/100"
        "severe recurring: no_response, tls_failure"

    We collapse these to a keyword so that e.g. "5 critical drift run(s)"
    and "3 critical drift run(s)" share the same counter bucket.
    """
    d = driver.lower()
    if "critical drift" in d:
        return "critical_drift"
    if "warning drift" in d:
        return "warning_drift"
    if "info drift" in d:
        return "info_drift"
    if "health score" in d:
        return "health_score"
    if "regression episode" in d:
        return "regression_episodes"
    if "worsening" in d:
        return "trend_worsening"
    if "confidence" in d:
        return "confidence_dropping"
    if "backend delay" in d:
        return "backend_delay"
    if "severe recurring" in d:
        return "severe_recurring"
    if "recurring impairment" in d:
        return "recurring_impairment"
    if "return-path-problem" in d or "return_path_problem" in d:
        return "return_path_problem"
    if "action required" in d:
        return "action_required"
    return d.replace(" ", "_")[:40]


def learn_from_outcomes(outcomes):
    """Aggregate a list of outcome dicts into a compact learnings dict.

    Each element of ``outcomes`` should have the shape stored in
    ``MonitorOutcomeModel``:
      {
        "outcome": str,
        "root_cause_type": str | None,
        "signal_drivers": list[str],   # already-decoded
      }

    Returns:
      {
        "total":               int,
        "confirmed":           int,    # issue_confirmed + root_cause_identified
        "false_positives":     int,
        "transient":           int,
        "fp_rate":             float,  # false_positives / total (0 if total==0)
        "dominant_root_cause": str | None,
        "root_cause_dist":     {type: count},
        "signal_stats":        {driver_key: {confirmed, fp, total, fp_rate, confirm_rate}},
        "hints":               [str],  # human-readable learnings
      }
    """
    total = len(outcomes)
    confirmed = 0
    false_positives = 0
    transient = 0
    root_counts: dict = {}
    signal_confirmed: dict = {}
    signal_fp: dict = {}
    signal_total: dict = {}

    for o in outcomes:
        out = o.get("outcome")
        if out in _CONFIRMED_OUTCOMES:
            confirmed += 1
        elif out == "false_positive":
            false_positives += 1
        elif out == "transient_issue":
            transient += 1

        rct = o.get("root_cause_type")
        if rct:
            root_counts[rct] = root_counts.get(rct, 0) + 1

        for driver in o.get("signal_drivers") or []:
            key = _driver_key(driver)
            signal_total[key] = signal_total.get(key, 0) + 1
            if out in _CONFIRMED_OUTCOMES:
                signal_confirmed[key] = signal_confirmed.get(key, 0) + 1
            elif out == "false_positive":
                signal_fp[key] = signal_fp.get(key, 0) + 1

    fp_rate = round(false_positives / total, 3) if total else 0.0
    dominant_root_cause = (
        max(root_counts, key=root_counts.get) if root_counts else None
    )

    signal_stats: dict = {}
    for key in sorted(set(signal_total)):
        c = signal_confirmed.get(key, 0)
        f = signal_fp.get(key, 0)
        t = signal_total[key]
        signal_stats[key] = {
            "confirmed":    c,
            "fp":           f,
            "total":        t,
            "fp_rate":      round(f / t, 3) if t else 0.0,
            "confirm_rate": round(c / t, 3) if t else 0.0,
        }

    hints = _build_hints(
        total, confirmed, false_positives, transient,
        dominant_root_cause, root_counts, signal_stats,
    )

    return {
        "total":               total,
        "confirmed":           confirmed,
        "false_positives":     false_positives,
        "transient":           transient,
        "fp_rate":             fp_rate,
        "dominant_root_cause": dominant_root_cause,
        "root_cause_dist":     root_counts,
        "signal_stats":        signal_stats,
        "hints":               hints,
    }


def _build_hints(
    total, confirmed, false_positives, transient,
    dominant_root_cause, root_counts, signal_stats,
) -> list:
    """Synthesise 0–5 human-readable learning hints."""
    hints: list = []
    if total == 0:
        return hints

    # Dominant root cause
    if dominant_root_cause and root_counts.get(dominant_root_cause, 0) >= 2:
        n = root_counts[dominant_root_cause]
        hints.append(
            f"Historically this path was caused by {dominant_root_cause} "
            f"issues ({n}/{total} outcomes)"
        )

    # High false-positive rate
    fp_rate = false_positives / total if total else 0
    if false_positives >= 2 and fp_rate >= _FP_NOISY_THRESHOLD:
        pct = round(fp_rate * 100)
        hints.append(
            f"This monitor has a {pct}% false-positive rate — "
            f"consider adjusting thresholds"
        )

    # Strongly-confirmed signals
    for key, st in sorted(signal_stats.items()):
        if st["total"] >= 2 and st["confirm_rate"] >= _CONFIRM_STRONG_THRESHOLD:
            label = key.replace("_", " ")
            hints.append(
                f"'{label}' signal confirmed {st['confirmed']}/{st['total']} "
                f"times — high reliability"
            )

    # Noisy signals
    for key, st in sorted(signal_stats.items()):
        if st["total"] >= 2 and st["fp_rate"] >= _FP_NOISY_THRESHOLD:
            label = key.replace("_", " ")
            hints.append(
                f"'{label}' signal was false-positive {st['fp']}/{st['total']} "
                f"times — may be noisy"
            )

    # Transient pattern
    if transient >= 2:
        hints.append(
            f"This path had {transient} transient/self-resolving issues — "
            f"consider allowing more settling time"
        )

    return hints[:5]


def adjust_action(action, learnings):
    """Patch a ``decide_action`` result using historical outcome learnings.

    Modifications (in order):
      1. Append ``learnings["hints"]`` to ``action["focus"]`` so the analyst
         sees the historical context alongside the signal-based next steps.
      2. If the overall FP rate is very high (≥ 60% over ≥ 3 outcomes),
         de-prioritise: drop ``priority`` by one tier and set
         ``action_required = False``.  (The analyst keeps the option to
         investigate but the system doesn't flash red.)
      3. If any signal in the current action has a very high confirmation
         rate (≥ 70%), prepend a "historically confirmed" note to
         ``recommended_action`` so the analyst knows this signal is reliable.
      4. If the dominant root cause is known, prepend a root-cause hint to
         the focus list.

    Returns a NEW dict (action is not mutated).
    """
    if not learnings or learnings.get("total", 0) == 0:
        return action

    a = dict(action)  # shallow copy
    a["focus"] = list(a.get("focus") or [])
    a["reasons"] = list(a.get("reasons") or [])

    # 4 — Root-cause hint first (most valuable for the analyst)
    rc = learnings.get("dominant_root_cause")
    rc_dist = learnings.get("root_cause_dist") or {}
    if rc and rc_dist.get(rc, 0) >= 2:
        n = rc_dist[rc]
        total = learnings["total"]
        a["focus"].insert(
            0,
            f"Historically caused by {rc} issues ({n}/{total} past outcomes)"
        )

    # 3 — Strengthen a confirmed signal's recommendation
    stats = learnings.get("signal_stats") or {}
    for key, st in stats.items():
        if st["total"] >= 2 and st["confirm_rate"] >= _CONFIRM_STRONG_THRESHOLD:
            label = key.replace("_", " ")
            prefix = f"[confirmed {st['confirmed']}/{st['total']}×] "
            if prefix.lower() not in a.get("recommended_action", "").lower():
                a["recommended_action"] = prefix + a.get("recommended_action", "")
            break  # only strengthen one (the first matching)

    # 2 — De-prioritise noisy monitors
    fp_rate = learnings.get("fp_rate", 0)
    total = learnings.get("total", 0)
    if total >= 3 and fp_rate >= _FP_NOISY_THRESHOLD:
        old = a["priority"]
        rank = _PRIORITY_RANK.get(old, 0)
        rank = max(rank - 1, 0)
        a["priority"] = _PRIORITY_BY_RANK[rank]
        a["action_label"] = _LABEL_BY_PRIORITY[a["priority"]]
        a["action_required"] = False
        a["reasons"].append(
            f"de-prioritised {old}→{a['priority']}: "
            f"{round(fp_rate * 100)}% FP rate over {total} outcomes"
        )

    # 1 — Append hints
    for h in learnings.get("hints") or []:
        if h not in a["focus"]:
            a["focus"].append(h)

    return a


# ── Cross-monitor / system-wide intelligence ─────────────────────────────────
#
# ``compute_system_insights`` aggregates across every monitor's outcomes and
# recent runs to produce a single dashboard payload.  Pure function — the
# caller in main.py fetches the rows and converts them to dicts.
#
# Inputs (all lists of plain dicts):
#
#   monitors  — [{id, destination_ip, source_ip, saved_query_name,
#                  risk_score, risk_level, action_required, last_drift_severity,
#                  ...}]
#   outcomes  — union of all MonitorOutcomeModel rows across every monitor
#               [{outcome, root_cause_type, signal_drivers, monitored_path_id}]
#   recent_runs — most recent N runs per monitor
#               [{monitored_path_id, run_at, connection_outcome,
#                 primary_impairment, impairments, drift_severity, ...}]

_IMPAIRMENT_DISPLAY = {
    "no_response": "No response",
    "connection_refused": "Connection refused",
    "tls_failure": "TLS failure",
    "syn_timeout": "SYN timeout",
    "return_path_problem": "Return path problem",
    "backend_response_delay": "Backend delay",
    "packet_loss": "Packet loss",
    "firewall_interference": "Firewall interference",
    "lb_backend_issue": "LB / backend issue",
}


def compute_system_insights(monitors, outcomes, recent_runs):
    """Produce a system-wide intelligence digest.

    Returns a dict with the sections consumed by the frontend dashboard
    widget.  Every section is designed to fit in a compact card so the
    analyst can scan the system state in ≤10 seconds.
    """
    # ── 1. Global outcome aggregation ────────────────────────────────────────
    global_learnings = learn_from_outcomes(outcomes)

    # ── 2. Signal effectiveness (global) ─────────────────────────────────────
    # The per-signal stats are already in global_learnings.signal_stats.
    # We sort by confirm_rate descending so the "most reliable" signal is
    # first, and separately collect "noisiest" signals.
    signal_stats = global_learnings.get("signal_stats") or {}
    reliable_signals = sorted(
        (
            {"signal": k, **v}
            for k, v in signal_stats.items()
            if v["total"] >= 2
        ),
        key=lambda x: (-x["confirm_rate"], -x["total"]),
    )[:5]
    noisy_signals = sorted(
        (
            {"signal": k, **v}
            for k, v in signal_stats.items()
            if v["total"] >= 2 and v["fp_rate"] >= 0.5
        ),
        key=lambda x: (-x["fp_rate"], -x["total"]),
    )[:5]

    # ── 3. Correlation detection ─────────────────────────────────────────────
    # 3a. Monitors with the same current impairment or drift grouped by dest IP
    dest_groups: Dict[str, list] = {}
    for m in monitors:
        dst = m.get("destination_ip")
        if dst:
            dest_groups.setdefault(dst, []).append(m)

    # Active impairments per destination: if ≥2 monitors on the same dest
    # are currently degraded, flag as potential systemic issue.
    systemic_destinations: list = []
    for dst, group in dest_groups.items():
        degraded = [
            m for m in group
            if m.get("last_drift_severity") in ("warning", "critical")
            or m.get("action_required")
        ]
        if len(degraded) >= 2:
            systemic_destinations.append({
                "destination_ip": dst,
                "affected_count": len(degraded),
                "monitors": [
                    {
                        "id": m["id"],
                        "name": m.get("saved_query_name") or f"Monitor #{m['id']}",
                        "risk_score": m.get("risk_score", 0),
                        "risk_level": m.get("risk_level", "low"),
                    }
                    for m in degraded
                ],
            })
    systemic_destinations.sort(key=lambda x: -x["affected_count"])

    # 3b. Shared impairment across monitors (recent runs) — if the same
    # impairment appears on ≥2 different monitors in recent runs, it may be
    # infrastructure-wide.
    imp_to_monitors: Dict[str, set] = {}
    for r in recent_runs:
        mid = r.get("monitored_path_id")
        for imp in r.get("impairments") or []:
            imp_to_monitors.setdefault(imp, set()).add(mid)
    shared_impairments = sorted(
        (
            {
                "impairment": imp,
                "display": _IMPAIRMENT_DISPLAY.get(imp, imp.replace("_", " ")),
                "monitor_count": len(mids),
            }
            for imp, mids in imp_to_monitors.items()
            if len(mids) >= 2
        ),
        key=lambda x: (-x["monitor_count"], x["impairment"]),
    )[:10]

    # ── 4. System risk distribution ──────────────────────────────────────────
    risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    total_risk = 0
    for m in monitors:
        lvl = m.get("risk_level") or "low"
        risk_dist[lvl] = risk_dist.get(lvl, 0) + 1
        total_risk += int(m.get("risk_score") or 0)
    avg_risk = round(total_risk / len(monitors)) if monitors else 0

    action_required_count = sum(1 for m in monitors if m.get("action_required"))

    # ── 5. Top-level headline bullets (≤5) ───────────────────────────────────
    headlines: list = []

    rc = global_learnings.get("dominant_root_cause")
    rc_dist = global_learnings.get("root_cause_dist") or {}
    total_outcomes = global_learnings.get("total", 0)
    if rc and rc_dist.get(rc, 0) >= 2 and total_outcomes:
        pct = round(100 * rc_dist[rc] / total_outcomes)
        headlines.append(
            f"Most common root cause: {rc} ({pct}%)"
        )

    if reliable_signals:
        top = reliable_signals[0]
        label = top["signal"].replace("_", " ")
        headlines.append(
            f"Most reliable signal: '{label}' "
            f"(confirmed {top['confirmed']}/{top['total']})"
        )

    if noisy_signals:
        top = noisy_signals[0]
        label = top["signal"].replace("_", " ")
        pct = round(top["fp_rate"] * 100)
        headlines.append(
            f"Noisiest signal: '{label}' ({pct}% false positive)"
        )

    if systemic_destinations:
        top = systemic_destinations[0]
        headlines.append(
            f"Potential systemic issue at {top['destination_ip']} "
            f"({top['affected_count']} monitors affected)"
        )

    if shared_impairments:
        top = shared_impairments[0]
        headlines.append(
            f"'{top['display']}' seen across {top['monitor_count']} monitors"
        )

    fp_rate = global_learnings.get("fp_rate", 0)
    if total_outcomes >= 3 and fp_rate >= 0.5:
        headlines.append(
            f"System-wide FP rate is {round(fp_rate * 100)}% — "
            f"review thresholds"
        )

    return {
        "monitor_count":           len(monitors),
        "action_required_count":   action_required_count,
        "avg_risk_score":          avg_risk,
        "risk_distribution":       risk_dist,
        "headlines":               headlines[:5],
        # Global outcome aggregation
        "outcome_total":           total_outcomes,
        "outcome_confirmed":       global_learnings.get("confirmed", 0),
        "outcome_false_positives": global_learnings.get("false_positives", 0),
        "outcome_transient":       global_learnings.get("transient", 0),
        "outcome_fp_rate":         fp_rate,
        "dominant_root_cause":     rc,
        "root_cause_distribution": rc_dist,
        # Signal intelligence
        "reliable_signals":        reliable_signals,
        "noisy_signals":           noisy_signals,
        # Correlation
        "systemic_destinations":   systemic_destinations,
        "shared_impairments":      shared_impairments,
    }


# ── Suppression + baseline adaptation ─────────────────────────────────────────
#
# Two pure helpers that sit between compute_risk_score / decide_action and the
# final response dict:
#
#   apply_suppressions(action, suppressions, *, now) — checks active
#       suppression rules and may flip action_required to False, lower
#       priority, and annotate reasons[].
#
#   apply_baseline(action, risk_summary, baseline) — inspects baseline
#       expectations (accepted delay, accepted confidence range, known
#       noisy impairments) and may reduce the risk-derived priority, add
#       de-emphasis notes, and annotate reasons[].
#
# Both return a NEW dict (never mutate the input).

VALID_SUPPRESSION_KINDS = ("mute", "snooze", "impairment", "severity")


def _is_suppression_active(rule, now) -> bool:
    """Check enabled + within time window."""
    if not rule.get("enabled", True):
        return False
    until = rule.get("until")
    if until is not None:
        # ``until`` may be a datetime or an ISO string
        if isinstance(until, str):
            try:
                from datetime import datetime as _dt
                until = _dt.fromisoformat(until)
            except (ValueError, TypeError):
                return False
        if now > until:
            return False
    return True


def apply_suppressions(action, suppressions, *, now):
    """Apply active suppression rules to an action dict.

    ``suppressions`` is a list of dicts with the shape stored in
    ``MonitorSuppressionModel``:
      {kind, value, reason, enabled, until}

    Returns a NEW action dict.  The ``suppressed`` key is always present
    (True when any rule fired) and ``suppressed_rules`` lists the ids/kinds
    that fired, for audit display.
    """
    a = dict(action)
    a["focus"] = list(a.get("focus") or [])
    a["reasons"] = list(a.get("reasons") or [])
    a["suppressed"] = False
    a["suppressed_rules"] = []

    if not suppressions:
        return a

    active = [s for s in suppressions if _is_suppression_active(s, now)]
    if not active:
        return a

    for rule in active:
        kind = rule.get("kind")
        rid = rule.get("id")

        if kind in ("mute", "snooze"):
            # Full suppression — disable action_required, drop to low
            a["action_required"] = False
            a["priority"] = "low"
            a["action_label"] = _LABEL_BY_PRIORITY["low"]
            a["suppressed"] = True
            a["suppressed_rules"].append({"id": rid, "kind": kind})
            reason_text = rule.get("reason") or kind
            a["reasons"].append(f"suppressed ({kind}): {reason_text}")
            break  # mute/snooze is total — no point checking further

        elif kind == "impairment":
            # Only suppress if the target impairment appears in focus or
            # the action was driven by this impairment.  We check the
            # action's focus list for the token.
            token = (rule.get("value") or "").strip()
            if not token:
                continue
            focus_text = " ".join(a["focus"]).lower()
            drivers_text = " ".join(
                r for r in a.get("reasons", [])
            ).lower()
            if token.lower() in focus_text or token.lower() in drivers_text:
                a["suppressed"] = True
                a["suppressed_rules"].append({"id": rid, "kind": kind, "value": token})
                a["reasons"].append(
                    f"suppressed impairment '{token}': "
                    + (rule.get("reason") or "known noisy")
                )
                # Don't fully suppress — just de-escalate one tier
                rank = _PRIORITY_RANK.get(a["priority"], 0)
                rank = max(rank - 1, 0)
                a["priority"] = _PRIORITY_BY_RANK[rank]
                a["action_label"] = _LABEL_BY_PRIORITY[a["priority"]]
                if a["priority"] == "low":
                    a["action_required"] = False

        elif kind == "severity":
            # Suppress drifts AT OR BELOW the specified severity.
            # This affects action_required: if the current drift severity
            # is at or below the suppressed level, clear action_required.
            max_sev = (rule.get("value") or "none").strip()
            max_rank = _DRIFT_SEVERITY_RANK.get(max_sev, 0)
            # We don't have drift_severity on the action dict directly —
            # but we can read the base priority.  If priority maps to a
            # severity at or below the suppression level, de-escalate.
            if _PRIORITY_RANK.get(a["priority"], 0) <= max_rank:
                a["action_required"] = False
                a["suppressed"] = True
                a["suppressed_rules"].append({"id": rid, "kind": kind, "value": max_sev})
                a["reasons"].append(
                    f"suppressed severity ≤ {max_sev}: "
                    + (rule.get("reason") or "accepted")
                )

    return a


def apply_baseline(action, summary, baseline):
    """Reduce noise for signals that fall within the monitor's baseline.

    ``baseline`` is the parsed JSON blob from ``MonitoredPathModel.baseline_json``:
      {
        "accepted_delay_max_ms":   float | None,
        "accepted_confidence_min": int   | None,
        "known_noisy_impairments": [str, ...],
        "known_visibility_gaps":   [str, ...],
      }

    Returns a NEW action dict with ``baseline_applied`` set to True when
    any rule fired.  The focus list may gain "de-emphasised" notes so the
    analyst can see *why* the system lowered the priority.
    """
    a = dict(action)
    a["focus"] = list(a.get("focus") or [])
    a["reasons"] = list(a.get("reasons") or [])
    a["baseline_applied"] = False

    if not baseline:
        return a

    deemphasis_count = 0

    # 1. Accepted backend delay range — if the trend's recent avg is within
    #    the accepted range, remove the backend-delay-related focus items
    #    and lower severity if backend delay was the main driver.
    accepted_delay = baseline.get("accepted_delay_max_ms")
    if accepted_delay is not None and summary:
        bd = summary.get("backend_delay_trend") or {}
        recent_avg = bd.get("recent_avg")
        if (
            recent_avg is not None
            and isinstance(recent_avg, (int, float))
            and recent_avg <= accepted_delay
        ):
            a["baseline_applied"] = True
            deemphasis_count += 1
            a["reasons"].append(
                f"baseline: backend delay {recent_avg}ms ≤ accepted {accepted_delay}ms"
            )
            # Remove backend-delay-related focus items
            a["focus"] = [
                f for f in a["focus"]
                if "backend" not in f.lower() and "latency" not in f.lower()
            ]
            a["focus"].append(
                f"(de-emphasised: backend delay within accepted range ≤{accepted_delay}ms)"
            )

    # 2. Accepted confidence range
    accepted_conf = baseline.get("accepted_confidence_min")
    if accepted_conf is not None and summary:
        ct = summary.get("confidence_trend") or {}
        recent_avg = ct.get("recent_avg")
        if (
            recent_avg is not None
            and isinstance(recent_avg, (int, float))
            and recent_avg >= accepted_conf
        ):
            a["baseline_applied"] = True
            deemphasis_count += 1
            a["reasons"].append(
                f"baseline: confidence {recent_avg} ≥ accepted min {accepted_conf}"
            )
            a["focus"] = [
                f for f in a["focus"]
                if "confidence" not in f.lower()
            ]

    # 3. Known noisy impairments — matching impairments in focus are
    #    de-emphasised (not removed, so the audit trail stays intact).
    known_noisy = set(baseline.get("known_noisy_impairments") or [])
    if known_noisy:
        for imp in known_noisy:
            # Match the impairment token loosely against focus + reasons.
            # We check the raw token, its human form, and a shortened
            # version (first two words) so "return_path_problem" still
            # matches focus text like "return path asymmetry".
            imp_low = imp.lower()
            imp_human = imp_low.replace("_", " ")
            imp_short = " ".join(imp_human.split()[:2])  # "return path"
            all_text = " ".join(a["focus"] + a["reasons"]).lower()
            if imp_low in all_text or imp_human in all_text or (
                len(imp_short) >= 4 and imp_short in all_text
            ):
                a["baseline_applied"] = True
                deemphasis_count += 1
                a["reasons"].append(f"baseline: '{imp}' is a known noisy impairment")
                a["focus"].append(
                    f"(de-emphasised: '{imp}' is known noisy for this path)"
                )

    # 4. Known visibility gaps — informational only, appended to focus so
    #    the analyst is reminded when interpreting results.
    gaps = baseline.get("known_visibility_gaps") or []
    for gap in gaps[:3]:
        a["focus"].append(f"(known gap: {gap})")

    # If multiple baseline rules fired, de-escalate priority by one tier
    # (capped at low) to reduce the overall noise floor.
    if deemphasis_count >= 2:
        rank = _PRIORITY_RANK.get(a["priority"], 0)
        rank = max(rank - 1, 0)
        old = a["priority"]
        a["priority"] = _PRIORITY_BY_RANK[rank]
        a["action_label"] = _LABEL_BY_PRIORITY[a["priority"]]
        if a["priority"] == "low":
            a["action_required"] = False
        a["reasons"].append(
            f"baseline: {deemphasis_count} rules matched → "
            f"de-escalated {old}→{a['priority']}"
        )
        a["baseline_applied"] = True

    return a


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
