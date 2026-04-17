"""
calibration_metrics.py — Path Analysis calibration helper.

Accepts a list of PathAnalysisFeedback records (ORM instances, dataclasses,
or plain dicts) and returns five structured metric groups.

Usage:
    from core.calibration_metrics import compute_calibration_metrics

    rows = db.query(PathAnalysisFeedbackModel).all()
    metrics = compute_calibration_metrics(rows)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


# ── Confidence bucket definitions ─────────────────────────────────────────────

_BUCKETS: List[tuple] = [
    ("0-39",   0,   39),
    ("40-59",  40,  59),
    ("60-74",  60,  74),
    ("75-89",  75,  89),
    ("90-100", 90, 100),
]


def _get(row: Any, field: str) -> Any:
    """Uniform attribute access for ORM instances, dataclasses, and dicts."""
    if isinstance(row, dict):
        return row.get(field)
    return getattr(row, field, None)


def _is_correct(verdict: Optional[str]) -> bool:
    return verdict in ("correct", "partially_correct")


def _bucket_label(confidence: int) -> str:
    for label, lo, hi in _BUCKETS:
        if lo <= confidence <= hi:
            return label
    return "unknown"


def _empty_verdict_counts() -> Dict[str, int]:
    return {"correct": 0, "partially_correct": 0, "incorrect": 0}


def _accuracy(counts: Dict[str, int]) -> Optional[float]:
    total = counts.get("correct", 0) + counts.get("partially_correct", 0) + counts.get("incorrect", 0)
    if total == 0:
        return None
    correct_n = counts["correct"] + counts["partially_correct"]
    return round(correct_n / total, 4)


# ── Public entry point ─────────────────────────────────────────────────────────

def compute_calibration_metrics(rows: List[Any]) -> Dict[str, Any]:
    """
    Compute calibration metrics over a list of PathAnalysisFeedback records.

    Each row must expose (via attribute or dict key):
        predicted_confidence  int 0–100
        predicted_impairment  str | None
        predicted_outcome     str
        verdict               "correct" | "partially_correct" | "incorrect"
        misleading_step       str | None

    Returns a dict with five top-level keys:

        overconfident_incorrect_rate
            Fraction of high-confidence (≥75) predictions that were incorrect.
            High confidence + incorrect = the engine was misleading.

        underconfident_correct_rate
            Fraction of low-confidence (≤50) predictions that were actually
            correct. Low confidence + correct = the engine was too conservative.

        confidence_bucket_accuracy
            Per-bucket breakdown covering the full 0–100 range.

        impairment_accuracy
            Per-predicted-impairment-token accuracy.

        misleading_narrative_frequency
            Frequency table of reported misleading path steps, sorted by count.
    """
    if not rows:
        return {
            "total": 0,
            "overconfident_incorrect_rate": None,
            "underconfident_correct_rate": None,
            "confidence_bucket_accuracy": [],
            "impairment_accuracy": [],
            "misleading_narrative_frequency": [],
        }

    # ── Accumulators ──────────────────────────────────────────────────────────

    high_conf_total    = 0   # confidence >= 75
    high_conf_incorrect= 0
    low_conf_total     = 0   # confidence <= 50
    low_conf_correct   = 0

    bucket_counts: Dict[str, Dict[str, int]] = {
        label: _empty_verdict_counts() for label, *_ in _BUCKETS
    }

    impairment_counts: Dict[str, Dict[str, int]] = {}

    misleading: Dict[str, int] = {}

    # ── Single pass over rows ─────────────────────────────────────────────────

    for row in rows:
        confidence  = _get(row, "predicted_confidence") or 0
        impairment  = _get(row, "predicted_impairment") or "none"
        verdict     = _get(row, "verdict") or "incorrect"
        m_step      = _get(row, "misleading_step")

        # overconfident / underconfident tallies
        if confidence >= 75:
            high_conf_total += 1
            if verdict == "incorrect":
                high_conf_incorrect += 1

        if confidence <= 50:
            low_conf_total += 1
            if _is_correct(verdict):
                low_conf_correct += 1

        # confidence bucket
        label = _bucket_label(confidence)
        if label in bucket_counts:
            bucket_counts[label][verdict] = bucket_counts[label].get(verdict, 0) + 1

        # impairment breakdown
        imp_entry = impairment_counts.setdefault(impairment, _empty_verdict_counts())
        imp_entry[verdict] = imp_entry.get(verdict, 0) + 1

        # misleading narrative
        if m_step:
            step = m_step.strip()
            if step:
                misleading[step] = misleading.get(step, 0) + 1

    # ── Derived rates ─────────────────────────────────────────────────────────

    overconfident_incorrect_rate = (
        round(high_conf_incorrect / high_conf_total, 4)
        if high_conf_total > 0 else None
    )

    underconfident_correct_rate = (
        round(low_conf_correct / low_conf_total, 4)
        if low_conf_total > 0 else None
    )

    # ── Serialise confidence buckets ──────────────────────────────────────────

    confidence_bucket_accuracy = []
    for label, lo, hi in _BUCKETS:
        counts = bucket_counts[label]
        total  = counts["correct"] + counts["partially_correct"] + counts["incorrect"]
        confidence_bucket_accuracy.append({
            "label":             label,
            "range":             [lo, hi],
            "total":             total,
            "correct":           counts["correct"],
            "partially_correct": counts["partially_correct"],
            "incorrect":         counts["incorrect"],
            "accuracy_rate":     _accuracy(counts),
        })

    # ── Serialise impairment accuracy ─────────────────────────────────────────

    impairment_accuracy = sorted(
        [
            {
                "predicted_impairment": imp,
                "total":             c["correct"] + c["partially_correct"] + c["incorrect"],
                "correct":           c["correct"],
                "partially_correct": c["partially_correct"],
                "incorrect":         c["incorrect"],
                "accuracy_rate":     _accuracy(c),
            }
            for imp, c in impairment_counts.items()
        ],
        key=lambda x: -x["total"],
    )

    # ── Serialise misleading narrative frequency ──────────────────────────────

    misleading_narrative_frequency = sorted(
        [{"step": step, "count": count} for step, count in misleading.items()],
        key=lambda x: -x["count"],
    )

    return {
        "total":                        len(rows),
        "overconfident_incorrect_rate": overconfident_incorrect_rate,
        "underconfident_correct_rate":  underconfident_correct_rate,
        "confidence_bucket_accuracy":   confidence_bucket_accuracy,
        "impairment_accuracy":          impairment_accuracy,
        "misleading_narrative_frequency": misleading_narrative_frequency,
    }
