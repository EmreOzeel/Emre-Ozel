"""
Calibration guardrail regression tests for CausalPathEngine.

Loads the committed baseline snapshot and compares it against metrics
computed from the same reproducible corpus.  Any worsening beyond the
declared tolerances causes a test failure with a human-readable message
that names the metric, the baseline value, the current value, and the
allowed tolerance.

To intentionally update the baseline after an approved engine change:
    cd backend
    python tests/fixtures/path_calibration_baseline_corpus.py \
        > tests/fixtures/path_calibration_baseline.json
Then commit both files together and re-run this suite.
"""
from __future__ import annotations

import json
import pathlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from core.calibration_metrics import compute_calibration_metrics
from tests.fixtures.path_calibration_baseline_corpus import CORPUS

# ── Load baseline ─────────────────────────────────────────────────────────────

_BASELINE_PATH = (
    pathlib.Path(__file__).parent / "fixtures" / "path_calibration_baseline.json"
)

with _BASELINE_PATH.open(encoding="utf-8") as _f:
    _BASELINE: dict = json.load(_f)

# ── Compute current metrics once for the whole module ─────────────────────────

_CURRENT: dict = compute_calibration_metrics(CORPUS)

# ── Tolerances ────────────────────────────────────────────────────────────────

_TOL_OVERCONFIDENT  = 0.05   # max allowed absolute increase in overconfident rate
_TOL_UNDERCONFIDENT = 0.10   # max allowed absolute decrease in underconfident rate
_TOL_BUCKET         = 0.10   # max allowed drop per confidence bucket accuracy_rate
_TOL_IMPAIRMENT     = 0.10   # max allowed drop per impairment accuracy_rate
_TOL_MISLEADING     = 1      # max allowed count increase per misleading step


# ══════════════════════════════════════════════════════════════════════════════
# A — overconfident_incorrect_rate
# ══════════════════════════════════════════════════════════════════════════════

class TestOverconfidentRate:
    """
    Engine must not become more overconfident.

    overconfident_incorrect_rate = fraction of ≥75-confidence predictions
    that analysts judged incorrect.  An increase means more high-confidence
    wrong answers — the most harmful calibration failure.

    Tolerance: current may be AT MOST +0.05 above baseline.
    """

    def test_overconfident_rate_not_worsened(self):
        baseline = _BASELINE["overconfident_incorrect_rate"]
        current  = _CURRENT["overconfident_incorrect_rate"]

        if baseline is None and current is None:
            return  # no high-confidence data in either — pass

        if baseline is None:
            return  # baseline had no data; cannot compare — pass conservatively

        if current is None:
            # Corpus produced no high-confidence rows now; treat as 0.
            current = 0.0

        limit = round(baseline + _TOL_OVERCONFIDENT, 6)
        assert current <= limit, (
            f"overconfident_incorrect_rate worsened.\n"
            f"  baseline : {baseline}\n"
            f"  current  : {current}\n"
            f"  limit    : {limit}  (baseline + {_TOL_OVERCONFIDENT})\n"
            f"  worsened by {round(current - baseline, 4)}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# B — underconfident_correct_rate
# ══════════════════════════════════════════════════════════════════════════════

class TestUnderconfidentRate:
    """
    Engine must not become more underconfident on cases it gets right.

    underconfident_correct_rate = fraction of ≤50-confidence predictions
    that were actually correct.  A drop means the engine started hedging
    on easy, unambiguous cases.

    Tolerance: current may be AT MOST -0.10 below baseline.
    """

    def test_underconfident_rate_not_dropped(self):
        baseline = _BASELINE["underconfident_correct_rate"]
        current  = _CURRENT["underconfident_correct_rate"]

        if baseline is None and current is None:
            return

        if baseline is None:
            return

        if current is None:
            current = 0.0

        floor = round(baseline - _TOL_UNDERCONFIDENT, 6)
        assert current >= floor, (
            f"underconfident_correct_rate dropped.\n"
            f"  baseline : {baseline}\n"
            f"  current  : {current}\n"
            f"  floor    : {floor}  (baseline - {_TOL_UNDERCONFIDENT})\n"
            f"  dropped by {round(baseline - current, 4)}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# C — confidence_bucket_accuracy
# ══════════════════════════════════════════════════════════════════════════════

class TestConfidenceBucketAccuracy:
    """
    Per-bucket accuracy must not drop by more than 0.10 from baseline.

    Only buckets with baseline total > 0 are checked — empty baseline
    buckets have no established expectation.
    """

    @staticmethod
    def _current_by_label() -> dict:
        return {b["label"]: b for b in _CURRENT["confidence_bucket_accuracy"]}

    def test_buckets_not_worsened(self):
        current_map = self._current_by_label()
        failures    = []

        for bbase in _BASELINE["confidence_bucket_accuracy"]:
            label     = bbase["label"]
            b_total   = bbase["total"]
            b_acc     = bbase["accuracy_rate"]

            if b_total == 0 or b_acc is None:
                continue  # no baseline data for this bucket

            bcurr = current_map.get(label)
            if bcurr is None:
                failures.append(
                    f"  bucket '{label}': missing from current metrics"
                )
                continue

            c_acc = bcurr.get("accuracy_rate")
            if c_acc is None:
                failures.append(
                    f"  bucket '{label}': baseline accuracy={b_acc}, "
                    f"current has no data (total={bcurr.get('total', 0)})"
                )
                continue

            floor = round(b_acc - _TOL_BUCKET, 6)
            if c_acc < floor:
                failures.append(
                    f"  bucket '{label}': accuracy dropped.\n"
                    f"    baseline={b_acc}  current={c_acc}  "
                    f"floor={floor}  drop={round(b_acc - c_acc, 4)}"
                )

        assert not failures, (
            "confidence_bucket_accuracy worsened in one or more buckets:\n"
            + "\n".join(failures)
        )


# ══════════════════════════════════════════════════════════════════════════════
# D — impairment_accuracy
# ══════════════════════════════════════════════════════════════════════════════

class TestImpairmentAccuracy:
    """
    Per-impairment accuracy must not drop by more than 0.10 from baseline.

    Only impairment tokens with baseline total > 0 are checked.
    """

    @staticmethod
    def _current_by_impairment() -> dict:
        return {i["predicted_impairment"]: i for i in _CURRENT["impairment_accuracy"]}

    def test_impairment_accuracy_not_worsened(self):
        current_map = self._current_by_impairment()
        failures    = []

        for ibase in _BASELINE["impairment_accuracy"]:
            token   = ibase["predicted_impairment"]
            b_total = ibase["total"]
            b_acc   = ibase["accuracy_rate"]

            if b_total == 0 or b_acc is None:
                continue

            icurr = current_map.get(token)
            if icurr is None:
                failures.append(
                    f"  impairment '{token}': missing from current metrics"
                )
                continue

            c_acc = icurr.get("accuracy_rate")
            if c_acc is None:
                failures.append(
                    f"  impairment '{token}': baseline accuracy={b_acc}, "
                    f"current has no data (total={icurr.get('total', 0)})"
                )
                continue

            floor = round(b_acc - _TOL_IMPAIRMENT, 6)
            if c_acc < floor:
                failures.append(
                    f"  impairment '{token}': accuracy dropped.\n"
                    f"    baseline={b_acc}  current={c_acc}  "
                    f"floor={floor}  drop={round(b_acc - c_acc, 4)}"
                )

        assert not failures, (
            "impairment_accuracy worsened for one or more impairment tokens:\n"
            + "\n".join(failures)
        )


# ══════════════════════════════════════════════════════════════════════════════
# E — misleading_narrative_frequency
# ══════════════════════════════════════════════════════════════════════════════

class TestMisleadingNarrativeFrequency:
    """
    Misleading step counts must not increase beyond baseline + 1.

    Only steps present in the baseline are checked — new steps introduced
    by future changes are not caught here (that is handled by future
    impairment-specific tests).
    """

    @staticmethod
    def _current_by_step() -> dict:
        return {
            e["step"]: e["count"]
            for e in _CURRENT["misleading_narrative_frequency"]
        }

    def test_misleading_step_counts_not_increased(self):
        current_map = self._current_by_step()
        failures    = []

        for entry in _BASELINE["misleading_narrative_frequency"]:
            step    = entry["step"]
            b_count = entry["count"]
            c_count = current_map.get(step, 0)
            limit   = b_count + _TOL_MISLEADING

            if c_count > limit:
                # Truncate long step text for readability
                display = step[:100] + "…" if len(step) > 100 else step
                failures.append(
                    f"  step: \"{display}\"\n"
                    f"    baseline={b_count}  current={c_count}  "
                    f"limit={limit}  increase={c_count - b_count}"
                )

        assert not failures, (
            "misleading_narrative_frequency increased for one or more steps:\n"
            + "\n".join(failures)
        )
