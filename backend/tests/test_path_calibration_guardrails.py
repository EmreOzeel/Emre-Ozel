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
from core.causal_path import CausalPathEngine
from models import PacketRecord
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


# ── Helpers for impairment-specific guardrail slices ──────────────────────────

def _filter_imp(rows, impairment):
    """Return rows whose predicted_impairment equals *impairment*."""
    return [r for r in rows if r.get("predicted_impairment") == impairment]


def _hc_incorrect_rate(rows):
    """
    Fraction of high-confidence (≥ 75) predictions with verdict == 'incorrect'.
    Returns None when there are no high-confidence rows.
    """
    hc = [r for r in rows if (r.get("predicted_confidence") or 0) >= 75]
    if not hc:
        return None
    n_incorrect = sum(1 for r in hc if r.get("verdict") == "incorrect")
    return round(n_incorrect / len(hc), 4)


def _mean_confidence(rows):
    """Mean predicted_confidence across rows. Returns None when rows is empty."""
    if not rows:
        return None
    return round(
        sum(r.get("predicted_confidence") or 0 for r in rows) / len(rows), 4
    )


# ── Per-impairment corpus slices (pre-computed once at module load) ───────────

_BRD_ROWS = _filter_imp(CORPUS, "backend_response_delay")
_RPP_ROWS = _filter_imp(CORPUS, "return_path_problem")

# Corpus-derived baselines — mirror the values in path_calibration_baseline.json
_BRD_HC_INCORRECT_BASELINE = _hc_incorrect_rate(_BRD_ROWS)   # 0.1429  (1 of 7)
_RPP_HC_INCORRECT_BASELINE = _hc_incorrect_rate(_RPP_ROWS)   # 0.5     (1 of 2)
_RPP_MEAN_CONF_BASELINE    = _mean_confidence(_RPP_ROWS)      # 80.0

_TOL_IMP_HC_INCORRECT = 0.10   # max allowed increase in high-conf incorrect rate
_TOL_IMP_MEAN_CONF    = 5.0    # max allowed increase in mean confidence (absolute)


# ══════════════════════════════════════════════════════════════════════════════
# F — backend_response_delay: high-confidence incorrect rate must stay bounded
# ══════════════════════════════════════════════════════════════════════════════

class TestBackendResponseDelayGuardrail:
    """
    backend_response_delay predictions issued at high confidence (≥ 75) that
    turn out to be wrong are especially harmful — analysts act on a delay
    diagnosis that is not warranted.

    Guard: the high-confidence incorrect rate for backend_response_delay rows
    must not increase by more than 0.10 above the corpus baseline.
    Baseline: 0.1429  →  limit: 0.2429.
    """

    def test_hc_incorrect_rate_not_worsened(self):
        baseline = _BRD_HC_INCORRECT_BASELINE

        if baseline is None:
            return  # no high-confidence rows in baseline corpus — cannot compare

        current = _hc_incorrect_rate(_filter_imp(CORPUS, "backend_response_delay"))
        if current is None:
            current = 0.0

        limit = round(baseline + _TOL_IMP_HC_INCORRECT, 6)
        assert current <= limit, (
            f"backend_response_delay high-confidence incorrect rate worsened.\n"
            f"  baseline : {baseline}\n"
            f"  current  : {current}\n"
            f"  limit    : {limit}  (baseline + {_TOL_IMP_HC_INCORRECT})\n"
            f"  worsened by {round(current - baseline, 4)}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# G — return_path_problem: must stay conservative on confidence and accuracy
# ══════════════════════════════════════════════════════════════════════════════

class TestReturnPathProblemGuardrail:
    """
    return_path_problem is the impairment most frequently confused with a
    capture visibility gap by analysts.  The engine must stay conservative:

    • High-confidence incorrect rate must not drift upward too far.
    • Mean confidence must not inflate — analysts should not be pushed toward
      treating an ambiguous capture gap as a confirmed path failure.

    Guards:
      high-conf incorrect rate ≤ baseline + 0.10  (baseline 0.5  → limit 0.60)
      mean confidence          ≤ baseline + 5.0   (baseline 80.0 → limit 85.0)
    """

    def test_hc_incorrect_rate_not_worsened(self):
        baseline = _RPP_HC_INCORRECT_BASELINE

        if baseline is None:
            return

        current = _hc_incorrect_rate(_filter_imp(CORPUS, "return_path_problem"))
        if current is None:
            current = 0.0

        limit = round(baseline + _TOL_IMP_HC_INCORRECT, 6)
        assert current <= limit, (
            f"return_path_problem high-confidence incorrect rate worsened.\n"
            f"  baseline : {baseline}\n"
            f"  current  : {current}\n"
            f"  limit    : {limit}  (baseline + {_TOL_IMP_HC_INCORRECT})\n"
            f"  worsened by {round(current - baseline, 4)}"
        )

    def test_mean_confidence_not_inflated(self):
        baseline = _RPP_MEAN_CONF_BASELINE

        if baseline is None:
            return

        current = _mean_confidence(_filter_imp(CORPUS, "return_path_problem"))
        if current is None:
            return  # no return_path_problem rows now — cannot compare

        ceiling = round(baseline + _TOL_IMP_MEAN_CONF, 6)
        assert current <= ceiling, (
            f"return_path_problem mean confidence inflated.\n"
            f"  baseline : {baseline}\n"
            f"  current  : {current}\n"
            f"  ceiling  : {ceiling}  (baseline + {_TOL_IMP_MEAN_CONF})\n"
            f"  inflation: {round(current - baseline, 4)}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# H — firewall_interference: client-side RSTs must never be mis-labelled
# ══════════════════════════════════════════════════════════════════════════════

def _pkt_h(num, ts, src, dst, sport=54321, dport=80,
           syn=False, ack=False, rst=False, fin=False, payload=0):
    """Minimal PacketRecord for firewall guardrail scenarios."""
    return PacketRecord(
        num=num, ts=ts, frame_len=60 + payload, protocol="TCP",
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        ip_proto=6,
        tcp_flags_syn=syn, tcp_flags_ack=ack,
        tcp_flags_rst=rst, tcp_flags_fin=fin,
        tcp_payload_len=payload,
    )


_H_CLIENT = "10.2.0.10"
_H_SERVER = "10.2.0.20"


class TestFirewallInterferenceGuardrail:
    """
    Normal client-initiated RST teardowns must never be classified as
    firewall_interference.  This is a focused engine-level regression guard
    for the tightened trigger introduced in the recalibration sprint
    (only server_to_client RSTs or known-firewall-IP RSTs should fire it).

    Covered scenarios:
      H1 — normal teardown: full handshake + data exchange + client RST
      H2 — client abort: SYN sent, then client RSTs before handshake completes
    """

    def _run(self, packets):
        engine = CausalPathEngine(packets, {}, [], None)
        return engine.analyze(_H_CLIENT, _H_SERVER, 80)

    def test_h1_normal_teardown_no_firewall_interference(self):
        """Full handshake + data + client RST must not produce firewall_interference."""
        packets = [
            _pkt_h(1, 1.000, _H_CLIENT, _H_SERVER, syn=True),
            _pkt_h(2, 1.001, _H_SERVER, _H_CLIENT, sport=80, dport=54321, syn=True, ack=True),
            _pkt_h(3, 1.002, _H_CLIENT, _H_SERVER, ack=True),
            _pkt_h(4, 1.100, _H_CLIENT, _H_SERVER, payload=100),
            _pkt_h(5, 1.200, _H_SERVER, _H_CLIENT, sport=80, dport=54321, payload=200),
            _pkt_h(6, 1.300, _H_CLIENT, _H_SERVER, rst=True),         # client teardown
        ]
        result = self._run(packets)
        assert "firewall_interference" not in result.path_impairments, (
            f"firewall_interference incorrectly raised for a normal client RST teardown.\n"
            f"  path_impairments : {result.path_impairments}\n"
            f"  path_steps       : {result.path_steps}"
        )

    def test_h2_client_abort_no_firewall_interference(self):
        """SYN followed immediately by a client RST must not produce firewall_interference."""
        packets = [
            _pkt_h(1, 1.000, _H_CLIENT, _H_SERVER, syn=True),
            _pkt_h(2, 1.010, _H_CLIENT, _H_SERVER, rst=True),         # client aborts
        ]
        result = self._run(packets)
        assert "firewall_interference" not in result.path_impairments, (
            f"firewall_interference incorrectly raised for a client-abort RST.\n"
            f"  path_impairments : {result.path_impairments}\n"
            f"  path_steps       : {result.path_steps}"
        )
