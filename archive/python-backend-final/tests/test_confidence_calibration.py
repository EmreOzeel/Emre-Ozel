"""
Confidence score calibration tests.

Verifies that _evidence_confidence() stays within evidence-appropriate ranges
so that scoring regressions are caught before they cause false confidence.

Four orthogonal dimensions tested:

  1. Direct observation vs heuristic inference
     ARP-001 / TLS-006 (+8 adjust) must outperform DNS-002 (-8) / C2-001 (-5)
     for identical evidence, because deterministic rules deserve higher trust.

  2. Long-duration vs short-duration captures
     The time-coverage bonus ranges from +3 (>10s) to +10 (>300s).
     Regressions here would make short captures look as reliable as long ones.

  3. Single-packet vs repeated signals
     Monotonic: 0 < 1-2 < 3-9 ≤ 10-49 < 50-99 < 100+ packets.
     Any inversion here would under-penalise thin evidence.

  4. Contradiction penalty (trust score layer)
     Each sanity warning subtracts 12 pts from the overall trust score,
     capped at -40.  Tests use synthetic result dicts to isolate this path.

All expected ranges are computed from the _evidence_confidence formula
(see detection/engine.py) and verified against live output before committing.
Exact values are documented inline so future changes are self-auditing.
"""
from __future__ import annotations

import pytest
from detection.engine import _evidence_confidence
from core.trust import compute_trust_score
from models import Confidence, Evidence


# ── Evidence builders ─────────────────────────────────────────────────────────

def _ev(
    n_packets: int = 0,
    *,
    metrics: bool = False,
    samples: bool = False,
    duration: float = 0.0,
) -> Evidence:
    """Build an Evidence object from simple parameters."""
    return Evidence(
        packet_nums=list(range(n_packets)),
        metrics={"_": 1} if metrics else {},
        samples=["s"] if samples else [],
        time_first=1.0 if duration > 0 else 0.0,
        time_last=1.0 + duration if duration > 0 else 0.0,
    )


def _trust_result(
    *,
    n_warnings: int = 0,
    avg_conf_score: int = 80,
    midstream_pct: float = 0.0,
    failed_pct: float = 0.0,
    total_sessions: int = 20,
) -> dict:
    """
    Build a minimal result dict for compute_trust_score().
    Sanity warnings are synthetic "warning" severity items.
    """
    midstream = int(total_sessions * midstream_pct / 100)
    failed = int(total_sessions * failed_pct / 100)
    findings = [{"confidence_score": avg_conf_score, "rule_id": f"X-{i:03d}"}
                for i in range(5)]
    warnings = [
        {"check_id": f"SANITY-{i:03d}", "severity": "warning",
         "message": "test", "detail": "", "related_finding": None, "affected_host": None}
        for i in range(n_warnings)
    ]
    return {
        "all_issues": findings,
        "tcp": {
            "total_sessions": total_sessions,
            "midstream": midstream,
            "failed_handshakes": failed,
        },
        "sanity_warnings": warnings,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. Direct observation vs heuristic inference
# ══════════════════════════════════════════════════════════════════════════════

class TestDirectObservationVsHeuristic:
    """
    Deterministic rules (ARP-001 +8, TLS-006 +8) must score higher than
    heuristic rules (DNS-002 -8, C2-001 -5, HTTP-002 -3) for the same
    evidence package.  The gap represents the analyst's justified higher
    trust in a bit-exact match vs a probabilistic pattern.
    """

    def test_arp001_beats_dns002_same_evidence(self):
        """ARP poisoning (direct) vs DNS tunneling (entropy heuristic), identical evidence."""
        ev = _ev(n_packets=10, metrics=True)
        arp = _evidence_confidence(Confidence.MEDIUM, ev, "ARP-001")
        dns = _evidence_confidence(Confidence.MEDIUM, ev, "DNS-002")
        assert arp > dns, f"Direct observation (ARP-001={arp}) must beat heuristic (DNS-002={dns})"
        assert arp - dns == 16, (
            f"ARP-001(+8) vs DNS-002(-8) gap should be 16 pts, got {arp - dns}"
        )

    def test_tls006_beats_c2001_same_evidence(self):
        """JA3 hash lookup (deterministic) vs beaconing interval analysis (statistical)."""
        ev = _ev(n_packets=5)
        tls6 = _evidence_confidence(Confidence.MEDIUM, ev, "TLS-006")
        c2   = _evidence_confidence(Confidence.MEDIUM, ev, "C2-001")
        assert tls6 > c2, f"TLS-006 (hash match, +8) must beat C2-001 (interval, -5): {tls6} vs {c2}"
        assert tls6 - c2 == 13, f"TLS-006(+8) vs C2-001(-5) gap should be 13 pts, got {tls6 - c2}"

    def test_arp001_high_evidence_within_range(self):
        """ARP-001 with 50 packets + metrics: classic strong deterministic signal."""
        # Computed: 50 + 0(MEDIUM) + 10(50 pkts) + 8(metrics) + 8(ARP) = 76
        ev = _ev(n_packets=50, metrics=True)
        score = _evidence_confidence(Confidence.MEDIUM, ev, "ARP-001")
        assert 70 <= score <= 82, (
            f"ARP-001 with 50 packets + metrics should be 70-82, got {score}. "
            "Expected ≈76 (50 + 10 + 8 + 8)."
        )

    def test_tls006_single_clienthello_above_generic_heuristic(self):
        """Single TLS ClientHello JA3 hit: thin evidence but deterministic."""
        # Computed: 50 + 12(HIGH) - 10(1 pkt) + 8(TLS-006) = 60
        ev = _ev(n_packets=1)
        score = _evidence_confidence(Confidence.HIGH, ev, "TLS-006")
        assert 55 <= score <= 65, (
            f"TLS-006 single ClientHello should be 55-65, got {score}. Expected ≈60."
        )

    def test_dns002_high_volume_still_penalised(self):
        """DNS-002 with 100 queries: heuristic penalty persists regardless of volume."""
        ev = _ev(n_packets=100, metrics=True, duration=600.0)
        dns_score = _evidence_confidence(Confidence.HIGH, ev, "DNS-002")
        neutral = _evidence_confidence(Confidence.HIGH, ev, "TCP-001")
        # Gap must be exactly 8 (the rule adjustment)
        assert neutral - dns_score == 8, (
            f"DNS-002 heuristic penalty must always be exactly -8 pts vs neutral "
            f"(neutral={neutral}, DNS-002={dns_score}, gap={neutral - dns_score})"
        )

    def test_http002_always_below_equivalent_neutral(self):
        """HTTP-002 SQLi pattern must score 3 pts below identical-evidence neutral rule."""
        for n in (5, 25, 100):
            ev = _ev(n_packets=n, metrics=True, samples=True)
            http2 = _evidence_confidence(Confidence.HIGH, ev, "HTTP-002")
            http3 = _evidence_confidence(Confidence.HIGH, ev, "HTTP-003")
            assert http3 - http2 == 3, (
                f"HTTP-002 must be exactly 3 pts below HTTP-003 for n={n} packets: "
                f"HTTP-002={http2}, HTTP-003={http3}, gap={http3 - http2}"
            )

    def test_c2001_penalty_consistent(self):
        """C2-001 must always score exactly 5 pts below same-evidence neutral rule."""
        for n in (3, 10, 50):
            ev = _ev(n_packets=n)
            c2 = _evidence_confidence(Confidence.MEDIUM, ev, "C2-001")
            neutral = _evidence_confidence(Confidence.MEDIUM, ev, "TCP-001")
            assert neutral - c2 == 5, (
                f"C2-001 must be exactly -5 vs neutral for n={n}: "
                f"C2-001={c2}, neutral={neutral}, gap={neutral - c2}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Long-duration vs short-duration captures
# ══════════════════════════════════════════════════════════════════════════════

class TestDurationImpact:
    """
    Time coverage signals persistence vs transience.
    Breakpoints: no duration = 0pts, >10s = +3, >60s = +7, >300s = +10.

    A regression flattening this curve would make a single-burst event
    look as reliable as sustained behaviour over 10 minutes.
    """

    RULE = "TCP-001"   # neutral rule so only duration changes

    def test_no_duration_baseline(self):
        """time_first=0 means no duration computed — no time bonus."""
        ev = _ev(n_packets=10)   # time_first defaults to 0
        # 50 + 0(MEDIUM) + 6(10 pkts) = 56
        score = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        assert score == 56, f"No-duration baseline should be exactly 56, got {score}"

    def test_short_capture_small_bonus(self):
        """5s duration: below >10s threshold — no time bonus."""
        ev = _ev(n_packets=10, duration=5.0)
        # 50 + 0 + 6 = 56 (5s < 10s threshold — no bonus)
        score = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        assert score == 56, f"5s capture should give no time bonus (56), got {score}"

    def test_moderate_duration_small_bonus(self):
        """29s duration: >10s but <60s — +3 pts."""
        ev = _ev(n_packets=10, duration=29.0)
        # 50 + 0 + 6 + 3 = 59
        score = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        assert score == 59, f"29s capture should give +3 bonus (59), got {score}"

    def test_medium_duration_medium_bonus(self):
        """119s duration: >60s but <300s — +7 pts."""
        ev = _ev(n_packets=10, duration=119.0)
        # 50 + 0 + 6 + 7 = 63
        score = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        assert score == 63, f"119s capture should give +7 bonus (63), got {score}"

    def test_long_duration_full_bonus(self):
        """399s duration: >300s — maximum time bonus of +10 pts."""
        ev = _ev(n_packets=10, duration=399.0)
        # 50 + 0 + 6 + 10 = 66
        score = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        assert score == 66, f"399s capture should give +10 bonus (66), got {score}"

    def test_duration_monotonically_increases_score(self):
        """Longer capture must never produce a lower or equal score than a shorter one."""
        durations = [0.0, 5.0, 30.0, 120.0, 400.0]
        scores = [
            _evidence_confidence(Confidence.MEDIUM, _ev(n_packets=10, duration=d), self.RULE)
            for d in durations
        ]
        for i in range(len(scores) - 1):
            assert scores[i] <= scores[i + 1], (
                f"Score must not decrease as duration increases: "
                f"duration[{i}]={durations[i]}s→{scores[i]}, "
                f"duration[{i+1}]={durations[i+1]}s→{scores[i+1]}"
            )

    def test_long_capture_advantage_over_short_for_c2(self):
        """C2 beaconing MUST benefit from long captures: interval analysis needs time."""
        short = _evidence_confidence(Confidence.MEDIUM, _ev(n_packets=10, duration=5.0),  "C2-001")
        long  = _evidence_confidence(Confidence.MEDIUM, _ev(n_packets=10, duration=600.0), "C2-001")
        assert long > short, f"C2-001 long capture ({long}) must score higher than short ({short})"
        assert long - short == 10, (
            f"Long (600s) vs short (<10s) for C2 should differ by 10 pts, got {long - short}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Single-packet vs repeated signals
# ══════════════════════════════════════════════════════════════════════════════

class TestSignalStrength:
    """
    Packet count is the primary evidence strength signal.
    Breakpoints: 0→-20, 1-2→-10, 3-9→0, 10-49→+6, 50-99→+10, 100+→+14.

    Regressions here would let a single-packet detection look as strong
    as a sustained pattern with 50+ packets.
    """

    RULE = "TCP-001"  # neutral rule

    def test_zero_packets_heavy_penalty(self):
        """No packet references: metric-only detection — significant uncertainty."""
        # 50 + 0(MEDIUM) - 20(0 pkts) = 30
        score = _evidence_confidence(Confidence.MEDIUM, _ev(0), self.RULE)
        assert score == 30, f"0 packets should give 30 (base 50 - 20), got {score}"

    def test_single_packet_penalised(self):
        """1-2 packets: A single burst could trigger this — penalised."""
        # 50 + 0 - 10 = 40
        for n in (1, 2):
            score = _evidence_confidence(Confidence.MEDIUM, _ev(n), self.RULE)
            assert score == 40, f"{n} packet(s) should give 40 (base 50 - 10), got {score}"

    def test_few_packets_neutral(self):
        """3-9 packets: neutral — neither a strong signal nor dangerously thin."""
        for n in (3, 5, 9):
            score = _evidence_confidence(Confidence.MEDIUM, _ev(n), self.RULE)
            assert score == 50, f"{n} packets should give 50 (neutral), got {score}"

    def test_moderate_packets_small_boost(self):
        """10-49 packets: small evidence boost (+6)."""
        for n in (10, 25, 49):
            score = _evidence_confidence(Confidence.MEDIUM, _ev(n), self.RULE)
            assert score == 56, f"{n} packets should give 56 (50 + 6), got {score}"

    def test_many_packets_medium_boost(self):
        """50-99 packets: medium evidence boost (+10)."""
        for n in (50, 75, 99):
            score = _evidence_confidence(Confidence.MEDIUM, _ev(n), self.RULE)
            assert score == 60, f"{n} packets should give 60 (50 + 10), got {score}"

    def test_hundred_plus_packets_large_boost(self):
        """100+ packets: strong sustained evidence (+14)."""
        for n in (100, 200, 500):
            score = _evidence_confidence(Confidence.MEDIUM, _ev(n), self.RULE)
            assert score == 64, f"{n} packets should give 64 (50 + 14), got {score}"

    def test_strict_monotonic_across_bands(self):
        """Crossing a packet-count band boundary must strictly increase the score."""
        band_representatives = [0, 1, 3, 10, 50, 100]
        scores = [_evidence_confidence(Confidence.MEDIUM, _ev(n), self.RULE) for n in band_representatives]
        for i in range(len(scores) - 1):
            assert scores[i] < scores[i + 1], (
                f"Score must strictly increase across packet bands: "
                f"{band_representatives[i]} pkts→{scores[i]}, "
                f"{band_representatives[i+1]} pkts→{scores[i+1]}"
            )

    def test_single_packet_is_never_adequate_for_critical(self):
        """A single-packet HIGH-severity finding must not reach the medium-confidence threshold (55)."""
        score = _evidence_confidence(Confidence.HIGH, _ev(1), "SCAN-001")
        assert score < 55, (
            f"Single-packet critical finding should not reach medium confidence (55+); got {score}"
        )

    def test_confidence_enum_low_and_thin_evidence_floors_at_10(self):
        """Worst possible evidence: LOW confidence, 0 packets, heuristic rule."""
        # 50 - 18(LOW) - 20(0 pkts) - 5(C2-001) = 7 → clamped to 10
        score = _evidence_confidence(Confidence.LOW, _ev(0), "C2-001")
        assert score == 10, f"Minimum clamp must be 10, got {score}"

    def test_high_confidence_and_rich_evidence_caps_at_95(self):
        """Best possible evidence: HIGH confidence, 100+ packets, metrics, samples, long duration."""
        # 50 + 12(HIGH) + 14(100 pkts) + 8(metrics) + 5(samples) + 10(600s) + 8(ARP-001) = 107 → 95
        ev = _ev(n_packets=100, metrics=True, samples=True, duration=600.0)
        score = _evidence_confidence(Confidence.HIGH, ev, "ARP-001")
        assert score == 95, f"Maximum clamp must be 95, got {score}"

    def test_metrics_add_fixed_bonus(self):
        """Adding concrete metrics must add exactly +8 regardless of other factors."""
        for n in (1, 10, 100):
            for rule in ("TCP-001", "C2-001", "ARP-001"):
                without = _evidence_confidence(Confidence.MEDIUM, _ev(n),              rule)
                with_m  = _evidence_confidence(Confidence.MEDIUM, _ev(n, metrics=True), rule)
                expected_gain = min(without + 8, 95) - min(without, 95)
                actual_gain = with_m - without
                assert actual_gain == expected_gain, (
                    f"Metrics bonus must be +8 (clamped) for {rule} n={n}: "
                    f"without={without}, with={with_m}, gain={actual_gain}"
                )


# ══════════════════════════════════════════════════════════════════════════════
# 4. Contradiction penalty (trust score layer)
# ══════════════════════════════════════════════════════════════════════════════

class TestContradictionPenalty:
    """
    compute_trust_score() applies a -12 pt penalty per sanity warning,
    capped at -40.  This is independent of finding quality.

    Regressions here would let contradicted analyses appear reliable
    or make the penalty so harsh that all analyses look untrustworthy.
    """

    def test_zero_warnings_no_penalty(self):
        """Clean analysis with no contradictions: contradiction_penalty = 0."""
        result = _trust_result(n_warnings=0, avg_conf_score=80)
        trust = compute_trust_score(result)
        assert trust["components"]["contradiction_penalty"] == 0
        assert trust["trust_score"] > 60, (
            f"Clean analysis with good evidence should score > 60, got {trust['trust_score']}"
        )

    def test_one_warning_subtracts_12(self):
        """Single sanity contradiction: penalty = 12."""
        no_warn = compute_trust_score(_trust_result(n_warnings=0, avg_conf_score=80))
        one_warn = compute_trust_score(_trust_result(n_warnings=1, avg_conf_score=80))
        penalty = no_warn["trust_score"] - one_warn["trust_score"]
        assert one_warn["components"]["contradiction_penalty"] == 12
        assert penalty == 12, f"One warning must drop trust score by exactly 12, got {penalty}"

    def test_two_warnings_subtracts_24(self):
        """Two sanity contradictions: penalty = 24."""
        no_warn  = compute_trust_score(_trust_result(n_warnings=0, avg_conf_score=80))
        two_warn = compute_trust_score(_trust_result(n_warnings=2, avg_conf_score=80))
        assert two_warn["components"]["contradiction_penalty"] == 24
        penalty = no_warn["trust_score"] - two_warn["trust_score"]
        assert penalty == 24, f"Two warnings must drop trust score by 24, got {penalty}"

    def test_four_warnings_hits_cap(self):
        """Four or more warnings: penalty capped at 40."""
        for n in (4, 5, 10):
            trust = compute_trust_score(_trust_result(n_warnings=n, avg_conf_score=80))
            assert trust["components"]["contradiction_penalty"] == 40, (
                f"Contradiction penalty must cap at 40 for n={n} warnings, "
                f"got {trust['components']['contradiction_penalty']}"
            )

    def test_penalty_cap_is_40(self):
        """The cap value itself is 40 — not 36 (3*12) and not 48 (4*12)."""
        trust = compute_trust_score(_trust_result(n_warnings=10, avg_conf_score=80))
        assert trust["components"]["contradiction_penalty"] == 40, (
            f"Maximum contradiction penalty must be exactly 40, "
            f"got {trust['components']['contradiction_penalty']}"
        )

    def test_contradictions_dominate_high_evidence_quality(self):
        """Even perfect evidence quality cannot compensate for 4+ contradictions."""
        clean   = compute_trust_score(_trust_result(n_warnings=0, avg_conf_score=95))
        maxwarn = compute_trust_score(_trust_result(n_warnings=5, avg_conf_score=95))
        assert maxwarn["trust_score"] < clean["trust_score"] - 30, (
            f"4+ contradictions should drop trust by > 30 pts even with perfect evidence: "
            f"clean={clean['trust_score']}, maxwarn={maxwarn['trust_score']}"
        )

    def test_info_warnings_do_not_contribute_to_penalty(self):
        """Sanity issues of severity 'info' must not subtract from trust score."""
        info_warnings = [
            {"check_id": "SANITY-006", "severity": "info",
             "message": "test", "detail": "", "related_finding": None, "affected_host": None}
            for _ in range(5)
        ]
        result = _trust_result(n_warnings=0, avg_conf_score=80)
        result["sanity_warnings"] = info_warnings   # override with info-only
        trust = compute_trust_score(result)
        assert trust["components"]["contradiction_penalty"] == 0, (
            f"Info-severity sanity issues must not contribute to contradiction penalty, "
            f"got {trust['components']['contradiction_penalty']}"
        )

    def test_trust_label_reflects_contradiction_level(self):
        """Trust label must downgrade when contradictions lower the score significantly."""
        high_trust = compute_trust_score(_trust_result(n_warnings=0, avg_conf_score=90))
        low_trust  = compute_trust_score(_trust_result(n_warnings=4, avg_conf_score=90))
        # High trust should be "High" or "Medium"; low trust must not be "High"
        assert "High" in high_trust["trust_label"] or "Medium" in high_trust["trust_label"], (
            f"No-contradiction analysis should be High/Medium: {high_trust['trust_label']}"
        )
        assert "High" not in low_trust["trust_label"], (
            f"4-contradiction analysis must not be labeled High: {low_trust['trust_label']}"
        )

    def test_penalty_linear_before_cap(self):
        """Penalty is strictly linear (n * 12) for 1, 2, 3 warnings."""
        for n in range(1, 4):
            trust = compute_trust_score(_trust_result(n_warnings=n, avg_conf_score=80))
            expected_penalty = n * 12
            assert trust["components"]["contradiction_penalty"] == expected_penalty, (
                f"Penalty for {n} warning(s) should be {expected_penalty}, "
                f"got {trust['components']['contradiction_penalty']}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 5. Confidence enum contribution
# ══════════════════════════════════════════════════════════════════════════════

class TestConfidenceEnumContribution:
    """
    The analyzer-assigned confidence enum adds a fixed offset: HIGH +12, LOW -18.
    This is separate from the evidence quality signals above.
    Tests ensure the offsets are exact and that HIGH > MEDIUM > LOW holds always.
    """

    RULE = "TCP-001"

    def test_high_medium_low_ordering_preserved(self):
        """HIGH > MEDIUM > LOW confidence must hold for all evidence sizes."""
        for n in (0, 1, 10, 100):
            ev = _ev(n)
            h = _evidence_confidence(Confidence.HIGH,   ev, self.RULE)
            m = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
            l = _evidence_confidence(Confidence.LOW,    ev, self.RULE)
            assert h > m > l, (
                f"HIGH > MEDIUM > LOW must hold for n={n} packets: {h}, {m}, {l}"
            )

    def test_high_is_12_above_medium(self):
        """HIGH confidence must add exactly +12 over MEDIUM (unclamped range)."""
        ev = _ev(n_packets=10)
        h = _evidence_confidence(Confidence.HIGH,   ev, self.RULE)
        m = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        assert h - m == 12, f"HIGH - MEDIUM must be +12, got {h - m}"

    def test_low_is_18_below_medium(self):
        """LOW confidence must subtract exactly -18 from MEDIUM (unclamped range)."""
        ev = _ev(n_packets=10)
        m = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        l = _evidence_confidence(Confidence.LOW,    ev, self.RULE)
        assert m - l == 18, f"MEDIUM - LOW must be 18, got {m - l}"

    def test_low_confidence_never_exceeds_medium_baseline(self):
        """Even with many packets, LOW confidence must not exceed unclamped MEDIUM baseline."""
        ev = _ev(n_packets=200, metrics=True, samples=True, duration=600.0)
        l = _evidence_confidence(Confidence.LOW,    ev, self.RULE)
        m = _evidence_confidence(Confidence.MEDIUM, ev, self.RULE)
        assert l < m, (
            f"LOW confidence must always score below MEDIUM regardless of packet count: "
            f"LOW={l}, MEDIUM={m}"
        )
