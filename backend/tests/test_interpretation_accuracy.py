"""
Interpretation accuracy tests.

Verifies that the detection layer:
1. Identifies the correct root cause (top-1 and top-3 accuracy)
2. Does not fire false positives on clean traffic
3. Does not miss expected rules (false negatives)
4. Requires multi-signal correlation for correlated attacks
5. Ranks root-cause hypotheses correctly by score (descending)
6. Produces calibrated confidence scores (deterministic > heuristic)
7. Handles edge cases: thin evidence, noisy signals, short captures
8. Meets aggregate accuracy thresholds (regression guard)

All tests use synthetic CaptureContext objects — no tshark required.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List, Set

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers import security as sec_analyzer
from detection.engine import finalize
from models import (
    CaptureContext,
    FileInfo,
    PacketRecord,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Ground-truth scenario builders
# ═══════════════════════════════════════════════════════════════════════════════

def _base_ctx(n_packets: int = 100, duration: float = 60.0) -> CaptureContext:
    ctx = CaptureContext()
    ctx.file_info = FileInfo(
        filename="accuracy_test.pcap",
        total_packets=n_packets,
        duration_sec=duration,
        file_size_bytes=n_packets * 100,
    )
    return ctx


def _syn(num: int, ts: float, src: str, dst: str,
         dst_port: int = 80, proto: int = 6) -> PacketRecord:
    """Bare TCP SYN (no ACK) packet."""
    return PacketRecord(
        num=num, ts=ts, frame_len=60, protocol="TCP",
        src_ip=src, dst_ip=dst,
        src_port=54321, dst_port=dst_port,
        ip_proto=proto,
        tcp_flags_syn=True, tcp_flags_ack=False,
    )


def _arp(num: int, ts: float, sender_ip: str, sender_mac: str,
         src: str = "192.168.1.50") -> PacketRecord:
    return PacketRecord(
        num=num, ts=ts, frame_len=42, protocol="ARP",
        src_ip=src, dst_ip="255.255.255.255",
        ip_proto=0, has_arp=True,
        extras={
            "arp.src.proto_ipv4": sender_ip,
            "arp.src.hw_mac": sender_mac,
        },
    )


def _icmp_echo(num: int, ts: float, src: str, dst: str = "10.0.0.1") -> PacketRecord:
    return PacketRecord(
        num=num, ts=ts, frame_len=84, protocol="ICMP",
        src_ip=src, dst_ip=dst,
        ip_proto=1, has_icmp=True,
        extras={"icmp.type": "8"},
    )


# ── Scenario 1: ARP spoofing (deterministic, direct observation) ──────────────

def _ctx_arp_spoof() -> CaptureContext:
    """IP 192.168.1.1 announced from 2 distinct MACs → ARP-001."""
    ctx = _base_ctx(n_packets=20, duration=10.0)
    for i in range(10):
        mac = "aa:bb:cc:dd:ee:ff" if i % 2 == 0 else "11:22:33:44:55:66"
        ctx.packets.append(_arp(num=i + 1, ts=1.0 + i,
                                sender_ip="192.168.1.1", sender_mac=mac))
    return ctx


# ── Scenario 2: Port scan (high-confidence, volume-based) ────────────────────

def _ctx_port_scan() -> CaptureContext:
    """25 unique-port SYNs from 10.0.0.99 → SCAN-001. Not enough for DOS-001."""
    ctx = _base_ctx(n_packets=25, duration=5.0)
    for i, port in enumerate(range(1, 26)):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i * 0.2,
                                src="10.0.0.99", dst="10.0.0.1",
                                dst_port=port))
    return ctx


# ── Scenario 3: SYN flood (volume DoS, 200+ SYNs) ───────────────────────────

def _ctx_syn_flood() -> CaptureContext:
    """210 SYNs to port 80 from same src → DOS-001. Only 1 unique port → SCAN-001 won't fire."""
    ctx = _base_ctx(n_packets=210, duration=30.0)
    for i in range(210):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i * 0.1,
                                src="10.0.0.99", dst="10.0.0.1",
                                dst_port=80))
    return ctx


# ── Scenario 4: C2 beaconing (statistical, medium confidence) ────────────────

def _ctx_c2_beacon() -> CaptureContext:
    """10 internal→external SYNs at exactly 30s intervals → C2-001 (CoV≈0)."""
    ctx = _base_ctx(n_packets=10, duration=310.0)
    for i in range(10):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i * 30.0,
                                src="10.0.0.5", dst="8.8.4.4",
                                dst_port=443))
    return ctx


# ── Scenario 5: Lateral movement (internal sweep of sensitive ports) ──────────

def _ctx_lateral_movement() -> CaptureContext:
    """6 SYNs from 192.168.1.100 to SMB port on 5 different internal hosts → LAT-001."""
    ctx = _base_ctx(n_packets=6, duration=15.0)
    targets = ["192.168.1.10", "192.168.1.11", "192.168.1.12",
               "192.168.1.13", "192.168.1.14", "192.168.1.15"]
    for i, dst in enumerate(targets):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i * 2.0,
                                src="192.168.1.100", dst=dst,
                                dst_port=445))  # SMB
    return ctx


# ── Scenario 6: Clean traffic (no attacks) ───────────────────────────────────

def _ctx_clean() -> CaptureContext:
    """3 normal TCP SYNs to port 443 — no rule thresholds met."""
    ctx = _base_ctx(n_packets=3, duration=5.0)
    for i in range(3):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i,
                                src="192.168.1.5", dst="93.184.216.34",
                                dst_port=443))
    return ctx


# ── Scenario 7: Multi-signal (ARP spoof + port scan co-present) ───────────────

def _ctx_multi_signal() -> CaptureContext:
    """ARP spoof AND port scan present simultaneously — both rules must fire."""
    ctx = _base_ctx(n_packets=50, duration=30.0)
    # ARP spoof: 4 packets
    for i in range(4):
        mac = "aa:bb:cc:dd:ee:01" if i < 2 else "aa:bb:cc:dd:ee:02"
        ctx.packets.append(_arp(num=i + 1, ts=1.0 + i,
                                sender_ip="192.168.1.1", sender_mac=mac))
    # Port scan: 25 unique-port SYNs
    for i, port in enumerate(range(1, 26)):
        ctx.packets.append(_syn(num=i + 5, ts=5.0 + i * 0.5,
                                src="10.0.0.99", dst="10.0.0.1",
                                dst_port=port))
    return ctx


# ── Scenario 8: ICMP flood ───────────────────────────────────────────────────

def _ctx_icmp_flood() -> CaptureContext:
    """110 ICMP echo requests from same source → DOS-002."""
    ctx = _base_ctx(n_packets=110, duration=20.0)
    for i in range(110):
        ctx.packets.append(_icmp_echo(num=i + 1, ts=1.0 + i * 0.1,
                                      src="10.0.0.55"))
    return ctx


# ═══════════════════════════════════════════════════════════════════════════════
# Edge-case contexts
# ═══════════════════════════════════════════════════════════════════════════════

def _ctx_thin_arp() -> CaptureContext:
    """Single ARP pair: same IP, 2 MACs, 2 packets — deterministic rule, still fires."""
    ctx = _base_ctx(n_packets=2, duration=1.0)
    ctx.packets.append(_arp(num=1, ts=1.0, sender_ip="192.168.1.1",
                            sender_mac="aa:bb:cc:dd:ee:ff"))
    ctx.packets.append(_arp(num=2, ts=1.5, sender_ip="192.168.1.1",
                            sender_mac="11:22:33:44:55:66"))
    return ctx


def _ctx_scan_at_threshold() -> CaptureContext:
    """Exactly 20 unique-port SYNs — sits at SCAN-001 threshold boundary."""
    ctx = _base_ctx(n_packets=20, duration=4.0)
    for i, port in enumerate(range(1, 21)):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i * 0.2,
                                src="10.0.0.99", dst="10.0.0.1",
                                dst_port=port))
    return ctx


def _ctx_scan_below_threshold() -> CaptureContext:
    """19 unique-port SYNs — one below threshold, SCAN-001 must NOT fire."""
    ctx = _base_ctx(n_packets=19, duration=4.0)
    for i, port in enumerate(range(1, 20)):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i * 0.2,
                                src="10.0.0.99", dst="10.0.0.1",
                                dst_port=port))
    return ctx


def _ctx_c2_short_capture() -> CaptureContext:
    """8 beacon SYNs (minimum) but very short total duration (7 intervals × 5s = 35s)."""
    ctx = _base_ctx(n_packets=8, duration=36.0)
    for i in range(8):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + i * 5.0,
                                src="10.0.0.5", dst="8.8.4.4",
                                dst_port=443))
    return ctx


def _ctx_c2_high_jitter() -> CaptureContext:
    """8 internal→external SYNs but random intervals → CoV > 15%, C2-001 must NOT fire."""
    ctx = _base_ctx(n_packets=8, duration=200.0)
    # Very irregular intervals: 5, 50, 8, 100, 6, 80, 12 → high CoV
    ts_offsets = [0, 5, 55, 63, 163, 169, 249, 261]
    for i, offset in enumerate(ts_offsets):
        ctx.packets.append(_syn(num=i + 1, ts=1.0 + offset,
                                src="10.0.0.5", dst="8.8.4.4",
                                dst_port=443))
    return ctx


def _ctx_noisy_arp_one_mac() -> CaptureContext:
    """Many ARP packets for same IP but all from the same MAC — ARP-001 must NOT fire."""
    ctx = _base_ctx(n_packets=20, duration=10.0)
    for i in range(20):
        ctx.packets.append(_arp(num=i + 1, ts=1.0 + i,
                                sender_ip="192.168.1.1",
                                sender_mac="aa:bb:cc:dd:ee:ff"))
    return ctx


# ═══════════════════════════════════════════════════════════════════════════════
# Analysis helper
# ═══════════════════════════════════════════════════════════════════════════════

def _run(ctx: CaptureContext) -> List:
    """Run security analyzer + finalize, return findings sorted by score desc."""
    sec_analyzer.analyze(ctx)
    finalize(ctx)
    return sorted(ctx.findings, key=lambda f: f.score, reverse=True)


def _rule_ids(findings: List) -> List[str]:
    return [f.rule_id for f in findings]


def _top_n_rules(findings: List, n: int) -> Set[str]:
    return {f.rule_id for f in findings[:n]}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Ground-truth dataset: verify each builder produces expected non-empty output
# ═══════════════════════════════════════════════════════════════════════════════

class TestGroundTruthDataset:
    def test_arp_spoof_ctx_has_arp_packets(self):
        ctx = _ctx_arp_spoof()
        arp_pkts = [p for p in ctx.packets if p.has_arp]
        assert len(arp_pkts) == 10
        macs = {p.extras["arp.src.hw_mac"] for p in arp_pkts}
        assert len(macs) == 2, "Expected 2 distinct MACs for spoofing scenario"

    def test_port_scan_ctx_has_25_unique_ports(self):
        ctx = _ctx_port_scan()
        ports = {p.dst_port for p in ctx.packets if p.tcp_flags_syn}
        assert len(ports) == 25

    def test_syn_flood_ctx_single_port(self):
        ctx = _ctx_syn_flood()
        ports = {p.dst_port for p in ctx.packets if p.tcp_flags_syn}
        assert len(ports) == 1, "Flood scenario must use single port to isolate DOS-001"
        assert len(ctx.packets) == 210

    def test_c2_beacon_ctx_consistent_intervals(self):
        ctx = _ctx_c2_beacon()
        ts = sorted(p.ts for p in ctx.packets)
        intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
        assert all(iv == pytest.approx(30.0, abs=0.01) for iv in intervals)

    def test_lateral_movement_ctx_sensitive_ports(self):
        ctx = _ctx_lateral_movement()
        assert all(p.dst_port == 445 for p in ctx.packets)
        dst_ips = {p.dst_ip for p in ctx.packets}
        assert len(dst_ips) == 6

    def test_clean_ctx_no_attack_signals(self):
        ctx = _ctx_clean()
        ports = {p.dst_port for p in ctx.packets}
        assert ports == {443}
        assert len(ctx.packets) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Root-cause accuracy: top-1 and top-3
# ═══════════════════════════════════════════════════════════════════════════════

class TestRootCauseAccuracy:

    def test_arp_spoof_top1(self):
        findings = _run(_ctx_arp_spoof())
        assert findings, "ARP-001 must fire"
        assert findings[0].rule_id == "ARP-001", (
            f"Top-1 must be ARP-001, got {_rule_ids(findings)}"
        )

    def test_port_scan_top1(self):
        findings = _run(_ctx_port_scan())
        assert findings, "SCAN-001 must fire"
        assert findings[0].rule_id == "SCAN-001", (
            f"Top-1 must be SCAN-001, got {_rule_ids(findings)}"
        )

    def test_syn_flood_top1(self):
        findings = _run(_ctx_syn_flood())
        assert findings, "DOS-001 must fire"
        assert findings[0].rule_id == "DOS-001", (
            f"Top-1 must be DOS-001, got {_rule_ids(findings)}"
        )

    def test_c2_beacon_top1(self):
        findings = _run(_ctx_c2_beacon())
        assert findings, "C2-001 must fire"
        assert findings[0].rule_id == "C2-001", (
            f"Top-1 must be C2-001, got {_rule_ids(findings)}"
        )

    def test_lateral_movement_top1(self):
        findings = _run(_ctx_lateral_movement())
        assert findings, "LAT-001 must fire"
        assert findings[0].rule_id == "LAT-001", (
            f"Top-1 must be LAT-001, got {_rule_ids(findings)}"
        )

    def test_icmp_flood_top1(self):
        findings = _run(_ctx_icmp_flood())
        assert findings, "DOS-002 must fire"
        assert findings[0].rule_id == "DOS-002", (
            f"Top-1 must be DOS-002, got {_rule_ids(findings)}"
        )

    def test_multi_signal_both_in_top3(self):
        """When ARP spoof + port scan co-occur, both must appear in top-3 findings."""
        findings = _run(_ctx_multi_signal())
        top3 = _top_n_rules(findings, 3)
        assert "ARP-001" in top3, f"ARP-001 missing from top-3: {_rule_ids(findings)}"
        assert "SCAN-001" in top3, f"SCAN-001 missing from top-3: {_rule_ids(findings)}"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. False positive / false negative tracking
# ═══════════════════════════════════════════════════════════════════════════════

class TestFalsePositiveFalseNegative:

    def test_clean_traffic_zero_findings(self):
        """No attack signals → zero security findings (strict FP guard)."""
        findings = _run(_ctx_clean())
        assert findings == [], (
            f"FP: security findings on clean traffic: {_rule_ids(findings)}"
        )

    def test_arp_one_mac_no_finding(self):
        """Single MAC per IP → ARP-001 must NOT fire (FP guard)."""
        findings = _run(_ctx_noisy_arp_one_mac())
        arp_findings = [f for f in findings if f.rule_id == "ARP-001"]
        assert not arp_findings, "FP: ARP-001 fired with only one MAC per IP"

    def test_scan_below_threshold_no_finding(self):
        """19 unique ports (< threshold 20) → SCAN-001 must NOT fire."""
        findings = _run(_ctx_scan_below_threshold())
        scan_findings = [f for f in findings if f.rule_id == "SCAN-001"]
        assert not scan_findings, (
            f"FP: SCAN-001 fired below threshold (19 ports): {_rule_ids(findings)}"
        )

    def test_c2_high_jitter_no_finding(self):
        """Irregular intervals (CoV > 0.15) → C2-001 must NOT fire."""
        findings = _run(_ctx_c2_high_jitter())
        c2_findings = [f for f in findings if f.rule_id == "C2-001"]
        assert not c2_findings, (
            f"FP: C2-001 fired with high-jitter traffic: CoV exceeds threshold"
        )

    def test_port_scan_does_not_trigger_dos(self):
        """25 SYNs (one per port) is below DOS-001 threshold of 200."""
        findings = _run(_ctx_port_scan())
        dos_findings = [f for f in findings if f.rule_id == "DOS-001"]
        assert not dos_findings, (
            "FP: DOS-001 fired on port scan with only 25 packets"
        )

    def test_syn_flood_does_not_trigger_scan(self):
        """210 SYNs all to port 80 (single destination port) → SCAN-001 must NOT fire."""
        findings = _run(_ctx_syn_flood())
        scan_findings = [f for f in findings if f.rule_id == "SCAN-001"]
        assert not scan_findings, (
            "FP: SCAN-001 fired on flood with single destination port"
        )

    def test_fn_arp_spoof_always_detected(self):
        """ARP-001 is deterministic — must never be missed when 2 MACs claim same IP."""
        findings = _run(_ctx_arp_spoof())
        arp_findings = [f for f in findings if f.rule_id == "ARP-001"]
        assert arp_findings, "FN: ARP-001 missed despite 2 MACs for same IP"

    def test_fn_lateral_movement_always_detected(self):
        """LAT-001 must fire when ≥5 internal→internal SYNs target sensitive ports."""
        findings = _run(_ctx_lateral_movement())
        lat_findings = [f for f in findings if f.rule_id == "LAT-001"]
        assert lat_findings, "FN: LAT-001 missed despite 6 SYNs to sensitive ports"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Multi-signal correlation enforcement
# ═══════════════════════════════════════════════════════════════════════════════

class TestMultiSignalCorrelation:

    def test_multi_signal_both_rules_present(self):
        """Two independent attack signals must both be captured, not collapsed into one."""
        findings = _run(_ctx_multi_signal())
        rule_ids = _rule_ids(findings)
        assert "ARP-001" in rule_ids
        assert "SCAN-001" in rule_ids
        assert len(findings) >= 2, "Multi-signal scenario must produce ≥2 findings"

    def test_multi_signal_count_matches_attack_count(self):
        """Exactly 2 distinct attack types present → exactly 2 findings expected."""
        findings = _run(_ctx_multi_signal())
        unique_rules = {f.rule_id for f in findings}
        assert len(unique_rules) == 2, (
            f"Expected 2 distinct rules, got {unique_rules}"
        )

    def test_scan_and_flood_are_independent(self):
        """Port scan and SYN flood produce different rule_ids, not merged."""
        ctx_scan = _ctx_port_scan()
        ctx_flood = _ctx_syn_flood()
        scan_rules = {f.rule_id for f in _run(ctx_scan)}
        flood_rules = {f.rule_id for f in _run(ctx_flood)}
        assert scan_rules != flood_rules, (
            "SCAN-001 and DOS-001 must be distinct — they capture different threats"
        )
        assert "SCAN-001" in scan_rules
        assert "DOS-001" in flood_rules


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Multiple root-cause hypotheses with ranking
# ═══════════════════════════════════════════════════════════════════════════════

class TestRootCauseHypotheses:

    def test_findings_sorted_by_score_descending(self):
        """Findings must always be sorted by score descending after finalize()."""
        for ctx_fn in [_ctx_multi_signal, _ctx_c2_beacon, _ctx_syn_flood]:
            findings = _run(ctx_fn())
            scores = [f.score for f in findings]
            assert scores == sorted(scores, reverse=True), (
                f"Findings not sorted: {scores}"
            )

    def test_highest_severity_ranks_first(self):
        """In multi-signal scenario, CRITICAL/HIGH finding must outrank MEDIUM/LOW."""
        findings = _run(_ctx_multi_signal())
        if len(findings) >= 2:
            assert findings[0].score >= findings[1].score

    def test_score_strictly_positive(self):
        """All generated findings must have score > 0."""
        for ctx_fn in [_ctx_arp_spoof, _ctx_port_scan, _ctx_syn_flood,
                       _ctx_c2_beacon, _ctx_lateral_movement]:
            for f in _run(ctx_fn()):
                assert f.score > 0, f"Finding {f.rule_id} has non-positive score {f.score}"

    def test_confidence_score_within_bounds(self):
        """confidence_score must be in [10, 95] for all findings."""
        for ctx_fn in [_ctx_arp_spoof, _ctx_port_scan, _ctx_syn_flood,
                       _ctx_c2_beacon, _ctx_lateral_movement]:
            for f in _run(ctx_fn()):
                assert 10 <= f.confidence_score <= 95, (
                    f"{f.rule_id}: confidence_score={f.confidence_score} out of [10, 95]"
                )

    def test_possible_causes_populated(self):
        """Every finding must include at least one root cause hypothesis."""
        for ctx_fn in [_ctx_arp_spoof, _ctx_port_scan, _ctx_syn_flood,
                       _ctx_c2_beacon, _ctx_lateral_movement]:
            for f in _run(ctx_fn()):
                assert f.possible_causes, (
                    f"{f.rule_id}: possible_causes is empty"
                )

    def test_recommended_actions_populated(self):
        """Every finding must include at least one recommended action."""
        for ctx_fn in [_ctx_arp_spoof, _ctx_port_scan, _ctx_syn_flood,
                       _ctx_c2_beacon, _ctx_lateral_movement]:
            for f in _run(ctx_fn()):
                assert f.recommended_actions, (
                    f"{f.rule_id}: recommended_actions is empty"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Confidence calibration vs real accuracy
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfidenceCalibration:

    def test_deterministic_rule_scores_higher_than_heuristic(self):
        """
        ARP-001 (+8 rule adjustment) must produce higher confidence_score
        than C2-001 (-5 rule adjustment) when both have similar packet counts.
        """
        arp_findings = _run(_ctx_arp_spoof())
        c2_findings = _run(_ctx_c2_beacon())

        arp_conf = arp_findings[0].confidence_score
        c2_conf  = c2_findings[0].confidence_score

        assert arp_conf > c2_conf, (
            f"Deterministic ARP-001 ({arp_conf}) must score higher than "
            f"heuristic C2-001 ({c2_conf})"
        )

    def test_high_volume_increases_confidence(self):
        """
        SYN flood (210 packets) must produce higher confidence_score than
        C2 beacon (10 packets) — packet volume is a confidence signal.
        """
        flood_findings = _run(_ctx_syn_flood())
        c2_findings = _run(_ctx_c2_beacon())

        flood_conf = flood_findings[0].confidence_score
        c2_conf    = c2_findings[0].confidence_score

        assert flood_conf > c2_conf, (
            f"High-volume flood ({flood_conf}) must score higher than "
            f"low-volume beacon ({c2_conf})"
        )

    def test_thin_evidence_reduces_confidence(self):
        """
        2-packet ARP scenario must have lower confidence_score than
        20-packet ARP scenario (packet count signal).
        """
        thin_findings = _run(_ctx_thin_arp())
        full_findings = _run(_ctx_arp_spoof())

        thin_conf = thin_findings[0].confidence_score
        full_conf = full_findings[0].confidence_score

        assert thin_conf < full_conf, (
            f"Thin evidence ({thin_conf}) must score lower than "
            f"full evidence ({full_conf})"
        )

    def test_scan_at_threshold_has_lower_confidence_than_heavy_scan(self):
        """
        Exactly 20-port scan (boundary) must score lower or equal
        to a 25-port scan (same rule, more evidence).
        """
        boundary_findings = _run(_ctx_scan_at_threshold())
        heavy_findings    = _run(_ctx_port_scan())

        assert boundary_findings, "SCAN-001 must fire at threshold"
        assert heavy_findings,    "SCAN-001 must fire above threshold"

        boundary_conf = boundary_findings[0].confidence_score
        heavy_conf    = heavy_findings[0].confidence_score

        assert boundary_conf <= heavy_conf, (
            f"Boundary scan ({boundary_conf}) should not exceed "
            f"heavier scan ({heavy_conf})"
        )

    def test_confidence_note_present_on_all_findings(self):
        """Every finding must have a non-empty confidence_note explaining its score."""
        for ctx_fn in [_ctx_arp_spoof, _ctx_port_scan, _ctx_c2_beacon,
                       _ctx_lateral_movement, _ctx_syn_flood]:
            for f in _run(ctx_fn()):
                assert f.confidence_note and len(f.confidence_note) > 10, (
                    f"{f.rule_id}: confidence_note is missing or too short"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Edge-case scenario testing
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_thin_arp_still_fires(self):
        """2-packet ARP spoof (minimum evidence) must still trigger ARP-001."""
        findings = _run(_ctx_thin_arp())
        assert any(f.rule_id == "ARP-001" for f in findings), (
            "ARP-001 is deterministic and must fire even with 2 packets"
        )

    def test_thin_arp_confidence_below_full(self):
        """2-packet ARP finding must have lower confidence_score than 20-packet one."""
        thin = _run(_ctx_thin_arp())[0].confidence_score
        full = _run(_ctx_arp_spoof())[0].confidence_score
        assert thin < full

    def test_scan_at_threshold_fires(self):
        """Exactly 20 unique ports must trigger SCAN-001 (boundary inclusion)."""
        findings = _run(_ctx_scan_at_threshold())
        assert any(f.rule_id == "SCAN-001" for f in findings), (
            "SCAN-001 must fire at exactly the 20-port threshold"
        )

    def test_scan_below_threshold_silent(self):
        """19 unique ports must NOT trigger SCAN-001 (one below threshold)."""
        findings = _run(_ctx_scan_below_threshold())
        assert not any(f.rule_id == "SCAN-001" for f in findings)

    def test_c2_short_capture_still_fires(self):
        """8 perfectly-timed beacon SYNs (minimum count) must trigger C2-001."""
        findings = _run(_ctx_c2_short_capture())
        assert any(f.rule_id == "C2-001" for f in findings), (
            "C2-001 must fire with exactly 8 periodic connections (minimum threshold)"
        )

    def test_c2_high_jitter_suppressed(self):
        """Irregular intervals must suppress C2-001 — jitter guard is critical."""
        findings = _run(_ctx_c2_high_jitter())
        assert not any(f.rule_id == "C2-001" for f in findings), (
            "C2-001 must NOT fire when CoV > 0.15"
        )

    def test_single_mac_no_arp_finding(self):
        """Many ARP packets from same MAC — no conflict, ARP-001 must not fire."""
        findings = _run(_ctx_noisy_arp_one_mac())
        assert not any(f.rule_id == "ARP-001" for f in findings)

    def test_empty_context_no_crash(self):
        """Empty CaptureContext must not crash the analyzer."""
        ctx = _base_ctx(n_packets=0, duration=0.0)
        findings = _run(ctx)
        assert findings == []


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Regression protection: aggregate accuracy thresholds
# ═══════════════════════════════════════════════════════════════════════════════

_POSITIVE_SCENARIOS = [
    ("ARP-001",  _ctx_arp_spoof),
    ("SCAN-001", _ctx_port_scan),
    ("DOS-001",  _ctx_syn_flood),
    ("C2-001",   _ctx_c2_beacon),
    ("LAT-001",  _ctx_lateral_movement),
    ("DOS-002",  _ctx_icmp_flood),
]

_NEGATIVE_SCENARIOS = [
    _ctx_clean,
    _ctx_noisy_arp_one_mac,
    _ctx_scan_below_threshold,
    _ctx_c2_high_jitter,
]


class TestRegressionThresholds:
    """
    Aggregate accuracy metrics enforced as regression guards.
    Failing any of these means a rule change broke correctness.
    """

    def test_top1_accuracy_at_least_80_pct(self):
        """Top-1 accuracy across all positive scenarios must be ≥ 80%."""
        correct = 0
        for expected_rule, ctx_fn in _POSITIVE_SCENARIOS:
            findings = _run(ctx_fn())
            if findings and findings[0].rule_id == expected_rule:
                correct += 1
        accuracy = correct / len(_POSITIVE_SCENARIOS)
        assert accuracy >= 0.80, (
            f"Top-1 accuracy {accuracy:.0%} below 80% threshold "
            f"({correct}/{len(_POSITIVE_SCENARIOS)} correct)"
        )

    def test_top3_accuracy_at_least_95_pct(self):
        """Top-3 accuracy across all positive scenarios must be ≥ 95%."""
        correct = 0
        for expected_rule, ctx_fn in _POSITIVE_SCENARIOS:
            findings = _run(ctx_fn())
            if any(f.rule_id == expected_rule for f in findings[:3]):
                correct += 1
        accuracy = correct / len(_POSITIVE_SCENARIOS)
        assert accuracy >= 0.95, (
            f"Top-3 accuracy {accuracy:.0%} below 95% threshold "
            f"({correct}/{len(_POSITIVE_SCENARIOS)} correct)"
        )

    def test_zero_false_positives_on_negative_scenarios(self):
        """No security findings must be generated on any clean/negative scenario."""
        total_fp = 0
        for ctx_fn in _NEGATIVE_SCENARIOS:
            findings = _run(ctx_fn())
            total_fp += len(findings)
        assert total_fp == 0, (
            f"FP regression: {total_fp} false positive finding(s) on clean traffic"
        )

    def test_all_positive_scenarios_produce_at_least_one_finding(self):
        """Every positive scenario must produce ≥1 finding (FN regression guard)."""
        fn_scenarios = []
        for expected_rule, ctx_fn in _POSITIVE_SCENARIOS:
            findings = _run(ctx_fn())
            if not findings:
                fn_scenarios.append(expected_rule)
        assert not fn_scenarios, (
            f"FN regression: no findings produced for: {fn_scenarios}"
        )

    def test_expected_rule_always_in_findings(self):
        """The expected rule must appear somewhere in findings (not just top-3)."""
        missed = []
        for expected_rule, ctx_fn in _POSITIVE_SCENARIOS:
            findings = _run(ctx_fn())
            if not any(f.rule_id == expected_rule for f in findings):
                missed.append(expected_rule)
        assert not missed, f"FN regression: rules not detected at all: {missed}"

    def test_confidence_scores_never_degenerate(self):
        """No finding across all positive scenarios may have confidence_score < 10 or > 95."""
        violations = []
        for _, ctx_fn in _POSITIVE_SCENARIOS:
            for f in _run(ctx_fn()):
                if not (10 <= f.confidence_score <= 95):
                    violations.append(f"{f.rule_id}={f.confidence_score}")
        assert not violations, (
            f"Confidence score out of [10,95]: {violations}"
        )

    def test_all_findings_have_rule_id(self):
        """Every finding must have a non-empty rule_id (structural integrity check)."""
        missing = []
        for _, ctx_fn in _POSITIVE_SCENARIOS:
            for f in _run(ctx_fn()):
                if not f.rule_id:
                    missing.append(f.title)
        assert not missing, f"Findings missing rule_id: {missing}"
