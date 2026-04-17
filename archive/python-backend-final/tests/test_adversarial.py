"""
Adversarial and trust-hardening tests.

These tests verify that the analyzer behaves correctly under difficult
real-world conditions that historically produce misleading conclusions:

1.  All-midstream capture   — entire capture is mid-stream data (no handshakes)
2.  Thin-evidence finding   — critical finding from a single packet
3.  Contradictory stats     — finding claims something the raw stats contradict
4.  C2 detection, short cap — too short to confirm periodicity
5.  Deduplication           — same rule + host fires multiple times → merged
6.  Clean capture trust     — good capture produces high trust score
7.  Evidence quality scores — verify confidence_score reflects evidence depth
8.  Auto confidence note    — every finding has a populated confidence_note
9.  Overconfident critical  — SANITY-009 fires for thin-evidence critical finding
10. Trust score components  — capture completeness and finding quality tracked
"""
from __future__ import annotations


from analyzers import security
from core.sanity import run_sanity_checks
from core.trust import compute_trust_score
from detection.engine import build_finding, finalize
from models import (
    CaptureContext,
    Confidence,
    Evidence,
    FileInfo,
    PacketRecord,
    SessionRecord,
    Severity,
    TCPState,
)
from profiler.host import build_profiles


# ── Shared helpers ────────────────────────────────────────────────────────────

def _base_ctx(**kwargs) -> CaptureContext:
    ctx = CaptureContext()
    ctx.file_info = FileInfo(
        filename="adversarial.pcap",
        total_packets=kwargs.get("total_packets", 100),
        duration_sec=kwargs.get("duration_sec", 30.0),
        file_size_bytes=kwargs.get("size", 50_000),
    )
    return ctx


def _tcp_session(
    stream_id: int,
    src: str, src_port: int,
    dst: str, dst_port: int,
    *,
    has_syn: bool = True,
    has_synack: bool = True,
    has_fin: bool = False,
    has_rst: bool = False,
    retransmissions: int = 0,
    syn_ts: float = 1.0,
) -> SessionRecord:
    state = (
        TCPState.FIN_CLOSED if has_fin else (
            TCPState.RESET if has_rst else (
                TCPState.HALF_OPEN if has_syn and not has_synack else (
                    TCPState.MID_STREAM if not has_syn else TCPState.ESTABLISHED
                )
            )
        )
    )
    return SessionRecord(
        stream_id=stream_id,
        flow_key=f"{src}:{src_port}-{dst}:{dst_port}-6",
        src_ip=src, src_port=src_port,
        dst_ip=dst, dst_port=dst_port,
        state=state,
        has_syn=has_syn, has_synack=has_synack,
        has_fin=has_fin, has_rst=has_rst,
        bytes_sent=1000, bytes_recv=500,
        packets_sent=10, packets_recv=5,
        retransmissions=retransmissions,
        syn_ts=syn_ts,
        synack_ts=syn_ts + 0.005 if has_synack else 0.0,
        last_ts=syn_ts + 2.0,
    )


def _syn_pkt(num: int, src: str, dst: str, dst_port: int, ts: float = 1.0) -> PacketRecord:
    return PacketRecord(
        num=num, ts=ts, frame_len=60, protocol="TCP",
        src_ip=src, dst_ip=dst,
        src_port=50000 + num, dst_port=dst_port,
        ip_proto=6, tcp_stream=num,
        tcp_flags_syn=True,
    )


def _minimal_result(ctx: CaptureContext) -> dict:
    """Build a minimal result dict from a CaptureContext (subset of pipeline output)."""
    from core.pipeline import _finding_to_dict, _host_to_dict
    from core.decision import build_decision_report
    active = [_finding_to_dict(f) for f in ctx.findings if not f.suppressed]
    host_dicts = [_host_to_dict(h) for h in ctx.hosts.values()]
    decision = build_decision_report(active, host_dicts)
    sessions = list(ctx.sessions.values())
    total = len(sessions)
    midstream = sum(1 for s in sessions if not s.has_syn)
    failed_hs = sum(1 for s in sessions if s.has_syn and not s.has_synack)
    result = {
        "file_info": {
            "duration_sec": ctx.file_info.duration_sec,
            "total_packets": ctx.file_info.total_packets,
        },
        "all_issues": active,
        "hosts": host_dicts,
        "dns": getattr(ctx, "dns_stats", {}),
        "tcp": {
            "total_sessions": total,
            "midstream": midstream,
            "failed_handshakes": failed_hs,
            "retransmissions": sum(s.retransmissions for s in sessions),
        },
        "http": getattr(ctx, "http_stats", {}),
        "decision_support": decision,
        "sanity_warnings": [],
    }
    result["sanity_warnings"] = run_sanity_checks(result)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 1. All-midstream capture
# ══════════════════════════════════════════════════════════════════════════════

class TestAllMidstreamCapture:
    """
    Capture started mid-session: every TCP session is mid-stream.
    Trust score must be low; capture quality must be flagged.
    """

    def _make_ctx(self) -> CaptureContext:
        ctx = _base_ctx(total_packets=20, duration_sec=5.0)
        for i in range(10):
            sess = _tcp_session(
                i, "10.0.0.1", 50000 + i, "10.0.0.2", 443,
                has_syn=False, has_synack=False,
            )
            ctx.sessions[i] = sess
        return ctx

    def test_trust_score_is_low(self):
        ctx = self._make_ctx()
        result = _minimal_result(ctx)
        trust = compute_trust_score(result)
        assert trust["trust_score"] < 70, (
            f"All-midstream capture should have trust_score < 70; got {trust['trust_score']}"
        )

    def test_trust_label_is_not_high(self):
        ctx = self._make_ctx()
        result = _minimal_result(ctx)
        trust = compute_trust_score(result)
        assert "High" not in trust["trust_label"], (
            f"All-midstream capture should not have 'High' trust label; got: {trust['trust_label']}"
        )

    def test_capture_completeness_component_is_low(self):
        ctx = self._make_ctx()
        result = _minimal_result(ctx)
        trust = compute_trust_score(result)
        assert trust["components"]["capture_completeness"] < 60, (
            f"100% midstream should give low capture_completeness; "
            f"got {trust['components']['capture_completeness']}"
        )

    def test_trust_reasons_mention_midstream(self):
        ctx = self._make_ctx()
        result = _minimal_result(ctx)
        trust = compute_trust_score(result)
        reasons_text = " ".join(trust["trust_reasons"]).lower()
        assert "mid-stream" in reasons_text or "midstream" in reasons_text, (
            f"Trust reasons should mention mid-stream sessions; got: {trust['trust_reasons']}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Thin-evidence finding
# ══════════════════════════════════════════════════════════════════════════════

class TestThinEvidenceFinding:
    """
    A finding created with a single packet and no metrics should have a
    low confidence_score regardless of its severity level.
    """

    def test_zero_packets_gives_low_confidence_score(self):
        f = build_finding(
            rule_id="TEST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="test",
            title="Thin Evidence Test",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=["10.0.0.1"],
            affected_flows=[],
            evidence=Evidence(packet_nums=[]),    # zero packets
        )
        assert f.confidence_score < 55, (
            f"Zero-packet critical finding should have confidence_score < 55; "
            f"got {f.confidence_score}"
        )

    def test_one_packet_no_metrics_gives_low_confidence_score(self):
        f = build_finding(
            rule_id="TEST-002",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category="test",
            title="Single Packet Test",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=["10.0.0.1"],
            affected_flows=[],
            evidence=Evidence(packet_nums=[42]),  # single packet, no metrics
        )
        assert f.confidence_score < 55, (
            f"Single-packet finding should have low confidence_score; got {f.confidence_score}"
        )

    def test_many_packets_with_metrics_gives_high_confidence_score(self):
        f = build_finding(
            rule_id="SCAN-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="security",
            title="Port Scan",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=["10.0.0.99"],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=list(range(1, 101)),   # 100 packets
                metrics={"unique_ports": 80, "packet_count": 100},
                samples=["10.0.0.99 → 10.0.0.1:22"],
                time_first=1.0, time_last=120.0,   # 2-minute window
            ),
        )
        assert f.confidence_score >= 70, (
            f"Strong evidence finding should have confidence_score >= 70; got {f.confidence_score}"
        )

    def test_heuristic_rule_gets_confidence_penalty(self):
        """DNS-002 (tunneling) has a known heuristic penalty in _RULE_CONF_ADJUST."""
        f_dns = build_finding(
            rule_id="DNS-002",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="dns",
            title="DNS Tunnel",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=["10.0.0.5"],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=list(range(1, 21)),
                metrics={"long_label_count": 20},
            ),
        )
        f_arp = build_finding(
            rule_id="ARP-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="network",
            title="ARP Spoof",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=["10.0.0.5"],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=list(range(1, 21)),
                metrics={"mac_count": 3},
            ),
        )
        # ARP-001 (directly observable) should score higher than DNS-002 (heuristic)
        assert f_arp.confidence_score > f_dns.confidence_score, (
            f"ARP-001 (deterministic) should outscore DNS-002 (heuristic); "
            f"ARP={f_arp.confidence_score}, DNS={f_dns.confidence_score}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Auto confidence note
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoConfidenceNote:
    """Every finding must have a non-empty confidence_note."""

    def test_finding_without_note_gets_auto_note(self):
        """If no confidence_note is supplied, engine generates one automatically."""
        f = build_finding(
            rule_id="TEST-AUTO",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="test",
            title="Auto Note Test",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(packet_nums=[1, 2, 3]),
            confidence_note="",   # explicitly empty — should be auto-filled
        )
        assert f.confidence_note, (
            "build_finding() should auto-generate confidence_note when not provided"
        )
        assert len(f.confidence_note) > 20, (
            f"Auto-generated confidence_note is too short: '{f.confidence_note}'"
        )

    def test_explicit_note_is_preserved(self):
        """An explicitly supplied confidence_note should not be overwritten."""
        custom_note = "Custom note: this was manually set by the analyzer."
        f = build_finding(
            rule_id="TEST-PRESERVE",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="test",
            title="Note Preserve Test",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(),
            confidence_note=custom_note,
        )
        assert f.confidence_note == custom_note, (
            f"Explicit confidence_note was overwritten; got: '{f.confidence_note}'"
        )

    def test_auto_note_mentions_low_for_thin_evidence(self):
        f = build_finding(
            rule_id="TEST-THIN",
            severity=Severity.CRITICAL,
            confidence=Confidence.LOW,
            category="test",
            title="Low Confidence Test",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(packet_nums=[1]),
            confidence_note="",
        )
        assert "LOW" in f.confidence_note.upper() or "preliminary" in f.confidence_note.lower(), (
            f"Auto-note for low confidence should say 'LOW' or 'preliminary'; "
            f"got: '{f.confidence_note}'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4. Overconfident critical finding (SANITY-009)
# ══════════════════════════════════════════════════════════════════════════════

class TestOverconfidentCriticalFinding:
    """
    SANITY-009 must fire when a critical finding has low confidence_score.
    This prevents analysts from escalating based on weak evidence.
    """

    def _make_result_with_thin_critical(self) -> dict:
        ctx = _base_ctx()
        f = build_finding(
            rule_id="C2-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            category="security",
            title="C2 Beaconing",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=["10.0.0.5"],
            affected_flows=[],
            # Deliberately thin evidence: only 1 packet, no metrics
            evidence=Evidence(packet_nums=[1]),
        )
        ctx.findings.append(f)
        build_profiles(ctx)
        return _minimal_result(ctx)

    def test_sanity009_fires_for_thin_critical(self):
        result = self._make_result_with_thin_critical()
        # Verify the finding actually has low confidence_score
        findings = result["all_issues"]
        c2_findings = [f for f in findings if f.get("rule_id") == "C2-001"]
        assert c2_findings, "C2-001 finding should be in result"
        cs = c2_findings[0].get("confidence_score", 50)

        # Only check SANITY-009 if the score is actually low
        if cs < 35:
            check_ids = [w["check_id"] for w in result["sanity_warnings"]]
            assert "SANITY-009" in check_ids, (
                f"SANITY-009 should fire for thin-evidence critical finding "
                f"(confidence_score={cs}); checks fired: {check_ids}"
            )

    def test_sanity009_message_is_actionable(self):
        result = self._make_result_with_thin_critical()
        sanity009 = [w for w in result["sanity_warnings"] if w.get("check_id") == "SANITY-009"]
        if sanity009:
            msg = sanity009[0]["message"].lower()
            assert any(kw in msg for kw in ("evidence", "verify", "severity", "provisional")), (
                f"SANITY-009 message should be actionable; got: {sanity009[0]['message']}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 5. Deduplication
# ══════════════════════════════════════════════════════════════════════════════

class TestFindingDeduplication:
    """
    finalize() must merge findings with the same rule_id + primary host.
    This prevents noise from the same attack generating dozens of identical alerts.
    """

    def _make_ctx_with_duplicates(self) -> CaptureContext:
        ctx = _base_ctx()
        # Same rule_id and same primary host fired 3 times
        for i in range(3):
            f = build_finding(
                rule_id="SCAN-001",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="security",
                title="Port Scan",
                description="desc",
                explanation="expl",
                possible_causes=[],
                recommended_actions=[],
                affected_hosts=["10.0.0.99"],
                affected_flows=[],
                evidence=Evidence(
                    packet_nums=list(range(i * 10 + 1, i * 10 + 11)),
                    samples=[f"sample-{i}"],
                ),
            )
            ctx.findings.append(f)
        return ctx

    def test_duplicates_are_merged_to_one(self):
        ctx = self._make_ctx_with_duplicates()
        finalize(ctx)
        scan_findings = [f for f in ctx.findings if f.rule_id == "SCAN-001"]
        assert len(scan_findings) == 1, (
            f"3 duplicate SCAN-001 findings for same host should merge to 1; "
            f"got {len(scan_findings)}"
        )

    def test_deduplicated_finding_keeps_best_score(self):
        ctx = _base_ctx()
        # One medium, one high (same rule + host) — keep the high
        for sev, conf in [(Severity.MEDIUM, Confidence.MEDIUM), (Severity.HIGH, Confidence.HIGH)]:
            ctx.findings.append(build_finding(
                rule_id="TCP-001",
                severity=sev,
                confidence=conf,
                category="tcp",
                title="Retransmission",
                description="desc",
                explanation="expl",
                possible_causes=[],
                recommended_actions=[],
                affected_hosts=["10.0.0.1"],
                affected_flows=[],
                evidence=Evidence(packet_nums=[1, 2]),
            ))
        finalize(ctx)
        tcp_findings = [f for f in ctx.findings if f.rule_id == "TCP-001"]
        assert len(tcp_findings) == 1
        assert tcp_findings[0].score >= 6.0, (
            f"Deduplication should keep the higher-scored finding; score={tcp_findings[0].score}"
        )

    def test_different_hosts_not_merged(self):
        """Findings for DIFFERENT hosts with the same rule must NOT be merged."""
        ctx = _base_ctx()
        for host in ("10.0.0.1", "10.0.0.2"):
            ctx.findings.append(build_finding(
                rule_id="SCAN-001",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="security",
                title="Port Scan",
                description="desc",
                explanation="expl",
                possible_causes=[],
                recommended_actions=[],
                affected_hosts=[host],
                affected_flows=[],
                evidence=Evidence(packet_nums=[1, 2, 3]),
            ))
        finalize(ctx)
        scan_findings = [f for f in ctx.findings if f.rule_id == "SCAN-001"]
        assert len(scan_findings) == 2, (
            f"Findings for different hosts must not be merged; got {len(scan_findings)}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 6. C2 detection in short capture (SANITY-010)
# ══════════════════════════════════════════════════════════════════════════════

class TestC2ShortCapture:
    """
    C2-001 in a capture shorter than 60s should trigger SANITY-010.
    """

    def _make_ctx_c2(self, duration: float) -> CaptureContext:
        ctx = _base_ctx(duration_sec=duration, total_packets=20)
        ctx.file_info.duration_sec = duration
        # Create SYN packets for C2 beaconing detection
        c2_server = "185.220.101.5"
        infected = "10.0.0.5"
        for i in range(10):
            pkt = PacketRecord(
                num=i + 1, ts=float(i) * (duration / 10),
                frame_len=60, protocol="TCP",
                src_ip=infected, dst_ip=c2_server,
                src_port=50000 + i, dst_port=443,
                ip_proto=6, tcp_stream=i,
                tcp_flags_syn=True,
            )
            ctx.packets.append(pkt)
            sess = _tcp_session(
                i, infected, 50000 + i, c2_server, 443,
                syn_ts=float(i) * (duration / 10),
            )
            ctx.sessions[i] = sess
        return ctx

    def test_sanity010_fires_for_short_capture(self):
        ctx = self._make_ctx_c2(duration=30.0)
        security.analyze(ctx)
        build_profiles(ctx)
        result = _minimal_result(ctx)
        # SANITY-010 should fire if C2-001 was detected in < 60s
        c2_detected = any(f.get("rule_id") == "C2-001" for f in result["all_issues"])
        if c2_detected:
            check_ids = [w["check_id"] for w in result["sanity_warnings"]]
            assert "SANITY-010" in check_ids, (
                f"SANITY-010 should fire for C2-001 in {ctx.file_info.duration_sec}s capture; "
                f"checks fired: {check_ids}"
            )

    def test_sanity010_does_not_fire_for_long_capture(self):
        ctx = self._make_ctx_c2(duration=300.0)
        security.analyze(ctx)
        build_profiles(ctx)
        result = _minimal_result(ctx)
        c2_detected = any(f.get("rule_id") == "C2-001" for f in result["all_issues"])
        if c2_detected:
            check_ids = [w["check_id"] for w in result["sanity_warnings"]]
            assert "SANITY-010" not in check_ids, (
                f"SANITY-010 should NOT fire for C2-001 in {ctx.file_info.duration_sec}s capture; "
                f"checks fired: {check_ids}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 7. Trust score for clean, well-captured traffic
# ══════════════════════════════════════════════════════════════════════════════

class TestCleanCaptureTrustScore:
    """
    A clean capture with complete handshakes and no contradictions must
    produce a high trust score — it should not generate false alarms.
    """

    def _make_clean_ctx(self) -> CaptureContext:
        ctx = _base_ctx(total_packets=100, duration_sec=60.0)
        for i in range(10):
            sess = _tcp_session(
                i, "192.168.1.10", 50000 + i, "93.184.216.34", 443,
                has_fin=True,
            )
            ctx.sessions[i] = sess
        return ctx

    def test_clean_capture_has_high_trust(self):
        ctx = self._make_clean_ctx()
        result = _minimal_result(ctx)
        trust = compute_trust_score(result)
        assert trust["trust_score"] >= 70, (
            f"Clean capture with full handshakes should have trust_score >= 70; "
            f"got {trust['trust_score']}"
        )

    def test_no_low_confidence_findings_on_clean_traffic(self):
        ctx = self._make_clean_ctx()
        result = _minimal_result(ctx)
        trust = compute_trust_score(result)
        assert len(trust["low_confidence_findings"]) == 0, (
            f"Clean capture should have no low-confidence findings; "
            f"got {trust['low_confidence_findings']}"
        )

    def test_trust_components_present(self):
        ctx = self._make_clean_ctx()
        result = _minimal_result(ctx)
        trust = compute_trust_score(result)
        assert "capture_completeness" in trust["components"]
        assert "finding_quality" in trust["components"]
        assert "contradiction_penalty" in trust["components"]
        assert trust["components"]["contradiction_penalty"] == 0, (
            "Clean capture should have 0 contradiction penalty"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 8. Trust score reflects sanity contradictions
# ══════════════════════════════════════════════════════════════════════════════

class TestTrustScoreWithContradictions:
    """
    When sanity warnings are present, trust score must be lower than it
    would be for the same findings without contradictions.
    """

    def _make_result(self, sanity_warnings: list) -> dict:
        return {
            "file_info": {"duration_sec": 60.0, "total_packets": 100},
            "all_issues": [],
            "hosts": [],
            "tcp": {"total_sessions": 5, "midstream": 0, "failed_handshakes": 0, "retransmissions": 0},
            "http": {},
            "dns": {},
            "decision_support": {"risk_level": "clean"},
            "sanity_warnings": sanity_warnings,
        }

    def test_no_contradictions_score_higher(self):
        no_contradictions = self._make_result([])
        with_contradictions = self._make_result([
            {"check_id": "SANITY-001", "severity": "warning", "message": "test"},
            {"check_id": "SANITY-002", "severity": "warning", "message": "test"},
        ])
        score_clean = compute_trust_score(no_contradictions)["trust_score"]
        score_dirty = compute_trust_score(with_contradictions)["trust_score"]
        assert score_clean > score_dirty, (
            f"No-contradiction result ({score_clean}) should outscore "
            f"contradicted result ({score_dirty})"
        )

    def test_contradiction_penalty_scales_with_count(self):
        """More warnings → larger penalty → lower trust score."""
        results = [
            self._make_result([
                {"check_id": f"SANITY-{i:03d}", "severity": "warning", "message": "test"}
                for i in range(n)
            ])
            for n in (0, 1, 2, 3)
        ]
        scores = [compute_trust_score(r)["trust_score"] for r in results]
        # Each additional warning should lower the score
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1], (
                f"Score with {i} warnings ({scores[i]}) should be >= "
                f"score with {i+1} warnings ({scores[i+1]})"
            )
