"""
Semantic analysis regression tests.

Unlike test_corpus_regression.py (which tests the extraction layer),
these tests validate the *analysis* layer: finding detection, host role
inference, and storyline content.

Tests build CaptureContext objects directly — no tshark required.
"""
from __future__ import annotations

import pytest

from analyzers import dns, security, tcp
from correlator.engine import correlate
from models import (
    CaptureContext,
    Confidence,
    DnsTransaction,
    Evidence,
    FileInfo,
    FlowRecord,
    PacketRecord,
    SessionRecord,
    Severity,
    TCPState,
)
from profiler.host import build_profiles

# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_ctx(**kwargs) -> CaptureContext:
    ctx = CaptureContext()
    ctx.file_info = FileInfo(
        filename="test.pcap",
        total_packets=kwargs.get("total_packets", 100),
        duration_sec=kwargs.get("duration_sec", 10.0),
        file_size_bytes=1024,
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
    bytes_sent: int = 1000,
    bytes_recv: int = 500,
    retransmissions: int = 0,
    syn_ts: float = 1.0,
) -> SessionRecord:
    state = TCPState.FIN_CLOSED if has_fin else (
        TCPState.RESET if has_rst else (
            TCPState.HALF_OPEN if has_syn and not has_synack else (
                TCPState.MID_STREAM if not has_syn else TCPState.ESTABLISHED
            )
        )
    )
    s = SessionRecord(
        stream_id=stream_id,
        flow_key=f"{min(src,dst)}:{min(src_port,dst_port)}-{max(src,dst)}:{max(src_port,dst_port)}-6",
        src_ip=src, src_port=src_port,
        dst_ip=dst, dst_port=dst_port,
        state=state,
        has_syn=has_syn, has_synack=has_synack,
        has_fin=has_fin, has_rst=has_rst,
        bytes_sent=bytes_sent, bytes_recv=bytes_recv,
        packets_sent=10, packets_recv=5,
        retransmissions=retransmissions,
        syn_ts=syn_ts, synack_ts=syn_ts + 0.005, last_ts=syn_ts + 1.0,
    )
    return s


def _syn_pkt(num: int, src: str, dst_port: int, ts: float = 1.0) -> PacketRecord:
    pkt = PacketRecord(
        num=num, ts=ts, frame_len=60, protocol="TCP",
        src_ip=src, dst_ip="10.0.0.1",
        src_port=54000 + num, dst_port=dst_port,
        ip_proto=6, tcp_stream=num,
        tcp_flags_syn=True,
    )
    return pkt


# ── SCAN-001: Port scan detection ─────────────────────────────────────────────

class TestPortScanDetection:
    """SCAN-001 fires when ≥20 unique ports are contacted via SYN."""

    def _make_scan_ctx(self, port_count: int) -> CaptureContext:
        ctx = _base_ctx(total_packets=port_count)
        scanner = "192.168.1.50"
        target = "10.0.0.1"
        for i in range(port_count):
            pkt = _syn_pkt(i + 1, scanner, 1024 + i, ts=1.0 + i * 0.01)
            pkt.dst_ip = target
            ctx.packets.append(pkt)
            # No SYN-ACK → HALF_OPEN sessions
            sess = _tcp_session(
                i, scanner, 54000 + i, target, 1024 + i,
                has_synack=False, has_fin=False,
                bytes_recv=0, syn_ts=1.0 + i * 0.01,
            )
            ctx.sessions[i] = sess
        return ctx

    def test_scan_fires_at_20_ports(self):
        ctx = self._make_scan_ctx(20)
        security.analyze(ctx)
        scan_findings = [f for f in ctx.findings if f.rule_id == "SCAN-001"]
        assert len(scan_findings) == 1, (
            f"Expected SCAN-001 with 20 ports, found {len(scan_findings)} findings: "
            f"{[f.rule_id for f in ctx.findings]}"
        )

    def test_scan_severity_high_at_20_ports(self):
        ctx = self._make_scan_ctx(20)
        security.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "SCAN-001")
        assert f.severity in (Severity.HIGH, "high")

    def test_scan_severity_critical_at_100_ports(self):
        ctx = self._make_scan_ctx(100)
        security.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "SCAN-001")
        assert f.severity in (Severity.CRITICAL, "critical")

    def test_scan_does_not_fire_below_threshold(self):
        ctx = self._make_scan_ctx(5)
        security.analyze(ctx)
        scan_findings = [f for f in ctx.findings if f.rule_id == "SCAN-001"]
        assert len(scan_findings) == 0

    def test_scan_confidence_high(self):
        ctx = self._make_scan_ctx(25)
        security.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "SCAN-001")
        assert f.confidence in (Confidence.HIGH, "high")

    def test_scan_evidence_contains_packet_nums(self):
        ctx = self._make_scan_ctx(20)
        security.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "SCAN-001")
        assert len(f.evidence.packet_nums) > 0

    def test_scan_confidence_note_present(self):
        ctx = self._make_scan_ctx(20)
        security.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "SCAN-001")
        assert f.confidence_note, "confidence_note must be non-empty for SCAN-001"
        assert "HIGH" in f.confidence_note.upper()

    def test_scan_affected_host_is_scanner(self):
        ctx = self._make_scan_ctx(20)
        security.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "SCAN-001")
        assert "192.168.1.50" in f.affected_hosts


# ── TCP-001: Retransmission rate detection ────────────────────────────────────

class TestRetransmissionDetection:
    """TCP-001 fires when retransmission rate ≥ 1% with ≥50 retransmissions."""

    def _make_retrans_ctx(self, total: int, retrans: int) -> CaptureContext:
        """
        TCP-001 reads from ctx.flows (not sessions).
        Build a FlowRecord with the desired retransmission count.
        """
        ctx = _base_ctx(total_packets=total)
        src, dst = "192.168.1.1", "10.0.0.1"
        flow_key = f"{src}:1234-{dst}:443-6"
        flow = FlowRecord(
            key=flow_key,
            proto=6,
            src_ip=src, src_port=1234,
            dst_ip=dst, dst_port=443,
            first_seen=1.0, last_seen=1.0 + total * 0.001,
            fwd_packets=total, rev_packets=0,
            fwd_bytes=total * 100, rev_bytes=0,
            tcp_stream=0,
            retransmissions=retrans,
            packet_nums=list(range(1, min(total + 1, 21))),
        )
        ctx.flows[flow_key] = flow
        return ctx

    def test_retrans_fires_at_threshold(self):
        ctx = self._make_retrans_ctx(1000, 60)   # 6% rate, 60 retrans ≥ 50
        tcp.analyze(ctx)
        findings = [f for f in ctx.findings if f.rule_id == "TCP-001"]
        assert len(findings) == 1

    def test_retrans_does_not_fire_below_count_threshold(self):
        ctx = self._make_retrans_ctx(1000, 5)   # only 5 retrans < 50 minimum
        tcp.analyze(ctx)
        findings = [f for f in ctx.findings if f.rule_id == "TCP-001"]
        assert len(findings) == 0

    def test_retrans_severity_critical_above_5pct(self):
        ctx = self._make_retrans_ctx(1000, 60)  # 6% > 5%
        tcp.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "TCP-001")
        assert f.severity in (Severity.CRITICAL, "critical")

    def test_retrans_severity_high_at_2pct(self):
        ctx = self._make_retrans_ctx(2500, 50)   # 2% rate, 50 retrans
        tcp.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "TCP-001")
        assert f.severity in (Severity.HIGH, "high")

    def test_retrans_confidence_note_present(self):
        ctx = self._make_retrans_ctx(1000, 60)
        tcp.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "TCP-001")
        assert f.confidence_note, "confidence_note must be non-empty for TCP-001"


# ── DNS-001: NXDOMAIN storm ───────────────────────────────────────────────────

class TestNxdomainStorm:
    """DNS-001 fires when NXDOMAIN count ≥ 20."""

    def _make_nxdomain_ctx(self, count: int) -> CaptureContext:
        ctx = _base_ctx()
        for i in range(count):
            tx = DnsTransaction(
                txid=i, query_pkt=i + 1, response_pkt=i + 100,
                ts_query=1.0 + i * 0.1, ts_response=1.05 + i * 0.1,
                client_ip="192.168.1.5",
                resolver_ip="8.8.8.8",
                qname=f"random{i:06d}.example.invalid",
                qtype="A",
                rcode="3",
                is_nxdomain=True,
                rtt_ms=50.0,
            )
            ctx.dns_transactions.append(tx)
        return ctx

    def test_nxdomain_fires_at_20(self):
        ctx = self._make_nxdomain_ctx(20)
        dns.analyze(ctx)
        findings = [f for f in ctx.findings if f.rule_id == "DNS-001"]
        assert len(findings) == 1

    def test_nxdomain_does_not_fire_at_19(self):
        ctx = self._make_nxdomain_ctx(19)
        dns.analyze(ctx)
        findings = [f for f in ctx.findings if f.rule_id == "DNS-001"]
        assert len(findings) == 0

    def test_nxdomain_severity_critical_at_100(self):
        ctx = self._make_nxdomain_ctx(100)
        dns.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "DNS-001")
        assert f.severity in (Severity.CRITICAL, "critical")

    def test_nxdomain_confidence_high(self):
        ctx = self._make_nxdomain_ctx(30)
        dns.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "DNS-001")
        assert f.confidence in (Confidence.HIGH, "high")

    def test_nxdomain_confidence_note_present(self):
        ctx = self._make_nxdomain_ctx(30)
        dns.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "DNS-001")
        assert f.confidence_note
        assert "HIGH" in f.confidence_note.upper()

    def test_nxdomain_evidence_metrics(self):
        ctx = self._make_nxdomain_ctx(25)
        dns.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "DNS-001")
        assert f.evidence.metrics.get("nxdomain_count") == 25


# ── Host role inference ───────────────────────────────────────────────────────

class TestHostRoleInference:
    """build_profiles() assigns correct roles from session patterns."""

    def _server_client_ctx(self) -> CaptureContext:
        """One server (many accepted) and one client (many initiated)."""
        ctx = _base_ctx()
        server_ip = "10.0.0.1"
        client_ip = "192.168.1.10"
        # 5 sessions: client initiates all, server accepts all on port 443
        for i in range(5):
            sess = _tcp_session(
                i, client_ip, 50000 + i, server_ip, 443,
                bytes_sent=100, bytes_recv=5000,
            )
            ctx.sessions[i] = sess
        return ctx

    def test_server_role_assigned(self):
        ctx = self._server_client_ctx()
        build_profiles(ctx)
        server = ctx.hosts.get("10.0.0.1")
        assert server is not None
        role_val = server.role.value if hasattr(server.role, "value") else server.role
        # Server accepted 5 sessions; should be WEB_SERVER (port 443) or SERVER
        assert role_val in ("web_server", "server"), f"Expected server role, got {role_val}"

    def test_client_role_assigned(self):
        ctx = self._server_client_ctx()
        build_profiles(ctx)
        client = ctx.hosts.get("192.168.1.10")
        assert client is not None
        role_val = client.role.value if hasattr(client.role, "value") else client.role
        assert role_val == "client", f"Expected client role, got {role_val}"

    def test_dns_resolver_role(self):
        ctx = _base_ctx()
        client_ip = "192.168.1.1"
        resolver_ip = "10.0.0.53"
        for i in range(5):
            sess = _tcp_session(
                i, client_ip, 50000 + i, resolver_ip, 53,
                bytes_sent=50, bytes_recv=200,
            )
            ctx.sessions[i] = sess
        build_profiles(ctx)
        resolver = ctx.hosts.get(resolver_ip)
        assert resolver is not None
        role_val = resolver.role.value if hasattr(resolver.role, "value") else resolver.role
        assert role_val == "dns_resolver", f"Expected dns_resolver, got {role_val}"

    def test_connection_success_ratio_all_success(self):
        ctx = self._server_client_ctx()
        build_profiles(ctx)
        client = ctx.hosts.get("192.168.1.10")
        # All 5 sessions have synack → 100% success
        assert client.connection_success_ratio == pytest.approx(1.0)

    def test_connection_success_ratio_with_failures(self):
        ctx = _base_ctx()
        client = "192.168.1.20"
        target = "10.0.0.1"
        # 3 successful, 2 failed
        for i in range(3):
            ctx.sessions[i] = _tcp_session(i, client, 50000 + i, target, 80)
        for i in range(3, 5):
            ctx.sessions[i] = _tcp_session(
                i, client, 50000 + i, target, 80,
                has_synack=False, bytes_recv=0,
            )
        build_profiles(ctx)
        h = ctx.hosts.get(client)
        # initiated=3+2=5 (all had has_syn=True), failed=2
        assert h.connection_success_ratio == pytest.approx(0.6)

    def test_peer_roles_populated(self):
        ctx = self._server_client_ctx()
        build_profiles(ctx)
        client = ctx.hosts.get("192.168.1.10")
        assert "10.0.0.1" in client.peer_roles
        assert client.peer_roles["10.0.0.1"] in ("web_server", "server")

    def test_protocol_mix_pct_sums_to_100(self):
        ctx = self._server_client_ctx()
        build_profiles(ctx)
        for ip, h in ctx.hosts.items():
            if h.protocol_mix_pct:
                total = sum(h.protocol_mix_pct.values())
                assert abs(total - 100.0) < 1.0, (
                    f"{ip} protocol_mix_pct sums to {total}, expected ~100"
                )

    def test_unique_dst_ports_used_in_anomaly_scoring(self):
        """
        Regression: unique_dst_ports must be computed BEFORE anomaly scoring
        or the scanning anomaly score is always 0.

        The profiler registers hosts from sessions/flows.  Packets provide the
        per-IP unique dst-port counts.  We need both to test the ordering fix.
        """
        ctx = _base_ctx()
        scanner = "192.168.1.99"
        target = "10.0.0.1"
        # Register the scanner via a flow so build_profiles sees it
        flow_key = f"{scanner}:54000-{target}:80-6"
        ctx.flows[flow_key] = FlowRecord(
            key=flow_key, proto=6,
            src_ip=scanner, src_port=54000,
            dst_ip=target, dst_port=80,
            first_seen=1.0, last_seen=2.0,
            fwd_packets=60, rev_packets=0,
        )
        # 60 packets each to a different destination port
        for i in range(60):
            pkt = _syn_pkt(i + 1, scanner, 1024 + i, ts=1.0 + i * 0.01)
            pkt.dst_ip = target
            ctx.packets.append(pkt)
        build_profiles(ctx)
        h = ctx.hosts.get(scanner)
        assert h is not None
        assert h.unique_dst_ports == 60, f"Expected 60, got {h.unique_dst_ports}"
        assert h.anomaly_score > 0, (
            "anomaly_score should be > 0 for a host contacting 60 unique ports. "
            "This likely means unique_dst_ports was computed after anomaly scoring."
        )


# ── Storyline content validation ──────────────────────────────────────────────

class TestStorylineContent:
    """Captures without findings produce correct narrative content."""

    def test_capture_story_contains_protocol_info(self):
        ctx = _base_ctx()
        ctx.protocol_stats = {"TCP": 500, "DNS": 100, "ARP": 10}
        correlate(ctx)
        assert "TCP" in ctx.capture_story
        assert "500" in ctx.capture_story

    def test_capture_story_mentions_critical_finding(self):
        from detection.engine import build_finding
        ctx = _base_ctx()
        f = build_finding(
            rule_id="TEST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="test",
            title="Test Critical Finding",
            description="desc",
            explanation="expl",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(),
        )
        ctx.findings.append(f)
        correlate(ctx)
        # Story should mention critical finding in the conclusion
        assert "critical" in ctx.capture_story.lower()

    def test_host_story_includes_peer_role(self):
        ctx = _base_ctx()
        client = "192.168.1.10"
        server = "10.0.0.1"
        ctx.sessions[0] = _tcp_session(0, client, 50000, server, 443)
        build_profiles(ctx)
        correlate(ctx)
        # The client's host story should mention the server IP
        client_story = ctx.host_stories.get(client, "")
        if client_story:   # only generated for top-N anomalous hosts
            assert server in client_story or "peer" in client_story.lower()

    def test_capture_story_no_findings_mentions_no_anomalies(self):
        ctx = _base_ctx()
        correlate(ctx)
        assert (
            "no" in ctx.capture_story.lower()
            or "not detected" in ctx.capture_story.lower()
        )


# ── ARP spoofing detection ────────────────────────────────────────────────────

class TestArpSpoofDetection:
    """ARP-001 fires when the same IP appears with 2+ MAC addresses."""

    def _make_arp_ctx(self, mac_count: int) -> CaptureContext:
        ctx = _base_ctx()
        ip = "192.168.1.1"
        for i in range(mac_count):
            pkt = PacketRecord(
                num=i + 1, ts=1.0 + i * 0.1, frame_len=42,
                protocol="ARP",
                src_ip=ip, dst_ip="192.168.1.255",
                src_port=0, dst_port=0,
                ip_proto=0, has_arp=True,
                extras={
                    "arp.src.proto_ipv4": ip,
                    "arp.src.hw_mac": f"aa:bb:cc:dd:ee:{i:02x}",
                },
            )
            ctx.packets.append(pkt)
        return ctx

    def test_arp_fires_with_two_macs(self):
        ctx = self._make_arp_ctx(2)
        security.analyze(ctx)
        findings = [f for f in ctx.findings if f.rule_id == "ARP-001"]
        assert len(findings) == 1

    def test_arp_does_not_fire_with_one_mac(self):
        ctx = self._make_arp_ctx(1)
        security.analyze(ctx)
        findings = [f for f in ctx.findings if f.rule_id == "ARP-001"]
        assert len(findings) == 0

    def test_arp_confidence_note_present(self):
        ctx = self._make_arp_ctx(2)
        security.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "ARP-001")
        assert f.confidence_note
        assert "HIGH" in f.confidence_note.upper()
