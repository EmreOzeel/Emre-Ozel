"""
Real-world validation tests for the PCAP analyzer.

Each test class simulates a real network incident scenario using
CaptureContext objects (no tshark required).  For each scenario we verify:

  1. Correct findings are detected
  2. Decision support gives specific (non-generic) root cause guidance
  3. No major false positives on clean traffic
  4. Decision support investigation steps are scenario-specific

Scenarios
---------
1. TCP connectivity failure     — SYN→RST refusal on firewall-blocked port
2. DNS failure storm            — 30+ NXDOMAIN responses from misconfigured app
3. TLS handshake failure        — TLS alert, self-signed cert, deprecated version
4. Web application attack       — SQLi pattern + 5xx error surge
5. C2 beaconing + lateral move  — periodic outbound + internal scan of SMB

These tests also serve as a regression guard for the decision support engine:
any generic fallback ("Anomalous network behavior") where a specific cause
is available is treated as a test failure.
"""
from __future__ import annotations


from analyzers import dns, http, security, tcp, tls
from core.decision import build_decision_report
from models import (
    CaptureContext,
    DnsTransaction,
    FileInfo,
    FlowRecord,
    HttpTransaction,
    PacketRecord,
    SessionRecord,
    TCPState,
    TlsHandshake,
)
from profiler.host import build_profiles

# ── Shared helpers ────────────────────────────────────────────────────────────

_GENERIC_FALLBACK = "Anomalous network behavior requiring investigation"


def _base_ctx(**kwargs) -> CaptureContext:
    ctx = CaptureContext()
    ctx.file_info = FileInfo(
        filename="scenario.pcap",
        total_packets=kwargs.get("total_packets", 200),
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
    bytes_sent: int = 1_000,
    bytes_recv: int = 500,
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
        flow_key=(
            f"{min(src, dst)}:{min(src_port, dst_port)}"
            f"-{max(src, dst)}:{max(src_port, dst_port)}-6"
        ),
        src_ip=src, src_port=src_port,
        dst_ip=dst, dst_port=dst_port,
        state=state,
        has_syn=has_syn, has_synack=has_synack,
        has_fin=has_fin, has_rst=has_rst,
        bytes_sent=bytes_sent, bytes_recv=bytes_recv,
        packets_sent=max(1, bytes_sent // 1460),
        packets_recv=max(1, bytes_recv // 1460),
        retransmissions=retransmissions,
        syn_ts=syn_ts,
        synack_ts=syn_ts + 0.005 if has_synack else 0.0,
        last_ts=syn_ts + 1.0,
    )


def _syn_pkt(num: int, src: str, dst: str, dst_port: int, ts: float = 1.0) -> PacketRecord:
    return PacketRecord(
        num=num, ts=ts, frame_len=60, protocol="TCP",
        src_ip=src, dst_ip=dst,
        src_port=50000 + num, dst_port=dst_port,
        ip_proto=6, tcp_stream=num,
        tcp_flags_syn=True,
    )


def _flow(src: str, dst: str, dst_port: int,
          retransmissions: int = 0,
          fwd_packets: int = 100,
          rev_packets: int = 100) -> tuple[str, FlowRecord]:
    key = f"{src}:50000-{dst}:{dst_port}-6"
    return key, FlowRecord(
        key=key, proto=6,
        src_ip=src, src_port=50000,
        dst_ip=dst, dst_port=dst_port,
        first_seen=1.0, last_seen=60.0,
        fwd_packets=fwd_packets,
        rev_packets=rev_packets,
        fwd_bytes=fwd_packets * 800,
        rev_bytes=rev_packets * 800,
        retransmissions=retransmissions,
    )


def _decision(ctx: CaptureContext) -> dict:
    """Serialize active findings and return the decision report."""
    from core.pipeline import _finding_to_dict, _host_to_dict
    active = [_finding_to_dict(f) for f in ctx.findings if not f.suppressed]
    host_dicts = [_host_to_dict(h) for h in ctx.hosts.values()]
    return build_decision_report(active, host_dicts)


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 1 — TCP Connectivity Failure
# Client tries to connect to a firewall-blocked port; gets RST or no reply.
# Expected: TCP-003 finding, decision says connectivity/firewall, not generic.
# ══════════════════════════════════════════════════════════════════════════════

class TestTCPConnectivityFailure:
    """
    Scenario: App server 10.0.1.20 repeatedly fails to connect to DB server
    10.0.1.50:5432 (PostgreSQL).  SYN sent, no SYN-ACK.  12 failed attempts.
    """

    def _make_ctx(self) -> CaptureContext:
        ctx = _base_ctx(total_packets=24)
        client, server = "10.0.1.20", "10.0.1.50"
        for i in range(12):
            sess = _tcp_session(
                i, client, 50000 + i, server, 5432,
                has_synack=False, has_rst=False,
                bytes_recv=0, syn_ts=1.0 + i * 2.0,
            )
            ctx.sessions[i] = sess
            pkt = _syn_pkt(i + 1, client, server, 5432, ts=1.0 + i * 2.0)
            ctx.packets.append(pkt)
        return ctx

    def test_tcp003_detected(self):
        ctx = self._make_ctx()
        tcp.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "TCP-003" in rule_ids, (
            f"Expected TCP-003 (failed handshakes) but got: {rule_ids}"
        )

    def test_decision_is_not_generic(self):
        ctx = self._make_ctx()
        tcp.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        causes = [c["cause"] for c in report["ranked_causes"]]
        assert all(c != _GENERIC_FALLBACK for c in causes), (
            f"Decision support gave generic fallback for TCP connectivity failure: {causes}"
        )

    def test_decision_mentions_connectivity(self):
        ctx = self._make_ctx()
        tcp.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        causes_text = " ".join(c["cause"].lower() for c in report["ranked_causes"])
        assert any(kw in causes_text for kw in ("firewall", "filter", "unreachable", "connectivity")), (
            f"Decision cause should mention connectivity/firewall; got: {causes_text}"
        )

    def test_decision_steps_include_firewall_check(self):
        ctx = self._make_ctx()
        tcp.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        all_steps = " ".join(report["investigation_steps"]).lower()
        assert any(kw in all_steps for kw in ("firewall", "port", "service", "listen", "block")), (
            f"Investigation steps should reference firewall/port checks; got: {all_steps[:300]}"
        )

    def test_risk_level_is_medium_or_higher(self):
        ctx = self._make_ctx()
        tcp.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        assert report["risk_level"] in ("medium", "high", "critical"), (
            f"12 failed handshakes should be medium+ risk; got: {report['risk_level']}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 2 — DNS Misconfiguration / NXDOMAIN Storm
# App generates hundreds of NXDOMAIN responses from wrong DNS config.
# Expected: DNS-002 finding, decision points to misconfiguration or DGA.
# ══════════════════════════════════════════════════════════════════════════════

class TestDNSMisconfigurationStorm:
    """
    Scenario: Newly deployed service contacts legacy.internal.corp, which was
    renamed.  DNS returns NXDOMAIN 35 times in 30 seconds.
    """

    def _make_ctx(self, count: int = 35) -> CaptureContext:
        ctx = _base_ctx(total_packets=count * 2)
        base_domain = "legacy.internal.corp"
        for i in range(count):
            tx = DnsTransaction(
                txid=i,
                query_pkt=i * 2 + 1,
                response_pkt=i * 2 + 2,
                ts_query=1.0 + i * 0.8,
                ts_response=1.05 + i * 0.8,
                client_ip="10.10.0.5",
                resolver_ip="10.10.0.1",
                qname=base_domain,
                qtype="A",
                rcode="3",
                is_nxdomain=True,
                rtt_ms=10.0,
            )
            ctx.dns_transactions.append(tx)
        return ctx

    def test_dns001_detected(self):
        ctx = self._make_ctx()
        dns.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "DNS-001" in rule_ids, (
            f"Expected DNS-001 (NXDOMAIN storm) but got: {rule_ids}"
        )

    def test_decision_is_not_generic(self):
        ctx = self._make_ctx()
        dns.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        causes = [c["cause"] for c in report["ranked_causes"]]
        assert all(c != _GENERIC_FALLBACK for c in causes), (
            f"Generic fallback for DNS storm: {causes}"
        )

    def test_decision_mentions_dns_or_misconfiguration(self):
        ctx = self._make_ctx()
        dns.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        causes_text = " ".join(c["cause"].lower() for c in report["ranked_causes"])
        assert any(kw in causes_text for kw in ("dns", "nxdomain", "misconfigur", "resolver", "dga")), (
            f"DNS storm cause should mention DNS/NXDOMAIN; got: {causes_text}"
        )

    def test_evidence_metrics_in_finding(self):
        ctx = self._make_ctx(35)
        dns.analyze(ctx)
        f = next(f for f in ctx.findings if f.rule_id == "DNS-001")
        assert f.evidence.metrics.get("nxdomain_count") == 35

    def test_clean_dns_no_findings(self):
        """Single NXDOMAIN should not trigger DNS-002 (threshold is 20)."""
        ctx = _base_ctx(total_packets=2)
        tx = DnsTransaction(
            txid=1, query_pkt=1, response_pkt=2,
            ts_query=1.0, ts_response=1.05,
            client_ip="10.0.0.1", resolver_ip="8.8.8.8",
            qname="typo.example.com", qtype="A",
            rcode="3", is_nxdomain=True, rtt_ms=50.0,
        )
        ctx.dns_transactions.append(tx)
        dns.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "DNS-002" not in rule_ids, "Single NXDOMAIN should not trigger DNS-002"


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — TLS Handshake Failure
# Client hits a server with expired certificate, triggers TLS alert.
# Expected: TLS-002 (alert), TLS-004 (self-signed) findings.
# ══════════════════════════════════════════════════════════════════════════════

class TestTLSHandshakeFailure:
    """
    Scenario: Internal app hits payment gateway with expired certificate.
    TLS alert fired. Also one self-signed cert on internal proxy.
    """

    def _make_ctx(self) -> CaptureContext:
        ctx = _base_ctx(total_packets=30)
        # Handshake 1: TLS alert (handshake_failure) — cert expired
        ctx.tls_handshakes.append(TlsHandshake(
            stream_id=0,
            client_ip="10.0.0.5", server_ip="203.0.113.10",
            dst_port=443,
            sni="payment.example.com",
            tls_version="TLSv1.3",
            client_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            has_alert=True,
            alert_description="certificate_expired",
            cert_expired=True,
            client_pkt=1, server_pkt=0,
            ts_client=1.0,
        ))
        # Handshake 2: Self-signed certificate on internal service
        ctx.tls_handshakes.append(TlsHandshake(
            stream_id=1,
            client_ip="10.0.0.5", server_ip="10.0.1.100",
            dst_port=8443,
            sni="internal.corp",
            tls_version="TLSv1.2",
            client_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            cert_self_signed=True,
            cert_common_name="internal.corp",
            client_pkt=5, server_pkt=6,
            ts_client=2.0,
        ))
        # Handshake 3: Deprecated TLS 1.0 to legacy backend
        ctx.tls_handshakes.append(TlsHandshake(
            stream_id=2,
            client_ip="10.0.0.5", server_ip="10.0.1.200",
            dst_port=443,
            sni="legacy-api.corp",
            tls_version="TLSv1.0",
            client_version="TLSv1.0",
            cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
            client_pkt=10, server_pkt=11,
            ts_client=3.0,
        ))
        return ctx

    def test_tls002_alert_detected(self):
        ctx = self._make_ctx()
        tls.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "TLS-002" in rule_ids, (
            f"Expected TLS-002 (TLS alert) but got: {rule_ids}"
        )

    def test_tls004_self_signed_detected(self):
        ctx = self._make_ctx()
        tls.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "TLS-004" in rule_ids, (
            f"Expected TLS-004 (self-signed cert) but got: {rule_ids}"
        )

    def test_tls001_deprecated_detected(self):
        ctx = self._make_ctx()
        tls.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "TLS-001" in rule_ids, (
            f"Expected TLS-001 (deprecated TLS version) but got: {rule_ids}"
        )

    def test_decision_tls002_not_generic(self):
        ctx = self._make_ctx()
        tls.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        # TLS-002 cause should mention certificate validation or MitM
        tls002_causes = [
            c["cause"] for c in report["ranked_causes"]
            if c.get("rule_id") == "TLS-002"
        ]
        if tls002_causes:
            assert tls002_causes[0] != _GENERIC_FALLBACK, (
                f"TLS-002 decision is generic fallback: {tls002_causes[0]}"
            )
            assert any(kw in tls002_causes[0].lower() for kw in (
                "certificate", "tls", "handshake", "mitm", "alert"
            )), f"TLS-002 cause doesn't mention certificates/TLS: {tls002_causes[0]}"

    def test_decision_tls004_not_generic(self):
        ctx = self._make_ctx()
        tls.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        tls004_causes = [
            c["cause"] for c in report["ranked_causes"]
            if c.get("rule_id") == "TLS-004"
        ]
        if tls004_causes:
            assert tls004_causes[0] != _GENERIC_FALLBACK, (
                f"TLS-004 decision is generic fallback: {tls004_causes[0]}"
            )

    def test_decision_tls001_steps_include_upgrade(self):
        ctx = self._make_ctx()
        tls.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        all_steps = " ".join(report["investigation_steps"]).lower()
        assert any(kw in all_steps for kw in ("tls", "version", "upgrade", "certificate", "1.2")), (
            f"TLS investigation steps missing TLS-specific guidance: {all_steps[:400]}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 4 — Web Application Attack
# Attacker runs sqlmap against web app, triggering 5xx errors.
# Expected: HTTP-002 (attack patterns), HTTP-004 (5xx surge).
# ══════════════════════════════════════════════════════════════════════════════

class TestWebApplicationAttack:
    """
    Scenario: External scanner at 198.51.100.99 runs SQL injection probes
    against web app on 10.0.0.80.  Web server returns 500 errors.
    """

    def _make_ctx(self) -> CaptureContext:
        ctx = _base_ctx(total_packets=100)
        attacker, server = "198.51.100.99", "10.0.0.80"

        # 25 SQLi probe requests
        sqli_payloads = [
            "/search?q=' OR 1=1--",
            "/user?id=1 UNION SELECT * FROM users",
            "/login?u=admin'--&p=x",
            "/api?data=1; DROP TABLE users--",
        ]
        for i in range(25):
            tx = HttpTransaction(
                client_ip=attacker, server_ip=server,
                src_port=50000 + i, dst_port=80,
                stream_id=i,
                method="GET",
                uri=sqli_payloads[i % len(sqli_payloads)],
                host="www.example.com",
                user_agent="sqlmap/1.7",
                status_code=500,
                request_pkt=i * 2 + 1,
                response_pkt=i * 2 + 2,
                ts_request=1.0 + i * 0.5,
                ts_response=1.1 + i * 0.5,
                latency_ms=100.0,
            )
            ctx.http_transactions.append(tx)

        # 15 more 5xx errors from normal-looking requests
        for i in range(15):
            tx = HttpTransaction(
                client_ip=attacker, server_ip=server,
                src_port=51000 + i, dst_port=80,
                stream_id=100 + i,
                method="POST",
                uri="/api/submit",
                host="www.example.com",
                user_agent="sqlmap/1.7",
                status_code=503,
                request_pkt=200 + i * 2,
                response_pkt=201 + i * 2,
                ts_request=15.0 + i * 0.5,
                ts_response=15.1 + i * 0.5,
                latency_ms=500.0,
            )
            ctx.http_transactions.append(tx)

        return ctx

    def test_http002_detected(self):
        ctx = self._make_ctx()
        http.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "HTTP-002" in rule_ids, (
            f"Expected HTTP-002 (web attack patterns) but got: {rule_ids}"
        )

    def test_http001_suspicious_ua_detected(self):
        ctx = self._make_ctx()
        http.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "HTTP-001" in rule_ids, (
            f"Expected HTTP-001 (suspicious UA: sqlmap) but got: {rule_ids}"
        )

    def test_http004_5xx_detected(self):
        ctx = self._make_ctx()
        http.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "HTTP-004" in rule_ids, (
            f"Expected HTTP-004 (5xx error surge) but got: {rule_ids}"
        )

    def test_decision_http002_not_generic(self):
        ctx = self._make_ctx()
        http.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        http002_causes = [
            c["cause"] for c in report["ranked_causes"]
            if c.get("rule_id") == "HTTP-002"
        ]
        if http002_causes:
            assert http002_causes[0] != _GENERIC_FALLBACK, (
                f"HTTP-002 decision is generic fallback: {http002_causes[0]}"
            )
            assert any(kw in http002_causes[0].lower() for kw in (
                "injection", "web", "attack", "exploit", "sql", "traversal"
            )), f"HTTP-002 cause doesn't mention web attacks: {http002_causes[0]}"

    def test_decision_http001_not_generic(self):
        ctx = self._make_ctx()
        http.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        http001_causes = [
            c["cause"] for c in report["ranked_causes"]
            if c.get("rule_id") == "HTTP-001"
        ]
        if http001_causes:
            assert http001_causes[0] != _GENERIC_FALLBACK, (
                f"HTTP-001 decision is generic fallback: {http001_causes[0]}"
            )

    def test_decision_steps_mention_web_investigation(self):
        ctx = self._make_ctx()
        http.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        all_steps = " ".join(report["investigation_steps"]).lower()
        assert any(kw in all_steps for kw in (
            "uri", "response", "payload", "waf", "log", "exploit", "server"
        )), f"Web attack steps missing web-specific guidance: {all_steps[:400]}"

    def test_decision_risk_level_high_or_critical(self):
        ctx = self._make_ctx()
        http.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        assert report["risk_level"] in ("high", "critical"), (
            f"Active web attack should be high/critical; got: {report['risk_level']}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 5 — C2 Beaconing + Lateral Movement
# Infected host beacons periodically; also scans internal SMB.
# Expected: C2-001, LAT-001; decision gives IR-focused steps.
# ══════════════════════════════════════════════════════════════════════════════

class TestC2BeaconingAndLateralMovement:
    """
    Scenario: Host 10.0.2.5 beacons every ~60s to 185.220.101.5 (external).
    Also makes 5 SYN attempts to internal hosts on SMB port 445.
    """

    def _make_ctx(self) -> CaptureContext:
        ctx = _base_ctx(total_packets=300, duration_sec=600.0)
        infected = "10.0.2.5"
        c2_server = "185.220.101.5"

        # ── C2 beaconing flow: 10 connections every ~60s ──────────────────────
        # We simulate this via packets (security.analyze reads packets for C2)
        beacon_times = [60.0 * i for i in range(10)]
        for i, ts in enumerate(beacon_times):
            pkt = PacketRecord(
                num=i + 1, ts=ts, frame_len=60, protocol="TCP",
                src_ip=infected, dst_ip=c2_server,
                src_port=50000 + i, dst_port=443,
                ip_proto=6, tcp_stream=i,
                tcp_flags_syn=True,
            )
            ctx.packets.append(pkt)
            # Corresponding session (full handshake, no FIN — persistent)
            sess = _tcp_session(
                i, infected, 50000 + i, c2_server, 443,
                bytes_sent=200, bytes_recv=800,
                syn_ts=ts,
            )
            ctx.sessions[i] = sess

        # ── Lateral movement: 5 SYNs to internal SMB ─────────────────────────
        internal_targets = [
            "10.0.2.10", "10.0.2.11", "10.0.2.12", "10.0.2.13", "10.0.2.14",
        ]
        for j, target in enumerate(internal_targets):
            pkt = PacketRecord(
                num=100 + j, ts=300.0 + j * 0.5, frame_len=60, protocol="TCP",
                src_ip=infected, dst_ip=target,
                src_port=60000 + j, dst_port=445,
                ip_proto=6, tcp_stream=100 + j,
                tcp_flags_syn=True,
            )
            ctx.packets.append(pkt)
            sess = _tcp_session(
                100 + j, infected, 60000 + j, target, 445,
                has_synack=False, bytes_recv=0,
                syn_ts=300.0 + j * 0.5,
            )
            ctx.sessions[100 + j] = sess

        return ctx

    def test_c2_001_detected(self):
        ctx = self._make_ctx()
        security.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "C2-001" in rule_ids, (
            f"Expected C2-001 (beaconing) but got: {rule_ids}"
        )

    def test_lat001_detected(self):
        ctx = self._make_ctx()
        security.analyze(ctx)
        rule_ids = [f.rule_id for f in ctx.findings]
        assert "LAT-001" in rule_ids, (
            f"Expected LAT-001 (lateral movement) but got: {rule_ids}"
        )

    def test_decision_c2_not_generic(self):
        ctx = self._make_ctx()
        security.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        c2_causes = [
            c["cause"] for c in report["ranked_causes"]
            if c.get("rule_id") == "C2-001"
        ]
        if c2_causes:
            assert c2_causes[0] != _GENERIC_FALLBACK, (
                f"C2-001 decision is generic fallback: {c2_causes[0]}"
            )
            assert any(kw in c2_causes[0].lower() for kw in (
                "command", "control", "malware", "beacon", "c2"
            )), f"C2-001 cause doesn't mention malware/C2: {c2_causes[0]}"

    def test_decision_lat001_not_generic(self):
        ctx = self._make_ctx()
        security.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        lat_causes = [
            c["cause"] for c in report["ranked_causes"]
            if c.get("rule_id") == "LAT-001"
        ]
        if lat_causes:
            assert lat_causes[0] != _GENERIC_FALLBACK, (
                f"LAT-001 decision is generic fallback: {lat_causes[0]}"
            )
            assert any(kw in lat_causes[0].lower() for kw in (
                "lateral", "movement", "internal", "credential", "spread"
            )), f"LAT-001 cause doesn't mention lateral movement: {lat_causes[0]}"

    def test_decision_steps_include_isolation(self):
        ctx = self._make_ctx()
        security.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        all_steps = " ".join(report["investigation_steps"]).lower()
        assert any(kw in all_steps for kw in (
            "isolat", "block", "forensic", "malware", "threat", "memory"
        )), f"C2/lateral steps should include isolation/forensics: {all_steps[:400]}"

    def test_risk_level_is_critical_or_high(self):
        ctx = self._make_ctx()
        security.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        assert report["risk_level"] in ("critical", "high"), (
            f"Active C2 + lateral movement should be critical/high; got: {report['risk_level']}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Clean-traffic false-positive guard
# ══════════════════════════════════════════════════════════════════════════════

class TestCleanTrafficNoFalsePositives:
    """
    Normal HTTPS browsing session should produce no high/critical findings
    and the decision report should say 'clean'.
    """

    def _make_ctx(self) -> CaptureContext:
        ctx = _base_ctx(total_packets=50, duration_sec=10.0)
        client, server = "192.168.1.10", "93.184.216.34"
        # 3 complete TLS 1.3 sessions to example.com — normal browsing
        for i in range(3):
            sess = _tcp_session(
                i, client, 50000 + i, server, 443,
                has_fin=True, bytes_sent=2_000, bytes_recv=15_000,
                syn_ts=float(i),
            )
            ctx.sessions[i] = sess
            ctx.tls_handshakes.append(TlsHandshake(
                stream_id=i,
                client_ip=client, server_ip=server,
                dst_port=443,
                sni="www.example.com",
                tls_version="TLSv1.3",
                client_version="TLSv1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                client_pkt=i * 3 + 1, server_pkt=i * 3 + 2,
                ts_client=float(i),
            ))
        return ctx

    def test_no_high_critical_findings(self):
        ctx = self._make_ctx()
        tcp.analyze(ctx)
        tls.analyze(ctx)
        security.analyze(ctx)
        build_profiles(ctx)
        high_crit = [
            f for f in ctx.findings
            if not f.suppressed and str(f.severity).lower() in ("critical", "high", "severity.critical", "severity.high")
        ]
        assert len(high_crit) == 0, (
            f"Normal TLS browsing produced false-positive findings: "
            f"{[(f.rule_id, f.title) for f in high_crit]}"
        )

    def test_decision_report_clean(self):
        ctx = self._make_ctx()
        tcp.analyze(ctx)
        tls.analyze(ctx)
        security.analyze(ctx)
        build_profiles(ctx)
        report = _decision(ctx)
        assert report["risk_level"] == "clean", (
            f"Normal browsing should give 'clean' risk level; got: {report['risk_level']}"
        )
