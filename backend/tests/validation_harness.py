"""
Real-world validation harness for the PCAP analyzer platform.

Runs 5 representative incident scenarios through the full backend analysis
chain (analyzers → finalize → decision → sanity → trust), then measures:

  - Time to root cause (finding rank position in sorted results)
  - Misleading findings (distractors that inflate alarm count)
  - Low-confidence findings that should not drive action
  - Places trust scoring correctly warned the analyst
  - Places trust scoring failed to warn

Each scenario is evaluated against ground-truth expectations and produces
a PASS / WARN / FAIL verdict per criterion.

Usage
-----
  cd backend
  python -m tests.validation_harness          # text report
  python -m tests.validation_harness --json   # JSON dump
"""
from __future__ import annotations

import dataclasses
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from analyzers import dns, http, security, tcp, tls
from core.decision import build_decision_report
from core.pipeline import _finding_to_dict, _host_to_dict
from core.sanity import run_sanity_checks
from core.trust import compute_trust_score
from detection.engine import finalize
from models import (
    CaptureContext,
    DnsTransaction,
    FileInfo,
    HttpTransaction,
    PacketRecord,
    SessionRecord,
    TCPState,
    TlsHandshake,
)
from profiler.host import build_profiles


# ── Constants ─────────────────────────────────────────────────────────────────

_GENERIC_FALLBACK = "Anomalous network behavior requiring investigation"
_LINE = "═" * 72
_THIN = "─" * 72


# ── Shared context builders ───────────────────────────────────────────────────

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


# ── Full analysis runner (no tshark needed) ───────────────────────────────────

def _run_analysis(ctx: CaptureContext) -> Dict[str, Any]:
    """Serialize a pre-built CaptureContext through the full post-normalize chain."""
    build_profiles(ctx)
    finalize(ctx)

    active = [_finding_to_dict(f) for f in ctx.findings if not f.suppressed]
    host_dicts = [_host_to_dict(h) for h in ctx.hosts.values()]
    decision = build_decision_report(active, host_dicts)

    result: Dict[str, Any] = {
        "all_issues": active,
        "hosts": host_dicts,
        "dns": getattr(ctx, "dns_stats", {}) or {},
        "tcp": {
            "total_sessions": len(ctx.sessions),
            "retransmissions": sum(s.retransmissions for s in ctx.sessions.values()),
            "resets": sum(1 for s in ctx.sessions.values() if s.has_rst),
            "failed_handshakes": sum(
                1 for s in ctx.sessions.values() if s.has_syn and not s.has_synack
            ),
            "midstream": sum(1 for s in ctx.sessions.values() if not s.has_syn),
        },
        "http": getattr(ctx, "http_stats", {}) or {},
        "file_info": dataclasses.asdict(ctx.file_info) if ctx.file_info else {},
        "decision_support": decision,
        "sanity_warnings": [],
    }

    result["sanity_warnings"] = run_sanity_checks(result)
    result["trust"] = compute_trust_score(result)
    return result


# ── Scenario specs ────────────────────────────────────────────────────────────

@dataclass
class ScenarioSpec:
    name: str
    description: str
    primary_rule_ids: List[str]       # rules that ARE the root cause
    secondary_rule_ids: List[str]     # valid but secondary findings
    acceptable_risk_levels: List[str] # risk_level values that are correct
    trust_min: int                    # trust_score must be >= this
    trust_max: int                    # trust_score must be <= this
    max_ttrc: int                     # primary finding must be in top-N


# ── Scenario 1 — TCP Connectivity Failure ─────────────────────────────────────

def _build_scenario_tcp() -> CaptureContext:
    """12 SYN packets to port 5432, no SYN-ACK — firewall/service down."""
    ctx = _base_ctx(total_packets=24, duration_sec=25.0)
    client, server = "10.0.1.20", "10.0.1.50"
    for i in range(12):
        ctx.sessions[i] = _tcp_session(
            i, client, 50000 + i, server, 5432,
            has_synack=False, bytes_recv=0, syn_ts=1.0 + i * 2.0,
        )
        ctx.packets.append(_syn_pkt(i + 1, client, server, 5432, ts=1.0 + i * 2.0))
    tcp.analyze(ctx)
    return ctx


_SPEC_TCP = ScenarioSpec(
    name="TCP Connectivity Failure",
    description=(
        "App server 10.0.1.20 repeatedly fails to connect to DB 10.0.1.50:5432. "
        "12 SYN packets sent, no SYN-ACK — port blocked or service down."
    ),
    primary_rule_ids=["TCP-003"],
    secondary_rule_ids=[],
    acceptable_risk_levels=["medium", "high", "critical"],
    trust_min=60,
    trust_max=100,
    max_ttrc=2,
)


# ── Scenario 2 — DNS NXDOMAIN Storm ──────────────────────────────────────────

def _build_scenario_dns() -> CaptureContext:
    """35 NXDOMAIN responses for legacy.internal.corp — misconfigured app."""
    ctx = _base_ctx(total_packets=70, duration_sec=30.0)
    for i in range(35):
        ctx.dns_transactions.append(DnsTransaction(
            txid=i,
            query_pkt=i * 2 + 1, response_pkt=i * 2 + 2,
            ts_query=1.0 + i * 0.8, ts_response=1.05 + i * 0.8,
            client_ip="10.10.0.5", resolver_ip="10.10.0.1",
            qname="legacy.internal.corp",
            qtype="A", rcode="3", is_nxdomain=True, rtt_ms=10.0,
        ))
    dns.analyze(ctx)
    return ctx


_SPEC_DNS = ScenarioSpec(
    name="DNS NXDOMAIN Storm",
    description=(
        "App queries legacy.internal.corp which no longer exists. "
        "35 NXDOMAIN responses in 30s — renamed host or misconfigured app."
    ),
    primary_rule_ids=["DNS-001"],
    secondary_rule_ids=[],
    acceptable_risk_levels=["medium", "high", "critical"],
    trust_min=55,
    trust_max=100,
    max_ttrc=2,
)


# ── Scenario 3 — TLS Handshake Failure ────────────────────────────────────────

def _build_scenario_tls() -> CaptureContext:
    """Expired cert on payment gateway, self-signed on proxy, deprecated TLS 1.0."""
    ctx = _base_ctx(total_packets=30, duration_sec=10.0)
    ctx.tls_handshakes.append(TlsHandshake(
        stream_id=0, client_ip="10.0.0.5", server_ip="203.0.113.10", dst_port=443,
        sni="payment.example.com", tls_version="TLSv1.3", client_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        has_alert=True, alert_description="certificate_expired", cert_expired=True,
        client_pkt=1, server_pkt=0, ts_client=1.0,
    ))
    ctx.tls_handshakes.append(TlsHandshake(
        stream_id=1, client_ip="10.0.0.5", server_ip="10.0.1.100", dst_port=8443,
        sni="internal.corp", tls_version="TLSv1.2", client_version="TLSv1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        cert_self_signed=True, cert_common_name="internal.corp",
        client_pkt=5, server_pkt=6, ts_client=2.0,
    ))
    ctx.tls_handshakes.append(TlsHandshake(
        stream_id=2, client_ip="10.0.0.5", server_ip="10.0.1.200", dst_port=443,
        sni="legacy-api.corp", tls_version="TLSv1.0", client_version="TLSv1.0",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        client_pkt=10, server_pkt=11, ts_client=3.0,
    ))
    tls.analyze(ctx)
    return ctx


_SPEC_TLS = ScenarioSpec(
    name="TLS Handshake Failure",
    description=(
        "Payment gateway has expired certificate (TLS alert fired). "
        "Internal proxy uses self-signed cert. Legacy API still on TLS 1.0."
    ),
    primary_rule_ids=["TLS-002", "TLS-004"],
    secondary_rule_ids=["TLS-001"],
    acceptable_risk_levels=["medium", "high", "critical"],
    trust_min=35,
    trust_max=80,
    max_ttrc=3,
)


# ── Scenario 4 — Web Application Attack ──────────────────────────────────────

def _build_scenario_web() -> CaptureContext:
    """sqlmap SQL injection probe + 5xx error surge."""
    ctx = _base_ctx(total_packets=100, duration_sec=20.0)
    attacker, server = "198.51.100.99", "10.0.0.80"
    sqli_payloads = [
        "/search?q=' OR 1=1--",
        "/user?id=1 UNION SELECT * FROM users",
        "/login?u=admin'--&p=x",
        "/api?data=1; DROP TABLE users--",
    ]
    for i in range(25):
        ctx.http_transactions.append(HttpTransaction(
            client_ip=attacker, server_ip=server,
            src_port=50000 + i, dst_port=80, stream_id=i,
            method="GET", uri=sqli_payloads[i % len(sqli_payloads)],
            host="www.example.com", user_agent="sqlmap/1.7",
            status_code=500, request_pkt=i * 2 + 1, response_pkt=i * 2 + 2,
            ts_request=1.0 + i * 0.5, ts_response=1.1 + i * 0.5, latency_ms=100.0,
        ))
    for i in range(15):
        ctx.http_transactions.append(HttpTransaction(
            client_ip=attacker, server_ip=server,
            src_port=51000 + i, dst_port=80, stream_id=100 + i,
            method="POST", uri="/api/submit",
            host="www.example.com", user_agent="sqlmap/1.7",
            status_code=503, request_pkt=200 + i * 2, response_pkt=201 + i * 2,
            ts_request=15.0 + i * 0.5, ts_response=15.1 + i * 0.5, latency_ms=500.0,
        ))
    http.analyze(ctx)
    return ctx


_SPEC_WEB = ScenarioSpec(
    name="Web Application Attack",
    description=(
        "External scanner 198.51.100.99 runs sqlmap SQL injection probes "
        "against 10.0.0.80. 25 attack requests + 15 resulting 5xx errors."
    ),
    primary_rule_ids=["HTTP-002", "HTTP-001"],
    secondary_rule_ids=["HTTP-004"],
    acceptable_risk_levels=["high", "critical"],
    trust_min=60,
    trust_max=100,
    max_ttrc=2,
)


# ── Scenario 5 — C2 Beaconing + Lateral Movement ─────────────────────────────

def _build_scenario_c2() -> CaptureContext:
    """Periodic beaconing to C2 + internal SMB scan."""
    ctx = _base_ctx(total_packets=300, duration_sec=600.0)
    infected, c2 = "10.0.2.5", "185.220.101.5"
    for i in range(10):
        ts = 60.0 * i
        ctx.packets.append(PacketRecord(
            num=i + 1, ts=ts, frame_len=60, protocol="TCP",
            src_ip=infected, dst_ip=c2,
            src_port=50000 + i, dst_port=443,
            ip_proto=6, tcp_stream=i, tcp_flags_syn=True,
        ))
        ctx.sessions[i] = _tcp_session(
            i, infected, 50000 + i, c2, 443,
            bytes_sent=200, bytes_recv=800, syn_ts=ts,
        )
    for j, target in enumerate(
        ["10.0.2.10", "10.0.2.11", "10.0.2.12", "10.0.2.13", "10.0.2.14"]
    ):
        ctx.packets.append(PacketRecord(
            num=100 + j, ts=300.0 + j * 0.5, frame_len=60, protocol="TCP",
            src_ip=infected, dst_ip=target,
            src_port=60000 + j, dst_port=445,
            ip_proto=6, tcp_stream=100 + j, tcp_flags_syn=True,
        ))
        ctx.sessions[100 + j] = _tcp_session(
            100 + j, infected, 60000 + j, target, 445,
            has_synack=False, bytes_recv=0, syn_ts=300.0 + j * 0.5,
        )
    security.analyze(ctx)
    return ctx


_SPEC_C2 = ScenarioSpec(
    name="C2 Beaconing + Lateral Movement",
    description=(
        "Host 10.0.2.5 beacons every ~60s to 185.220.101.5 (external) over 10min. "
        "Also sends 5 SYN probes to internal hosts on SMB port 445."
    ),
    primary_rule_ids=["C2-001", "LAT-001"],
    secondary_rule_ids=[],
    acceptable_risk_levels=["high", "critical"],
    trust_min=30,
    trust_max=80,
    max_ttrc=3,
)


# ── Evaluation logic ──────────────────────────────────────────────────────────

@dataclass
class CriterionResult:
    name: str
    verdict: str     # PASS / WARN / FAIL / SKIP
    detail: str


@dataclass
class ScenarioReport:
    spec: ScenarioSpec
    result: Dict[str, Any]
    criteria: List[CriterionResult] = field(default_factory=list)
    overall: str = "PASS"   # PASS / WARN / FAIL
    elapsed_ms: float = 0.0

    def add(self, name: str, verdict: str, detail: str) -> None:
        self.criteria.append(CriterionResult(name, verdict, detail))
        if verdict == "FAIL" and self.overall != "FAIL":
            self.overall = "FAIL"
        elif verdict == "WARN" and self.overall == "PASS":
            self.overall = "WARN"


def _evaluate(spec: ScenarioSpec, result: Dict[str, Any]) -> ScenarioReport:
    report = ScenarioReport(spec=spec, result=result)
    findings = result.get("all_issues", [])
    decision = result.get("decision_support", {}) or {}
    sanity = result.get("sanity_warnings", [])
    trust = result.get("trust", {}) or {}

    # Sort by score descending (same order as pipeline)
    sorted_findings = sorted(findings, key=lambda f: -f.get("score", 0))
    rule_ids = [f.get("rule_id") for f in sorted_findings]

    # ── C1: Root cause detected ──────────────────────────────────────────────
    missing = [r for r in spec.primary_rule_ids if r not in rule_ids]
    if missing:
        report.add("root_cause_detected", "FAIL",
                   f"Expected rule(s) not found: {missing}. Got: {rule_ids}")
    else:
        report.add("root_cause_detected", "PASS",
                   f"All primary rules detected: {spec.primary_rule_ids}")

    # ── C2: Time to root cause ────────────────────────────────────────────────
    positions = [
        rule_ids.index(r) + 1
        for r in spec.primary_rule_ids
        if r in rule_ids
    ]
    if not positions:
        report.add("time_to_root_cause", "FAIL",
                   "Primary finding absent — TTRC cannot be measured")
    else:
        best_pos = min(positions)
        verdict = "PASS" if best_pos <= spec.max_ttrc else "WARN"
        report.add("time_to_root_cause", verdict,
                   f"Primary finding first appears at rank #{best_pos} "
                   f"(threshold: #{spec.max_ttrc}, total findings: {len(sorted_findings)})")

    # ── C3: Guidance is specific (not generic fallback) ───────────────────────
    ranked_causes = decision.get("ranked_causes", [])
    generic_causes = [
        c for c in ranked_causes
        if c.get("rule_id") in spec.primary_rule_ids
        and c.get("cause") == _GENERIC_FALLBACK
    ]
    if generic_causes:
        report.add("guidance_is_specific", "FAIL",
                   f"Generic fallback returned for: {[c['rule_id'] for c in generic_causes]}")
    elif not ranked_causes:
        report.add("guidance_is_specific", "WARN",
                   "No ranked causes in decision report")
    else:
        causes_text = "; ".join(
            f"{c.get('rule_id','?')}: \"{c.get('cause','?')[:60]}...\""
            for c in ranked_causes[:2]
        )
        report.add("guidance_is_specific", "PASS",
                   f"Specific guidance: {causes_text}")

    # ── C4: Risk level appropriate ────────────────────────────────────────────
    risk = decision.get("risk_level", "")
    if risk in spec.acceptable_risk_levels:
        report.add("risk_level_appropriate", "PASS",
                   f"risk_level='{risk}' (acceptable: {spec.acceptable_risk_levels})")
    else:
        verdict = "FAIL" if risk in ("clean", "") else "WARN"
        report.add("risk_level_appropriate", verdict,
                   f"risk_level='{risk}' but expected one of {spec.acceptable_risk_levels}")

    # ── C5: Trust score in expected range ─────────────────────────────────────
    trust_score = trust.get("trust_score", 0)
    if spec.trust_min <= trust_score <= spec.trust_max:
        report.add("trust_score_range", "PASS",
                   f"trust_score={trust_score} within [{spec.trust_min}, {spec.trust_max}]")
    elif trust_score < spec.trust_min:
        report.add("trust_score_range", "WARN",
                   f"trust_score={trust_score} below expected minimum {spec.trust_min} "
                   f"— platform may be too conservative for this scenario")
    else:
        report.add("trust_score_range", "WARN",
                   f"trust_score={trust_score} above expected maximum {spec.trust_max} "
                   f"— platform may be overconfident for this scenario")

    # ── C6: Low-confidence high-severity findings are flagged ─────────────────
    overconfident = [
        f for f in findings
        if f.get("severity") in ("critical", "high")
        and f.get("confidence_score", 50) < 45
    ]
    sanity_009_rules = {
        w.get("related_finding")
        for w in sanity
        if w.get("check_id") == "SANITY-009"
    }
    unflagged = [
        f for f in overconfident
        if f.get("rule_id") not in sanity_009_rules
    ]
    if unflagged:
        report.add("low_conf_findings_flagged", "WARN",
                   f"{len(unflagged)} high/critical finding(s) with confidence_score<45 "
                   f"NOT flagged by SANITY-009: "
                   f"{[f.get('rule_id') for f in unflagged]}")
    else:
        if overconfident:
            report.add("low_conf_findings_flagged", "PASS",
                       f"All {len(overconfident)} low-confidence high-severity finding(s) "
                       f"correctly flagged by SANITY-009")
        else:
            report.add("low_conf_findings_flagged", "PASS",
                       "No high/critical findings with thin evidence (none needed flagging)")

    # ── C7: Trust correctly warned when there are contradictions ─────────────
    warning_count = sum(1 for w in sanity if w.get("severity") == "warning")
    if warning_count > 0 and trust_score >= 80:
        report.add("trust_warned_with_contradictions", "WARN",
                   f"{warning_count} sanity warning(s) present but trust_score={trust_score} "
                   f"(>= 80) — trust may not adequately reflect contradictions")
    elif warning_count > 0:
        report.add("trust_warned_with_contradictions", "PASS",
                   f"{warning_count} sanity warning(s) reduced trust_score to {trust_score}")
    else:
        report.add("trust_warned_with_contradictions", "PASS",
                   f"No sanity contradictions (trust_score={trust_score} reflects clean analysis)")

    return report


# ── Text report formatter ─────────────────────────────────────────────────────

_VERDICT_SYMBOL = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗", "SKIP": "–"}


def _fmt_finding(f: Dict, primary_ids: List[str], secondary_ids: List[str],
                 rank: int) -> str:
    rule = f.get("rule_id", "?")
    sev = (f.get("severity") or "?").upper()[:8]
    cs = f.get("confidence_score", 0)
    score = f.get("score", 0)
    title = (f.get("title") or "")[:45]
    marker = " ← ROOT CAUSE" if rule in primary_ids else (
             " ← secondary" if rule in secondary_ids else "")
    return (f"  #{rank:2d}  [{sev:<8}] [evidence {cs:3d}/100] "
            f"[score {score:4.1f}]  {rule:<10} {title}{marker}")


def _fmt_cause(c: Dict, max_len: int = 68) -> str:
    rule = c.get("rule_id", "?")
    cause = (c.get("cause") or "")[:max_len]
    prob = c.get("probability_pct", 0)
    return f"  {rule:<10} {prob:3d}%  {cause}"


def print_report(reports: List[ScenarioReport]) -> None:
    print()
    print(_LINE)
    print("  PCAP ANALYZER — REAL-WORLD VALIDATION REPORT")
    print(_LINE)
    print()

    for sr in reports:
        spec = sr.spec
        result = sr.result
        findings = sorted(result.get("all_issues", []), key=lambda f: -f.get("score", 0))
        trust = result.get("trust", {}) or {}
        decision = result.get("decision_support", {}) or {}
        sanity = result.get("sanity_warnings", [])

        print(_LINE)
        print(f"  SCENARIO: {spec.name}")
        print(_LINE)
        print(f"  {spec.description}")
        print()

        # Trust
        ts = trust.get("trust_score", 0)
        tl = trust.get("trust_label", "?")
        comp = trust.get("components", {})
        print(f"  TRUST  {ts}/100 — {tl}")
        print(f"         Capture quality : {comp.get('capture_completeness', 0):.0f}/100")
        print(f"         Evidence quality: {comp.get('finding_quality', 0):.0f}/100")
        print(f"         Contradictions  : −{comp.get('contradiction_penalty', 0)} pts")
        print()

        # Findings
        print(f"  FINDINGS ({len(findings)} active):")
        for i, f in enumerate(findings[:8], 1):
            print(_fmt_finding(f, spec.primary_rule_ids, spec.secondary_rule_ids, i))
        if len(findings) > 8:
            print(f"  ... ({len(findings) - 8} more findings not shown)")
        print()

        # Decision
        risk = decision.get("risk_level", "?")
        print(f"  DECISION  risk_level={risk}")
        for c in decision.get("ranked_causes", [])[:3]:
            print(_fmt_cause(c))
        steps = decision.get("investigation_steps", [])
        if steps:
            print(f"  Top step: {steps[0][:68]}")
        print()

        # Sanity
        if sanity:
            print(f"  SANITY WARNINGS ({len(sanity)}):")
            for w in sanity:
                sym = "⚠" if w.get("severity") == "warning" else "ℹ"
                msg = (w.get("message") or "")[:65]
                print(f"    {sym} [{w.get('check_id','?')}] {msg}")
        else:
            print("  SANITY WARNINGS: none")
        print()

        # Criteria
        print("  VALIDATION CRITERIA:")
        for cr in sr.criteria:
            sym = _VERDICT_SYMBOL.get(cr.verdict, "?")
            verdict_pad = f"[{cr.verdict:<4}]"
            print(f"    {sym} {verdict_pad} {cr.name}")
            print(f"           {cr.detail[:65]}")
        print()

        overall_sym = _VERDICT_SYMBOL.get(sr.overall, "?")
        print(f"  RESULT: {overall_sym} {sr.overall}  "
              f"(elapsed {sr.elapsed_ms:.0f} ms)")
        print()

    # Summary table
    print(_LINE)
    print("  SUMMARY")
    print(_THIN)
    verdicts = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for sr in reports:
        verdicts[sr.overall] = verdicts.get(sr.overall, 0) + 1
        sym = _VERDICT_SYMBOL.get(sr.overall, "?")
        elapsed = f"{sr.elapsed_ms:.0f}ms"
        print(f"  {sym} {sr.overall:<4}  {sr.spec.name:<40} {elapsed}")
    print(_THIN)
    print(f"  PASS: {verdicts['PASS']}  WARN: {verdicts['WARN']}  "
          f"FAIL: {verdicts['FAIL']}  (of {len(reports)} scenarios)")
    print(_LINE)


# ── Main runner ───────────────────────────────────────────────────────────────

_SCENARIOS = [
    ("TCP Connectivity Failure",        _build_scenario_tcp, _SPEC_TCP),
    ("DNS NXDOMAIN Storm",              _build_scenario_dns, _SPEC_DNS),
    ("TLS Handshake Failure",           _build_scenario_tls, _SPEC_TLS),
    ("Web Application Attack",          _build_scenario_web, _SPEC_WEB),
    ("C2 Beaconing + Lateral Movement", _build_scenario_c2,  _SPEC_C2),
]


def _collect_scenario_reports() -> List[ScenarioReport]:
    reports = []
    for name, builder_fn, spec in _SCENARIOS:
        t0 = time.perf_counter()
        ctx = builder_fn()
        result = _run_analysis(ctx)
        elapsed = (time.perf_counter() - t0) * 1000
        sr = _evaluate(spec, result)
        sr.elapsed_ms = elapsed
        reports.append(sr)
    return reports


def run_all_scenarios() -> None:
    if "--json" in sys.argv:
        reports = _collect_scenario_reports()
        out = []
        for sr in reports:
            out.append({
                "scenario": sr.spec.name,
                "overall": sr.overall,
                "elapsed_ms": sr.elapsed_ms,
                "trust": sr.result.get("trust"),
                "risk_level": (sr.result.get("decision_support") or {}).get("risk_level"),
                "finding_count": len(sr.result.get("all_issues", [])),
                "sanity_warning_count": len(sr.result.get("sanity_warnings", [])),
                "criteria": [
                    {"name": c.name, "verdict": c.verdict, "detail": c.detail}
                    for c in sr.criteria
                ],
                "findings": [
                    {
                        "rank": i + 1,
                        "rule_id": f.get("rule_id"),
                        "severity": f.get("severity"),
                        "confidence_score": f.get("confidence_score"),
                        "score": f.get("score"),
                        "title": f.get("title"),
                    }
                    for i, f in enumerate(
                        sorted(sr.result.get("all_issues", []),
                               key=lambda x: -x.get("score", 0))
                    )
                ],
                "ranked_causes": (sr.result.get("decision_support") or {}).get("ranked_causes", []),
                "sanity_warnings": sr.result.get("sanity_warnings", []),
            })
        print(json.dumps(out, indent=2))
    else:
        reports = _collect_scenario_reports()
        print_report(reports)


# ── pytest entry-point ────────────────────────────────────────────────────────

def test_all_scenarios_pass():
    """All scenarios must reach PASS or WARN. FAIL = platform regression."""
    reports = _collect_scenario_reports()
    failures = [
        f"{r.spec.name}:\n" + "\n".join(
            f"  [{c.verdict}] {c.name}: {c.detail}"
            for c in r.criteria if c.verdict == "FAIL"
        )
        for r in reports if r.overall == "FAIL"
    ]
    assert not failures, (
        f"{len(failures)} scenario(s) FAILED:\n\n" + "\n\n".join(failures)
    )


if __name__ == "__main__":
    run_all_scenarios()
