"""Natural Language Generation — produces human-readable analyst commentary from CaptureContext."""
from __future__ import annotations

from models import CaptureContext


def _fmt_dur(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    if s < 3600:
        return f"{int(s//60)}m {int(s%60)}s"
    return f"{int(s//3600)}h {int((s%3600)//60)}m"


def _fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024**2:
        return f"{b/1024:.1f} KB"
    if b < 1024**3:
        return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"


def generate_executive_summary(ctx: CaptureContext) -> str:
    """2-4 sentence executive summary for non-technical stakeholders."""
    fi = ctx.file_info
    active_findings = [f for f in ctx.findings if not f.suppressed]
    critical = [f for f in active_findings if f.severity == "critical"]
    high = [f for f in active_findings if f.severity == "high"]
    warnings = [f for f in active_findings if f.severity in ("medium", "high")]

    lines = []

    # Opening
    if fi.duration_sec > 0:
        lines.append(
            f"This network capture spans {_fmt_dur(fi.duration_sec)} and contains "
            f"{fi.total_packets:,} packets ({_fmt_bytes(fi.file_size_bytes)})."
        )
    else:
        lines.append(f"This capture contains {fi.total_packets:,} packets.")

    # Risk assessment
    if critical:
        top = critical[:2]
        lines.append(
            f"The analysis identified {len(critical)} critical security finding(s) "
            f"requiring immediate attention: {'; '.join(f.title for f in top)}."
        )
    elif high:
        lines.append(
            f"The analysis found {len(high)} high-severity issue(s): "
            f"{'; '.join(f.title for f in high[:2])}."
        )
    elif warnings:
        lines.append(
            f"The analysis found {len(warnings)} warning(s) that should be reviewed: "
            f"{warnings[0].title}."
        )
    else:
        lines.append("No critical or high-severity security issues were detected.")

    # Protocol context
    if ctx.protocol_stats:
        top3 = sorted(ctx.protocol_stats.items(), key=lambda x: -x[1])[:3]
        lines.append(
            f"Dominant protocols: {', '.join(f'{p} ({c:,} frames)' for p, c in top3)}."
        )

    # Host anomaly callout
    anomalous = [h for h in ctx.hosts.values() if h.anomaly_score >= 5.0]
    if anomalous:
        lines.append(
            f"{len(anomalous)} host(s) exhibit suspicious behavioral patterns "
            f"(anomaly score ≥ 5.0): {', '.join(h.ip for h in anomalous[:3])}."
        )

    return " ".join(lines)


def generate_technical_summary(ctx: CaptureContext) -> str:
    """Structured technical summary for network/security engineers."""
    fi = ctx.file_info
    sections = []

    sections.append(
        f"**Capture Overview**: {fi.total_packets:,} packets | "
        f"Duration: {_fmt_dur(fi.duration_sec)} | "
        f"File: {_fmt_bytes(fi.file_size_bytes)} | "
        f"Analyzed: {ctx.packets_analyzed:,} packets | "
        f"Analysis time: {ctx.analysis_time_sec}s"
    )

    # TCP
    tcp_sessions = len(ctx.sessions)
    total_retrans = sum(s.retransmissions for s in ctx.sessions.values())
    total_resets = sum(1 for s in ctx.sessions.values() if s.has_rst)
    failed_hs = sum(1 for s in ctx.sessions.values() if s.has_syn and not s.has_synack)
    if tcp_sessions:
        sections.append(
            f"**TCP**: {tcp_sessions} sessions | {total_retrans} retrans | "
            f"{total_resets} RSTs | {failed_hs} failed handshakes"
        )

    # DNS
    dns_stats = getattr(ctx, "dns_stats", {})
    if dns_stats.get("total_queries", 0):
        sections.append(
            f"**DNS**: {dns_stats['total_queries']:,} queries | "
            f"{dns_stats.get('unique_domains', 0)} unique domains | "
            f"{dns_stats.get('nxdomain_count', 0)} NXDOMAIN | "
            f"{dns_stats.get('servfail_count', 0)} SERVFAIL | "
            f"avg RTT {dns_stats.get('avg_rtt_ms', 0):.1f}ms"
        )

    # HTTP
    http_stats = getattr(ctx, "http_stats", {})
    if http_stats.get("total_requests", 0):
        sections.append(
            f"**HTTP**: {http_stats['total_requests']:,} requests | "
            f"{http_stats.get('error_4xx', 0)} 4xx | "
            f"{http_stats.get('error_5xx', 0)} 5xx | "
            f"avg latency {http_stats.get('avg_latency_ms', 0):.0f}ms"
        )

    # TLS
    tls_stats = getattr(ctx, "tls_stats", {})
    if tls_stats.get("total_streams", 0):
        dep = tls_stats.get("deprecated_count", 0)
        sections.append(
            f"**TLS**: {tls_stats['total_streams']} streams | "
            f"{tls_stats.get('unique_sni', 0)} unique SNI | "
            + (f"⚠ {dep} deprecated version connections" if dep else "all modern versions")
        )

    # Security
    active = [f for f in ctx.findings if not f.suppressed]
    c = sum(1 for f in active if f.severity == "critical")
    h = sum(1 for f in active if f.severity == "high")
    m = sum(1 for f in active if f.severity == "medium")
    if active:
        sections.append(
            f"**Security Findings**: {c} critical | {h} high | {m} medium | "
            f"{len(active)} total (+ {len(ctx.findings) - len(active)} suppressed)"
        )

    # Hosts
    anomalous = [h for h in ctx.hosts.values() if h.anomaly_score >= 3.0]
    if anomalous:
        sections.append(
            f"**Host Anomalies**: {len(anomalous)} hosts with elevated anomaly scores. "
            f"Top: {', '.join(f'{h.ip} ({h.anomaly_score:.1f})' for h in sorted(anomalous, key=lambda x: -x.anomaly_score)[:3])}"
        )

    return "\n\n".join(sections)
