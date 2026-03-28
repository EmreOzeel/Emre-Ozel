"""
Cross-protocol correlation engine.
Correlates DNS, TCP, TLS, HTTP events into a unified, sorted timeline
and generates natural-language storylines.
"""
from __future__ import annotations
from typing import List, Dict
from models import CaptureContext, TimelineEvent, Severity


def _format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b}B"
    if b < 1024 ** 2:
        return f"{b/1024:.1f}KB"
    if b < 1024 ** 3:
        return f"{b/1024**2:.1f}MB"
    return f"{b/1024**3:.2f}GB"


def _format_dur(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    if s < 3600:
        return f"{s/60:.1f}m"
    return f"{s/3600:.1f}h"


# ── Timeline enrichment ───────────────────────────────────────────────────────

def _add_dns_events(ctx: CaptureContext) -> None:
    for tx in ctx.dns_transactions:
        if not tx.ts_query:
            continue
        sev = Severity.INFO
        label = f"DNS {tx.qtype} {tx.qname}"
        detail = f"{tx.client_ip} → {tx.resolver_ip}: {tx.qtype} {tx.qname}"
        if tx.is_nxdomain:
            sev = Severity.INFO
            label = f"DNS NXDOMAIN: {tx.qname}"
        elif tx.is_servfail:
            sev = Severity.INFO
            label = f"DNS SERVFAIL: {tx.qname}"
        ctx.timeline.append(TimelineEvent(
            ts=tx.ts_query, event_type="dns_query",
            src_ip=tx.client_ip, dst_ip=tx.resolver_ip,
            label=label, detail=detail, severity=sev,
            packet_num=tx.query_pkt, protocol="DNS",
        ))
        if tx.is_nxdomain:
            ctx.timeline.append(TimelineEvent(
                ts=tx.ts_response, event_type="dns_nxdomain",
                src_ip=tx.resolver_ip, dst_ip=tx.client_ip,
                label=f"DNS NXDOMAIN: {tx.qname}",
                detail=f"NXDOMAIN for {tx.qname} (RTT {tx.rtt_ms:.0f}ms)",
                severity=Severity.INFO, packet_num=tx.response_pkt, protocol="DNS",
            ))


def _add_http_events(ctx: CaptureContext) -> None:
    for tx in ctx.http_transactions:
        if not tx.ts_request:
            continue
        sev = Severity.INFO
        if tx.status_code >= 500:
            sev = Severity.MEDIUM
        elif tx.status_code >= 400:
            sev = Severity.INFO
        label = f"HTTP {tx.method} {tx.host}{tx.uri[:60]}"
        detail = (
            f"{tx.client_ip} → {tx.server_ip}: {tx.method} {tx.host}{tx.uri} "
            f"→ {tx.status_code} ({tx.latency_ms:.0f}ms)"
        )
        ctx.timeline.append(TimelineEvent(
            ts=tx.ts_request, event_type="http_request",
            src_ip=tx.client_ip, dst_ip=tx.server_ip,
            label=label, detail=detail, severity=sev,
            packet_num=tx.request_pkt, protocol="HTTP",
        ))


def _add_tls_events(ctx: CaptureContext) -> None:
    for hs in ctx.tls_handshakes:
        if not hs.ts_client:
            continue
        sev = Severity.INFO
        label = f"TLS→ {hs.sni or hs.server_ip}"
        detail = (
            f"{hs.client_ip} → {hs.server_ip} "
            f"SNI={hs.sni or 'N/A'} JA3={hs.ja3[:8] if hs.ja3 else 'N/A'}"
        )
        ctx.timeline.append(TimelineEvent(
            ts=hs.ts_client, event_type="tls_client_hello",
            src_ip=hs.client_ip, dst_ip=hs.server_ip,
            label=label, detail=detail, severity=sev,
            packet_num=hs.client_pkt, protocol="TLS",
        ))


def _add_finding_events(ctx: CaptureContext) -> None:
    for f in ctx.findings:
        if f.suppressed:
            continue
        ev = f.evidence
        ts = ev.time_first or 0.0
        if not ts:
            continue
        ctx.timeline.append(TimelineEvent(
            ts=ts, event_type=f"finding_{f.category}",
            src_ip=f.affected_hosts[0] if f.affected_hosts else "",
            dst_ip="",
            label=f"[{f.severity.upper()}] {f.title}",
            detail=f.description[:200],
            severity=f.severity,
            protocol=f.category.upper(),
        ))


# ── Storyline generation ──────────────────────────────────────────────────────

def _capture_story(ctx: CaptureContext) -> str:
    fi = ctx.file_info
    lines = []

    total = fi.total_packets
    dur = fi.duration_sec
    lines.append(
        f"This capture spans {_format_dur(dur)} and contains {total:,} packets "
        f"({_format_bytes(fi.file_size_bytes)})."
    )

    # Protocol composition
    if ctx.protocol_stats:
        top = sorted(ctx.protocol_stats.items(), key=lambda x: -x[1])[:4]
        top_str = ", ".join(f"{p} ({c:,})" for p, c in top)
        lines.append(f"The dominant protocols are: {top_str}.")

    # DNS activity
    dns_stats = getattr(ctx, "dns_stats", {})
    if dns_stats.get("total_queries", 0) > 0:
        lines.append(
            f"DNS activity includes {dns_stats['total_queries']:,} queries to "
            f"{len(dns_stats.get('resolvers', []))} resolver(s), "
            f"resolving {dns_stats.get('unique_domains', 0)} unique domains."
        )
        if dns_stats.get("nxdomain_count", 0) > 10:
            lines.append(
                f"There are {dns_stats['nxdomain_count']} NXDOMAIN failures, "
                "which may indicate misconfigured clients, DGA malware, or C2 activity."
            )

    # HTTP activity
    http_stats = getattr(ctx, "http_stats", {})
    if http_stats.get("total_requests", 0) > 0:
        lines.append(
            f"HTTP traffic includes {http_stats['total_requests']:,} requests "
            f"with {http_stats.get('error_5xx', 0)} server errors and "
            f"{http_stats.get('error_4xx', 0)} client errors."
        )

    # TLS
    tls_stats = getattr(ctx, "tls_stats", {})
    if tls_stats.get("total_streams", 0) > 0:
        lines.append(
            f"TLS traffic includes {tls_stats['total_streams']} encrypted connections "
            f"to {tls_stats.get('unique_sni', 0)} unique hostnames."
        )

    # Security summary
    critical = [f for f in ctx.findings if f.severity == "critical" and not f.suppressed]
    if critical:
        lines.append(
            f"Security analysis flagged {len(critical)} critical finding(s): "
            f"{'; '.join(f.title for f in critical[:2])}."
        )
    else:
        lines.append("No critical security anomalies were detected.")

    return " ".join(lines)


def _host_story(ctx: CaptureContext, ip: str) -> str:
    profile = ctx.hosts.get(ip)
    if not profile:
        return ""
    lines = [f"Host {ip} ({profile.role.value}):"]

    total_bytes = profile.bytes_sent + profile.bytes_recv
    lines.append(
        f"transferred {_format_bytes(total_bytes)} "
        f"({_format_bytes(profile.bytes_sent)} sent, {_format_bytes(profile.bytes_recv)} received)."
    )

    if profile.unique_peers:
        top_peers = profile.top_peers[:3]
        peer_str = ", ".join(f"{p} ({_format_bytes(b)})" for p, b in top_peers)
        lines.append(f"Top communication partners: {peer_str}.")

    if profile.tcp_sessions_initiated > 0:
        fail_rate = profile.tcp_sessions_failed / max(profile.tcp_sessions_initiated, 1)
        lines.append(
            f"Initiated {profile.tcp_sessions_initiated} TCP connections "
            f"({fail_rate*100:.0f}% failed)."
        )

    if profile.periodic_interval_sec > 0:
        lines.append(
            f"Exhibits periodic outbound connections every ~{profile.periodic_interval_sec:.0f}s "
            f"(jitter={profile.periodic_jitter:.2f}) — possible beaconing."
        )

    if profile.suspicious_behaviors:
        lines.append("Suspicious behaviors: " + "; ".join(profile.suspicious_behaviors) + ".")

    return " ".join(lines)


def _flow_story(ctx: CaptureContext, flow_key: str) -> str:
    fl = ctx.flows.get(flow_key)
    if not fl:
        return ""

    proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(fl.proto, str(fl.proto))
    lines = [
        f"{proto} flow {fl.src_ip}:{fl.src_port} → {fl.dst_ip}:{fl.dst_port}:"
    ]
    lines.append(
        f"{fl.total_packets:,} packets, {_format_bytes(fl.total_bytes)}, "
        f"duration {_format_dur(fl.duration)}."
    )
    if fl.retransmissions:
        lines.append(f"{fl.retransmissions} retransmissions.")
    if fl.avg_rtt_ms:
        lines.append(f"Average RTT: {fl.avg_rtt_ms:.1f}ms.")
    if fl.has_tls:
        hs = next((h for h in ctx.tls_handshakes if h.stream_id == fl.tcp_stream), None)
        if hs:
            lines.append(
                f"TLS encrypted to {hs.sni or 'unknown'} "
                f"({hs.tls_version}, JA3={hs.ja3[:8] if hs.ja3 else 'N/A'})."
            )

    return " ".join(lines)


# ── Main entry point ──────────────────────────────────────────────────────────

def correlate(ctx: CaptureContext) -> None:
    """
    Correlate all protocol events into timeline and generate storylines.
    Must be called AFTER all analyzers have run.
    """
    _add_dns_events(ctx)
    _add_http_events(ctx)
    _add_tls_events(ctx)
    _add_finding_events(ctx)

    # Sort timeline by timestamp, put ts=0 events at end
    ctx.timeline.sort(key=lambda e: e.ts if e.ts > 0 else float("inf"))
    ctx.timeline = ctx.timeline[:2000]

    # Generate stories
    ctx.capture_story = _capture_story(ctx)

    # Host stories for top 20 hosts by anomaly score
    top_hosts = sorted(ctx.hosts.values(), key=lambda h: -h.anomaly_score)[:20]
    for profile in top_hosts:
        ctx.host_stories[profile.ip] = _host_story(ctx, profile.ip)

    # Flow stories for top 20 flows by bytes
    top_flows = sorted(ctx.flows.values(), key=lambda f: -f.total_bytes)[:20]
    for fl in top_flows:
        ctx.flow_stories[fl.key] = _flow_story(ctx, fl.key)
