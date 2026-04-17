"""
Cross-protocol correlation engine.
Correlates DNS, TCP, TLS, HTTP events into a unified, sorted timeline
and generates natural-language storylines.
"""
from __future__ import annotations

from typing import Dict, List

from models import CaptureContext, Severity, TimelineEvent


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
    """
    Event-driven capture narrative.  Tells a temporal story: what happened first,
    what the dominant activity was, and what anomalies were detected.
    """
    fi = ctx.file_info
    paragraphs: List[str] = []

    # ── Opening: capture overview ─────────────────────────────────────────────
    dur = fi.duration_sec
    total = fi.total_packets
    if dur > 0:
        opening = (
            f"This capture spans {_format_dur(dur)} and contains {total:,} packets "
            f"({_format_bytes(fi.file_size_bytes)})."
        )
    else:
        opening = (
            f"This capture contains {total:,} packets ({_format_bytes(fi.file_size_bytes)})."
        )

    if ctx.protocol_stats:
        top = sorted(ctx.protocol_stats.items(), key=lambda x: -x[1])[:3]
        top_str = ", ".join(f"{p} ({c:,} frames)" for p, c in top)
        opening += f" Dominant protocols: {top_str}."
    paragraphs.append(opening)

    # ── Temporal markers from timeline ────────────────────────────────────────
    events = [e for e in ctx.timeline if e.ts > 0]
    if events:
        finding_events = [e for e in events if e.event_type.startswith("finding_")]
        proto_events = [e for e in events if not e.event_type.startswith("finding_")]

        temporal_parts: List[str] = []
        if proto_events:
            first_proto = proto_events[0]
            temporal_parts.append(
                f"The first captured event is a {first_proto.protocol or first_proto.event_type} "
                f"event from {first_proto.src_ip or 'unknown'}"
                + (f" to {first_proto.dst_ip}" if first_proto.dst_ip else "")
                + f" ({first_proto.label})."
            )

        # DNS-to-connection correlation
        dns_events = [e for e in proto_events if e.event_type == "dns_query"]
        tcp_events = [e for e in events if e.event_type == "finding_reconnaissance"]
        if dns_events and not tcp_events:
            resolvers = list(dict.fromkeys(e.dst_ip for e in dns_events if e.dst_ip))[:3]
            temporal_parts.append(
                f"DNS resolution activity was observed throughout: "
                f"{len(dns_events)} queries, "
                f"resolver(s): {', '.join(resolvers) or 'unknown'}."
            )

        # Scan / anomaly events with temporal context
        if finding_events:
            first_anomaly = finding_events[0]
            temporal_parts.append(
                f"The first security event occurred at approximately "
                f"T+{_format_dur(first_anomaly.ts - events[0].ts if events[0].ts > 0 else 0)} "
                f"into the capture: {first_anomaly.label}."
            )

        if temporal_parts:
            paragraphs.append(" ".join(temporal_parts))

    # ── Protocol-layer narrative ──────────────────────────────────────────────
    proto_parts: List[str] = []
    dns_stats = getattr(ctx, "dns_stats", {})
    http_stats = getattr(ctx, "http_stats", {})
    tls_stats = getattr(ctx, "tls_stats", {})

    if dns_stats.get("total_queries", 0) > 0:
        nxd = dns_stats.get("nxdomain_count", 0)
        nxd_str = f", including {nxd} NXDOMAIN failures" if nxd > 0 else ""
        proto_parts.append(
            f"DNS: {dns_stats['total_queries']:,} queries to "
            f"{dns_stats.get('unique_domains', 0)} unique domain(s){nxd_str}."
        )
        if nxd > 10:
            proto_parts.append(
                f"The {nxd} NXDOMAIN failures may indicate DGA malware, "
                "misconfigured search suffixes, or a sinkholed C2 domain."
            )

    if http_stats.get("total_requests", 0) > 0:
        errs = http_stats.get("error_4xx", 0) + http_stats.get("error_5xx", 0)
        proto_parts.append(
            f"HTTP: {http_stats['total_requests']:,} requests"
            + (f", {errs} error responses" if errs else "")
            + f", avg latency {http_stats.get('avg_latency_ms', 0):.0f}ms."
        )

    if tls_stats.get("total_streams", 0) > 0:
        dep = tls_stats.get("deprecated_count", 0)
        tls_note = f" — {dep} using deprecated TLS versions" if dep else ""
        proto_parts.append(
            f"TLS: {tls_stats['total_streams']} encrypted stream(s) "
            f"to {tls_stats.get('unique_sni', 0)} unique hostname(s){tls_note}."
        )

    if proto_parts:
        paragraphs.append(" ".join(proto_parts))

    # ── Security conclusion ───────────────────────────────────────────────────
    active = [f for f in ctx.findings if not f.suppressed]
    critical = [f for f in active if str(f.severity) in ("critical", "Severity.CRITICAL")]
    high = [f for f in active if str(f.severity) in ("high", "Severity.HIGH")]

    if critical:
        paragraphs.append(
            f"CRITICAL: The analysis identified {len(critical)} critical finding(s): "
            f"{'; '.join(f.title for f in critical[:2])}. "
            "Immediate investigation is warranted."
        )
    elif high:
        paragraphs.append(
            f"The analysis found {len(high)} high-severity finding(s): "
            f"{'; '.join(f.title for f in high[:2])}."
        )
    elif active:
        paragraphs.append(
            f"The analysis flagged {len(active)} finding(s) — none critical."
        )
    else:
        paragraphs.append("No security anomalies were detected in this capture.")

    return "\n\n".join(paragraphs)


def _host_story(ctx: CaptureContext, ip: str) -> str:
    """
    Evidence-backed host narrative.
    Describes role, communication partners (with their roles), protocol mix,
    connection quality, and any anomalous behaviors observed.
    """
    profile = ctx.hosts.get(ip)
    if not profile:
        return ""

    parts: List[str] = []

    # ── Role and traffic overview ─────────────────────────────────────────────
    role_label = profile.role.value if hasattr(profile.role, "value") else profile.role
    network_type = "internal" if profile.is_internal else "external"
    total_bytes = profile.bytes_sent + profile.bytes_recv
    parts.append(
        f"Host {ip} is classified as a **{role_label}** ({network_type}). "
        f"Total traffic: {_format_bytes(total_bytes)} "
        f"({_format_bytes(profile.bytes_sent)} sent, {_format_bytes(profile.bytes_recv)} received) "
        f"to/from {profile.unique_peers} peer(s)."
    )

    # ── Peer relationships with roles ────────────────────────────────────────
    if profile.top_peers:
        peer_descs: List[str] = []
        for peer_ip, peer_bytes in profile.top_peers[:4]:
            peer_role = profile.peer_roles.get(peer_ip, "unknown")
            peer_descs.append(f"{peer_ip} [{peer_role}, {_format_bytes(peer_bytes)}]")
        parts.append(f"Top peers: {', '.join(peer_descs)}.")

    # ── Protocol mix ─────────────────────────────────────────────────────────
    if profile.protocol_mix_pct:
        top_protos = sorted(profile.protocol_mix_pct.items(), key=lambda x: -x[1])[:4]
        proto_str = ", ".join(f"{p} {pct:.0f}%" for p, pct in top_protos)
        parts.append(f"Protocol mix: {proto_str}.")

    # ── Connection quality ────────────────────────────────────────────────────
    if profile.tcp_sessions_initiated > 0:
        success_pct = profile.connection_success_ratio * 100
        fail_count = profile.tcp_sessions_failed
        parts.append(
            f"Initiated {profile.tcp_sessions_initiated} TCP connection(s): "
            f"{success_pct:.0f}% succeeded"
            + (f", {fail_count} failed" if fail_count > 0 else "")
            + "."
        )

    # ── Beaconing ────────────────────────────────────────────────────────────
    if profile.periodic_interval_sec > 0:
        parts.append(
            f"ALERT: Exhibits periodic outbound connections every "
            f"~{profile.periodic_interval_sec:.0f}s "
            f"(timing jitter CoV={profile.periodic_jitter:.2f} — "
            + ("very regular, likely automated)" if profile.periodic_jitter < 0.05 else
               "low variance, consistent with beaconing)")
            + "."
        )

    # ── Other suspicious behaviors ────────────────────────────────────────────
    if profile.suspicious_behaviors:
        parts.append(
            "Observed anomalies: " + "; ".join(profile.suspicious_behaviors) + "."
        )

    return "\n".join(parts)


# ── Well-known port → service label ──────────────────────────────────────────
_WELL_KNOWN: Dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 179: "BGP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-submission", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle-DB",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def _service_label(port: int, has_tls: bool = False) -> str:
    if port in _WELL_KNOWN:
        return _WELL_KNOWN[port]
    if has_tls and port in (443, 8443):
        return "HTTPS"
    if 1024 > port > 0:
        return f"port/{port} (privileged)"
    return f"port/{port}"


def _flow_story(ctx: CaptureContext, flow_key: str) -> str:
    fl = ctx.flows.get(flow_key)
    if not fl:
        return ""

    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(fl.proto, f"proto/{fl.proto}")
    svc = _service_label(fl.dst_port, fl.has_tls)
    parts: List[str] = []

    # ── What is this flow? ────────────────────────────────────────────────────
    # Enrich with TLS context
    tls_hs = None
    if fl.has_tls:
        tls_hs = next((h for h in ctx.tls_handshakes if h.stream_id == fl.tcp_stream), None)

    # Enrich with HTTP context
    http_txs = [tx for tx in ctx.http_transactions if tx.stream_id == fl.tcp_stream] if fl.has_http else []

    if tls_hs and tls_hs.sni:
        dest_label = f"{tls_hs.sni} ({fl.dst_ip}:{fl.dst_port}, {tls_hs.tls_version or 'TLS'})"
    elif http_txs:
        host = http_txs[0].host or fl.dst_ip
        dest_label = f"{host} ({fl.dst_ip}:{fl.dst_port}, HTTP)"
    else:
        dest_label = f"{fl.dst_ip}:{fl.dst_port} ({svc})"

    what = (
        f"**What:** {proto_name} connection from {fl.src_ip}:{fl.src_port} "
        f"to {dest_label}."
    )
    parts.append(what)

    # ── Traffic volume & direction ────────────────────────────────────────────
    vol_parts = [
        f"{fl.total_packets:,} packets, {_format_bytes(fl.total_bytes)} total",
        f"duration {_format_dur(fl.duration)}",
    ]
    if fl.fwd_bytes and fl.rev_bytes:
        ratio = fl.fwd_bytes / max(fl.fwd_bytes + fl.rev_bytes, 1)
        if ratio > 0.85:
            direction_note = "mostly upload (client → server)"
        elif ratio < 0.15:
            direction_note = "mostly download (server → client)"
        else:
            direction_note = "bidirectional"
        vol_parts.append(direction_note)
    if fl.avg_rtt_ms > 0:
        vol_parts.append(f"avg RTT {fl.avg_rtt_ms:.1f}ms")
    parts.append("Volume: " + ", ".join(vol_parts) + ".")

    # ── HTTP request context ──────────────────────────────────────────────────
    if http_txs:
        sample = http_txs[0]
        req_line = f"{sample.method} {sample.uri[:80]}"
        if len(http_txs) > 1:
            req_line += f" (+ {len(http_txs) - 1} more requests)"
        codes = {}
        for tx in http_txs:
            if tx.status_code:
                codes[tx.status_code] = codes.get(tx.status_code, 0) + 1
        codes_str = ", ".join(f"HTTP {c} ×{n}" for c, n in sorted(codes.items()))
        parts.append(f"HTTP: {req_line}. Responses: {codes_str or 'unknown'}.")

    # ── TLS certificate / version notes ──────────────────────────────────────
    if tls_hs:
        tls_notes = []
        if tls_hs.tls_version and tls_hs.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            tls_notes.append(f"uses deprecated {tls_hs.tls_version}")
        if tls_hs.cert_expired:
            tls_notes.append("server certificate is expired")
        if tls_hs.cert_self_signed:
            tls_notes.append("server uses a self-signed certificate")
        if tls_hs.cert_mismatch:
            tls_notes.append("certificate CN does not match SNI")
        if tls_notes:
            parts.append("TLS issues: " + "; ".join(tls_notes) + ".")
        elif tls_hs.cipher_suite:
            parts.append(f"TLS cipher: {tls_hs.cipher_suite}.")

    # ── Why it matters ────────────────────────────────────────────────────────
    why_notes: List[str] = []

    # Large external transfers
    import ipaddress as _ip
    def _is_priv(addr: str) -> bool:
        try:
            return _ip.ip_address(addr).is_private
        except ValueError:
            return False

    src_priv = _is_priv(fl.src_ip)
    dst_priv = _is_priv(fl.dst_ip)

    if src_priv and not dst_priv and fl.fwd_bytes > 10 * 1024 * 1024:
        why_notes.append(
            f"large outbound transfer of {_format_bytes(fl.fwd_bytes)} to an external host "
            "— monitor for data exfiltration"
        )
    elif not src_priv and dst_priv and fl.rev_bytes > 50 * 1024 * 1024:
        why_notes.append(
            f"large inbound transfer of {_format_bytes(fl.rev_bytes)} from an external host"
        )

    # Sensitive service access
    sensitive = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
                 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                 6379: "Redis", 27017: "MongoDB", 5900: "VNC"}
    if fl.dst_port in sensitive:
        why_notes.append(
            f"connection to sensitive service {sensitive[fl.dst_port]} — "
            "verify authorization"
        )

    # High retransmission rate
    total_pkts = fl.total_packets or 1
    retrans_rate = fl.retransmissions / total_pkts
    if retrans_rate > 0.10:
        why_notes.append(
            f"high retransmission rate ({fl.retransmissions}/{total_pkts} pkts, "
            f"{retrans_rate*100:.0f}%) — significant packet loss on this path"
        )
    elif fl.retransmissions > 5:
        why_notes.append(f"{fl.retransmissions} retransmissions — possible congestion")

    if why_notes:
        parts.append("**Why it matters:** " + "; ".join(why_notes) + ".")

    # ── Root cause assessment ─────────────────────────────────────────────────
    root_cause_parts: List[str] = []

    # Classify overall behavior
    session = next(
        (s for s in ctx.sessions.values() if s.flow_key == flow_key), None
    )
    if session:
        if session.has_syn and not session.has_synack:
            root_cause_parts.append(
                "The TCP handshake was never completed (SYN sent, no SYN-ACK received). "
                "The target host may be offline, the port is filtered by a firewall, "
                "or the service is not listening."
            )
        elif session.has_rst:
            root_cause_parts.append(
                "The connection was reset (RST). The server actively refused the connection "
                "or an intermediate device (firewall, load balancer) terminated it."
            )

    if fl.has_http and http_txs:
        errors = [tx for tx in http_txs if tx.status_code >= 400]
        if len(errors) == len(http_txs) and errors:
            root_cause_parts.append(
                f"All HTTP requests returned error codes "
                f"({', '.join(str(tx.status_code) for tx in errors[:3])}). "
                "The resource may not exist (404), access may be denied (403), "
                "or the server is overloaded (5xx)."
            )

    if retrans_rate > 0.10:
        root_cause_parts.append(
            "High packet loss suggests network congestion, a faulty link, "
            "a duplex mismatch, or a saturated uplink."
        )

    if tls_hs and tls_hs.cert_expired:
        root_cause_parts.append(
            "Expired certificate: the server's TLS certificate has passed its validity date. "
            "This may cause client warnings and broken connections."
        )

    if not root_cause_parts:
        # Normal flow — describe purpose
        if fl.has_tls and tls_hs and tls_hs.sni:
            root_cause_parts.append(
                f"Normal encrypted session to {tls_hs.sni}. "
                "Traffic content is not visible due to TLS encryption."
            )
        elif fl.has_http and http_txs:
            root_cause_parts.append("Normal HTTP web or API traffic.")
        elif fl.dst_port == 53:
            root_cause_parts.append("Standard DNS resolution traffic.")
        elif fl.dst_port in (22,):
            root_cause_parts.append("Interactive SSH session or automated remote command.")
        else:
            root_cause_parts.append(
                f"Application-layer traffic on {svc}. "
                "No anomalies detected in packet-level metrics."
            )

    parts.append("**Root cause:** " + " ".join(root_cause_parts))

    return "\n\n".join(parts)


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
