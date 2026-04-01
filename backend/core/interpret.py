"""
Interpretation engine — analyst-grade explanations for TCP sessions,
host behavior, and capture quality.

Key principle: be honest about uncertainty. If something cannot be confirmed
from the capture, say so explicitly. Use "observed", "likely", and
"cannot confirm from this capture" rather than misleading certainty.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List

from models import CaptureContext, SessionRecord

# ── Port → service label ──────────────────────────────────────────────────────
_PORT_SERVICE: Dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 135: "RPC/DCOM", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-submission", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle-DB", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

_SENSITIVE_PORTS: set = {
    22, 23, 3389, 5900, 5985, 5986,
    1433, 3306, 5432, 6379, 27017, 9200, 445, 135, 139,
}


def _service(port: int, has_tls: bool = False, has_http: bool = False) -> str:
    if has_tls and port in (443, 8443, 8444):
        return "HTTPS"
    if has_http and port in (80, 8080, 8008):
        return "HTTP"
    return _PORT_SERVICE.get(port, f"TCP/{port}")


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _fmt_bytes(b: int) -> str:
    if not b:
        return "0 B"
    if b < 1024:
        return f"{b} B"
    if b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    if b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    return f"{b / 1024 ** 3:.2f} GB"


def _fmt_dur(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    if s < 3600:
        return f"{int(s // 60)}m {int(s % 60)}s"
    return f"{int(s // 3600)}h {int((s % 3600) // 60)}m"


# ── Per-session interpretation ────────────────────────────────────────────────

def interpret_session(session: SessionRecord, ctx: CaptureContext) -> Dict[str, Any]:
    """
    Return a structured interpretation dict for one TCP session.
    All conclusions are hedged by what is directly observable.
    """
    fl = ctx.flows.get(session.flow_key)

    # Application-layer context
    tls_hs = next(
        (h for h in ctx.tls_handshakes if h.stream_id == session.stream_id), None
    )
    http_txs = [
        tx for tx in ctx.http_transactions
        if tx.stream_id == session.stream_id
    ]
    has_tls = (fl.has_tls if fl else False) or bool(tls_hs)
    has_http = (fl.has_http if fl else False) or bool(http_txs)

    protocol_guess = _service(session.dst_port, has_tls=has_tls, has_http=has_http)

    # ── Handshake status ──────────────────────────────────────────────────────
    if session.has_syn and session.has_synack:
        handshake_status = "complete"
        handshake_label = "Complete — SYN and SYN-ACK both observed"
        confidence = "high"
        confidence_note = (
            "Full 3-way handshake was captured. Session establishment is directly confirmed."
        )
    elif session.has_syn and not session.has_synack:
        handshake_status = "failed"
        handshake_label = "Failed — SYN sent, no SYN-ACK received"
        confidence = "medium"
        confidence_note = (
            "Connection attempt did not complete. The remote host did not respond "
            "with SYN-ACK within the capture window."
        )
    else:
        handshake_status = "mid_stream"
        handshake_label = "Mid-stream — no handshake visible in this capture"
        confidence = "low"
        confidence_note = (
            "No SYN or SYN-ACK observed. The session was likely already established "
            "when the capture began, or the handshake packets were not captured at "
            "this tap point. Protocol identification and state reconstruction have "
            "reduced confidence."
        )

    # ── Close behavior ────────────────────────────────────────────────────────
    if session.has_fin:
        close_behavior = "fin"
        close_label = "Graceful FIN close — observed"
    elif session.has_rst:
        close_behavior = "rst"
        close_label = "RST termination — abrupt close observed"
    else:
        close_behavior = "unknown"
        close_label = "No close observed — session may continue beyond capture window"

    # ── Traffic asymmetry ─────────────────────────────────────────────────────
    sent = session.bytes_sent or 0
    recv = session.bytes_recv or 0
    total_bytes = sent + recv
    asymmetry_type = "balanced"
    asymmetry_note = ""

    if sent > 0 and recv > 0:
        ratio = sent / max(recv, 1)
        if ratio > 5:
            asymmetry_type = "client_heavy"
            asymmetry_note = (
                f"Client-heavy: {_fmt_bytes(sent)} sent vs {_fmt_bytes(recv)} received "
                f"({ratio:.1f}× asymmetry). Possible interpretations: large client upload, "
                "server not responding normally, one-directional SPAN capture, "
                "or missing return traffic."
            )
        elif ratio < 0.2:
            asymmetry_type = "server_heavy"
            asymmetry_note = (
                f"Server-heavy: {_fmt_bytes(recv)} received vs {_fmt_bytes(sent)} sent "
                f"({1/ratio:.1f}× asymmetry). Consistent with a large download or "
                "streaming server response."
            )
    elif sent > 0 and recv == 0:
        asymmetry_type = "one_sided_send"
        asymmetry_note = (
            f"Only outbound traffic observed ({_fmt_bytes(sent)} sent, 0 received). "
            "Return path may not be captured at this tap point — possible asymmetric "
            "routing or one-sided SPAN mirror."
        )
    elif recv > 0 and sent == 0:
        asymmetry_type = "one_sided_recv"
        asymmetry_note = (
            f"Only inbound traffic observed ({_fmt_bytes(recv)} received, 0 sent). "
            "Outbound path may not pass through this capture point."
        )

    # ── Quality indicators ────────────────────────────────────────────────────
    total_pkts = (session.packets_sent or 0) + (session.packets_recv or 0)
    quality_notes: List[str] = []

    if session.retransmissions and total_pkts > 0:
        rate = session.retransmissions / total_pkts
        if rate > 0.10:
            quality_notes.append(
                f"High retransmission rate: {session.retransmissions} retransmissions "
                f"out of {total_pkts} packets ({rate * 100:.0f}%). "
                "Severe packet loss or network degradation on this path."
            )
        elif session.retransmissions > 3:
            quality_notes.append(
                f"{session.retransmissions} retransmission(s) — minor packet loss detected."
            )

    if session.dup_acks and session.dup_acks > 3:
        quality_notes.append(
            f"{session.dup_acks} duplicate ACKs — receiver is signaling missing segments."
        )

    if session.zero_windows and session.zero_windows > 2:
        quality_notes.append(
            f"{session.zero_windows} zero-window event(s) — receive buffer was full, "
            "causing sender to pause. Indicates application-layer backpressure or slow consumer."
        )

    # ── Narrative sections ────────────────────────────────────────────────────

    # What
    what_parts: List[str] = []
    if tls_hs and tls_hs.sni:
        dest_desc = f"{tls_hs.sni} ({tls_hs.tls_version or 'TLS'})"
    elif http_txs and http_txs[0].host:
        dest_desc = http_txs[0].host
    else:
        dest_desc = f"{session.dst_ip}:{session.dst_port}"

    what_parts.append(
        f"{protocol_guess} session: {session.src_ip}:{session.src_port} → {dest_desc}. "
        f"{handshake_label}. {close_label}."
    )

    if http_txs:
        methods = list(dict.fromkeys(tx.method for tx in http_txs if tx.method))
        codes = list(dict.fromkeys(str(tx.status_code) for tx in http_txs if tx.status_code))
        what_parts.append(
            f"{len(http_txs)} HTTP request(s): {', '.join(methods[:3])}. "
            f"Response codes: {', '.join(codes[:5]) or 'not captured'}."
        )

    if tls_hs:
        tls_issues = []
        if tls_hs.cert_expired:
            tls_issues.append("expired certificate")
        if tls_hs.cert_self_signed:
            tls_issues.append("self-signed certificate")
        if tls_hs.cert_mismatch:
            tls_issues.append("SNI/cert CN mismatch")
        if tls_hs.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            tls_issues.append(f"deprecated {tls_hs.tls_version}")
        if tls_issues:
            what_parts.append(f"TLS issues: {', '.join(tls_issues)}.")

    if total_bytes > 0:
        what_parts.append(
            f"Volume: {_fmt_bytes(total_bytes)} total "
            f"({_fmt_bytes(sent)} sent, {_fmt_bytes(recv)} received)."
        )

    if asymmetry_note:
        what_parts.append(asymmetry_note)
    what_parts.extend(quality_notes)

    # Why it matters
    why_parts: List[str] = []
    src_priv = _is_private(session.src_ip)
    dst_priv = _is_private(session.dst_ip)

    if session.dst_port in _SENSITIVE_PORTS:
        svc = _PORT_SERVICE.get(session.dst_port, str(session.dst_port))
        why_parts.append(
            f"Access to {svc} (port {session.dst_port}) — a sensitive service. "
            "Authorization should be verified."
        )

    if src_priv and not dst_priv and sent > 10 * 1024 * 1024:
        why_parts.append(
            f"Large outbound transfer of {_fmt_bytes(sent)} from internal host "
            f"to external address {session.dst_ip}. Review for potential data exfiltration."
        )

    if handshake_status == "failed":
        why_parts.append(
            "Failed connection — destination did not respond. "
            "Could indicate port filtering, unreachable host, or connection probing."
        )

    if not why_parts:
        if total_bytes > 0:
            why_parts.append(
                f"Session transferred {_fmt_bytes(total_bytes)} between "
                f"{session.src_ip} and {session.dst_ip}:{session.dst_port}. "
                "No anomalies detected in packet-level metrics."
            )
        else:
            why_parts.append("Session observed with no significant data transfer.")

    # Root cause
    root_cause_parts: List[str] = []

    if handshake_status == "mid_stream":
        root_cause_parts.append(
            "Capture began after this session was established — the initial handshake "
            "is not available. This reduces confidence in protocol identification and "
            "makes exact session intent unknown. Consider re-capturing from session "
            "start for complete analysis."
        )
    elif handshake_status == "failed":
        root_cause_parts.append(
            "Most likely causes: firewall blocking the destination port, "
            "destination host is offline, or the service is not listening on this port."
        )
    elif handshake_status == "complete":
        if close_behavior == "rst":
            root_cause_parts.append(
                "RST termination can indicate: application-level error, firewall "
                "forcibly closing the connection, idle timeout on a middlebox, "
                "or the application explicitly reset the connection."
            )
        elif close_behavior == "unknown":
            root_cause_parts.append(
                "No FIN or RST observed. The session either continues beyond the capture "
                "window, or the close sequence was not captured at this tap point."
            )
        else:
            root_cause_parts.append(
                "Normal session with clean FIN close — standard termination."
            )

    if session.retransmissions and total_pkts > 0 and (session.retransmissions / total_pkts) > 0.10:
        root_cause_parts.append(
            "High retransmission rate is typically caused by: network congestion, "
            "duplex mismatch, faulty NIC or cable, or a saturated link."
        )

    # What to check next
    check_next: List[str] = []
    if handshake_status == "mid_stream":
        check_next.append("Re-capture from before the session starts for complete analysis.")
    if handshake_status == "failed":
        check_next.append("Check firewall rules on the destination host.")
        check_next.append("Verify the target service is running and listening.")
    if session.dst_port in _SENSITIVE_PORTS:
        svc = _PORT_SERVICE.get(session.dst_port, "this service")
        check_next.append(f"Confirm {svc} access is authorized from {session.src_ip}.")
    if tls_hs and tls_hs.cert_expired:
        check_next.append("Renew TLS certificate on the destination server immediately.")
    if src_priv and not dst_priv and sent > 10 * 1024 * 1024:
        check_next.append("Cross-reference with DLP logs — large outbound transfer detected.")
    if asymmetry_type in ("one_sided_send", "one_sided_recv"):
        check_next.append("Verify capture point — return traffic may route differently.")
    if not check_next:
        check_next.append("No immediate action required based on observed metrics.")

    return {
        "protocol_guess": protocol_guess,
        "handshake_status": handshake_status,
        "handshake_label": handshake_label,
        "close_behavior": close_behavior,
        "close_label": close_label,
        "confidence": confidence,
        "confidence_note": confidence_note,
        "asymmetry_type": asymmetry_type,
        "asymmetry_note": asymmetry_note,
        "quality_notes": quality_notes,
        "what": " ".join(what_parts),
        "why_matters": " ".join(why_parts),
        "root_cause": " ".join(root_cause_parts),
        "check_next": check_next,
    }


# ── Capture quality assessment ────────────────────────────────────────────────

def assess_capture_quality(ctx: CaptureContext) -> Dict[str, Any]:
    """
    Honestly assess the completeness and reliability of this capture.
    Returns structured dict for the Expert Info / Capture Assessment panel.
    """
    sessions = list(ctx.sessions.values())
    total = len(sessions)

    if total == 0:
        # Distinguish: (a) no TCP traffic, (b) TCP present but sessions not reconstructed
        proto_stats = getattr(ctx, "protocol_stats", {})
        tcp_pkts = proto_stats.get("tcp", 0)
        udp_pkts = proto_stats.get("udp", 0)
        icmp_pkts = proto_stats.get("icmp", 0)
        arp_pkts = proto_stats.get("arp", 0)

        if tcp_pkts > 0:
            issue_msg = (
                f"TCP traffic detected ({tcp_pkts:,} packets in protocol hierarchy) "
                "but no TCP sessions could be reconstructed — tcp.stream field was absent "
                "in all packets. Sessions have been grouped by IP 4-tuple as a fallback; "
                "if you see 0 sessions, the capture may contain only TCP headers with no "
                "usable port information."
            )
        elif udp_pkts > 0:
            parts = [f"UDP: {udp_pkts:,} packets"]
            if icmp_pkts:
                parts.append(f"ICMP: {icmp_pkts:,} packets")
            if arp_pkts:
                parts.append(f"ARP: {arp_pkts:,} packets")
            issue_msg = (
                f"No TCP traffic found. Capture contains: {', '.join(parts)}. "
                "TCP session analysis does not apply. Check the DNS and Protocol tabs "
                "for UDP-based protocol analysis."
            )
        else:
            present = [p for p in ("arp", "icmp", "eth", "ip") if proto_stats.get(p, 0) > 0]
            issue_msg = (
                "No TCP or UDP sessions found. Capture appears to contain only "
                + (f"{', '.join(present).upper()} traffic." if present else "non-IP or empty traffic.")
            )

        return {
            "quality": "unknown",
            "quality_label": "Unknown — No TCP Sessions",
            "issues": [issue_msg],
            "reliable": [],
            "low_confidence": ["All TCP-based conclusions — no sessions to analyze"],
            "inferred": [],
            "observed": ["Raw packet fields (IP headers, timestamps, byte counts)"],
            "midstream_count": 0,
            "midstream_pct": 0.0,
            "failed_handshake_count": 0,
            "no_close_count": 0,
            "total_sessions": 0,
        }

    midstream = [s for s in sessions if not s.has_syn]
    failed_hs = [s for s in sessions if s.has_syn and not s.has_synack]
    no_close = [s for s in sessions if not s.has_fin and not s.has_rst]
    rst_close = [s for s in sessions if s.has_rst]

    midstream_pct = len(midstream) / total
    failed_pct = len(failed_hs) / total
    no_close_pct = len(no_close) / total

    issues: List[str] = []
    reliable: List[str] = []
    low_confidence: List[str] = []
    inferred: List[str] = []
    observed: List[str] = []

    # Quality grade
    if midstream_pct > 0.5:
        quality = "poor"
        quality_label = "Poor — majority of sessions are mid-stream"
    elif midstream_pct > 0.2 or failed_pct > 0.2:
        quality = "partial"
        quality_label = "Partial — some sessions are incomplete"
    else:
        quality = "good"
        quality_label = "Good"

    if midstream_pct > 0:
        issues.append(
            f"{len(midstream)} of {total} TCP sessions ({midstream_pct * 100:.0f}%) "
            "are mid-stream — no SYN/SYN-ACK observed. The capture likely started "
            "after these sessions were established, or the capture tap point does not "
            "see the initial handshake. Handshake timing, intent, and true session "
            "start cannot be confirmed for these sessions."
        )
        low_confidence.append("Protocol identification for mid-stream sessions (port-based guessing only)")
        low_confidence.append("Accurate session start time and establishment intent for mid-stream sessions")

    if failed_pct > 0.05:
        issues.append(
            f"{len(failed_hs)} sessions ({failed_pct * 100:.0f}%) sent SYN but "
            "received no SYN-ACK. These connections did not complete. May indicate "
            "port scanning, firewall blocking, or deliberate connection probing."
        )

    if no_close_pct > 0.5:
        issues.append(
            f"{len(no_close)} sessions ({no_close_pct * 100:.0f}%) have no observed "
            "close (FIN or RST). The capture may end before session termination, "
            "or the close sequence was not captured at this tap point. "
            "Session duration and termination reason cannot be confirmed."
        )
        low_confidence.append("Session duration and termination reason for sessions without observed close")

    if len(rst_close) / total > 0.3:
        issues.append(
            f"{len(rst_close)} sessions ({len(rst_close) / total * 100:.0f}%) "
            "closed via RST. Elevated RST rate may indicate: firewall intervention, "
            "aggressive timeout policies, or application errors."
        )

    # What IS reliable
    complete_sessions = total - len(midstream)
    if complete_sessions > 0:
        reliable.append(
            f"Full 3-way handshake observed for {complete_sessions} session(s) — "
            "session establishment is directly confirmed for these."
        )

    dns_stats = getattr(ctx, "dns_stats", {})
    if dns_stats.get("total_queries", 0) > 0:
        reliable.append(
            f"DNS resolution data: {dns_stats['total_queries']} queries, "
            "responses, and error codes are directly observed."
        )

    http_stats = getattr(ctx, "http_stats", {})
    if http_stats.get("total_requests", 0) > 0:
        reliable.append(
            f"HTTP transactions: {http_stats['total_requests']} request/response "
            "pairs with methods, URIs, Host headers, and status codes captured."
        )

    tls_stats = getattr(ctx, "tls_stats", {})
    if tls_stats.get("total_streams", 0) > 0:
        reliable.append(
            f"TLS metadata (SNI, version, JA3 fingerprints) from ClientHello/ServerHello "
            f"for {tls_stats['total_streams']} stream(s). "
            "Note: TLS payload content remains encrypted and is not visible."
        )

    # Inferred (not directly stated)
    if ctx.hosts:
        inferred.append(
            "Host roles (client/server/gateway) — inferred from connection patterns, "
            "not directly stated in traffic"
        )
    if ctx.findings:
        inferred.append(
            "Security finding severity and confidence — rule-based heuristics, "
            "not forensic certainty"
        )
    inferred.append(
        "Protocol identification for sessions without application-layer markers "
        "(DNS/HTTP/TLS) — based on port numbers only"
    )

    # Directly observed
    observed.append("Packet timestamps, IP addresses, TCP/UDP port numbers")
    observed.append("TCP flags (SYN, ACK, FIN, RST, PSH, URG)")
    observed.append("Packet sizes and byte counts per direction")
    if dns_stats.get("total_queries", 0) > 0:
        observed.append("DNS query names, types, and response codes (NOERROR, NXDOMAIN, SERVFAIL)")
    if http_stats.get("total_requests", 0) > 0:
        observed.append("HTTP methods, URIs, Host headers, status codes (cleartext only)")
    if tls_stats.get("total_streams", 0) > 0:
        observed.append(
            "TLS SNI, version negotiation, cipher suites "
            "(TLS application data is encrypted and not visible)"
        )

    return {
        "quality": quality,
        "quality_label": quality_label,
        "issues": issues,
        "reliable": reliable,
        "low_confidence": low_confidence,
        "inferred": inferred,
        "observed": observed,
        "midstream_count": len(midstream),
        "midstream_pct": round(midstream_pct * 100, 1),
        "failed_handshake_count": len(failed_hs),
        "no_close_count": len(no_close),
        "total_sessions": total,
    }


# ── Bullet-point executive summary ───────────────────────────────────────────

def generate_bullet_summary(ctx: CaptureContext) -> List[str]:
    """
    Generate 4–8 investigator-grade bullet points describing what happened.
    Uses only directly observable data; hedges uncertain conclusions explicitly.
    """
    bullets: List[str] = []
    fi = ctx.file_info
    sessions = list(ctx.sessions.values())

    # Capture basics
    if fi.duration_sec > 0:
        bullets.append(
            f"Capture spans {_fmt_dur(fi.duration_sec)} "
            f"({fi.total_packets:,} packets, {_fmt_bytes(fi.file_size_bytes)})."
        )
    else:
        bullets.append(
            f"Capture contains {fi.total_packets:,} packets "
            f"({_fmt_bytes(fi.file_size_bytes)})."
        )

    # Protocol presence summary when no TCP sessions
    if not sessions:
        proto_stats = getattr(ctx, "protocol_stats", {})
        tcp_pkts = proto_stats.get("tcp", 0)
        udp_pkts = proto_stats.get("udp", 0)
        icmp_pkts = proto_stats.get("icmp", 0)
        arp_pkts = proto_stats.get("arp", 0)
        if tcp_pkts > 0:
            bullets.append(
                f"TCP traffic present ({tcp_pkts:,} packets) but no sessions could be "
                "reconstructed from the capture — tcp.stream field was absent in all packets."
            )
        elif udp_pkts > 0:
            bullets.append(
                f"No TCP sessions found. Capture is UDP-dominant ({udp_pkts:,} packets). "
                "TCP session analysis does not apply to this capture."
            )
        elif icmp_pkts or arp_pkts:
            bullets.append(
                f"No TCP/UDP sessions found. Capture contains ICMP/ARP traffic only "
                f"({icmp_pkts:,} ICMP, {arp_pkts:,} ARP packets)."
            )

    # Dominant flow
    if sessions:
        top = max(
            sessions,
            key=lambda s: (s.bytes_sent or 0) + (s.bytes_recv or 0),
            default=None,
        )
        if top:
            total_b = (top.bytes_sent or 0) + (top.bytes_recv or 0)
            if total_b > 0:
                tls_hs = next(
                    (h for h in ctx.tls_handshakes if h.stream_id == top.stream_id),
                    None,
                )
                has_http = any(tx.stream_id == top.stream_id for tx in ctx.http_transactions)
                svc = _service(top.dst_port, has_tls=bool(tls_hs), has_http=has_http)
                dest = tls_hs.sni if (tls_hs and tls_hs.sni) else f"{top.dst_ip}:{top.dst_port}"
                bullets.append(
                    f"Dominant flow: {top.src_ip} → {dest} ({svc}), "
                    f"{_fmt_bytes(total_b)} transferred."
                )

    # Mid-stream warning
    if sessions:
        midstream = [s for s in sessions if not s.has_syn]
        if midstream:
            pct = len(midstream) / len(sessions) * 100
            bullets.append(
                f"{len(midstream)} of {len(sessions)} TCP session(s) ({pct:.0f}%) "
                "are mid-stream — capture began after these sessions were established. "
                "Handshake analysis is unavailable; protocol identification confidence is reduced."
            )

        # Failed connections
        failed = [s for s in sessions if s.has_syn and not s.has_synack]
        if failed:
            bullets.append(
                f"{len(failed)} connection attempt(s) not answered "
                "(SYN sent, no SYN-ACK received) — refused or filtered connections."
            )

    # Security findings
    active = [f for f in ctx.findings if not f.suppressed]
    crit = [f for f in active if str(f.severity).lower() in ("critical", "severity.critical")]
    high = [f for f in active if str(f.severity).lower() in ("high", "severity.high")]

    if crit:
        bullets.append(
            f"{len(crit)} critical security finding(s): "
            f"{'; '.join(f.title for f in crit[:2])}."
        )
    elif high:
        bullets.append(
            f"{len(high)} high-severity finding(s): "
            f"{'; '.join(f.title for f in high[:2])}."
        )
    elif active:
        bullets.append(
            f"{len(active)} security/anomaly finding(s) flagged (none critical)."
        )
    else:
        bullets.append("No security anomalies detected in this capture.")

    # Protocol highlights
    dns_stats = getattr(ctx, "dns_stats", {})
    http_stats = getattr(ctx, "http_stats", {})
    tls_stats = getattr(ctx, "tls_stats", {})

    if dns_stats.get("total_queries", 0) > 0:
        nxd = dns_stats.get("nxdomain_count", 0)
        suffix = f" — {nxd} NXDOMAIN failure(s)" if nxd > 0 else ""
        bullets.append(
            f"DNS: {dns_stats['total_queries']} queries to "
            f"{dns_stats.get('unique_domains', 0)} unique domain(s){suffix}."
        )

    if http_stats.get("total_requests", 0) > 0:
        errs = http_stats.get("error_4xx", 0) + http_stats.get("error_5xx", 0)
        suffix = f", {errs} HTTP error(s)" if errs else ""
        bullets.append(
            f"HTTP: {http_stats['total_requests']} request(s){suffix}."
        )

    if tls_stats.get("deprecated_count", 0) > 0:
        bullets.append(
            f"TLS: {tls_stats['deprecated_count']} connection(s) using deprecated "
            "version (TLS 1.0/1.1) — encryption strength is insufficient."
        )

    return bullets[:8]
