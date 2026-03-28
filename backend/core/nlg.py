"""Natural Language Generation — produces human-readable analyst commentary."""
from typing import Dict, Any, List


def _severity_prefix(sev: str) -> str:
    return {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO"}.get(sev, sev.upper())


def generate_executive_summary(result: Dict[str, Any]) -> str:
    """2-4 sentence executive summary for non-technical stakeholders."""
    lines = []

    file_info = result.get("file_info", {})
    total_pkts = file_info.get("total_packets", 0)
    duration = file_info.get("duration_sec", 0)
    all_issues = result.get("all_issues", [])
    critical = [i for i in all_issues if i.get("severity") == "critical"]
    warnings = [i for i in all_issues if i.get("severity") == "warning"]

    # Opening
    if duration > 0:
        lines.append(
            f"This capture contains {total_pkts:,} packets spanning "
            f"{_format_duration(duration)}."
        )
    else:
        lines.append(f"This capture contains {total_pkts:,} packets.")

    # Risk assessment
    if critical:
        lines.append(
            f"Analysis identified {len(critical)} critical security finding(s) "
            f"requiring immediate attention: {', '.join(i['title'] for i in critical[:2])}."
        )
    elif warnings:
        lines.append(
            f"Analysis found {len(warnings)} warning(s) that should be reviewed: "
            f"{', '.join(i['title'] for i in warnings[:2])}."
        )
    else:
        lines.append("No critical security issues were detected in this capture.")

    # Traffic composition
    protos = result.get("protocol_hierarchy", {})
    if protos:
        top_protos = sorted(protos.items(), key=lambda x: -x[1])[:3]
        lines.append(
            f"Dominant protocols: {', '.join(f'{p} ({c:,} frames)' for p, c in top_protos)}."
        )

    # DNS health
    dns = result.get("dns", {})
    if dns.get("nxdomain_count", 0) >= 10:
        lines.append(
            f"DNS health is degraded with {dns['nxdomain_count']} NXDOMAIN failures."
        )

    return " ".join(lines)


def generate_technical_summary(result: Dict[str, Any]) -> str:
    """Detailed technical summary for network engineers."""
    sections = []

    file_info = result.get("file_info", {})
    total_pkts = file_info.get("total_packets", 0)
    duration = file_info.get("duration_sec", 0)
    file_size = file_info.get("file_size_bytes", 0)

    # File overview
    sections.append(
        f"**Capture Overview**: {total_pkts:,} packets | "
        f"Duration: {_format_duration(duration)} | "
        f"File size: {_format_bytes(file_size)}"
    )

    # TCP health
    tcp = result.get("tcp", {})
    if tcp:
        retrans = tcp.get("retransmissions", 0)
        resets = tcp.get("resets", 0)
        sessions = tcp.get("total_sessions", 0)
        failed = tcp.get("failed_handshakes", 0)
        tcp_line = f"**TCP**: {sessions} sessions, {retrans} retransmissions, {resets} RSTs"
        if failed > 0:
            tcp_line += f", {failed} failed handshakes"
        sections.append(tcp_line)

    # DNS health
    dns = result.get("dns", {})
    if dns.get("total_queries", 0) > 0:
        sections.append(
            f"**DNS**: {dns.get('total_queries', 0):,} queries, "
            f"{dns.get('unique_domains', 0)} unique domains, "
            f"{dns.get('nxdomain_count', 0)} NXDOMAIN, "
            f"{dns.get('servfail_count', 0)} SERVFAIL, "
            f"avg RTT {dns.get('avg_rtt_ms', 0):.1f}ms"
        )

    # HTTP
    http = result.get("http", {})
    if http.get("total_requests", 0) > 0:
        sections.append(
            f"**HTTP**: {http.get('total_requests', 0):,} requests, "
            f"{http.get('error_4xx', 0)} 4xx, {http.get('error_5xx', 0)} 5xx errors, "
            f"avg RTT {http.get('avg_rtt_ms', 0):.0f}ms"
        )

    # TLS
    tls = result.get("tls", {})
    if tls.get("total_tls_streams", 0) > 0:
        tls_line = (
            f"**TLS**: {tls.get('total_tls_streams', 0)} encrypted streams, "
            f"{tls.get('unique_sni', 0)} unique SNI hosts"
        )
        if tls.get("deprecated_version_count", 0) > 0:
            tls_line += f", {tls['deprecated_version_count']} deprecated version connections"
        sections.append(tls_line)

    # Security
    security = result.get("security", {})
    scanners = security.get("port_scanners", [])
    arp_spoof = security.get("arp_spoofing", [])
    beacons = security.get("beacon_suspects", [])
    if scanners or arp_spoof or beacons:
        sec_parts = []
        if scanners:
            sec_parts.append(f"{len(scanners)} port scanner(s)")
        if arp_spoof:
            sec_parts.append(f"{len(arp_spoof)} ARP spoofing incident(s)")
        if beacons:
            sec_parts.append(f"{len(beacons)} potential C2 beacon(s)")
        sections.append(f"**Security Anomalies**: {', '.join(sec_parts)}")

    # All issues summary
    all_issues = result.get("all_issues", [])
    if all_issues:
        critical = sum(1 for i in all_issues if i.get("severity") == "critical")
        warning = sum(1 for i in all_issues if i.get("severity") == "warning")
        sections.append(
            f"**Findings**: {critical} critical, {warning} warning(s) detected across all protocol layers"
        )

    return "\n\n".join(sections)


def generate_findings_narrative(issues: List[Dict]) -> List[Dict]:
    """Enrich issues with analyst narrative."""
    enriched = []
    for issue in issues:
        e = dict(issue)
        # Add recommendation based on category + severity
        cat = issue.get("category", "")
        sev = issue.get("severity", "info")
        title = issue.get("title", "")

        rec = _get_recommendation(cat, title, sev)
        if rec:
            e["recommendation"] = rec

        enriched.append(e)
    return enriched


def _get_recommendation(category: str, title: str, severity: str) -> str:
    title_lower = title.lower()

    if "arp spoof" in title_lower:
        return (
            "Deploy Dynamic ARP Inspection (DAI) on managed switches. "
            "Consider implementing 802.1X port authentication to prevent unauthorized devices."
        )
    if "c2 beacon" in title_lower or "beaconing" in title_lower:
        return (
            "Isolate the source host immediately for forensic analysis. "
            "Block the destination IPs at the firewall and run endpoint malware scans. "
            "Preserve packet captures and logs as evidence."
        )
    if "port scan" in title_lower:
        return (
            "Investigate the scanning source — if internal, check for compromise or authorized scanning. "
            "If external, ensure firewall rules are blocking unnecessary ports. "
            "Consider deploying an IDS/IPS with port scan detection rules."
        )
    if "syn flood" in title_lower:
        return (
            "Enable SYN cookies on affected servers. "
            "Apply rate limiting on the firewall for new connection attempts. "
            "Consider upstream DDoS mitigation if attack is external."
        )
    if "lateral movement" in title_lower:
        return (
            "Segment the network using VLANs and host-based firewalls. "
            "Restrict lateral access to administrative ports (SMB, RDP, SSH) via ACLs. "
            "Enable Windows Firewall and audit successful/failed logon events."
        )
    if "nxdomain" in title_lower:
        return (
            "Investigate hosts generating NXDOMAIN responses for DGA malware infection. "
            "Deploy DNS filtering (e.g., Pi-hole, Umbrella) to block malicious domains."
        )
    if "dns tunnel" in title_lower:
        return (
            "Block or monitor DNS traffic to external resolvers. "
            "Enforce internal DNS-only policy and alert on queries with labels exceeding 40 characters."
        )
    if "ftp" in title_lower and "cleartext" in title_lower:
        return "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS immediately."
    if "deprecated tls" in title_lower or "tls" in title_lower and "deprecated" in title_lower:
        return (
            "Update TLS configuration to require TLSv1.2 minimum, preferably TLSv1.3. "
            "Disable SSLv3, TLSv1.0, and TLSv1.1 in server configuration."
        )
    if "cleartext credential" in title_lower or "plaintext" in title_lower:
        return (
            "Enforce HTTPS for all web authentication. "
            "Implement HSTS (HTTP Strict Transport Security) headers. "
            "Audit all services transmitting credentials over unencrypted channels."
        )
    if "retransmission" in title_lower:
        return (
            "Investigate network path for packet loss using traceroute/MTR. "
            "Check for duplex mismatch, cable issues, or congested links."
        )
    if "slow dns" in title_lower:
        return (
            "Evaluate DNS resolver performance and consider switching to faster resolvers. "
            "Implement DNS caching at the network edge."
        )
    if "snmp" in title_lower:
        return "Upgrade to SNMPv3 with authentication (SHA) and privacy (AES) enabled."
    if "ssh" in title_lower and "sshv1" in title_lower:
        return "Disable SSHv1 in sshd_config: add 'Protocol 2' and restart the SSH service."
    if "kerberos" in title_lower:
        return (
            "Audit Active Directory for misconfigured accounts. "
            "Check for Kerberoasting or AS-REP roasting attack patterns."
        )

    # Default by severity
    if severity == "critical":
        return "Immediate investigation and remediation required."
    if severity == "warning":
        return "Review and remediate during the next maintenance window."
    return ""


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds//60)}m {int(seconds%60)}s"
    else:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"


def _format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024**2:
        return f"{b/1024:.1f} KB"
    elif b < 1024**3:
        return f"{b/1024**2:.1f} MB"
    else:
        return f"{b/1024**3:.2f} GB"
