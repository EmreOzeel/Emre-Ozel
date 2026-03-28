"""
Security anomaly detector — port scans, ARP spoofing, SYN/ICMP floods,
C2 beaconing (jitter-based), and lateral movement detection.
Operates on normalized PacketRecord and FlowRecord models.
"""
from __future__ import annotations
import math
import ipaddress
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from models import (
    CaptureContext, Evidence, Severity, Confidence, TimelineEvent,
)
from detection.engine import build_finding, _is_private
from detection.rules import load_rules, get_threshold

_SENSITIVE_PORT_NAMES: Dict[int, str] = {
    22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS",
    445: "SMB", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 5900: "VNC",
}


def _cov(values: List[float]) -> float:
    """Coefficient of variation."""
    if len(values) < 2:
        return 1.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 1.0
    var = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(var) / mean


def analyze(ctx: CaptureContext) -> None:
    config = load_rules()

    # Aggregation structures
    # Port scan: src_ip → set of (dst_ip, dst_port) contacted via SYN
    src_port_contacts: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
    # ARP: ip → set of MACs
    arp_ip_macs: Dict[str, Set[str]] = defaultdict(set)
    # SYN flood: src_ip → syn count
    syn_counts: Dict[str, int] = defaultdict(int)
    # ICMP flood: src_ip → echo req count
    icmp_echo_counts: Dict[str, int] = defaultdict(int)
    # Beaconing: (src, dst) → sorted syn timestamps
    beacon_ts: Dict[str, List[float]] = defaultdict(list)
    # Lateral movement: list of (src, dst, port, ts)
    lateral: List[Dict] = []

    sensitive_ports: Set[int] = set(get_threshold(config, "LAT-001", "sensitive_ports",
                                                   list(_SENSITIVE_PORT_NAMES.keys())))

    for pkt in ctx.packets:
        src, dst = pkt.src_ip, pkt.dst_ip
        if not src or not dst:
            continue

        # ARP spoofing
        if pkt.has_arp:
            sender_ip = pkt.extras.get("arp.src.proto_ipv4", "")
            sender_mac = pkt.extras.get("arp.src.hw_mac", "")
            if sender_ip and sender_mac:
                arp_ip_macs[sender_ip].add(sender_mac.lower())

        # TCP SYN-based detections
        if pkt.tcp_flags_syn and not pkt.tcp_flags_ack:
            syn_counts[src] += 1
            dst_port = pkt.dst_port
            src_port_contacts[src].add((dst, dst_port))

            # C2 beaconing tracking (internal → external only)
            if _is_private(src) and not _is_private(dst):
                flow_key = f"{src}→{dst}"
                beacon_ts[flow_key].append(pkt.ts)

            # Lateral movement
            if _is_private(src) and _is_private(dst) and dst_port in sensitive_ports:
                lateral.append({"src": src, "dst": dst, "port": dst_port, "ts": pkt.ts})

        # ICMP echo request flood
        if pkt.has_icmp and pkt.extras.get("icmp.type") == "8":
            icmp_echo_counts[src] += 1

    # ── Port scan ─────────────────────────────────────────────────────────────
    min_ports = get_threshold(config, "SCAN-001", "min_unique_ports", 20)
    critical_ports = get_threshold(config, "SCAN-001", "critical_at", 100)
    scanners = []
    for src, contacts in src_port_contacts.items():
        if len(contacts) >= min_ports:
            unique_dsts = len({c[0] for c in contacts})
            unique_ports = len({c[1] for c in contacts})
            scanners.append({
                "src_ip": src,
                "unique_ports": unique_ports,
                "unique_targets": unique_dsts,
                "contacts": contacts,
            })
    scanners.sort(key=lambda x: -x["unique_ports"])

    if scanners:
        top = scanners[0]
        sev = Severity.CRITICAL if top["unique_ports"] >= critical_ports else Severity.HIGH
        # First few packet numbers for evidence
        ev_pkts = [
            pkt.num for pkt in ctx.packets
            if pkt.src_ip == top["src_ip"] and pkt.tcp_flags_syn
               and not pkt.tcp_flags_ack
        ][:20]
        ctx.findings.append(build_finding(
            rule_id="SCAN-001",
            severity=sev, confidence=Confidence.HIGH,
            category="reconnaissance",
            title=f"Port Scan Detected — {len(scanners)} Scanner(s)",
            description=(
                f"{len(scanners)} source(s) contacted an unusually high number of ports. "
                f"Top: {top['src_ip']} probed {top['unique_ports']} unique ports "
                f"across {top['unique_targets']} target(s)."
            ),
            explanation=(
                "A host contacting many ports in rapid succession is performing automated "
                "port scanning. Scanners map open services for subsequent exploitation. "
                f"{top['src_ip']} is the most active scanner by port count. "
                "This is a strong indicator of network reconnaissance."
            ),
            possible_causes=[
                "Unauthorized network reconnaissance (external attacker)",
                "Internal security scanner (Nmap, Nessus) — verify authorization",
                "Compromised internal host performing lateral reconnaissance",
                "Automated vulnerability scanner or worm",
            ],
            recommended_actions=[
                "Identify if the source IP is an authorized scanner",
                "Block unauthorized scanning sources at firewall",
                "Deploy IDS/IPS rules for port scan detection (Snort/Suricata)",
                "Investigate source host for compromise if internal",
            ],
            affected_hosts=[top["src_ip"]],
            affected_flows=[],
            evidence=Evidence(
                metrics={
                    "scanner_count": len(scanners),
                    "top_scanner": top["src_ip"],
                    "unique_ports": top["unique_ports"],
                    "unique_targets": top["unique_targets"],
                },
                samples=[f"{top['src_ip']} → port {p}" for _, p in list(top["contacts"])[:10]],
                packet_nums=ev_pkts,
                host_ips=[s["src_ip"] for s in scanners[:5]],
            ),
            mitre_keys=["port_scan"],
        ))
        ctx.timeline.append(TimelineEvent(
            ts=0.0, event_type="port_scan",
            src_ip=top["src_ip"], dst_ip="",
            label=f"Port Scan: {top['src_ip']} ({top['unique_ports']} ports)",
            detail=f"{top['src_ip']} probed {top['unique_ports']} ports on {top['unique_targets']} targets",
            severity=sev, protocol="TCP",
        ))

    # ── ARP spoofing ──────────────────────────────────────────────────────────
    arp_spoof = {ip: macs for ip, macs in arp_ip_macs.items() if len(macs) > 1}
    if arp_spoof:
        spoofed_list = [f"{ip} → {', '.join(macs)}" for ip, macs in list(arp_spoof.items())[:5]]
        ctx.findings.append(build_finding(
            rule_id="ARP-001",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            category="network",
            title=f"ARP Cache Poisoning — {len(arp_spoof)} IP(s) with Multiple MACs",
            description=(
                f"{len(arp_spoof)} IP address(es) advertised with multiple MAC addresses: "
                f"{'; '.join(spoofed_list[:3])}."
            ),
            explanation=(
                "ARP cache poisoning (ARP spoofing) occurs when an attacker sends gratuitous "
                "ARP replies associating their MAC address with another host's IP. "
                "Victims update their ARP caches and send traffic to the attacker, "
                "enabling man-in-the-middle interception of all LAN traffic to that IP. "
                "This is the mechanism behind SSLstrip, credential harvesting, and session hijacking."
            ),
            possible_causes=[
                "Active ARP cache poisoning / MITM attack on the LAN",
                "Legitimate VRRP/HSRP gateway failover (verify with timestamps)",
                "MAC address change after NIC replacement (check timing)",
            ],
            recommended_actions=[
                "Enable Dynamic ARP Inspection (DAI) on managed switches",
                "Implement 802.1X port authentication to prevent rogue devices",
                "Deploy ARP monitoring tools (arpwatch) for alerting",
                "Segment network to limit ARP broadcast domains",
            ],
            affected_hosts=list(arp_spoof.keys()),
            affected_flows=[],
            evidence=Evidence(
                metrics={"poisoned_ip_count": len(arp_spoof)},
                samples=spoofed_list,
                host_ips=list(arp_spoof.keys())[:10],
            ),
            mitre_keys=["arp_spoofing"],
        ))
        for ip in list(arp_spoof.keys())[:3]:
            ctx.timeline.append(TimelineEvent(
                ts=0.0, event_type="arp_spoof",
                src_ip=ip, dst_ip="",
                label=f"ARP Spoofing: {ip}",
                detail=f"{ip} seen with MACs: {', '.join(list(arp_spoof[ip])[:3])}",
                severity=Severity.CRITICAL, protocol="ARP",
            ))

    # ── SYN flood ─────────────────────────────────────────────────────────────
    min_syns = get_threshold(config, "DOS-001", "min_syns_per_src", 200)
    syn_floods = {ip: c for ip, c in syn_counts.items() if c >= min_syns}
    if syn_floods:
        top_syn = sorted(syn_floods.items(), key=lambda x: -x[1])
        ctx.findings.append(build_finding(
            rule_id="DOS-001",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            category="dos",
            title=f"SYN Flood Attack — {sum(syn_floods.values())} SYNs from {len(syn_floods)} Source(s)",
            description=(
                f"{len(syn_floods)} source(s) sent excessive TCP SYN packets. "
                f"Top: {top_syn[0][0]} sent {top_syn[0][1]} SYNs."
            ),
            explanation=(
                "A SYN flood is a denial-of-service attack where the attacker sends a large "
                "number of SYN packets without completing handshakes. Each half-open connection "
                "consumes kernel memory in the connection table until timeout. "
                "Sufficient volume exhausts the table, refusing new legitimate connections."
            ),
            possible_causes=[
                "External SYN flood DoS attack against public-facing server",
                "Spoofed-source SYN flood amplification",
                "Internal compromised host participating in DDoS botnet",
            ],
            recommended_actions=[
                "Enable TCP SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1",
                "Rate-limit new connection SYN packets per source IP at firewall",
                "Reduce tcp_synack_retries: sysctl -w net.ipv4.tcp_synack_retries=2",
                "Consider upstream DDoS mitigation service (Cloudflare, Akamai)",
            ],
            affected_hosts=[ip for ip, _ in top_syn[:5]],
            affected_flows=[],
            evidence=Evidence(
                metrics={
                    "syn_flood_sources": len(syn_floods),
                    "total_syn_packets": sum(syn_floods.values()),
                    "top_sources": {ip: c for ip, c in top_syn[:5]},
                },
                host_ips=[ip for ip, _ in top_syn[:5]],
            ),
            mitre_keys=["dos_syn_flood"],
        ))

    # ── ICMP flood ────────────────────────────────────────────────────────────
    min_icmp = get_threshold(config, "DOS-002", "min_echo_requests", 100)
    icmp_floods = {ip: c for ip, c in icmp_echo_counts.items() if c >= min_icmp}
    if icmp_floods:
        top_icmp = sorted(icmp_floods.items(), key=lambda x: -x[1])
        ctx.findings.append(build_finding(
            rule_id="DOS-002",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            category="dos",
            title=f"ICMP Flood — {sum(icmp_floods.values())} Echo Requests",
            description=(
                f"{len(icmp_floods)} source(s) sent excessive ICMP Echo Requests. "
                f"Top: {top_icmp[0][0]} sent {top_icmp[0][1]} pings."
            ),
            explanation=(
                "A ping flood sends ICMP Echo Requests faster than the target can process. "
                "This consumes both bandwidth and CPU on the target. "
                "High volumes can also indicate ICMP-based network discovery sweeps."
            ),
            possible_causes=[
                "Ping flood DoS attack against target",
                "Network discovery sweep (ping sweep across subnet)",
                "Monitoring system with excessive check intervals",
            ],
            recommended_actions=[
                "Rate-limit ICMP at border firewall",
                "Block ICMP Echo from untrusted sources if not operationally required",
                "For internal sweeps, verify authorization",
            ],
            affected_hosts=[ip for ip, _ in top_icmp[:5]],
            affected_flows=[],
            evidence=Evidence(
                metrics={"icmp_flood_sources": len(icmp_floods),
                         "total_echo_requests": sum(icmp_floods.values())},
                host_ips=[ip for ip, _ in top_icmp[:5]],
            ),
            mitre_keys=["dos_icmp_flood"],
        ))

    # ── C2 beaconing ──────────────────────────────────────────────────────────
    min_conns = get_threshold(config, "C2-001", "min_connections", 8)
    max_jitter = get_threshold(config, "C2-001", "max_jitter", 0.15)
    min_interval = get_threshold(config, "C2-001", "min_interval_sec", 5)
    max_interval = get_threshold(config, "C2-001", "max_interval_sec", 3600)

    beacon_suspects = []
    for flow_key, timestamps in beacon_ts.items():
        if len(timestamps) < min_conns:
            continue
        timestamps_sorted = sorted(timestamps)
        intervals = [timestamps_sorted[i+1] - timestamps_sorted[i]
                     for i in range(len(timestamps_sorted)-1)]
        intervals = [x for x in intervals if min_interval <= x <= max_interval]
        if len(intervals) < min_conns - 1:
            continue
        mean_interval = sum(intervals) / len(intervals)
        jitter = _cov(intervals)
        if jitter <= max_jitter:
            src, dst = flow_key.split("→")
            beacon_suspects.append({
                "src_ip": src, "dst_ip": dst,
                "interval_sec": round(mean_interval, 1),
                "jitter": round(jitter, 3),
                "connection_count": len(timestamps),
                "first_ts": timestamps_sorted[0],
                "last_ts": timestamps_sorted[-1],
            })

    beacon_suspects.sort(key=lambda x: x["jitter"])

    if beacon_suspects:
        top = beacon_suspects[0]
        ctx.findings.append(build_finding(
            rule_id="C2-001",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            category="c2",
            title=f"C2 Beaconing Suspected — {len(beacon_suspects)} Regular Flow(s)",
            description=(
                f"{len(beacon_suspects)} flow(s) show highly regular connection intervals. "
                f"Most regular: {top['src_ip']} → {top['dst_ip']} "
                f"every ~{top['interval_sec']}s (jitter={top['jitter']*100:.1f}%, "
                f"{top['connection_count']} connections)."
            ),
            explanation=(
                "Command & Control (C2) implants typically beacon home at regular intervals "
                "to receive commands or exfiltrate data. Unlike human traffic, C2 beacons "
                "show extremely low variance in connection timing (jitter < 15%). "
                f"The flow {top['src_ip']} → {top['dst_ip']} has only "
                f"{top['jitter']*100:.1f}% jitter over {top['connection_count']} connections — "
                "consistent with automated C2 callback behavior."
            ),
            possible_causes=[
                "Remote Access Trojan (RAT) or implant beaconing to C2 server",
                "Cobalt Strike, Empire, Metasploit stage-0 beaconing",
                "Legitimate monitoring agent with fixed check interval",
                "Scheduled task or cron job making regular network calls",
            ],
            recommended_actions=[
                "Isolate the source host immediately for forensic investigation",
                "Block the destination IP at perimeter firewall",
                "Capture full session content for C2 protocol analysis",
                "Run EDR/AV scan on source host and check for persistence",
                "Submit destination IP to threat intelligence platforms",
            ],
            affected_hosts=[b["src_ip"] for b in beacon_suspects[:5]],
            affected_flows=[f"{b['src_ip']}→{b['dst_ip']}" for b in beacon_suspects[:5]],
            evidence=Evidence(
                metrics={
                    "beacon_count": len(beacon_suspects),
                    "top_beacon_interval_sec": top["interval_sec"],
                    "top_beacon_jitter": top["jitter"],
                    "top_beacon_connections": top["connection_count"],
                },
                samples=[
                    f"{b['src_ip']}→{b['dst_ip']} every {b['interval_sec']}s (jitter={b['jitter']*100:.1f}%)"
                    for b in beacon_suspects[:5]
                ],
                time_first=top["first_ts"],
                time_last=top["last_ts"],
                host_ips=[b["src_ip"] for b in beacon_suspects[:5]],
            ),
            mitre_keys=["c2_beaconing"],
        ))
        ctx.timeline.append(TimelineEvent(
            ts=top["first_ts"], event_type="c2_beacon",
            src_ip=top["src_ip"], dst_ip=top["dst_ip"],
            label=f"C2 Beacon: {top['src_ip']} → {top['dst_ip']}",
            detail=(
                f"Regular callbacks every {top['interval_sec']}s, "
                f"jitter={top['jitter']*100:.1f}%, {top['connection_count']} connections"
            ),
            severity=Severity.CRITICAL, protocol="TCP",
        ))

    # ── Lateral movement ──────────────────────────────────────────────────────
    min_lat = get_threshold(config, "LAT-001", "min_attempts", 5)
    if len(lateral) >= min_lat:
        unique_srcs = {lm["src"] for lm in lateral}
        unique_dsts = {lm["dst"] for lm in lateral}
        ports_used = {lm["port"] for lm in lateral}
        port_names = [_SENSITIVE_PORT_NAMES.get(p, str(p)) for p in ports_used]
        ctx.findings.append(build_finding(
            rule_id="LAT-001",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            category="lateral_movement",
            title=f"Lateral Movement — {len(lateral)} Internal Admin Port Attempts",
            description=(
                f"{len(unique_srcs)} internal host(s) attempted connections to "
                f"{len(unique_dsts)} internal target(s) on sensitive ports: "
                f"{', '.join(port_names[:5])}."
            ),
            explanation=(
                "An attacker who has compromised an internal host typically moves laterally "
                "by probing other internal systems via administrative protocols. "
                "Connections from workstations or servers to SMB (445), RDP (3389), "
                "SSH (22), or database ports on other internal hosts are a strong "
                "indicator of post-exploitation lateral movement."
            ),
            possible_causes=[
                "Attacker pivoting through compromised internal host",
                "Automated worm spreading via SMB (WannaCry, NotPetya pattern)",
                "Penetration tester performing authorized lateral movement testing",
                "Legitimate IT admin using bulk management scripts",
            ],
            recommended_actions=[
                "Implement micro-segmentation: restrict lateral access by role",
                "Deploy host-based firewall rules blocking admin ports between workstations",
                "Enable Windows Firewall and audit successful/failed logon events",
                "Review who initiated traffic from the source host(s)",
                "Check for Pass-the-Hash or Pass-the-Ticket credential abuse",
            ],
            affected_hosts=list(unique_srcs | unique_dsts)[:10],
            affected_flows=[],
            evidence=Evidence(
                metrics={
                    "total_attempts": len(lateral),
                    "unique_sources": len(unique_srcs),
                    "unique_targets": len(unique_dsts),
                    "protocols_targeted": port_names,
                },
                samples=[
                    f"{lm['src']} → {lm['dst']}:{lm['port']} ({_SENSITIVE_PORT_NAMES.get(lm['port'], str(lm['port']))})"
                    for lm in lateral[:10]
                ],
                host_ips=list(unique_srcs)[:5],
                time_first=min(lm["ts"] for lm in lateral),
                time_last=max(lm["ts"] for lm in lateral),
            ),
            mitre_keys=["lateral_movement", "smb_lateral", "rdp_lateral"],
        ))

    # Store security stats
    ctx.security_stats = {
        "port_scanners": [
            {"src_ip": s["src_ip"], "unique_ports": s["unique_ports"],
             "unique_targets": s["unique_targets"]}
            for s in scanners[:20]
        ],
        "arp_spoofing": [{"ip": ip, "macs": list(macs)} for ip, macs in arp_spoof.items()],
        "syn_flood_sources": [{"src_ip": ip, "count": c} for ip, c in sorted(syn_floods.items(), key=lambda x: -x[1])[:10]],
        "icmp_flood_sources": [{"src_ip": ip, "count": c} for ip, c in sorted(icmp_floods.items(), key=lambda x: -x[1])[:10]],
        "beacon_suspects": beacon_suspects[:20],
        "lateral_movement": lateral[:50],
    }
