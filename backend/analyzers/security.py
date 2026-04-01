"""
Security analyzer — detects network-layer attacks by inspecting
ctx.packets (List[PacketRecord]) and ctx.flows (Dict[str, FlowRecord]).

Detects:
  SCAN-001  Port scan (per source IP, >= 20 unique ports via SYN)
  ARP-001   ARP spoofing (same IP → multiple MAC addresses)
  DOS-001   SYN flood (>= 200 SYNs from one source, no ACK)
  DOS-002   ICMP flood (>= 100 echo requests from one source)
  C2-001    C2 beaconing (internal→external, >= 8 SYNs, CoV <= 15%, 5s–3600s intervals)
  LAT-001   Lateral movement (internal→internal SYN to sensitive ports, >= 5 attempts)

Timeline events: port scan detected, ARP spoof detected, C2 beacon detected.
Stats stored in ctx.security_stats.
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from detection.engine import _is_private, build_finding
from detection.rules import get_threshold, load_rules
from models import (
    CaptureContext,
    Confidence,
    Evidence,
    Severity,
    TimelineEvent,
)

# ── Sensitive port definitions ────────────────────────────────────────────────
_SENSITIVE_PORTS: Set[int] = {
    22, 23, 135, 139, 445, 3389, 5985, 5986,
    1433, 3306, 5432, 6379, 27017, 5900,
}
_PORT_NAMES: Dict[int, str] = {
    22:    "SSH",
    23:    "Telnet",
    135:   "RPC",
    139:   "NetBIOS",
    445:   "SMB",
    3389:  "RDP",
    5985:  "WinRM-HTTP",
    5986:  "WinRM-HTTPS",
    1433:  "MSSQL",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    5900:  "VNC",
}


def _cov(values: List[float]) -> float:
    """Coefficient of variation (population std / mean).  Returns inf for degenerate inputs."""
    n = len(values)
    if n < 2:
        return float("inf")
    mean = sum(values) / n
    if mean == 0.0:
        return float("inf")
    variance = sum((x - mean) ** 2 for x in values) / n
    return math.sqrt(variance) / mean


def analyze(ctx: CaptureContext) -> None:
    config = load_rules()

    # ── Configurable thresholds (with hard-coded defaults) ────────────────────
    min_ports_scan   = get_threshold(config, "SCAN-001", "min_unique_ports",  20)
    min_syns_flood   = get_threshold(config, "DOS-001",  "min_syns_per_src",  200)
    min_icmp_flood   = get_threshold(config, "DOS-002",  "min_echo_requests", 100)
    min_beacon_conns = get_threshold(config, "C2-001",   "min_connections",   8)
    max_beacon_jitter= get_threshold(config, "C2-001",   "max_jitter",        0.15)
    min_beacon_iv    = get_threshold(config, "C2-001",   "min_interval_sec",  5)
    max_beacon_iv    = get_threshold(config, "C2-001",   "max_interval_sec",  3600)
    min_lat_attempts = get_threshold(config, "LAT-001",  "min_attempts",      5)
    cfg_sens_ports   = get_threshold(config, "LAT-001",  "sensitive_ports",   None)
    sensitive_ports: Set[int] = set(cfg_sens_ports) if cfg_sens_ports else _SENSITIVE_PORTS

    # ── Per-packet aggregation structures ─────────────────────────────────────

    # SCAN-001: src_ip → {dst_port: first_syn_pkt_num}
    scan_ports: Dict[str, Dict[int, int]] = defaultdict(dict)

    # ARP-001: arp_sender_ip → {mac_address}
    arp_ip_macs: Dict[str, Set[str]] = defaultdict(set)
    # ARP-001: arp_sender_ip → first pkt num seen
    arp_first_pkt: Dict[str, int] = {}

    # DOS-001: src_ip → [pkt_num, ...]   (pure SYNs, no ACK)
    syn_flood_pkts: Dict[str, List[int]] = defaultdict(list)

    # DOS-002: src_ip → [pkt_num, ...]   (ICMP echo request type=8)
    icmp_flood_pkts: Dict[str, List[int]] = defaultdict(list)

    # C2-001: (src_ip, dst_ip) → [(ts, pkt_num), ...]   internal→external SYNs
    beacon_data: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)

    # LAT-001: src_ip → {(dst_ip, dst_port): [pkt_num, ...]}
    lat_data: Dict[str, Dict[Tuple[str, int], List[int]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for pkt in ctx.packets:
        src = pkt.src_ip
        dst = pkt.dst_ip
        if not src or not dst:
            continue

        # ── ARP spoofing ──────────────────────────────────────────────────────
        if pkt.has_arp:
            sender_ip  = pkt.extras.get("arp.src.proto_ipv4", "") or src
            sender_mac = pkt.extras.get("arp.src.hw_mac", "").lower()
            if sender_ip and sender_mac:
                arp_ip_macs[sender_ip].add(sender_mac)
                if sender_ip not in arp_first_pkt:
                    arp_first_pkt[sender_ip] = pkt.num

        # ── TCP SYN (no ACK) — covers scan, flood, beacon, lateral ───────────
        if pkt.ip_proto == 6 and pkt.tcp_flags_syn and not pkt.tcp_flags_ack:
            # SCAN-001: record first pkt per dst_port for this source
            if pkt.dst_port > 0 and pkt.dst_port not in scan_ports[src]:
                scan_ports[src][pkt.dst_port] = pkt.num

            # DOS-001: accumulate all SYN packets per source
            syn_flood_pkts[src].append(pkt.num)

            src_priv = _is_private(src)
            dst_priv = _is_private(dst)

            # C2-001: internal → external
            if src_priv and not dst_priv:
                beacon_data[(src, dst)].append((pkt.ts, pkt.num))

            # LAT-001: internal → internal on sensitive port
            if src_priv and dst_priv and pkt.dst_port in sensitive_ports:
                lat_data[src][(dst, pkt.dst_port)].append(pkt.num)

        # ── ICMP echo request (type 8) ────────────────────────────────────────
        if pkt.has_icmp and pkt.ip_proto == 1 and pkt.extras.get("icmp.type") == "8":
            icmp_flood_pkts[src].append(pkt.num)

    # =========================================================================
    # SCAN-001: Port scan — emit one finding per scanning source IP
    # =========================================================================
    scanners_summary: List[Dict[str, Any]] = []

    for src_ip, port_map in scan_ports.items():
        if len(port_map) < min_ports_scan:
            continue

        sorted_ports   = sorted(port_map.keys())
        # packet_nums of first SYN to each port (ordered by port number)
        ev_pkts        = [port_map[p] for p in sorted_ports]
        sample_strs    = [f"{src_ip}:{p}" for p in sorted_ports[:20]]

        # Determine earliest timestamp for timeline
        pkt_set        = set(ev_pkts[:20])
        first_ts       = min(
            (pkt.ts for pkt in ctx.packets if pkt.num in pkt_set),
            default=0.0,
        )

        sev = (
            Severity.CRITICAL
            if len(port_map) >= get_threshold(config, "SCAN-001", "critical_at", 100)
            else Severity.HIGH
        )

        ctx.timeline.append(TimelineEvent(
            ts=first_ts,
            event_type="port_scan_detected",
            src_ip=src_ip,
            dst_ip="",
            label=f"Port scan from {src_ip} ({len(port_map)} ports)",
            detail=f"First 10 ports: {', '.join(str(p) for p in sorted_ports[:10])}",
            severity=sev,
            packet_num=ev_pkts[0] if ev_pkts else 0,
            protocol="TCP",
        ))

        ctx.findings.append(build_finding(
            rule_id="SCAN-001",
            severity=sev,
            confidence=Confidence.HIGH,
            category="reconnaissance",
            title=f"Port Scan Detected from {src_ip} ({len(port_map)} unique ports)",
            description=(
                f"Source {src_ip} contacted {len(port_map)} unique destination port(s) "
                "via TCP SYN packets, indicating automated port scanning."
            ),
            explanation=(
                "A host contacting a large number of distinct TCP ports in rapid succession "
                "is performing automated port scanning. Port scans are used to enumerate "
                "open services on target hosts, typically as a precursor to exploitation. "
                f"{src_ip} sent SYN packets to {len(port_map)} unique ports across the "
                "observed capture window."
            ),
            confidence_note=(
                f"Confidence is HIGH because the signal is unambiguous: {len(port_map)} "
                "distinct TCP SYN packets from a single source IP, each targeting a "
                "different destination port. False positives are unlikely unless this is "
                "an authorized scanner — verify scheduling."
            ),
            possible_causes=[
                "Unauthorized network reconnaissance (external attacker or compromised host)",
                "Automated network scanner: nmap, masscan, zmap",
                "Authorized internal vulnerability assessment — verify scheduling",
                "Worm or automated malware performing self-propagation discovery",
            ],
            recommended_actions=[
                "Verify whether a scheduled and authorized scan is in progress",
                "Block the source IP at the perimeter firewall if unauthorized",
                "Review firewall logs for the full scope of scanning activity",
                "Correlate with HTTP/TLS findings for follow-on exploitation evidence",
                "Alert SOC for immediate investigation if unauthorized",
            ],
            affected_hosts=[src_ip],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=ev_pkts[:50],
                host_ips=[src_ip],
                time_first=first_ts,
                metrics={
                    "unique_ports_contacted": len(port_map),
                    "port_range_min":         sorted_ports[0],
                    "port_range_max":         sorted_ports[-1],
                    "threshold":              min_ports_scan,
                },
                samples=sample_strs[:20],
            ),
            mitre_keys=["reconnaissance", "active-scanning", "network-service-discovery"],
            tags=["scan", "port-scan", "tcp", "reconnaissance"],
        ))

        scanners_summary.append({
            "src_ip":        src_ip,
            "unique_ports":  len(port_map),
        })

    # =========================================================================
    # ARP-001: ARP spoofing — one finding per conflicted IP address
    # =========================================================================
    arp_spoof_summary: List[Dict[str, Any]] = []

    for ip_addr, macs in arp_ip_macs.items():
        if len(macs) < 2:
            continue

        mac_list   = sorted(macs)
        first_pkt  = arp_first_pkt.get(ip_addr, 0)
        # collect all ARP packet nums for this IP
        arp_pkts   = [
            pkt.num for pkt in ctx.packets
            if pkt.has_arp
            and (pkt.extras.get("arp.src.proto_ipv4", "") or pkt.src_ip) == ip_addr
        ]
        first_ts   = next(
            (pkt.ts for pkt in ctx.packets if pkt.num == first_pkt),
            0.0,
        )

        ctx.timeline.append(TimelineEvent(
            ts=first_ts,
            event_type="arp_spoof_detected",
            src_ip=ip_addr,
            dst_ip="",
            label=f"ARP spoofing: {ip_addr} has {len(macs)} MACs",
            detail=f"MACs: {', '.join(mac_list)}",
            severity=Severity.HIGH,
            packet_num=first_pkt,
            protocol="ARP",
        ))

        ctx.findings.append(build_finding(
            rule_id="ARP-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="network-attack",
            title=f"ARP Spoofing Detected: {ip_addr} claims {len(macs)} MAC Addresses",
            description=(
                f"IP address {ip_addr} was observed with {len(macs)} distinct hardware "
                f"(MAC) addresses in ARP traffic: {', '.join(mac_list)}."
            ),
            explanation=(
                "ARP spoofing (ARP cache poisoning) occurs when an attacker sends forged "
                "ARP replies associating their MAC address with a legitimate IP. Victims "
                "update their caches and forward traffic to the attacker, enabling MitM "
                "interception, session hijacking, and credential capture. Observing "
                "multiple distinct MACs for a single IP is the primary detection signal."
            ),
            confidence_note=(
                f"Confidence is HIGH because the signal is directly observable in packet "
                f"headers: {ip_addr} appeared with {len(macs)} different MAC addresses "
                "in ARP replies. The only benign explanations (VRRP failover, VM migration) "
                "can be verified against network topology."
            ),
            possible_causes=[
                "Active ARP poisoning attack (arpspoof, bettercap, ettercap)",
                "Man-in-the-middle attack targeting LAN traffic",
                "Legitimate VRRP/HSRP gateway failover (verify against topology)",
                "NIC replacement or virtual machine MAC address change",
                "Duplicate IP address misconfiguration",
            ],
            recommended_actions=[
                "Enable Dynamic ARP Inspection (DAI) on managed switches",
                "Verify the network topology to rule out legitimate failover",
                "Identify the legitimate MAC for the IP and block the rogue MAC at the switch",
                "Capture and inspect traffic through the suspected MitM host",
                "Deploy arpwatch or equivalent ARP monitoring for ongoing alerting",
            ],
            affected_hosts=[ip_addr],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=arp_pkts[:50],
                host_ips=[ip_addr],
                time_first=first_ts,
                metrics={
                    "ip_address": ip_addr,
                    "mac_count":  len(macs),
                },
                samples=[f"{ip_addr} → MAC: {mac}" for mac in mac_list],
            ),
            mitre_keys=["credential-access", "adversary-in-the-middle", "arp-cache-poisoning"],
            tags=["arp", "spoofing", "mitm", "layer2"],
        ))

        arp_spoof_summary.append({"ip": ip_addr, "macs": mac_list})

    # =========================================================================
    # DOS-001: SYN flood — one finding per flooding source
    # =========================================================================
    syn_flood_summary: List[Dict[str, Any]] = []

    for src_ip, pkt_list in syn_flood_pkts.items():
        if len(pkt_list) < min_syns_flood:
            continue

        pkt_set  = set(pkt_list[:200])
        ts_vals  = [pkt.ts for pkt in ctx.packets if pkt.num in pkt_set]

        ctx.findings.append(build_finding(
            rule_id="DOS-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="denial-of-service",
            title=f"SYN Flood from {src_ip} ({len(pkt_list)} SYN packets)",
            description=(
                f"Source {src_ip} sent {len(pkt_list)} TCP SYN packets without "
                "completing the three-way handshake, consistent with a SYN flood DoS attack."
            ),
            explanation=(
                "A SYN flood exhausts the target's TCP connection backlog by sending "
                "large volumes of SYN packets and never completing handshakes. Each "
                "half-open connection consumes kernel memory until the SYN timeout "
                "expires. Sufficient volume prevents legitimate clients from connecting."
            ),
            possible_causes=[
                "Deliberate TCP SYN flood denial-of-service attack",
                "Botnet coordinating a volumetric DoS campaign",
                "Spoofed-source SYN packets amplifying the effective rate",
                "Network scanner issuing rapid SYNs (possible false positive)",
            ],
            recommended_actions=[
                "Enable TCP SYN cookies on affected servers",
                "Rate-limit new TCP SYN packets per source IP at the firewall",
                "Reduce tcp_synack_retries to limit half-open connection lifetime",
                "Engage upstream provider or DDoS mitigation service if external",
                "Monitor server connection table utilization and response times",
            ],
            affected_hosts=[src_ip],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=pkt_list[:50],
                host_ips=[src_ip],
                time_first=min(ts_vals) if ts_vals else 0.0,
                time_last=max(ts_vals) if ts_vals else 0.0,
                metrics={
                    "syn_packet_count": len(pkt_list),
                    "threshold":        min_syns_flood,
                },
                samples=[f"SYN from {src_ip} pkt#{n}" for n in pkt_list[:10]],
            ),
            mitre_keys=["impact", "network-denial-of-service", "direct-network-flood"],
            tags=["dos", "syn-flood", "tcp", "denial-of-service"],
        ))

        syn_flood_summary.append({"src_ip": src_ip, "count": len(pkt_list)})

    # =========================================================================
    # DOS-002: ICMP echo flood — one finding per flooding source
    # =========================================================================
    icmp_flood_summary: List[Dict[str, Any]] = []

    for src_ip, pkt_list in icmp_flood_pkts.items():
        if len(pkt_list) < min_icmp_flood:
            continue

        pkt_set  = set(pkt_list[:200])
        ts_vals  = [pkt.ts for pkt in ctx.packets if pkt.num in pkt_set]

        ctx.findings.append(build_finding(
            rule_id="DOS-002",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="denial-of-service",
            title=f"ICMP Echo Flood from {src_ip} ({len(pkt_list)} echo requests)",
            description=(
                f"Source {src_ip} sent {len(pkt_list)} ICMP echo (ping) requests, "
                "consistent with an ICMP flood denial-of-service attack."
            ),
            explanation=(
                "An ICMP flood sends a high volume of echo request packets to saturate "
                "the target's bandwidth or CPU. High-rate ICMP floods can degrade or "
                "completely deny service by consuming all available network or processing "
                "resources on the target host. Very high rates may also indicate a smurf "
                "amplification attack using broadcast addresses."
            ),
            possible_causes=[
                "Ping flood / ICMP DoS attack targeting network availability",
                "Smurf attack exploiting broadcast amplification",
                "Misconfigured monitoring system with excessive polling rate",
                "Network discovery sweep (ping sweep) across a subnet",
            ],
            recommended_actions=[
                "Rate-limit or block inbound ICMP echo requests at the firewall",
                "Verify whether the source is an authorized monitoring system",
                "Enable ICMP rate limiting on the target host OS",
                "Contact upstream provider for traffic filtering if attack is external",
            ],
            affected_hosts=[src_ip],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=pkt_list[:50],
                host_ips=[src_ip],
                time_first=min(ts_vals) if ts_vals else 0.0,
                time_last=max(ts_vals) if ts_vals else 0.0,
                metrics={
                    "icmp_echo_count": len(pkt_list),
                    "threshold":       min_icmp_flood,
                },
                samples=[f"ICMP echo from {src_ip} pkt#{n}" for n in pkt_list[:10]],
            ),
            mitre_keys=["impact", "network-denial-of-service", "direct-network-flood"],
            tags=["dos", "icmp-flood", "icmp", "denial-of-service"],
        ))

        icmp_flood_summary.append({"src_ip": src_ip, "count": len(pkt_list)})

    # =========================================================================
    # C2-001: C2 beaconing — one finding per (src_ip, dst_ip) pair
    # =========================================================================
    beacon_summary: List[Dict[str, Any]] = []

    for (src_ip, dst_ip), entries in beacon_data.items():
        if len(entries) < min_beacon_conns:
            continue

        # Sort by timestamp and extract parallel lists
        entries_sorted  = sorted(entries, key=lambda e: e[0])
        timestamps      = [e[0] for e in entries_sorted]
        pkt_nums        = [e[1] for e in entries_sorted]

        # Compute inter-connection intervals
        intervals = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]

        # Filter to beacon-range intervals only
        valid_iv = [
            iv for iv in intervals
            if min_beacon_iv <= iv <= max_beacon_iv
        ]
        if len(valid_iv) < min_beacon_conns - 1:
            continue

        jitter       = _cov(valid_iv)
        if jitter > max_beacon_jitter:
            continue

        avg_interval = sum(valid_iv) / len(valid_iv)
        conn_count   = len(timestamps)

        ctx.timeline.append(TimelineEvent(
            ts=timestamps[0],
            event_type="c2_beacon_detected",
            src_ip=src_ip,
            dst_ip=dst_ip,
            label=f"C2 beaconing: {src_ip} → {dst_ip}",
            detail=(
                f"connections={conn_count} "
                f"interval={avg_interval:.1f}s "
                f"jitter={jitter:.3f}"
            ),
            severity=Severity.CRITICAL,
            packet_num=pkt_nums[0],
            protocol="TCP",
        ))

        ctx.findings.append(build_finding(
            rule_id="C2-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            category="command-and-control",
            title=(
                f"C2 Beaconing: {src_ip} → {dst_ip} "
                f"(~{avg_interval:.0f}s interval, {jitter:.1%} jitter)"
            ),
            description=(
                f"Internal host {src_ip} made {conn_count} periodic TCP connections "
                f"to external host {dst_ip} with an average interval of "
                f"{avg_interval:.1f}s and a coefficient of variation of {jitter:.3f} "
                f"(threshold ≤ {max_beacon_jitter}), indicating automated C2 beaconing."
            ),
            explanation=(
                "Command-and-control implants beacon to their C2 servers at regular "
                "intervals to check for tasking or exfiltrate data. Unlike human-driven "
                "traffic, beaconing exhibits very low timing variance. A coefficient of "
                "variation (std/mean of inter-connection intervals) below 15% over at "
                "least 8 connections is a reliable statistical indicator of automated "
                "beacon behavior."
            ),
            confidence_note=(
                f"Confidence is MEDIUM because the statistical pattern ({conn_count} "
                f"connections, CoV={jitter:.3f}) is consistent with beaconing but cannot "
                "rule out legitimate heartbeat or monitoring agents. Confirmation requires "
                "process identification on the source host."
            ),
            possible_causes=[
                "Malware implant or RAT beaconing to command-and-control server",
                "Post-exploitation framework (Cobalt Strike, Empire, Metasploit) callback",
                "Legitimate monitoring or heartbeat agent with fixed poll interval",
                "Scheduled task or cron job making regular network requests",
            ],
            recommended_actions=[
                "Immediately isolate the internal host from the network",
                "Block the external destination IP at the perimeter firewall",
                "Collect memory and disk forensics from the beaconing host",
                "Identify the process responsible for the outbound connections",
                "Submit the destination IP/domain to threat intelligence platforms",
                "Initiate incident response and hunt for lateral movement",
            ],
            affected_hosts=[src_ip, dst_ip],
            affected_flows=[f"{src_ip}→{dst_ip}"],
            evidence=Evidence(
                packet_nums=pkt_nums[:50],
                host_ips=[src_ip, dst_ip],
                time_first=timestamps[0],
                time_last=timestamps[-1],
                metrics={
                    "interval_sec":     round(avg_interval, 2),
                    "jitter":           round(jitter, 4),
                    "connection_count": conn_count,
                    "min_interval_sec": round(min(valid_iv), 2),
                    "max_interval_sec": round(max(valid_iv), 2),
                },
                samples=[
                    f"{src_ip} → {dst_ip} interval={iv:.1f}s"
                    for iv in valid_iv[:10]
                ],
            ),
            mitre_keys=["command-and-control", "application-layer-protocol"],
            tags=["c2", "beaconing", "periodic", "malware"],
        ))

        beacon_summary.append({
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "interval_sec":  round(avg_interval, 2),
            "jitter":        round(jitter, 4),
            "connection_count": conn_count,
        })

    # =========================================================================
    # LAT-001: Lateral movement — one finding per internal source IP
    # =========================================================================
    lateral_summary: List[Dict[str, Any]] = []

    for src_ip, targets in lat_data.items():
        # Count total SYN attempts across all (dst, port) pairs
        total_attempts = sum(len(pkts) for pkts in targets.values())
        if total_attempts < min_lat_attempts:
            continue

        all_pkt_nums  = [n for pkts in targets.values() for n in pkts]
        unique_dsts   = list(dict.fromkeys(dst for (dst, _) in targets.keys()))
        ports_hit     = sorted({port for (_, port) in targets.keys()})
        port_labels   = [f"{p}/{_PORT_NAMES.get(p, str(p))}" for p in ports_hit]

        # Build detailed samples: "src→dst:port(SVC) xN pkt#FIRST"
        samples: List[str] = []
        for (dst_ip, dst_port), pkts in sorted(
            targets.items(), key=lambda kv: -len(kv[1])
        )[:20]:
            svc = _PORT_NAMES.get(dst_port, str(dst_port))
            samples.append(
                f"{src_ip} → {dst_ip}:{dst_port} ({svc}) x{len(pkts)} pkt#{pkts[0]}"
            )

        ts_vals = [
            pkt.ts for pkt in ctx.packets
            if pkt.num in set(all_pkt_nums[:200])
        ]

        ctx.findings.append(build_finding(
            rule_id="LAT-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category="lateral-movement",
            title=(
                f"Lateral Movement from {src_ip}: "
                f"{total_attempts} attempts on "
                f"{', '.join(port_labels[:6])}"
            ),
            description=(
                f"Internal host {src_ip} made {total_attempts} TCP SYN attempt(s) to "
                f"sensitive administrative ports ({', '.join(port_labels)}) on "
                f"{len(unique_dsts)} internal host(s), indicating possible lateral movement."
            ),
            explanation=(
                "Lateral movement occurs when an attacker with a foothold on one internal "
                "host probes other internal systems via administrative protocols. Sensitive "
                "ports such as SSH (22), RDP (3389), SMB (445), and database services "
                "are prime pivot targets. Automated probing across multiple internal hosts "
                "strongly suggests post-exploitation tooling or worm-like propagation."
            ),
            possible_causes=[
                "Compromised internal host running automated lateral movement tooling",
                "Ransomware or worm spreading via SMB or RDP (WannaCry, NotPetya pattern)",
                "Post-exploitation framework performing network enumeration",
                "Authorized internal vulnerability scan or penetration test",
                "Misconfigured management agent generating mass connection attempts",
            ],
            recommended_actions=[
                "Immediately isolate the source host and perform forensic analysis",
                "Check for successful authentications from the source on target services",
                "Apply micro-segmentation to restrict lateral admin-port access",
                "Rotate credentials for all services contacted from the source host",
                "Hunt for additional compromised hosts showing similar traffic patterns",
                "Check for Pass-the-Hash, Pass-the-Ticket, or credential dumping",
            ],
            affected_hosts=[src_ip] + unique_dsts[:19],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=all_pkt_nums[:50],
                host_ips=[src_ip] + unique_dsts[:19],
                time_first=min(ts_vals) if ts_vals else 0.0,
                time_last=max(ts_vals) if ts_vals else 0.0,
                metrics={
                    "total_attempts":        total_attempts,
                    "unique_targets":        len(unique_dsts),
                    "sensitive_ports_hit":   ports_hit,
                    "min_attempts_threshold": min_lat_attempts,
                },
                samples=samples[:20],
            ),
            mitre_keys=[
                "lateral-movement",
                "remote-services",
                "network-service-discovery",
            ],
            tags=["lateral-movement", "smb", "rdp", "ssh", "internal-scan"],
        ))

        lateral_summary.append({
            "src_ip":       src_ip,
            "total_attempts": total_attempts,
            "unique_targets": len(unique_dsts),
            "ports":        ports_hit,
        })

    # =========================================================================
    # Store aggregated security stats on the context
    # =========================================================================
    ctx.security_stats = {
        "port_scanners":     scanners_summary,
        "arp_spoofing":      arp_spoof_summary,
        "syn_flood_sources": syn_flood_summary,
        "icmp_flood_sources": icmp_flood_summary,
        "beacon_suspects":   beacon_summary,
        "lateral_movement":  lateral_summary,
    }
