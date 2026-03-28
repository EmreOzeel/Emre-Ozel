"""Security anomaly detection — port scans, ARP spoofing, C2 beaconing, lateral movement."""
from collections import defaultdict
from typing import List, Dict, Any
import math


def analyze(packets: List[Dict]) -> Dict[str, Any]:
    issues = []
    timeline_events = []

    # Port scan detection: src_ip → set of dst_port contacted
    src_to_ports: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    # ARP table: ip → set of MACs seen
    arp_table: Dict[str, set] = defaultdict(set)
    # ICMP flood: src_ip → count
    icmp_counts: Dict[str, int] = defaultdict(int)
    # UDP flood: src_ip → count
    udp_flood: Dict[str, int] = defaultdict(int)
    # Beaconing: (src_ip, dst_ip) → sorted list of timestamps
    beacon_flows: Dict[str, List[float]] = defaultdict(list)
    # RST per src_ip
    rst_per_src: Dict[str, int] = defaultdict(int)
    # SYN per src_ip
    syn_per_src: Dict[str, int] = defaultdict(int)
    # Failed connections (SYN without SYNACK)
    half_open: Dict[str, set] = defaultdict(set)   # src_ip → set of dst:port
    # Track seen SYN-ACK to remove from half-open
    synack_seen: set = set()

    # Lateral movement: RFC1918 → RFC1918 connections to sensitive ports
    lateral_movement: List[Dict] = []
    SENSITIVE_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986, 1433, 3306, 5432, 6379, 27017}

    # C2 interval analysis thresholds
    BEACON_MIN_COUNT = 8
    BEACON_MAX_JITTER = 0.15   # 15% jitter allowed

    def is_private(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            a, b = int(parts[0]), int(parts[1])
            return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168))
        except ValueError:
            return False

    for pkt in packets:
        ts_str = pkt.get("frame.time_epoch", "0")
        try:
            ts = float(ts_str)
        except ValueError:
            ts = 0.0

        src_ip = pkt.get("ip.src", pkt.get("ipv6.src", ""))
        dst_ip = pkt.get("ip.dst", pkt.get("ipv6.dst", ""))

        # ── ARP analysis ──────────────────────────────────────────────────────
        if "arp.opcode" in pkt:
            sender_ip = pkt.get("arp.src.proto_ipv4", "")
            sender_mac = pkt.get("arp.src.hw_mac", "")
            if sender_ip and sender_mac:
                arp_table[sender_ip].add(sender_mac.lower())

        # ── TCP flags analysis ────────────────────────────────────────────────
        if "tcp.flags.syn" in pkt:
            syn = pkt.get("tcp.flags.syn") == "1"
            ack = pkt.get("tcp.flags.ack") == "1"
            rst = pkt.get("tcp.flags.rst") == "1"
            dst_port_str = pkt.get("tcp.dstport", "")
            src_port_str = pkt.get("tcp.srcport", "")

            try:
                dst_port = int(dst_port_str)
            except (ValueError, TypeError):
                dst_port = 0

            if syn and not ack and src_ip and dst_ip:
                syn_per_src[src_ip] += 1
                src_to_ports[src_ip][dst_ip].add(dst_port_str)
                half_open[src_ip].add(f"{dst_ip}:{dst_port_str}")

                # Lateral movement detection
                if is_private(src_ip) and is_private(dst_ip) and dst_port in SENSITIVE_PORTS:
                    lateral_movement.append({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "dst_port": dst_port, "ts": ts,
                    })

            if syn and ack and dst_ip:
                synack_seen.add(f"{src_ip}:{src_port_str}")
                # Remove from half-open
                key = f"{dst_ip}:{dst_port_str}"
                if dst_ip in half_open and key in half_open[dst_ip]:
                    half_open[dst_ip].discard(key)

            if rst and src_ip:
                rst_per_src[src_ip] += 1

        # ── ICMP flood ────────────────────────────────────────────────────────
        if "icmp.type" in pkt and src_ip:
            icmp_type = pkt.get("icmp.type", "")
            if icmp_type == "8":   # Echo request
                icmp_counts[src_ip] += 1

        # ── UDP flood ─────────────────────────────────────────────────────────
        if "udp.srcport" in pkt and src_ip:
            udp_flood[src_ip] += 1

        # ── Beaconing / C2 tracking ───────────────────────────────────────────
        if src_ip and dst_ip and not is_private(dst_ip) and is_private(src_ip):
            flow_key = f"{src_ip}→{dst_ip}"
            beacon_flows[flow_key].append(ts)

    # ── Port scan detection ───────────────────────────────────────────────────
    port_scanners = []
    for src_ip, dst_dict in src_to_ports.items():
        total_ports = sum(len(ports) for ports in dst_dict.values())
        total_dsts = len(dst_dict)
        if total_ports >= 20:
            port_scanners.append({
                "src_ip": src_ip,
                "unique_ports": total_ports,
                "unique_targets": total_dsts,
            })

    if port_scanners:
        port_scanners.sort(key=lambda x: -x["unique_ports"])
        top = port_scanners[0]
        sev = "critical" if top["unique_ports"] >= 100 else "warning"
        issues.append({
            "severity": sev, "category": "security",
            "title": f"Port Scan Detected — {len(port_scanners)} Source(s)",
            "description": (
                f"{len(port_scanners)} source IP(s) contacted an unusually high number of ports. "
                f"Top scanner: {top['src_ip']} contacted {top['unique_ports']} unique ports "
                f"across {top['unique_targets']} targets. "
                "This is a strong indicator of automated port scanning or network reconnaissance."
            ),
            "count": len(port_scanners),
            "examples": [f"{s['src_ip']} ({s['unique_ports']} ports)" for s in port_scanners[:5]],
        })
        for s in port_scanners[:3]:
            timeline_events.append({
                "ts": 0, "type": "port_scan",
                "label": f"Port Scan: {s['src_ip']} ({s['unique_ports']} ports)",
                "detail": f"{s['src_ip']} scanned {s['unique_ports']} ports across {s['unique_targets']} hosts",
                "severity": "critical" if s["unique_ports"] >= 100 else "warning",
            })

    # ── ARP spoofing detection ────────────────────────────────────────────────
    arp_spoof_ips = {ip: macs for ip, macs in arp_table.items() if len(macs) > 1}
    if arp_spoof_ips:
        examples = [f"{ip} ({len(macs)} MACs)" for ip, macs in list(arp_spoof_ips.items())[:3]]
        issues.append({
            "severity": "critical", "category": "security",
            "title": f"ARP Spoofing Detected — {len(arp_spoof_ips)} IP(s)",
            "description": (
                f"{len(arp_spoof_ips)} IP address(es) were seen associated with multiple MAC addresses. "
                "This is the hallmark of ARP cache poisoning / ARP spoofing attacks, "
                "where an attacker intercepts network traffic by poisoning ARP caches. "
                f"Affected IPs: {', '.join(examples)}."
            ),
            "count": len(arp_spoof_ips),
            "examples": examples,
        })
        for ip, macs in list(arp_spoof_ips.items())[:3]:
            timeline_events.append({
                "ts": 0, "type": "arp_spoof",
                "label": f"ARP Spoofing: {ip}",
                "detail": f"{ip} seen with MACs: {', '.join(macs)}",
                "severity": "critical",
            })

    # ── SYN flood detection ───────────────────────────────────────────────────
    syn_flood_srcs = {ip: c for ip, c in syn_per_src.items() if c >= 200}
    if syn_flood_srcs:
        top_syn = sorted(syn_flood_srcs.items(), key=lambda x: -x[1])
        issues.append({
            "severity": "critical", "category": "security",
            "title": f"SYN Flood Attack — {len(syn_flood_srcs)} Source(s)",
            "description": (
                f"{len(syn_flood_srcs)} source(s) sent excessive TCP SYN packets. "
                f"Top: {top_syn[0][0]} sent {top_syn[0][1]} SYNs. "
                "A SYN flood is a DoS attack that exhausts server connection tables "
                "by sending SYN packets without completing the three-way handshake."
            ),
            "count": sum(syn_flood_srcs.values()),
        })

    # ── ICMP flood detection ──────────────────────────────────────────────────
    icmp_flood_srcs = {ip: c for ip, c in icmp_counts.items() if c >= 100}
    if icmp_flood_srcs:
        top_icmp = sorted(icmp_flood_srcs.items(), key=lambda x: -x[1])
        issues.append({
            "severity": "warning", "category": "security",
            "title": f"ICMP Flood — {sum(icmp_flood_srcs.values())} Echo Requests",
            "description": (
                f"Excessive ICMP Echo Requests detected from {len(icmp_flood_srcs)} source(s). "
                f"Top: {top_icmp[0][0]} sent {top_icmp[0][1]} pings. "
                "Could indicate a ping flood DoS attack or network discovery sweep."
            ),
            "count": sum(icmp_flood_srcs.values()),
        })

    # ── C2 Beaconing detection ────────────────────────────────────────────────
    beacon_suspects = []
    for flow_key, timestamps in beacon_flows.items():
        if len(timestamps) < BEACON_MIN_COUNT:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            continue
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1.0:   # Too fast to be beaconing
            continue
        if mean_interval > 3600:  # Too slow
            continue
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        jitter = std_dev / mean_interval if mean_interval > 0 else 1.0
        if jitter <= BEACON_MAX_JITTER:
            src, dst = flow_key.split("→")
            beacon_suspects.append({
                "src_ip": src, "dst_ip": dst,
                "interval_sec": round(mean_interval, 1),
                "jitter": round(jitter, 3),
                "connection_count": len(timestamps),
            })

    if beacon_suspects:
        beacon_suspects.sort(key=lambda x: x["jitter"])
        top_beacon = beacon_suspects[0]
        issues.append({
            "severity": "critical", "category": "security",
            "title": f"Possible C2 Beaconing — {len(beacon_suspects)} Suspicious Flow(s)",
            "description": (
                f"{len(beacon_suspects)} network flows show highly regular connection patterns "
                "consistent with Command & Control (C2) beaconing malware. "
                f"Most regular: {top_beacon['src_ip']} → {top_beacon['dst_ip']} "
                f"connects every ~{top_beacon['interval_sec']}s with only "
                f"{top_beacon['jitter']*100:.1f}% jitter over {top_beacon['connection_count']} connections. "
                "Legitimate applications typically show higher variance."
            ),
            "count": len(beacon_suspects),
            "examples": [
                f"{b['src_ip']}→{b['dst_ip']} every {b['interval_sec']}s"
                for b in beacon_suspects[:3]
            ],
        })
        for b in beacon_suspects[:3]:
            timeline_events.append({
                "ts": 0, "type": "c2_beacon",
                "label": f"C2 Beacon: {b['src_ip']} → {b['dst_ip']}",
                "detail": (
                    f"Regular connection every {b['interval_sec']}s "
                    f"(jitter={b['jitter']*100:.1f}%, count={b['connection_count']})"
                ),
                "severity": "critical",
            })

    # ── Lateral movement ──────────────────────────────────────────────────────
    if len(lateral_movement) >= 5:
        unique_targets = {f"{lm['dst_ip']}:{lm['dst_port']}" for lm in lateral_movement}
        unique_sources = {lm['src_ip'] for lm in lateral_movement}
        sensitive_port_names = {
            22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
            3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS",
            1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
        }
        ports_seen = {lm['dst_port'] for lm in lateral_movement}
        port_names = [sensitive_port_names.get(p, str(p)) for p in ports_seen if p in sensitive_port_names]
        issues.append({
            "severity": "critical", "category": "security",
            "title": "Lateral Movement Detected",
            "description": (
                f"{len(unique_sources)} internal IP(s) attempted connections to "
                f"{len(unique_targets)} internal targets on sensitive administrative ports "
                f"({', '.join(port_names[:5])}). "
                "This pattern is consistent with lateral movement — an attacker pivoting "
                "through internal systems after initial compromise."
            ),
            "count": len(lateral_movement),
            "examples": [
                f"{lm['src_ip']} → {lm['dst_ip']}:{lm['dst_port']}"
                for lm in lateral_movement[:3]
            ],
        })

    return {
        "port_scanners": port_scanners[:20],
        "arp_spoofing": [
            {"ip": ip, "macs": list(macs)} for ip, macs in arp_spoof_ips.items()
        ],
        "syn_flood_sources": [
            {"src_ip": ip, "syn_count": c}
            for ip, c in sorted(syn_flood_srcs.items(), key=lambda x: -x[1])[:10]
        ],
        "icmp_flood_sources": [
            {"src_ip": ip, "count": c}
            for ip, c in sorted(icmp_flood_srcs.items(), key=lambda x: -x[1])[:10]
        ],
        "beacon_suspects": beacon_suspects[:20],
        "lateral_movement": lateral_movement[:50],
        "issues": issues,
        "timeline_events": timeline_events[:200],
    }
