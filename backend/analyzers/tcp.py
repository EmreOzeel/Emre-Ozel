"""
TCP Analyzer
============
Receives a fully-populated CaptureContext and detects TCP-layer anomalies by
inspecting ctx.packets, ctx.flows, and ctx.sessions.  Results are appended to
ctx.findings and ctx.timeline — nothing is returned.

Detections
----------
TCP-001  High retransmission rate
TCP-002  Zero-window stalls
TCP-003  Failed TCP handshakes (SYN without SYN-ACK)
TCP-004  SYN flood / half-open connections
TCP-005  Asymmetric routing (one-sided flows)
TCP-006  RST flood per source
"""
from __future__ import annotations

import collections
from typing import Dict, List, Tuple

from models import (
    CaptureContext,
    Evidence,
    Severity,
    Confidence,
    TCPState,
    TimelineEvent,
)
from detection.engine import build_finding


# ── Tuning thresholds ─────────────────────────────────────────────────────────

# TCP-001: minimum absolute retransmissions before we even evaluate the rate
_TCP001_MIN_RETRANS: int = 50
# Retransmission rate at which we escalate to CRITICAL
_TCP001_CRITICAL_RATE: float = 0.05   # 5 %

# TCP-002: minimum zero-window events across all sessions
_TCP002_MIN_COUNT: int = 10

# TCP-003: minimum number of failed handshakes (SYN without SYN-ACK)
_TCP003_MIN_FAILED: int = 10

# TCP-004: minimum half-open sessions to flag as a SYN flood
_TCP004_MIN_HALF_OPEN: int = 50

# TCP-005: minimum number of one-sided flows to flag asymmetric routing
_TCP005_MIN_ONE_SIDED: int = 20

# TCP-006: minimum RSTs from a single source IP to flag RST flood
_TCP006_MIN_RST_PER_SRC: int = 100


# ── Helper utilities ──────────────────────────────────────────────────────────

def _first_last(timestamps: List[float]) -> Tuple[float, float]:
    """Return (min, max) of a list of epoch timestamps, or (0.0, 0.0) if empty."""
    if not timestamps:
        return 0.0, 0.0
    return min(timestamps), max(timestamps)


def _sample_strs(items: List[str], limit: int = 10) -> List[str]:
    """Return up to *limit* representative string samples."""
    return items[:limit]


# ── Timeline helpers ──────────────────────────────────────────────────────────

def _add_syn_events(ctx: CaptureContext) -> None:
    """
    Walk every packet and append a TimelineEvent for each TCP SYN
    (but not SYN-ACK) so the timeline shows where connection attempts occur.
    We cap at 500 events to avoid flooding the timeline in SYN-flood scenarios;
    the TCP-004 finding captures the aggregate picture.
    """
    count = 0
    for pkt in ctx.packets:
        if pkt.tcp_flags_syn and not pkt.tcp_flags_ack:
            ctx.timeline.append(
                TimelineEvent(
                    ts=pkt.ts,
                    event_type="tcp_syn",
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    label=f"TCP SYN → {pkt.dst_ip}:{pkt.dst_port}",
                    detail=(
                        f"Stream {pkt.tcp_stream} | "
                        f"pkt#{pkt.num} | seq={pkt.tcp_seq}"
                    ),
                    severity=Severity.INFO,
                    flow_key=pkt.flow_key,
                    packet_num=pkt.num,
                    protocol="TCP",
                )
            )
            count += 1
            if count >= 500:
                break


def _add_rst_events(ctx: CaptureContext) -> None:
    """
    Append a TimelineEvent for each TCP RST packet.
    Capped at 200 events; the TCP-006 finding carries per-source aggregates.
    """
    count = 0
    for pkt in ctx.packets:
        if pkt.tcp_flags_rst:
            ctx.timeline.append(
                TimelineEvent(
                    ts=pkt.ts,
                    event_type="tcp_rst",
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    label=f"TCP RST from {pkt.src_ip}:{pkt.src_port}",
                    detail=(
                        f"Stream {pkt.tcp_stream} | "
                        f"pkt#{pkt.num} | ack={pkt.tcp_flags_ack}"
                    ),
                    severity=Severity.LOW,
                    flow_key=pkt.flow_key,
                    packet_num=pkt.num,
                    protocol="TCP",
                )
            )
            count += 1
            if count >= 200:
                break


# ── Individual detection routines ─────────────────────────────────────────────

def _detect_high_retransmission(ctx: CaptureContext) -> None:
    """
    TCP-001 — High retransmission rate.

    Aggregates retransmission and total packet counts from ctx.flows (which are
    already computed by the normalizer).  If total retransmissions exceed the
    absolute minimum AND the rate exceeds the threshold, we emit a finding.
    Severity escalates from HIGH to CRITICAL above _TCP001_CRITICAL_RATE.
    """
    total_pkts: int = 0
    total_retrans: int = 0
    affected_flows: List[str] = []
    affected_hosts: set = set()
    # Per-flow retransmission counts for evidence metrics
    worst_flows: List[Tuple[float, str]] = []  # (rate, flow_key)
    packet_nums: List[int] = []
    timestamps: List[float] = []

    for flow in ctx.flows.values():
        flow_pkts = flow.total_packets
        flow_retrans = flow.retransmissions
        if flow_pkts == 0:
            continue
        total_pkts += flow_pkts
        total_retrans += flow_retrans
        if flow_retrans > 0:
            rate = flow_retrans / flow_pkts
            worst_flows.append((rate, flow.key))
            affected_flows.append(flow.key)
            affected_hosts.add(flow.src_ip)
            affected_hosts.add(flow.dst_ip)
            packet_nums.extend(flow.packet_nums[:5])
            timestamps.append(flow.first_seen)
            timestamps.append(flow.last_seen)

    if total_retrans < _TCP001_MIN_RETRANS:
        return

    if total_pkts == 0:
        return

    overall_rate = total_retrans / total_pkts
    if overall_rate < 0.01:   # below 1 % is expected noise
        return

    severity = (
        Severity.CRITICAL if overall_rate >= _TCP001_CRITICAL_RATE
        else Severity.HIGH
    )
    confidence = (
        Confidence.HIGH if total_retrans >= 200 else Confidence.MEDIUM
    )

    # Sort worst flows descending by rate; keep top 10 for samples
    worst_flows.sort(key=lambda x: x[0], reverse=True)
    samples = [
        f"flow={fk} retrans_rate={rate:.1%}"
        for rate, fk in worst_flows[:10]
    ]

    time_first, time_last = _first_last(timestamps)

    evidence = Evidence(
        packet_nums=list(dict.fromkeys(packet_nums))[:50],
        flow_keys=affected_flows[:20],
        host_ips=sorted(affected_hosts),
        time_first=time_first,
        time_last=time_last,
        metrics={
            "total_packets": total_pkts,
            "total_retransmissions": total_retrans,
            "overall_rate": round(overall_rate, 4),
            "affected_flow_count": len(affected_flows),
        },
        samples=samples,
    )

    finding = build_finding(
        rule_id="TCP-001",
        severity=severity,
        confidence=confidence,
        category="tcp_performance",
        title=f"High TCP Retransmission Rate ({overall_rate:.1%})",
        description=(
            f"Detected {total_retrans:,} retransmitted packets out of "
            f"{total_pkts:,} total TCP packets ({overall_rate:.1%} rate) "
            f"across {len(affected_flows)} flows."
        ),
        explanation=(
            "Elevated retransmission rates indicate persistent packet loss or "
            "network congestion.  Rates above 5 % degrade throughput "
            "significantly and may indicate an active attack, failing hardware, "
            "or a misconfigured network path.  High retransmission rates can "
            "also mask data exfiltration by fragmenting payloads over many "
            "retransmitted segments."
        ),
        possible_causes=[
            "Network congestion or bandwidth saturation on a bottleneck link",
            "Packet loss caused by faulty cables, switches, or NICs",
            "Firewall or middlebox silently dropping packets mid-stream",
            "TCP offload engine malfunction on a server NIC",
            "Active TCP injection or session hijacking attempt",
            "Asymmetric routing causing out-of-order delivery and spurious retransmits",
        ],
        recommended_actions=[
            "Inspect interface error counters on switches / routers in the affected path",
            "Capture on both ends of the suspect flows to isolate the loss point",
            "Review QoS / policing rules that may be dropping packets",
            "Examine the top offending flows listed in the evidence section",
            "Correlate with TCP-005 (asymmetric routing) if also triggered",
            "Consider enabling TCP selective acknowledgement (SACK) if not already active",
        ],
        affected_hosts=sorted(affected_hosts),
        affected_flows=affected_flows,
        evidence=evidence,
        mitre_keys=[],   # performance issue — no direct MITRE mapping
        tags=["tcp", "retransmission", "performance"],
    )

    ctx.findings.append(finding)


def _detect_zero_window_stalls(ctx: CaptureContext) -> None:
    """
    TCP-002 — Zero-window stalls.

    Counts zero-window advertisements across all sessions.  A session that
    repeatedly advertises a zero receive window causes the sender to stall,
    which is both a performance concern and a potential resource-exhaustion
    indicator.
    """
    total_zw: int = 0
    affected_sessions: List[int] = []
    affected_flows: List[str] = []
    affected_hosts: set = set()
    packet_nums: List[int] = []
    timestamps: List[float] = []
    per_session: List[Tuple[int, int]] = []  # (zero_windows, stream_id)

    for sid, sess in ctx.sessions.items():
        if sess.zero_windows > 0:
            total_zw += sess.zero_windows
            affected_sessions.append(sid)
            affected_flows.append(sess.flow_key)
            affected_hosts.add(sess.src_ip)
            affected_hosts.add(sess.dst_ip)
            packet_nums.extend(sess.packet_nums[:3])
            if sess.syn_ts:
                timestamps.append(sess.syn_ts)
            if sess.last_ts:
                timestamps.append(sess.last_ts)
            per_session.append((sess.zero_windows, sid))

    if total_zw < _TCP002_MIN_COUNT:
        return

    per_session.sort(reverse=True)
    severity = Severity.HIGH if total_zw >= 50 else Severity.MEDIUM
    confidence = Confidence.HIGH if total_zw >= 100 else Confidence.MEDIUM

    samples = [
        f"stream={sid} zero_windows={zw}"
        for zw, sid in per_session[:10]
    ]

    time_first, time_last = _first_last(timestamps)

    evidence = Evidence(
        packet_nums=list(dict.fromkeys(packet_nums))[:50],
        flow_keys=affected_flows[:20],
        host_ips=sorted(affected_hosts),
        time_first=time_first,
        time_last=time_last,
        metrics={
            "total_zero_windows": total_zw,
            "affected_session_count": len(affected_sessions),
        },
        samples=samples,
    )

    finding = build_finding(
        rule_id="TCP-002",
        severity=severity,
        confidence=confidence,
        category="tcp_performance",
        title=f"TCP Zero-Window Stalls Detected ({total_zw} events)",
        description=(
            f"Found {total_zw} zero-window advertisements across "
            f"{len(affected_sessions)} TCP sessions, causing sender stalls."
        ),
        explanation=(
            "A TCP zero-window advertisement occurs when the receiver's buffer "
            "is full and it signals the sender to pause transmission.  "
            "Recurring zero-window events indicate the receiving application is "
            "not consuming data fast enough.  Sustained stalls can be exploited "
            "to hold connections open and exhaust server file-descriptor or "
            "memory resources (a 'slow-read' denial-of-service pattern)."
        ),
        possible_causes=[
            "Receiving application is processing data slower than it arrives",
            "Receiver host under heavy CPU or memory pressure",
            "'Slow-read' DoS attack intentionally throttling the TCP window",
            "Incorrect socket buffer sizes on the receiver",
            "Misconfigured TCP receive window scaling",
        ],
        recommended_actions=[
            "Profile the receiving application for CPU/memory bottlenecks",
            "Review socket buffer sizes (SO_RCVBUF) on affected servers",
            "Check for anomalously long-lived connections from single clients",
            "Enable TCP window scaling if not already active",
            "Consider rate-limiting clients that repeatedly trigger zero-window stalls",
        ],
        affected_hosts=sorted(affected_hosts),
        affected_flows=affected_flows,
        evidence=evidence,
        mitre_keys=[],
        tags=["tcp", "zero-window", "dos", "performance"],
    )

    ctx.findings.append(finding)


def _detect_failed_handshakes(ctx: CaptureContext) -> None:
    """
    TCP-003 — Failed TCP handshakes (SYN without SYN-ACK).

    A session that has a SYN but no SYN-ACK either timed out before the
    response arrived in the capture, or the destination is unreachable /
    actively rejecting the connection.  A large count may indicate a port scan,
    a misconfigured firewall, or a host that is offline.
    """
    failed_sessions: List[int] = []
    affected_flows: List[str] = []
    affected_hosts: set = set()
    packet_nums: List[int] = []
    timestamps: List[float] = []
    # Count failed handshakes per destination IP
    dest_counts: Dict[str, int] = collections.Counter()

    for sid, sess in ctx.sessions.items():
        if sess.has_syn and not sess.has_synack:
            failed_sessions.append(sid)
            affected_flows.append(sess.flow_key)
            affected_hosts.add(sess.src_ip)
            affected_hosts.add(sess.dst_ip)
            packet_nums.extend(sess.packet_nums[:2])
            if sess.syn_ts:
                timestamps.append(sess.syn_ts)
            dest_counts[sess.dst_ip] += 1

    if len(failed_sessions) < _TCP003_MIN_FAILED:
        return

    severity = Severity.HIGH if len(failed_sessions) >= 50 else Severity.MEDIUM
    confidence = Confidence.HIGH if len(failed_sessions) >= 100 else Confidence.MEDIUM

    top_dests = sorted(dest_counts.items(), key=lambda x: x[1], reverse=True)
    samples = [
        f"dst={ip} failed_syns={cnt}"
        for ip, cnt in top_dests[:10]
    ]

    time_first, time_last = _first_last(timestamps)

    evidence = Evidence(
        packet_nums=list(dict.fromkeys(packet_nums))[:50],
        flow_keys=affected_flows[:20],
        host_ips=sorted(affected_hosts),
        time_first=time_first,
        time_last=time_last,
        metrics={
            "failed_handshake_count": len(failed_sessions),
            "unique_destinations": len(dest_counts),
            "top_targeted_dest": top_dests[0][0] if top_dests else "",
        },
        samples=samples,
    )

    finding = build_finding(
        rule_id="TCP-003",
        severity=severity,
        confidence=confidence,
        category="tcp_handshake",
        title=f"Failed TCP Handshakes ({len(failed_sessions)} SYNs without SYN-ACK)",
        description=(
            f"Detected {len(failed_sessions)} TCP connections where a SYN was "
            f"sent but no SYN-ACK was observed, targeting "
            f"{len(dest_counts)} distinct destination IPs."
        ),
        explanation=(
            "Failed handshakes can result from port scans, misconfigured "
            "firewalls, offline hosts, or aggressive connection attempts.  "
            "A concentrated burst to many destinations is a classic indicator "
            "of horizontal port scanning.  Bursts to a single destination "
            "suggest vertical (port) scanning or a SYN flood targeting that "
            "specific host."
        ),
        possible_causes=[
            "Network or port scanner (e.g., nmap, masscan) enumerating hosts",
            "Firewall dropping inbound SYN-ACK responses",
            "Target hosts are offline or ports are filtered",
            "Half-open SYN flood attack exhausting target connection tables",
            "Capture started mid-handshake for legitimate long-lived connections",
        ],
        recommended_actions=[
            "Identify the source IP(s) initiating the most failed connections",
            "Correlate with TCP-004 to determine if a SYN flood is in progress",
            "Review firewall rules for asymmetric paths that drop SYN-ACK",
            "Check IDS/IPS logs for contemporaneous scan signatures",
            "Block or rate-limit scanning source IPs at the perimeter",
        ],
        affected_hosts=sorted(affected_hosts),
        affected_flows=affected_flows,
        evidence=evidence,
        mitre_keys=["port_scan"],
        tags=["tcp", "handshake", "scan", "syn"],
    )

    ctx.findings.append(finding)


def _detect_syn_flood(ctx: CaptureContext) -> None:
    """
    TCP-004 — SYN flood / half-open connections.

    Counts sessions whose state is TCPState.HALF_OPEN (SYN sent, SYN-ACK
    received but no ACK completing the handshake) or sessions that only ever
    had a SYN and are classified as HALF_OPEN by the normalizer.  A large
    population of half-open sessions exhausts server connection-table resources.
    """
    half_open: List[int] = []
    affected_flows: List[str] = []
    affected_hosts: set = set()
    packet_nums: List[int] = []
    timestamps: List[float] = []
    # Count half-open connections per source IP
    src_counts: Dict[str, int] = collections.Counter()

    for sid, sess in ctx.sessions.items():
        if sess.state == TCPState.HALF_OPEN:
            half_open.append(sid)
            affected_flows.append(sess.flow_key)
            affected_hosts.add(sess.src_ip)
            affected_hosts.add(sess.dst_ip)
            packet_nums.extend(sess.packet_nums[:2])
            if sess.syn_ts:
                timestamps.append(sess.syn_ts)
            src_counts[sess.src_ip] += 1

    if len(half_open) < _TCP004_MIN_HALF_OPEN:
        return

    severity = Severity.CRITICAL if len(half_open) >= 200 else Severity.HIGH
    confidence = Confidence.HIGH if len(half_open) >= 200 else Confidence.MEDIUM

    top_srcs = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)
    samples = [
        f"src={ip} half_open={cnt}"
        for ip, cnt in top_srcs[:10]
    ]

    time_first, time_last = _first_last(timestamps)

    evidence = Evidence(
        packet_nums=list(dict.fromkeys(packet_nums))[:50],
        flow_keys=affected_flows[:20],
        host_ips=sorted(affected_hosts),
        time_first=time_first,
        time_last=time_last,
        metrics={
            "half_open_count": len(half_open),
            "unique_sources": len(src_counts),
            "top_source": top_srcs[0][0] if top_srcs else "",
            "top_source_half_open": top_srcs[0][1] if top_srcs else 0,
        },
        samples=samples,
    )

    finding = build_finding(
        rule_id="TCP-004",
        severity=severity,
        confidence=confidence,
        category="tcp_flood",
        title=f"SYN Flood / Half-Open Connection Surge ({len(half_open)} sessions)",
        description=(
            f"Detected {len(half_open)} half-open TCP sessions.  "
            f"{len(src_counts)} distinct source IPs contributed to this surge."
        ),
        explanation=(
            "A SYN flood attack sends large volumes of TCP SYN packets, "
            "consuming server connection-table (backlog queue) entries without "
            "completing handshakes.  The server allocates state for each "
            "half-open connection and eventually exhausts memory, refusing "
            "legitimate connections.  Spoofed source IPs are common in "
            "volumetric SYN floods, but botnets also use real addresses."
        ),
        possible_causes=[
            "Volumetric SYN flood denial-of-service attack (spoofed or real IPs)",
            "Botnet-coordinated TCP flood targeting the destination server",
            "Aggressive TCP port scanner consuming connection resources",
            "Misconfigured load balancer sending SYNs without completing handshakes",
            "One-arm capture topology where only inbound SYNs are visible",
        ],
        recommended_actions=[
            "Enable TCP SYN cookies on the target server to handle half-open state",
            "Configure rate limiting for SYN packets at the upstream firewall or router",
            "Contact upstream ISP to apply upstream scrubbing if attack is volumetric",
            "Deploy a DDoS mitigation appliance or cloud scrubbing service",
            "Verify source IPs are spoofed (TTL uniformity, geographic diversity)",
        ],
        affected_hosts=sorted(affected_hosts),
        affected_flows=affected_flows,
        evidence=evidence,
        mitre_keys=["dos_syn_flood"],
        tags=["tcp", "syn-flood", "dos", "half-open"],
    )

    ctx.findings.append(finding)


def _detect_asymmetric_routing(ctx: CaptureContext) -> None:
    """
    TCP-005 — Asymmetric routing / one-sided flows.

    A flow is 'one-sided' when all packets travel in a single direction:
    either fwd_packets > 0 and rev_packets == 0, or vice versa.  When many
    flows share this property it likely indicates an asymmetric capture path
    (a common false-positive source) but also appears in scanning, reflection
    attacks, and MITM scenarios where return traffic is dropped.
    """
    one_sided: List[str] = []
    affected_hosts: set = set()
    packet_nums: List[int] = []
    timestamps: List[float] = []
    # Count one-sided flows per source
    src_counts: Dict[str, int] = collections.Counter()

    for flow in ctx.flows.values():
        fwd = flow.fwd_packets
        rev = flow.rev_packets
        if (fwd > 0 and rev == 0) or (fwd == 0 and rev > 0):
            one_sided.append(flow.key)
            affected_hosts.add(flow.src_ip)
            affected_hosts.add(flow.dst_ip)
            packet_nums.extend(flow.packet_nums[:2])
            timestamps.append(flow.first_seen)
            timestamps.append(flow.last_seen)
            src_counts[flow.src_ip] += 1

    if len(one_sided) < _TCP005_MIN_ONE_SIDED:
        return

    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM  # asymmetric capture is a common benign cause

    top_srcs = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)
    samples = [
        f"src={ip} one_sided_flows={cnt}"
        for ip, cnt in top_srcs[:10]
    ]

    time_first, time_last = _first_last(timestamps)

    evidence = Evidence(
        packet_nums=list(dict.fromkeys(packet_nums))[:50],
        flow_keys=one_sided[:20],
        host_ips=sorted(affected_hosts),
        time_first=time_first,
        time_last=time_last,
        metrics={
            "one_sided_flow_count": len(one_sided),
            "unique_sources": len(src_counts),
            "total_flows": len(ctx.flows),
            "one_sided_ratio": round(len(one_sided) / max(len(ctx.flows), 1), 4),
        },
        samples=samples,
    )

    finding = build_finding(
        rule_id="TCP-005",
        severity=severity,
        confidence=confidence,
        category="tcp_routing",
        title=f"Asymmetric Routing / One-Sided Flows ({len(one_sided)} flows)",
        description=(
            f"Found {len(one_sided)} TCP flows where packets travel in only "
            f"one direction ({len(one_sided)/max(len(ctx.flows),1):.1%} of all "
            f"flows), suggesting an asymmetric capture path or routing anomaly."
        ),
        explanation=(
            "One-sided flows arise when the capture point only sees traffic in "
            "one direction.  This can be a benign artifact of asymmetric routing "
            "or a tap positioned on only one side of a link.  However, a sudden "
            "increase in one-sided flows can also indicate traffic black-holing, "
            "ACL-based drop storms, or an adversary intercepting return traffic "
            "on a different path."
        ),
        possible_causes=[
            "Capture interface positioned on an asymmetric routing path",
            "Firewall or ACL silently dropping return traffic",
            "ECMP or policy-based routing sending return traffic via a different link",
            "Network tap or SPAN port misconfiguration",
            "Active traffic interception or MITM on the return path",
        ],
        recommended_actions=[
            "Verify capture collection point covers both directions of suspect flows",
            "Check routing tables for asymmetric return paths",
            "Compare ingress vs. egress byte counts on intermediate routers",
            "Correlate with TCP-003 to determine if failed handshakes are related",
            "If one-sided flows are from a single source, investigate for exfiltration",
        ],
        affected_hosts=sorted(affected_hosts),
        affected_flows=one_sided,
        evidence=evidence,
        mitre_keys=[],
        tags=["tcp", "asymmetric", "routing", "one-sided"],
    )

    ctx.findings.append(finding)


def _detect_rst_flood(ctx: CaptureContext) -> None:
    """
    TCP-006 — RST flood per source.

    Counts RST packets per source IP.  A single host sending hundreds of RSTs
    is abnormal and may indicate a TCP reset attack (used for session
    hijacking, censorship injection, or IDS evasion) or a scanning tool.
    """
    # Count RSTs per source IP and collect evidence
    rst_by_src: Dict[str, int] = collections.Counter()
    packets_by_src: Dict[str, List[int]] = collections.defaultdict(list)
    timestamps_by_src: Dict[str, List[float]] = collections.defaultdict(list)
    flows_by_src: Dict[str, set] = collections.defaultdict(set)

    for pkt in ctx.packets:
        if pkt.tcp_flags_rst:
            rst_by_src[pkt.src_ip] += 1
            packets_by_src[pkt.src_ip].append(pkt.num)
            timestamps_by_src[pkt.src_ip].append(pkt.ts)
            flows_by_src[pkt.src_ip].add(pkt.flow_key)

    # Keep only sources that exceed the threshold
    flooding_srcs = {
        ip: cnt for ip, cnt in rst_by_src.items()
        if cnt >= _TCP006_MIN_RST_PER_SRC
    }

    if not flooding_srcs:
        return

    total_rsts = sum(flooding_srcs.values())
    affected_hosts: set = set(flooding_srcs.keys())
    affected_flows: List[str] = []
    for ip in flooding_srcs:
        affected_flows.extend(list(flows_by_src[ip])[:5])

    all_packet_nums: List[int] = []
    all_timestamps: List[float] = []
    for ip in flooding_srcs:
        all_packet_nums.extend(packets_by_src[ip][:10])
        all_timestamps.extend(timestamps_by_src[ip])

    severity = Severity.HIGH if total_rsts >= 500 else Severity.MEDIUM
    confidence = Confidence.HIGH

    top_srcs = sorted(flooding_srcs.items(), key=lambda x: x[1], reverse=True)
    samples = [
        f"src={ip} rst_count={cnt}"
        for ip, cnt in top_srcs[:10]
    ]

    time_first, time_last = _first_last(all_timestamps)

    evidence = Evidence(
        packet_nums=list(dict.fromkeys(all_packet_nums))[:50],
        flow_keys=list(dict.fromkeys(affected_flows))[:20],
        host_ips=sorted(affected_hosts),
        time_first=time_first,
        time_last=time_last,
        metrics={
            "total_rsts_from_flooding_sources": total_rsts,
            "flooding_source_count": len(flooding_srcs),
            "top_source": top_srcs[0][0] if top_srcs else "",
            "top_source_rst_count": top_srcs[0][1] if top_srcs else 0,
        },
        samples=samples,
    )

    finding = build_finding(
        rule_id="TCP-006",
        severity=severity,
        confidence=confidence,
        category="tcp_reset",
        title=f"TCP RST Flood Detected ({len(flooding_srcs)} sources, {total_rsts} RSTs)",
        description=(
            f"Detected {len(flooding_srcs)} source IP(s) each sending "
            f">= {_TCP006_MIN_RST_PER_SRC} RST packets; {total_rsts:,} RSTs "
            f"in total from these sources."
        ),
        explanation=(
            "A high volume of TCP RST packets from one or more sources can "
            "forcibly terminate active sessions.  TCP reset attacks are used "
            "by adversaries to disrupt communications, evade IDS by tearing "
            "down monitored sessions, or inject spoofed RSTs to kill legitimate "
            "connections (e.g., the 'TCP Reset Attack').  Firewalls and "
            "intrusion-prevention systems can also generate RSTs as part of "
            "inline blocking, which may produce a similar signature."
        ),
        possible_causes=[
            "TCP reset injection attack targeting active sessions",
            "Inline IPS/firewall generating RSTs to block policy-violating flows",
            "Network scanner (nmap -sT) completing scans with RST teardowns",
            "Buggy application or load balancer closing connections abnormally",
            "Anti-spoofing device injecting RSTs in response to forged traffic",
        ],
        recommended_actions=[
            "Identify if the RST-sending IPs are internal security appliances (IPS/FW)",
            "Verify RST sequence numbers are valid for existing sessions (spoof check)",
            "Review session state on servers targeted by the RSTs",
            "Enable TCP RST rate limiting on perimeter devices if not already set",
            "Investigate whether sessions broken by RSTs correlate with data exfiltration",
        ],
        affected_hosts=sorted(affected_hosts),
        affected_flows=list(dict.fromkeys(affected_flows)),
        evidence=evidence,
        mitre_keys=["port_scan"],
        tags=["tcp", "rst-flood", "injection", "dos"],
    )

    ctx.findings.append(finding)


# ── Public entry point ────────────────────────────────────────────────────────

def analyze(ctx: CaptureContext) -> None:
    """
    Run all TCP detection rules against *ctx* and append results.

    Order of operations:
    1. Populate timeline with SYN and RST events (background context).
    2. Run each detection rule in priority order.

    All mutations are append-only: ctx.findings and ctx.timeline are extended,
    never replaced.
    """
    # Populate timeline with raw SYN / RST events first so they appear even if
    # no threshold-level findings are generated.
    _add_syn_events(ctx)
    _add_rst_events(ctx)

    # Run detections in descending severity order so critical items are
    # evaluated before medium ones (each rule is independent, but ordering
    # makes the log easier to follow when debug prints are added later).
    _detect_syn_flood(ctx)           # TCP-004 (CRITICAL potential)
    _detect_rst_flood(ctx)           # TCP-006 (HIGH potential)
    _detect_failed_handshakes(ctx)   # TCP-003 (HIGH potential)
    _detect_high_retransmission(ctx) # TCP-001 (CRITICAL potential)
    _detect_zero_window_stalls(ctx)  # TCP-002 (HIGH potential)
    _detect_asymmetric_routing(ctx)  # TCP-005 (MEDIUM potential)
