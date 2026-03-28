"""
Host profiling — infers behavioral profiles from normalized flows and packets.
Determines likely role, top peers, protocol usage, connection ratios,
beaconing periodicity, and anomaly score.
"""
from __future__ import annotations
import math
import ipaddress
from collections import defaultdict
from typing import Dict, List, Tuple, Set

from models import (
    CaptureContext, HostProfile, HostRole, FlowRecord, PacketRecord,
)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _infer_role(profile: HostProfile, server_ports: Set[int]) -> HostRole:
    """Infer host role from connection patterns."""
    # Server: accepts more connections than it initiates
    if profile.tcp_sessions_accepted > profile.tcp_sessions_initiated * 2:
        if 53 in server_ports:
            return HostRole.DNS_RESOLVER
        if any(p in server_ports for p in (25, 465, 587)):
            return HostRole.MAIL_SERVER
        if any(p in server_ports for p in (80, 443, 8080, 8443)):
            return HostRole.WEB_SERVER
        return HostRole.SERVER

    # Gateway: high unique peer count + mix of inbound/outbound
    if profile.unique_peers > 20 and profile.bytes_sent > 0 and profile.bytes_recv > 0:
        ratio = profile.bytes_sent / max(profile.bytes_recv, 1)
        if 0.5 < ratio < 2.0:
            return HostRole.GATEWAY

    return HostRole.CLIENT


def _coefficient_of_variation(values: List[float]) -> float:
    """Returns CoV = std_dev / mean. Returns 1.0 for empty or zero-mean."""
    if len(values) < 2:
        return 1.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 1.0
    var = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(var) / mean


def _detect_periodicity(timestamps: List[float]) -> Tuple[float, float]:
    """
    Detect if a host has regular connection intervals.
    Returns (interval_sec, jitter_cov). interval=0 means not periodic.
    """
    if len(timestamps) < 8:
        return 0.0, 1.0
    timestamps = sorted(timestamps)
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    intervals = [x for x in intervals if 1.0 <= x <= 7200]
    if len(intervals) < 4:
        return 0.0, 1.0
    mean_interval = sum(intervals) / len(intervals)
    cov = _coefficient_of_variation(intervals)
    if cov <= 0.20:
        return round(mean_interval, 2), round(cov, 3)
    return 0.0, round(cov, 3)


def build_profiles(ctx: CaptureContext) -> None:
    """
    Build HostProfile for every IP seen in flows.
    Attaches profiles to ctx.hosts.
    """
    profiles: Dict[str, HostProfile] = {}
    # peer_bytes[ip][peer] = bytes
    peer_bytes: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # protocols[ip][proto] = count
    proto_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # connection timestamps: ip → list of first_seen timestamps
    conn_ts: Dict[str, List[float]] = defaultdict(list)
    # server ports per IP (ports on which it accepted connections)
    server_ports: Dict[str, Set[int]] = defaultdict(set)
    # SYN counts (ip → (initiated, accepted, failed))
    syn_init: Dict[str, int] = defaultdict(int)
    syn_accept: Dict[str, int] = defaultdict(int)
    syn_fail: Dict[str, int] = defaultdict(int)

    def ensure(ip: str) -> HostProfile:
        if ip not in profiles:
            profiles[ip] = HostProfile(ip=ip, is_internal=_is_private(ip))
        return profiles[ip]

    # Process sessions
    for sess in ctx.sessions.values():
        src, dst = sess.src_ip, sess.dst_ip
        if not src or not dst:
            continue
        ensure(src)
        ensure(dst)

        # Sender (initiator) stats
        profiles[src].bytes_sent += sess.bytes_sent
        profiles[src].packets_sent += sess.packets_sent
        profiles[dst].bytes_recv += sess.bytes_recv
        profiles[dst].packets_recv += sess.packets_recv

        peer_bytes[src][dst] += sess.bytes_sent
        peer_bytes[dst][src] += sess.bytes_recv

        if sess.has_syn:
            syn_init[src] += 1
            conn_ts[src].append(sess.syn_ts)
        if sess.has_synack:
            syn_accept[dst] += 1
            server_ports[dst].add(sess.dst_port)
        if sess.has_syn and not sess.has_synack:
            syn_fail[src] += 1

    # Process flows for protocol stats
    for fl in ctx.flows.values():
        src, dst = fl.src_ip, fl.dst_ip
        ensure(src)
        ensure(dst)
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(fl.proto, str(fl.proto))
        if fl.has_dns:
            proto_name = "DNS"
        elif fl.has_http:
            proto_name = "HTTP"
        elif fl.has_tls:
            proto_name = "TLS"
        proto_counts[src][proto_name] += fl.fwd_packets
        proto_counts[dst][proto_name] += fl.rev_packets

    # Process ARP for MACs
    for pkt in ctx.packets:
        if pkt.has_arp:
            sender_ip = pkt.extras.get("arp.src.proto_ipv4", "")
            sender_mac = pkt.extras.get("arp.src.hw_mac", "")
            if sender_ip:
                p = ensure(sender_ip)
                if sender_mac and not p.mac:
                    p.mac = sender_mac

    # Finalize profiles
    for ip, profile in profiles.items():
        profile.tcp_sessions_initiated = syn_init.get(ip, 0)
        profile.tcp_sessions_accepted = syn_accept.get(ip, 0)
        profile.tcp_sessions_failed = syn_fail.get(ip, 0)
        profile.unique_peers = len(peer_bytes[ip])
        profile.protocols = dict(proto_counts[ip])

        # Top peers
        peers_sorted = sorted(peer_bytes[ip].items(), key=lambda x: -x[1])[:10]
        profile.top_peers = peers_sorted

        # Role inference
        profile.role = _infer_role(profile, server_ports.get(ip, set()))
        profile.open_ports = sorted(server_ports.get(ip, set()))

        # Connection timestamp periodicity
        profile.connection_timestamps = sorted(conn_ts.get(ip, []))[:500]
        interval, jitter = _detect_periodicity(profile.connection_timestamps)
        profile.periodic_interval_sec = interval
        profile.periodic_jitter = jitter

        # Anomaly scoring (0-10)
        score = 0.0
        behaviors = []

        # Periodic external connection = strong anomaly
        if interval > 0 and not _is_private(ip):
            pass   # external server being beaconed TO isn't anomalous
        if interval > 0 and _is_private(ip):
            score += 3.0
            behaviors.append(f"Periodic connections every ~{interval:.0f}s (jitter={jitter:.2f})")

        # Scanning: many unique ports contacted
        if profile.unique_dst_ports > 50:
            score += 3.0
            behaviors.append(f"Contacted {profile.unique_dst_ports} unique destination ports")

        # High failure rate
        total = profile.tcp_sessions_initiated + profile.tcp_sessions_failed
        if total > 10:
            fail_rate = profile.tcp_sessions_failed / total
            if fail_rate > 0.5:
                score += 2.0
                behaviors.append(f"High connection failure rate ({fail_rate*100:.0f}%)")

        # Internal host initiating many outbound non-web connections
        if _is_private(ip) and profile.tcp_sessions_initiated > 50:
            non_web = sum(
                v for k, v in proto_counts[ip].items()
                if k not in ("HTTP", "TLS", "DNS")
            )
            if non_web > profile.tcp_sessions_initiated * 0.5:
                score += 1.5
                behaviors.append("Unusual non-web outbound connection mix")

        profile.anomaly_score = min(score, 10.0)
        profile.suspicious_behaviors = behaviors

    # Unique port counts from packets
    dst_port_counts: Dict[str, Set[int]] = defaultdict(set)
    src_port_counts: Dict[str, Set[int]] = defaultdict(set)
    for pkt in ctx.packets:
        if pkt.src_ip and pkt.dst_port:
            dst_port_counts[pkt.src_ip].add(pkt.dst_port)
        if pkt.dst_ip and pkt.src_port:
            src_port_counts[pkt.dst_ip].add(pkt.src_port)

    for ip, profile in profiles.items():
        profile.unique_dst_ports = len(dst_port_counts.get(ip, set()))
        profile.unique_src_ports = len(src_port_counts.get(ip, set()))

    ctx.hosts = profiles
