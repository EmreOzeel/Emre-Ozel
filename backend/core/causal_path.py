"""
CausalPathEngine — Foundation

Answers the question a senior network engineer asks when debugging a live issue:
  "Between source A and destination B on port P — where exactly did it break?"

This module provides the architectural skeleton.  Each step is a separate
method so deeper logic (firewall inference, LB detection, latency attribution)
can be added incrementally without restructuring.

Pipeline (Steps A–E):
  A. Filter relevant flows and packets between the pair
  B. Detect SYN  (was a connection even attempted?)
  C. Detect SYN-ACK  (did the far end respond to the handshake?)
  D. Detect application data  (did anything flow after the handshake?)
  E. Classify and narrate  (what most likely happened and why?)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════════════
# Connection state taxonomy
# ═══════════════════════════════════════════════════════════════════════════════

class ConnectionState(str, Enum):
    NO_ATTEMPT         = "no_connection_attempt"
    NO_RESPONSE        = "connection_not_established"
    ESTABLISHED_NO_DATA= "connection_established_no_data"
    DATA_OBSERVED      = "application_level_interaction"
    UNKNOWN            = "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# Result model
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HopObservation:
    """Single hop observation along the path (firewall, LB, backend, etc.)."""
    role: str                          # "firewall" | "load_balancer" | "backend" | "unknown"
    ip: str = ""
    observed: bool = False
    note: str = ""


@dataclass
class PathAnalysisResult:
    # ── Identifiers ──────────────────────────────────────────────────────────
    source_ip: str
    destination_ip: str
    destination_port: Optional[int]
    protocol: str                      # "TCP" | "UDP" | "ICMP" | "unknown"

    # ── Top-level verdict ────────────────────────────────────────────────────
    connection_state: ConnectionState
    path_summary: str                  # One-sentence human narrative

    # ── Path observations (populated by future reasoning layers) ─────────────
    hop_sequence: List[str] = field(default_factory=list)
    firewall_observation: HopObservation = field(
        default_factory=lambda: HopObservation(role="firewall"))
    load_balancer_observation: HopObservation = field(
        default_factory=lambda: HopObservation(role="load_balancer"))
    backend_observation: HopObservation = field(
        default_factory=lambda: HopObservation(role="backend"))

    # ── Timing ───────────────────────────────────────────────────────────────
    timing_breakdown: Dict[str, Any] = field(default_factory=dict)

    # ── Return path ──────────────────────────────────────────────────────────
    return_path_observation: str = ""

    # ── Failure attribution ──────────────────────────────────────────────────
    likely_failure_point: str = ""     # empty string = no failure detected
    alternative_hypotheses: List[str] = field(default_factory=list)

    # ── Confidence ───────────────────────────────────────────────────────────
    confidence_score: int = 0          # 0–100
    confidence_reasoning: str = ""

    # ── Supporting evidence ──────────────────────────────────────────────────
    evidence_packets: List[int] = field(default_factory=list)   # packet nums
    evidence_flows: List[str]   = field(default_factory=list)   # flow keys

    # ── Visibility gaps ──────────────────────────────────────────────────────
    missing_visibility_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-safe dict for API responses."""
        return {
            "source_ip":          self.source_ip,
            "destination_ip":     self.destination_ip,
            "destination_port":   self.destination_port,
            "protocol":           self.protocol,
            "connection_state":   self.connection_state.value,
            "path_summary":       self.path_summary,
            "hop_sequence":       self.hop_sequence,
            "firewall_observation": {
                "role":     self.firewall_observation.role,
                "ip":       self.firewall_observation.ip,
                "observed": self.firewall_observation.observed,
                "note":     self.firewall_observation.note,
            },
            "load_balancer_observation": {
                "role":     self.load_balancer_observation.role,
                "ip":       self.load_balancer_observation.ip,
                "observed": self.load_balancer_observation.observed,
                "note":     self.load_balancer_observation.note,
            },
            "backend_observation": {
                "role":     self.backend_observation.role,
                "ip":       self.backend_observation.ip,
                "observed": self.backend_observation.observed,
                "note":     self.backend_observation.note,
            },
            "timing_breakdown":         self.timing_breakdown,
            "return_path_observation":  self.return_path_observation,
            "likely_failure_point":     self.likely_failure_point,
            "alternative_hypotheses":   self.alternative_hypotheses,
            "confidence_score":         self.confidence_score,
            "confidence_reasoning":     self.confidence_reasoning,
            "evidence_packets":         self.evidence_packets,
            "evidence_flows":           self.evidence_flows,
            "missing_visibility_notes": self.missing_visibility_notes,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Engine
# ═══════════════════════════════════════════════════════════════════════════════

class CausalPathEngine:
    """
    Answers causal questions about traffic between two endpoints.

    Usage:
        engine = CausalPathEngine(ctx.packets, ctx.flows, ctx.findings, ctx)
        result = engine.analyze("10.0.0.5", "10.0.0.1", destination_port=443)
    """

    def __init__(self, packets, flows, findings, context=None):
        self._packets  = packets   # List[PacketRecord]
        self._flows    = flows     # Dict[str, FlowRecord]
        self._findings = findings  # List[Finding]
        self._ctx      = context   # CaptureContext (optional, for future use)

    # ── Public entry point ────────────────────────────────────────────────────

    def analyze(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: Optional[int] = None,
        roles: Optional[Dict[str, str]] = None,
    ) -> PathAnalysisResult:
        """
        Investigate the path between source_ip and destination_ip.

        Args:
            source_ip:        Initiating endpoint IP.
            destination_ip:   Target endpoint IP.
            destination_port: Optional TCP/UDP port to narrow the search.
            roles:            Optional dict hinting topology,
                              e.g. {"firewall": "10.0.0.254", "lb": "10.0.0.10"}.
                              Reserved for future reasoning layers.

        Returns:
            PathAnalysisResult with classification, narrative, and evidence.
        """
        # ── Step A: filter relevant traffic ───────────────────────────────────
        relevant_packets, relevant_flows = self._step_a_filter(
            source_ip, destination_ip, destination_port
        )

        # ── Step B: SYN detection ────────────────────────────────────────────
        syn_pkt = self._step_b_find_syn(
            relevant_packets, source_ip, destination_ip, destination_port
        )

        # ── Step C: SYN-ACK detection ────────────────────────────────────────
        synack_pkt = self._step_c_find_synack(
            relevant_packets, source_ip, destination_ip, destination_port
        )

        # ── Step D: application data detection ───────────────────────────────
        data_packets = self._step_d_find_data(relevant_packets, source_ip, destination_ip)

        # ── Step E: classify + narrate ───────────────────────────────────────
        state, summary, failure, hypotheses = self._step_e_classify(
            syn_pkt, synack_pkt, data_packets,
            source_ip, destination_ip, destination_port
        )

        # ── Timing breakdown ──────────────────────────────────────────────────
        timing = {
            "connect_time_ms": compute_connect_time_ms(relevant_packets),
            "first_response_time_ms": compute_first_response_time_ms(relevant_packets),
            "total_observed_latency_ms": compute_total_observed_latency_ms(relevant_packets),
        }

        # ── Confidence ────────────────────────────────────────────────────────
        conf_score, conf_reason = self._compute_confidence(
            relevant_packets, relevant_flows, syn_pkt, synack_pkt
        )

        # ── Visibility gaps ───────────────────────────────────────────────────
        visibility_notes = self._visibility_notes(
            relevant_packets, relevant_flows,
            syn_pkt, destination_port
        )

        # ── Determine protocol ────────────────────────────────────────────────
        protocol = self._infer_protocol(relevant_packets, destination_port)

        # ── Return path ───────────────────────────────────────────────────────
        return_note = self._return_path_note(relevant_packets, source_ip, destination_ip)

        return PathAnalysisResult(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            connection_state=state,
            path_summary=summary,
            hop_sequence=[source_ip, destination_ip],   # expanded by future topology layer
            timing_breakdown=timing,
            return_path_observation=return_note,
            likely_failure_point=failure,
            alternative_hypotheses=hypotheses,
            confidence_score=conf_score,
            confidence_reasoning=conf_reason,
            evidence_packets=[p.num for p in relevant_packets[:50]],
            evidence_flows=[f.key for f in relevant_flows],
            missing_visibility_notes=visibility_notes,
        )

    # ── Step A: filter ────────────────────────────────────────────────────────

    def _step_a_filter(self, src: str, dst: str, port: Optional[int]):
        """Return packets and flows that involve the src↔dst pair."""
        def _matches_pkt(p) -> bool:
            pair = (
                (p.src_ip == src and p.dst_ip == dst) or
                (p.src_ip == dst and p.dst_ip == src)
            )
            if not pair:
                return False
            if port is not None:
                return p.dst_port == port or p.src_port == port
            return True

        def _matches_flow(f) -> bool:
            pair = (
                (f.src_ip == src and f.dst_ip == dst) or
                (f.src_ip == dst and f.dst_ip == src)
            )
            if not pair:
                return False
            if port is not None:
                return f.dst_port == port or f.src_port == port
            return True

        pkts  = [p for p in self._packets if _matches_pkt(p)]
        flows = [f for f in self._flows.values() if _matches_flow(f)]
        return pkts, flows

    # ── Step B: SYN ───────────────────────────────────────────────────────────

    def _step_b_find_syn(self, packets, src, dst, port):
        """Return the first SYN packet from src→dst (no ACK)."""
        for p in sorted(packets, key=lambda x: x.ts):
            if (p.src_ip == src and p.dst_ip == dst and
                    p.tcp_flags_syn and not p.tcp_flags_ack):
                if port is None or p.dst_port == port:
                    return p
        return None

    # ── Step C: SYN-ACK ──────────────────────────────────────────────────────

    def _step_c_find_synack(self, packets, src, dst, port):
        """Return the first SYN-ACK from dst→src."""
        for p in sorted(packets, key=lambda x: x.ts):
            if (p.src_ip == dst and p.dst_ip == src and
                    p.tcp_flags_syn and p.tcp_flags_ack):
                if port is None or p.src_port == port:
                    return p
        return None

    # ── Step D: application data ──────────────────────────────────────────────

    def _step_d_find_data(self, packets, src, dst):
        """Return packets that carry payload in either direction."""
        return [
            p for p in packets
            if p.tcp_payload_len > 0 or
               (not p.tcp_flags_syn and not p.tcp_flags_fin and
                not p.tcp_flags_rst and not p.tcp_flags_ack and
                p.frame_len > 54)   # heuristic: non-handshake, non-RST content
        ]

    # ── Step E: classify + narrate ────────────────────────────────────────────

    def _step_e_classify(self, syn, synack, data_pkts, src, dst, port):
        """
        Returns (ConnectionState, summary_string, likely_failure, [hypotheses]).
        """
        port_str = f":{port}" if port else ""
        dst_label = f"{dst}{port_str}"

        if syn is None:
            # No connection attempt captured
            state   = ConnectionState.NO_ATTEMPT
            summary = (
                f"No connection attempt from {src} to {dst_label} was observed "
                "in this capture. The traffic may have occurred outside the capture "
                "window or on a different network path."
            )
            failure     = ""
            hypotheses  = [
                "Traffic occurred before or after the capture window.",
                "Connection used a different source port or IP not in this capture.",
                "Application never initiated the connection.",
            ]

        elif synack is None:
            # SYN sent, no SYN-ACK back
            state   = ConnectionState.NO_RESPONSE
            summary = (
                f"Client {src} initiated a connection to {dst_label} "
                f"(SYN at t={syn.ts:.3f}s) but received no SYN-ACK. "
                "The destination did not respond to the handshake."
            )
            failure = f"Connection blocked or unreachable at {dst_label}"
            hypotheses = [
                f"Firewall on the path dropped the SYN to {dst_label}.",
                f"Host {dst} is down or not listening on port {port or 'N/A'}.",
                "SYN-ACK was sent but not captured (asymmetric routing).",
                "RST response from an intermediate device rejected the connection.",
            ]

        elif not data_pkts:
            # Handshake completed, no application data
            state   = ConnectionState.ESTABLISHED_NO_DATA
            rtt_ms  = (synack.ts - syn.ts) * 1000
            summary = (
                f"Connection between {src} and {dst_label} was established "
                f"(handshake RTT {rtt_ms:.1f} ms) but no application data was exchanged. "
                "The session opened and closed without useful payload."
            )
            failure = "Application layer did not exchange data after handshake"
            hypotheses = [
                "Client connected and immediately closed (health check / probe).",
                "Application-layer negotiation failed (TLS error, auth rejection).",
                "Server accepted TCP but rejected the application protocol.",
                "Data packets were captured on a different interface / direction.",
            ]

        else:
            # Full interaction observed
            state   = ConnectionState.DATA_OBSERVED
            rtt_ms  = (synack.ts - syn.ts) * 1000 if synack and syn else 0.0
            n_data  = len(data_pkts)
            summary = (
                f"Server {dst} responded to {src} on {dst_label}. "
                f"Handshake RTT was {rtt_ms:.1f} ms and "
                f"{n_data} application-data packet(s) were observed. "
                "The interaction appears complete."
            )
            failure     = ""
            hypotheses  = []

        return state, summary, failure, hypotheses

    # ── Timing breakdown ──────────────────────────────────────────────────────

    def _compute_timing(self, syn, synack, data_pkts) -> Dict[str, Any]:
        timing: Dict[str, Any] = {}
        if syn:
            timing["syn_ts"] = round(syn.ts, 6)
        if synack and syn:
            timing["synack_ts"]  = round(synack.ts, 6)
            timing["handshake_rtt_ms"] = round((synack.ts - syn.ts) * 1000, 3)
        if data_pkts:
            timing["first_data_ts"] = round(min(p.ts for p in data_pkts), 6)
            timing["last_data_ts"]  = round(max(p.ts for p in data_pkts), 6)
            timing["data_duration_sec"] = round(
                max(p.ts for p in data_pkts) - min(p.ts for p in data_pkts), 3
            )
        return timing

    # ── Confidence ────────────────────────────────────────────────────────────

    def _compute_confidence(self, packets, flows, syn, synack) -> tuple:
        score   = 50
        reasons = []

        n = len(packets)
        if n == 0:
            score = 10
            reasons.append("No packets found for this pair — analysis is speculative.")
        elif n < 5:
            score -= 15
            reasons.append(f"Only {n} packet(s) captured for this pair — thin evidence.")
        elif n >= 20:
            score += 10
            reasons.append(f"{n} packets provide solid evidence.")

        if flows:
            score += 5
            reasons.append("Flow record available for this pair.")

        if syn:
            score += 10
            reasons.append("SYN packet captured — connection attempt confirmed.")
        else:
            score -= 10
            reasons.append("No SYN captured — capture may be mid-stream.")

        if synack:
            score += 10
            reasons.append("SYN-ACK captured — server reachability confirmed.")

        # Clamp
        score = max(10, min(95, score))
        return score, " ".join(reasons)

    # ── Visibility notes ──────────────────────────────────────────────────────

    def _visibility_notes(self, packets, flows, syn, port) -> List[str]:
        notes = []
        if not packets:
            notes.append(
                "No packets between this pair were found. "
                "Verify the capture covers the right network segment."
            )
        if syn is None and packets:
            notes.append(
                "Capture appears to be mid-stream (no SYN observed). "
                "Connection state conclusions may be unreliable."
            )
        if not flows:
            notes.append(
                "No flow record for this pair. "
                "Bidirectional byte counts and timing are unavailable."
            )
        if port is None:
            notes.append(
                "No destination port specified. "
                "Results cover all ports between this pair — consider narrowing by port."
            )
        return notes

    # ── Protocol inference ────────────────────────────────────────────────────

    def _infer_protocol(self, packets, port) -> str:
        if not packets:
            return "unknown"
        proto_counts: Dict[int, int] = {}
        for p in packets:
            proto_counts[p.ip_proto] = proto_counts.get(p.ip_proto, 0) + 1
        dominant = max(proto_counts, key=proto_counts.get, default=0)
        mapping = {6: "TCP", 17: "UDP", 1: "ICMP"}
        return mapping.get(dominant, f"proto/{dominant}")

    # ── Return path note ─────────────────────────────────────────────────────

    def _return_path_note(self, packets, src, dst) -> str:
        fwd = sum(1 for p in packets if p.src_ip == src and p.dst_ip == dst)
        rev = sum(1 for p in packets if p.src_ip == dst and p.dst_ip == src)
        if fwd == 0 and rev == 0:
            return "No packets captured in either direction."
        if rev == 0:
            return (
                f"Only forward traffic captured ({fwd} packets {src}→{dst}). "
                "Return path is invisible — possible asymmetric routing."
            )
        if fwd == 0:
            return (
                f"Only return traffic captured ({rev} packets {dst}→{src}). "
                "Forward path is invisible — capture point is behind the destination."
            )
        ratio = rev / fwd if fwd else 0
        return (
            f"{fwd} packet(s) {src}→{dst}, {rev} packet(s) {dst}→{src}. "
            f"Return ratio {ratio:.2f}x — "
            + ("symmetric." if 0.5 <= ratio <= 2.0 else "asymmetric — review capture position.")
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2 — Role-Aware Classification
# ═══════════════════════════════════════════════════════════════════════════════

import ipaddress as _ipaddress
from dataclasses import dataclass as _dataclass, field as _field
from typing import List as _List


@_dataclass
class TopologyRoles:
    """
    Caller-supplied topology hints.  All fields optional — only provide
    what is known.  Priority order for classification:
        firewall > load_balancer > backend (exact) > backend (subnet)
    """
    firewall_ips: _List[str]        = _field(default_factory=list)
    load_balancer_vips: _List[str]  = _field(default_factory=list)
    backend_ips: _List[str]         = _field(default_factory=list)
    backend_subnets: _List[str]     = _field(default_factory=list)

    @property
    def has_topology(self) -> bool:
        return bool(
            self.firewall_ips or self.load_balancer_vips
            or self.backend_ips or self.backend_subnets
        )


def _ip_in_subnet(ip: str, subnet: str) -> bool:
    """Return True if *ip* falls inside *subnet* (CIDR notation)."""
    try:
        return (
            _ipaddress.ip_address(ip)
            in _ipaddress.ip_network(subnet, strict=False)
        )
    except ValueError:
        return False


def classify_ip_role(ip: str, roles: TopologyRoles) -> str:
    """
    Return the infrastructure role of *ip* given the caller's topology hints.

    Priority (highest first):
        1. firewall   — exact match in roles.firewall_ips
        2. load_balancer — exact match in roles.load_balancer_vips
        3. backend    — exact match in roles.backend_ips
        4. backend    — falls inside any subnet in roles.backend_subnets
        5. unknown

    Args:
        ip:    The IP address string to classify.
        roles: Caller-supplied topology configuration.

    Returns:
        One of: "firewall" | "load_balancer" | "backend" | "unknown"
    """
    if ip in roles.firewall_ips:
        return "firewall"
    if ip in roles.load_balancer_vips:
        return "load_balancer"
    if ip in roles.backend_ips:
        return "backend"
    for subnet in roles.backend_subnets:
        if _ip_in_subnet(ip, subnet):
            return "backend"
    return "unknown"



# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2 — Hop Sequence Builder (role-aware)
# ═══════════════════════════════════════════════════════════════════════════════

_SLOW_BACKEND_THRESHOLD_MS = 500.0   # backend response considered slow above this


def build_hop_sequence(
    packets: list,
    src_ip: str,
    dst_ip: str,
    roles: "TopologyRoles",
    destination_port: "Optional[int]" = None,
    slow_threshold_ms: float = _SLOW_BACKEND_THRESHOLD_MS,
) -> list:
    """
    Build an ordered, role-aware hop sequence from raw packets.

    Base steps (always):
        client_initiated        — SYN seen from src → dst
        connection_established  — SYN-ACK seen (generic, non-role case)
        connection_failed       — RST or no reply (generic, non-role case)

    Role-specific steps (replace/extend base steps when roles are known):
        firewall_pass_observed          — SYN-ACK received from a firewall IP
        firewall_reset_observed         — RST received from a firewall IP
        firewall_drop_suspected         — SYN to firewall, no reply at all
        lb_frontend_connection_observed — SYN-ACK received from LB VIP
        lb_backend_connection_missing   — no LB→backend SYN found in capture
        backend_response_slow           — first backend response > slow_threshold_ms

    Each step dict contains:
        step        : str   — label
        src         : str   — source IP of the event
        dst         : str   — destination IP of the event
        source_role : str   — classify_ip_role(src, roles)
        dest_role   : str   — classify_ip_role(dst, roles)
        ts          : float — packet timestamp

    Args:
        packets:           Full unfiltered List[PacketRecord].
        src_ip:            Initiating endpoint.
        dst_ip:            Target endpoint.
        roles:             TopologyRoles for classification.
        destination_port:  Optional port to narrow packet matching.
        slow_threshold_ms: Backend response delay threshold in milliseconds.
    """

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _matches_pair(p) -> bool:
        pair = (
            (p.src_ip == src_ip and p.dst_ip == dst_ip) or
            (p.src_ip == dst_ip and p.dst_ip == src_ip)
        )
        if not pair:
            return False
        if destination_port is not None:
            return p.dst_port == destination_port or p.src_port == destination_port
        return True

    def _step(label: str, src: str, dst: str, ts: float, **extra) -> dict:
        d = {
            "step":        label,
            "src":         src,
            "dst":         dst,
            "source_role": classify_ip_role(src, roles),
            "dest_role":   classify_ip_role(dst, roles),
            "ts":          round(ts, 6),
        }
        d.update(extra)
        return d

    # ── Filter + sort relevant packets ────────────────────────────────────────

    relevant = sorted([p for p in packets if _matches_pair(p)], key=lambda p: p.ts)

    if not relevant:
        return []

    # ── Locate key packets in the src↔dst exchange ───────────────────────────

    syn_pkt    = None   # first SYN from src → dst
    synack_pkt = None   # first SYN-ACK from dst → src
    rst_pkt    = None   # first RST in either direction
    data_pkts  = []     # packets with payload in either direction

    for p in relevant:
        if syn_pkt is None and p.src_ip == src_ip and p.tcp_flags_syn and not p.tcp_flags_ack:
            syn_pkt = p
        if synack_pkt is None and p.src_ip == dst_ip and p.tcp_flags_syn and p.tcp_flags_ack:
            synack_pkt = p
        if rst_pkt is None and p.tcp_flags_rst:
            rst_pkt = p
        if p.tcp_payload_len > 0:
            data_pkts.append(p)

    if syn_pkt is None:
        return []   # no connection attempt in capture

    # ── Determine destination role ────────────────────────────────────────────

    dst_role = classify_ip_role(dst_ip, roles)

    steps: list = []

    # ── Step 1: client_initiated (always present when SYN found) ─────────────

    steps.append(_step("client_initiated", src_ip, dst_ip, syn_pkt.ts))

    # ── Steps 2+: role-specific path reasoning ────────────────────────────────

    if dst_role == "firewall":
        steps.extend(_reason_firewall(
            src_ip, dst_ip, syn_pkt, synack_pkt, rst_pkt, roles, _step
        ))

    elif dst_role == "load_balancer":
        steps.extend(_reason_load_balancer(
            src_ip, dst_ip, syn_pkt, synack_pkt, rst_pkt,
            packets, roles, destination_port, slow_threshold_ms, _step
        ))

    elif dst_role == "backend":
        steps.extend(_reason_backend(
            src_ip, dst_ip, syn_pkt, synack_pkt, rst_pkt,
            data_pkts, slow_threshold_ms, roles, _step
        ))

    else:
        # Unknown destination — fall back to generic steps
        if synack_pkt is not None:
            steps.append(_step("connection_established", dst_ip, src_ip, synack_pkt.ts))
        elif rst_pkt is not None:
            steps.append(_step("connection_failed", rst_pkt.src_ip, rst_pkt.dst_ip, rst_pkt.ts))
        else:
            steps.append(_step("connection_failed", dst_ip, src_ip, syn_pkt.ts))

    return steps


# ── Role-specific reasoning helpers ──────────────────────────────────────────

def _reason_firewall(src_ip, dst_ip, syn, synack, rst, roles, _step):
    """Return hop steps for a firewall destination."""
    if synack is not None:
        # Firewall passed — SYN-ACK received (transparent or acting as proxy)
        return [_step("firewall_pass_observed", dst_ip, src_ip, synack.ts)]
    if rst is not None and rst.src_ip == dst_ip:
        # RST from the firewall IP itself
        return [_step("firewall_reset_observed", rst.src_ip, rst.dst_ip, rst.ts)]
    # No reply at all
    return [_step("firewall_drop_suspected", dst_ip, src_ip, syn.ts)]


def _reason_load_balancer(
    src_ip, dst_ip, syn, synack, rst,
    all_packets, roles, port, slow_threshold_ms, _step
):
    """Return hop steps for a load balancer VIP destination."""
    result = []

    if synack is None:
        # Frontend connection itself failed
        if rst is not None and rst.src_ip == dst_ip:
            result.append(_step("connection_failed", rst.src_ip, rst.dst_ip, rst.ts))
        else:
            result.append(_step("connection_failed", dst_ip, src_ip, syn.ts))
        return result

    # Frontend handshake succeeded
    result.append(_step("lb_frontend_connection_observed", dst_ip, src_ip, synack.ts))

    # Look for LB → backend SYN in the full packet set
    backend_syn = _find_lb_backend_syn(dst_ip, roles, all_packets)

    if backend_syn is None:
        result.append(_step(
            "lb_backend_connection_missing",
            dst_ip,
            "(backend)",
            synack.ts,
            note="No SYN from LB toward any known backend IP was observed in this capture.",
        ))
    else:
        be_dst = backend_syn.dst_ip
        result.append(_step("connection_established", dst_ip, be_dst, backend_syn.ts))

    return result


def _reason_backend(src_ip, dst_ip, syn, synack, rst, data_pkts, threshold_ms, roles, _step):
    """Return hop steps for a direct backend destination."""
    result = []

    if synack is None:
        if rst is not None and rst.src_ip == dst_ip:
            result.append(_step("connection_failed", rst.src_ip, rst.dst_ip, rst.ts))
        else:
            result.append(_step("connection_failed", dst_ip, src_ip, syn.ts))
        return result

    result.append(_step("connection_established", dst_ip, src_ip, synack.ts))

    # Check for slow backend response
    first_response = _first_data_from(dst_ip, data_pkts)
    if first_response is not None:
        delay_ms = (first_response.ts - synack.ts) * 1000
        if delay_ms > threshold_ms:
            result.append(_step(
                "backend_response_slow", dst_ip, src_ip, first_response.ts,
                delay_ms=round(delay_ms, 1),
                threshold_ms=threshold_ms,
            ))

    return result


def _find_lb_backend_syn(lb_ip: str, roles: "TopologyRoles", packets: list):
    """
    Search ALL packets for the first SYN sent FROM lb_ip TO any known backend IP.
    Returns the matching packet or None.
    """
    all_backend_ips = set(roles.backend_ips)

    for p in sorted(packets, key=lambda x: x.ts):
        if (p.src_ip == lb_ip and p.tcp_flags_syn and not p.tcp_flags_ack):
            if p.dst_ip in all_backend_ips:
                return p
            # Also check subnets
            for subnet in roles.backend_subnets:
                if _ip_in_subnet(p.dst_ip, subnet):
                    return p
    return None


def _first_data_from(ip: str, data_pkts: list):
    """Return the earliest data packet whose source is *ip*, or None."""
    candidates = [p for p in data_pkts if p.src_ip == ip]
    return min(candidates, key=lambda p: p.ts) if candidates else None


def compute_connect_time_ms(flow_packets: list) -> "Optional[float]":
    """
    Compute TCP connect time from SYN to SYN-ACK.

    Robustness rules:
    - Uses the EARLIEST SYN (ignores retransmissions — all share the same ts order).
    - SYN-ACK must occur AFTER the SYN and travel in the reverse direction.
    - If SYN is missing (mid-stream capture) → returns None immediately.
    - If SYN-ACK is missing → returns None.

    Args:
        flow_packets: List[PacketRecord] for a single flow (any order).

    Returns:
        Connect time in milliseconds (float), or None.
    """
    if not flow_packets:
        return None

    ordered = sorted(flow_packets, key=lambda p: p.ts)

    # First valid SYN: client → server (syn=True, ack=False)
    syn = next(
        (p for p in ordered if p.tcp_flags_syn and not p.tcp_flags_ack),
        None,
    )
    if syn is None:
        return None   # mid-stream capture or no connection attempt

    # First SYN-ACK: must be reverse direction AND after the SYN
    synack = next(
        (
            p for p in ordered
            if p.tcp_flags_syn
            and p.tcp_flags_ack
            and p.ts >= syn.ts
            and p.src_ip == syn.dst_ip
            and p.dst_ip == syn.src_ip
        ),
        None,
    )
    if synack is None:
        return None

    return round((synack.ts - syn.ts) * 1000, 3)


def compute_first_response_time_ms(flow_packets: list) -> "Optional[float]":
    """
    Compute time from handshake completion (final ACK) to first server data.

    Handshake is considered complete when:
        1. SYN  : client → server  (syn=True,  ack=False)
        2. SYN-ACK : server → client  (syn=True,  ack=True)
        3. ACK  : client → server  (syn=False, ack=True, no payload)

    First server response: earliest packet from server → client with payload
    (tcp_payload_len > 0) that occurs after the final ACK.

    Returns:
        Milliseconds between final ACK and first server data, or None.
    """
    if not flow_packets:
        return None

    ordered = sorted(flow_packets, key=lambda p: p.ts)

    # Step 1: SYN (client → server)
    syn = next(
        (p for p in ordered if p.tcp_flags_syn and not p.tcp_flags_ack),
        None,
    )
    if syn is None:
        return None

    client = syn.src_ip
    server = syn.dst_ip

    # Step 2: SYN-ACK (server → client, after SYN)
    synack = next(
        (
            p for p in ordered
            if p.tcp_flags_syn and p.tcp_flags_ack
            and p.src_ip == server and p.dst_ip == client
            and p.ts >= syn.ts
        ),
        None,
    )
    if synack is None:
        return None

    # Step 3: final ACK (client → server, after SYN-ACK, no payload)
    final_ack = next(
        (
            p for p in ordered
            if not p.tcp_flags_syn and p.tcp_flags_ack
            and p.src_ip == client and p.dst_ip == server
            and p.tcp_payload_len == 0
            and p.ts >= synack.ts
        ),
        None,
    )
    if final_ack is None:
        return None

    # Step 4: first server data (server → client, after final ACK, with payload)
    first_data = next(
        (
            p for p in ordered
            if p.src_ip == server and p.dst_ip == client
            and p.tcp_payload_len > 0
            and p.ts >= final_ack.ts
        ),
        None,
    )
    if first_data is None:
        return None

    return round((first_data.ts - final_ack.ts) * 1000, 3)


def compute_total_observed_latency_ms(flow_packets: list) -> "Optional[float]":
    """
    Return the total observed duration of a flow in milliseconds.

    Computed as: last_packet.ts - first_packet.ts

    Args:
        flow_packets: List[PacketRecord] for a single flow (any order).

    Returns:
        Duration in milliseconds, 0.0 if only one packet, or None if empty.
    """
    if not flow_packets:
        return None
    ts_values = [p.ts for p in flow_packets]
    return round((max(ts_values) - min(ts_values)) * 1000, 3)
