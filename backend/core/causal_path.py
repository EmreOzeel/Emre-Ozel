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
        timing = self._compute_timing(syn_pkt, synack_pkt, data_packets)

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
# Phase 2 — Hop Sequence Builder
# ═══════════════════════════════════════════════════════════════════════════════

def build_hop_sequence(
    packets: list,
    src_ip: str,
    dst_ip: str,
    roles: "TopologyRoles",
    destination_port: "Optional[int]" = None,
) -> list:
    """
    Build a basic ordered hop sequence from raw packets.

    Detects:
        client_initiated     — SYN seen from src → dst
        connection_established — SYN-ACK seen from dst → src
        connection_failed    — RST seen OR SYN present but no SYN-ACK

    Each step dict always contains:
        step        : str   — step label
        src         : str   — source IP for this event
        dst         : str   — destination IP for this event
        source_role : str   — classify_ip_role(src)
        dest_role   : str   — classify_ip_role(dst)
        ts          : float — packet timestamp (0.0 if unavailable)

    Args:
        packets:          List[PacketRecord] — full unfiltered packet list.
        src_ip:           Initiating endpoint.
        dst_ip:           Target endpoint.
        roles:            TopologyRoles for role annotation.
        destination_port: Optional port to narrow packet matching.

    Returns:
        Ordered list of step dicts representing the observed sequence.
    """
    def _matches(p) -> bool:
        pair = (
            (p.src_ip == src_ip and p.dst_ip == dst_ip) or
            (p.src_ip == dst_ip and p.dst_ip == src_ip)
        )
        if not pair:
            return False
        if destination_port is not None:
            return p.dst_port == destination_port or p.src_port == destination_port
        return True

    def _step(label: str, src: str, dst: str, ts: float) -> dict:
        return {
            "step":        label,
            "src":         src,
            "dst":         dst,
            "source_role": classify_ip_role(src, roles),
            "dest_role":   classify_ip_role(dst, roles),
            "ts":          round(ts, 6),
        }

    relevant = sorted(
        [p for p in packets if _matches(p)],
        key=lambda p: p.ts,
    )

    steps: list = []

    # ── Find key packets ──────────────────────────────────────────────────────
    syn_pkt    = None
    synack_pkt = None
    rst_pkt    = None

    for p in relevant:
        if syn_pkt is None and p.src_ip == src_ip and p.tcp_flags_syn and not p.tcp_flags_ack:
            syn_pkt = p
        if synack_pkt is None and p.src_ip == dst_ip and p.tcp_flags_syn and p.tcp_flags_ack:
            synack_pkt = p
        if rst_pkt is None and p.tcp_flags_rst:
            rst_pkt = p

    # ── Build sequence ────────────────────────────────────────────────────────
    if syn_pkt is None:
        # No connection attempt captured at all
        return steps

    steps.append(_step("client_initiated", src_ip, dst_ip, syn_pkt.ts))

    if synack_pkt is not None:
        steps.append(_step("connection_established", dst_ip, src_ip, synack_pkt.ts))
    elif rst_pkt is not None:
        steps.append(_step("connection_failed", rst_pkt.src_ip, rst_pkt.dst_ip, rst_pkt.ts))
    else:
        # SYN present, no SYN-ACK, no RST — timed out / dropped
        steps.append(_step("connection_failed", dst_ip, src_ip, syn_pkt.ts))

    return steps
