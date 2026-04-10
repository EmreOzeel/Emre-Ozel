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

# ── Engine version ─────────────────────────────────────────────────────────────
# Bump this string whenever reasoning logic changes in a way that makes existing
# cached results stale.  All cache entries that carry a different version are
# treated as misses regardless of the other key components.
CACHE_ENGINE_VERSION = "1"


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
class EvidenceItem:
    """
    A single traceable piece of evidence backing an impairment or outcome claim.

    Attributes:
        type:            Impairment token this evidence supports.
        summary:         One-sentence human-readable description.
        flow_id:         Flow key if evidence is flow-level (else "").
        packet_refs:     Packet numbers from the capture (evidence_packets-style).
        timestamps:      Epoch float timestamps for the relevant events.
        signal_strength: "high" (direct observation) | "medium" (flow inference)
                         | "low" (capture-gap / indirect).
    """
    type: str
    summary: str
    flow_id: str = ""
    packet_refs: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    signal_strength: str = "medium"   # "high" | "medium" | "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":            self.type,
            "summary":         self.summary,
            "flow_id":         self.flow_id,
            "packet_refs":     self.packet_refs,
            "timestamps":      self.timestamps,
            "signal_strength": self.signal_strength,
        }


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
    path_steps: List[str] = field(default_factory=list)   # Step-by-step narrative

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
    timing_interpretation: str = ""

    # ── Return path ──────────────────────────────────────────────────────────
    return_path_observation: str = ""

    # ── Outcome / impairment model ───────────────────────────────────────────
    # Separates connectivity outcome from performance/visibility degradation.
    # A flow can be connection_outcome="success" yet still carry impairments.
    connection_outcome: str = "unknown"          # success | partial_success | failure | unknown
    primary_impairment: Optional[str] = None     # dominant impairment signal, or None
    path_impairments: List[str] = field(default_factory=list)
    # Valid impairment tokens:
    #   connection_establishment_failure | no_server_response | backend_response_delay
    #   lb_backend_issue | return_path_problem | firewall_interference

    # ── Failure attribution ──────────────────────────────────────────────────
    likely_failure_point: str = ""     # domain-oriented summary (kept for backward compat)
    alternative_hypotheses: List[str] = field(default_factory=list)

    # ── Confidence ───────────────────────────────────────────────────────────
    confidence_score: int = 0          # 0–100
    confidence_reasoning: str = ""

    # ── Path-analysis confidence ──────────────────────────────────────────────
    path_confidence_score: int = 0     # 0–100, penalty-based path analysis reliability
    confidence_reasons: List[str] = field(default_factory=list)

    # ── Supporting evidence ──────────────────────────────────────────────────
    evidence_packets: List[int] = field(default_factory=list)   # packet nums
    evidence_flows: List[str]   = field(default_factory=list)   # flow keys
    evidence_items: List["EvidenceItem"] = field(default_factory=list)  # structured

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
            "path_steps":         self.path_steps,
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
            "timing_interpretation":    self.timing_interpretation,
            "return_path_observation":  self.return_path_observation,
            "connection_outcome":        self.connection_outcome,
            "primary_impairment":       self.primary_impairment,
            "path_impairments":         self.path_impairments,
            "likely_failure_point":     self.likely_failure_point,
            "alternative_hypotheses":   self.alternative_hypotheses,
            "confidence_score":         self.confidence_score,
            "confidence_reasoning":     self.confidence_reasoning,
            "path_confidence_score":    self.path_confidence_score,
            "confidence_reasons":       self.confidence_reasons,
            "evidence_packets":         self.evidence_packets,
            "evidence_flows":           self.evidence_flows,
            "evidence_items":           [e.to_dict() for e in self.evidence_items],
            "missing_visibility_notes": self.missing_visibility_notes,
        }


def _build_evidence_items(
    source_ip: str,
    destination_ip: str,
    state: "ConnectionState",
    timing: Dict[str, Any],
    impairments: List[str],
    relevant_packets,
    relevant_flows,
    all_flows,
    roles: Optional[Dict[str, Any]] = None,
    lb_vis: Optional[Dict[str, Any]] = None,
    bq: Optional[Dict[str, Any]] = None,
    rp: Optional[Dict[str, Any]] = None,
    fw: Optional[Dict[str, Any]] = None,
) -> List["EvidenceItem"]:
    """
    Build structured EvidenceItem list from already-computed signals.
    Does not add new packet parsing — reuses timing, lb_vis, bq, rp, fw.
    One or more items per impairment token.
    """
    items: List[EvidenceItem] = []
    fw = fw or {}
    roles = roles or {}
    firewall_ips = roles.get("firewall_ips", []) or []

    # Helper: ordered packet list sorted by timestamp
    ordered = sorted(relevant_packets, key=lambda p: p.ts)

    def _first(predicate):
        return next((p for p in ordered if predicate(p)), None)

    # ── connection_establishment_failure ──────────────────────────────────────
    if "connection_establishment_failure" in impairments:
        syn = _first(lambda p: p.tcp_flags_syn and not p.tcp_flags_ack
                     and p.src_ip == source_ip)
        items.append(EvidenceItem(
            type="connection_establishment_failure",
            summary=(
                "SYN packet observed from client but no SYN-ACK received — "
                "connection could not be established."
            ),
            packet_refs=[syn.num] if syn else [],
            timestamps=[syn.ts] if syn else [],
            signal_strength="high" if syn else "medium",
        ))

    # ── no_server_response ────────────────────────────────────────────────────
    if "no_server_response" in impairments:
        synack = _first(lambda p: p.tcp_flags_syn and p.tcp_flags_ack
                        and p.src_ip == destination_ip)
        final_ack = _first(lambda p: p.tcp_flags_ack and not p.tcp_flags_syn
                           and p.tcp_payload_len == 0 and p.src_ip == source_ip
                           and (synack is None or p.ts >= synack.ts))
        refs = [p.num for p in [synack, final_ack] if p is not None]
        tss  = [p.ts  for p in [synack, final_ack] if p is not None]

        # Packet-level evidence (ESTABLISHED_NO_DATA)
        if state == ConnectionState.ESTABLISHED_NO_DATA:
            items.append(EvidenceItem(
                type="no_server_response",
                summary=(
                    "TCP handshake completed but no application data was observed "
                    "from the server — service may not have responded."
                ),
                packet_refs=refs,
                timestamps=tss,
                signal_strength="high",
            ))

        # Flow-level evidence (LB backend did not reply)
        if bq is not None and not bq["backend_response_observed"]:
            lb_flow_key = ""
            for f in all_flows:
                if f.src_ip == destination_ip:
                    lb_flow_key = f.key
                    break
            items.append(EvidenceItem(
                type="no_server_response",
                summary=(
                    "No response flow from backend toward the load balancer was "
                    "detected — backend may be down or not responding."
                ),
                flow_id=lb_flow_key,
                signal_strength="medium",
            ))

    # ── backend_response_delay ────────────────────────────────────────────────
    if "backend_response_delay" in impairments:
        frt = timing.get("first_response_time_ms")
        brd = (bq or {}).get("backend_response_delay_ms")

        if frt is not None and frt > 200:
            # Packet-level: find the pure ACK and first server data
            synack_p = _first(lambda p: p.tcp_flags_syn and p.tcp_flags_ack
                              and p.src_ip == destination_ip)
            ack_p = _first(lambda p: p.tcp_flags_ack and not p.tcp_flags_syn
                           and p.tcp_payload_len == 0 and p.src_ip == source_ip
                           and (synack_p is None or p.ts >= synack_p.ts))
            data_p = _first(lambda p: p.src_ip == destination_ip
                            and p.tcp_payload_len > 0
                            and (ack_p is None or p.ts >= ack_p.ts))
            refs = [p.num for p in [ack_p, data_p] if p is not None]
            tss  = [p.ts  for p in [ack_p, data_p] if p is not None]
            items.append(EvidenceItem(
                type="backend_response_delay",
                summary=(
                    f"Server first response observed {frt:.1f} ms after connection "
                    f"was established — application-level delay is likely."
                ),
                packet_refs=refs,
                timestamps=tss,
                signal_strength="high" if frt > 500 else "medium",
            ))

        elif brd is not None and brd > 200:
            # Flow-level: LB→backend to backend→LB timing
            items.append(EvidenceItem(
                type="backend_response_delay",
                summary=(
                    f"Backend response flow observed {brd:.1f} ms after LB forwarded "
                    f"the request — backend processing appears slow."
                ),
                signal_strength="medium",
            ))

    # ── lb_backend_issue ─────────────────────────────────────────────────────
    if "lb_backend_issue" in impairments:
        # Find the client→LB flow for traceability
        client_lb_flow = ""
        for f in relevant_flows:
            if f.src_ip == source_ip and f.dst_ip == destination_ip:
                client_lb_flow = f.key
                break
        items.append(EvidenceItem(
            type="lb_backend_issue",
            summary=(
                "Client-to-LB frontend flow was observed but no corresponding "
                "LB-to-backend forwarding flow was detected."
            ),
            flow_id=client_lb_flow,
            signal_strength="medium",
        ))

    # ── return_path_problem ───────────────────────────────────────────────────
    if "return_path_problem" in impairments:
        # Find the backend→LB flow as anchor
        be_lb_flow = ""
        for f in all_flows:
            be_ips = (roles.get("backend_ips", []) or [])
            be_nets = (roles.get("backend_subnets", []) or [])
            if f.dst_ip == destination_ip and (
                f.src_ip in be_ips
                or any(_ip_in_subnet(f.src_ip, n) for n in be_nets)
            ):
                be_lb_flow = f.key
                break
        items.append(EvidenceItem(
            type="return_path_problem",
            summary=(
                "Backend response was observed reaching the load balancer, but no "
                "return flow from the LB toward the client was detected — "
                "the return path may be interrupted or not visible at this capture point."
            ),
            flow_id=be_lb_flow,
            signal_strength="medium",
        ))

    # ── firewall_interference ─────────────────────────────────────────────────
    if "firewall_interference" in impairments:
        rst_pkts = [p for p in ordered if p.tcp_flags_rst]
        fw_involved = [
            p for p in rst_pkts
            if p.src_ip in firewall_ips or p.dst_ip in firewall_ips
        ]
        strength = "high" if fw_involved else "medium"
        rst_refs = [p.num for p in rst_pkts[:5]]
        rst_tss  = [p.ts  for p in rst_pkts[:5]]
        direction = fw.get("rst_direction") or "unknown"
        dir_label = {
            "server_to_client": "from destination toward client",
            "client_to_server": "from client toward destination",
        }.get(direction, "in an unknown direction")
        note = (
            " A known firewall address is directly involved."
            if fw_involved else
            " Firewall involvement cannot be confirmed from packet data alone."
        )
        items.append(EvidenceItem(
            type="firewall_interference",
            summary=(
                f"TCP RST packet observed {dir_label}.{note}"
            ),
            packet_refs=rst_refs,
            timestamps=rst_tss,
            signal_strength=strength,
        ))

    return items


# Impairment priority — first match becomes primary_impairment.
_IMPAIRMENT_PRIORITY = [
    "connection_establishment_failure",
    "no_server_response",
    "firewall_interference",
    "return_path_problem",
    "lb_backend_issue",
    "backend_response_delay",
]


def _classify_outcome_and_impairments(
    state: "ConnectionState",
    timing: Dict[str, Any],
    lb_vis: Optional[Dict[str, Any]] = None,
    bq: Optional[Dict[str, Any]] = None,
    rp: Optional[Dict[str, Any]] = None,
    fw: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Derive connection_outcome, primary_impairment, and path_impairments from
    existing analysis signals.

    Separates *connectivity outcome* from *performance/visibility impairment*
    so that DATA_OBSERVED flows can still surface degradation signals.

    connection_outcome values:
        success         — data exchanged, no significant impairment
        partial_success — data exchanged but end-to-end delivery questionable,
                          OR handshake completed but no application data
        failure         — connection never established, or no data after connect
        unknown         — no connection attempt observed

    path_impairments tokens (may co-occur):
        connection_establishment_failure
        no_server_response
        backend_response_delay
        lb_backend_issue
        return_path_problem
        firewall_interference
    """
    impairments: List[str] = []

    # ── Collect impairment signals ────────────────────────────────────────────

    # Connection-level failure
    if state in (ConnectionState.NO_RESPONSE, ConnectionState.NO_ATTEMPT):
        impairments.append("connection_establishment_failure")

    # No application data after a successful handshake
    if state == ConnectionState.ESTABLISHED_NO_DATA:
        impairments.append("no_server_response")

    # Backend slow response — check packet-level timing regardless of state
    frt = timing.get("first_response_time_ms")
    if frt is not None and frt > 200:
        impairments.append("backend_response_delay")

    # LB-level: LB did not forward to any backend
    if lb_vis is not None and not lb_vis["lb_backend_observed"]:
        impairments.append("lb_backend_issue")

    # LB-level: backend did not reply to LB
    if bq is not None and not bq["backend_response_observed"]:
        if "no_server_response" not in impairments:
            impairments.append("no_server_response")

    # LB-level: backend response was slow
    brd = (bq or {}).get("backend_response_delay_ms")
    if brd is not None and brd > 200:
        if "backend_response_delay" not in impairments:
            impairments.append("backend_response_delay")

    # Return-path problem (LB→client flow missing despite backend reply)
    if rp is not None and not rp["return_path_observed"]:
        impairments.append("return_path_problem")

    # Firewall interference: only when RST originates from the server side
    # (server_to_client) or involves a known firewall IP.  Client-originated
    # RSTs are often normal application-level connection teardown and should
    # not be conflated with firewall blocking.
    if fw is not None and (
        fw["firewall_evidence_notes"]  # RST involving a known firewall address
        or (
            fw["rst_observed"]
            and fw.get("rst_direction") == "server_to_client"
        )
    ):
        impairments.append("firewall_interference")

    # ── Derive outcome ────────────────────────────────────────────────────────
    if state == ConnectionState.DATA_OBSERVED:
        if "return_path_problem" in impairments:
            outcome = "partial_success"
        else:
            outcome = "success"
    elif state == ConnectionState.ESTABLISHED_NO_DATA:
        outcome = "failure"
    elif state == ConnectionState.NO_RESPONSE:
        outcome = "failure"
    elif state == ConnectionState.NO_ATTEMPT:
        outcome = "unknown"
    else:
        outcome = "unknown"

    # ── Primary impairment — highest-priority token present ───────────────────
    primary = next((i for i in _IMPAIRMENT_PRIORITY if i in impairments), None)

    return {
        "connection_outcome": outcome,
        "primary_impairment": primary,
        "path_impairments":   impairments,
    }


def _classify_failure_domain(timing: Dict[str, Any]):
    """
    First-pass timing-based failure-domain classification.

    Returns (failure_point: str, hypotheses: List[str]).

    Domains:
        front_end_connection_failure       — no connect, very short capture
        connection_establishment_failure   — no connect, unclear cause
        no_server_response_after_connection — connected, no server data
        slow_connection_establishment      — connect_time_ms > 100
        backend_or_application_delay       — fast connect, slow response
        no_obvious_failure_detected        — all within normal thresholds

    Note: callers should only apply the latency-specific domains
    (slow_connection_establishment, backend_or_application_delay,
    no_server_response_after_connection) as overrides; connectivity
    failures are better described by the connection-state classifier.
    """
    ct  = timing.get("connect_time_ms")
    frt = timing.get("first_response_time_ms")
    tot = timing.get("total_observed_latency_ms")

    if ct is None:
        if tot is not None and tot < 100:
            return (
                "front_end_connection_failure",
                [
                    "Connection attempt was blocked before reaching the service.",
                    "Capture window too short to observe a full handshake.",
                    "Service may not be running or is unreachable on this path.",
                ],
            )
        return (
            "connection_establishment_failure",
            [
                "A firewall or ACL on the path may be filtering this traffic.",
                "The service is not reachable from the source network.",
                "Capture does not cover the full connection attempt.",
            ],
        )

    if frt is None:
        return (
            "no_server_response_after_connection",
            [
                "Backend service accepted the TCP connection but sent no application data.",
                "Return-path visibility gap — server response may exist but is not captured.",
                "Application-layer negotiation failed (e.g., TLS error, auth rejection).",
            ],
        )

    if ct > 100:
        return (
            "slow_connection_establishment",
            [
                "High network latency between client and server.",
                "Server is overloaded and slow to complete the TCP handshake.",
                "Intermediate device (firewall, NAT) is adding latency.",
            ],
        )

    if frt > 200:
        return (
            "backend_or_application_delay",
            [
                "Backend service is processing the request slowly.",
                "Load balancer backend pool is under pressure.",
                "Application-level processing latency (database, compute).",
                "Response latency may be within normal baseline for this "
                "application — compare against historical measurements before "
                "treating this as a problem.",
            ],
        )

    return ("no_obvious_failure_detected", [])


def _classify_role_aware_failure_domain(
    result: "PathAnalysisResult",
    roles: Optional[Dict[str, Any]],
) -> tuple:
    """
    Conservatively enrich alternative_hypotheses and missing_visibility_notes
    based on the destination IP's known role.

    Does NOT rename likely_failure_point.
    Does NOT add new packet parsing logic.
    Only uses the roles dict supplied by the caller.

    Returns:
        (enriched_hypotheses: List[str], enriched_visibility_notes: List[str])
    """
    if not roles:
        return (list(result.alternative_hypotheses), list(result.missing_visibility_notes))

    dst = result.destination_ip
    failure = result.likely_failure_point
    hypotheses = list(result.alternative_hypotheses)
    visibility_notes = list(result.missing_visibility_notes)

    lb_vips       = roles.get("load_balancer_vips", []) or []
    backend_ips   = roles.get("backend_ips", []) or []
    backend_nets  = roles.get("backend_subnets", []) or []
    firewall_ips  = roles.get("firewall_ips", []) or []

    # ── Load balancer destination ─────────────────────────────────────────────
    if dst in lb_vips:
        if failure in ("connection_establishment_failure", "front_end_connection_failure"):
            hypotheses.extend([
                "Load balancer frontend is not accepting connections (VIP misconfiguration or LB down).",
                "Firewall or path filtering is blocking traffic before it reaches the load balancer.",
            ])
        elif failure == "no_server_response_after_connection":
            hypotheses.extend([
                "Load balancer accepted the connection but failed to forward to a backend (forwarding rule issue).",
                "Backend pool is unhealthy — no members are passing health checks.",
            ])

    # ── Backend destination ───────────────────────────────────────────────────
    elif dst in backend_ips or any(_ip_in_subnet(dst, net) for net in backend_nets):
        if failure == "backend_or_application_delay":
            hypotheses.extend([
                "Backend host is responding slowly (CPU/memory pressure or I/O wait).",
                "Application processing delay (e.g., slow database query, synchronous blocking call).",
            ])
        elif failure == "no_server_response_after_connection":
            hypotheses.extend([
                "Backend service accepted the TCP connection but the application layer did not respond.",
                "Return-path visibility gap — response may exist but is not visible at the capture point.",
            ])

    # ── Firewall destination ──────────────────────────────────────────────────
    elif dst in firewall_ips:
        visibility_notes.append(
            f"Destination {dst} is a known firewall address. "
            "Traffic is targeting the firewall itself; attribution of failures to upstream/downstream "
            "components is limited from this capture point."
        )

    return (hypotheses, visibility_notes)


def _detect_lb_backend_visibility(
    source_ip: str,
    destination_ip: str,
    flows,
    roles: Dict[str, Any],
) -> Dict[str, bool]:
    """
    Determine whether client-to-LB and LB-to-backend flows are both observed.

    Args:
        source_ip:        Originating client IP.
        destination_ip:   The load balancer VIP (already confirmed by caller).
        flows:            All flows — iterable of FlowRecord objects.
        roles:            Dict with optional backend_ips / backend_subnets lists.

    Returns:
        {
            "lb_frontend_observed": bool,  # flow from source_ip → LB VIP exists
            "lb_backend_observed":  bool,  # flow from LB VIP → any backend exists
        }

    Note: caller must only invoke this when destination_ip is a known LB VIP.
    """
    backend_ips  = roles.get("backend_ips", []) or []
    backend_nets = roles.get("backend_subnets", []) or []

    frontend_observed = False
    backend_observed  = False

    for f in flows:
        # Client → LB VIP
        if f.src_ip == source_ip and f.dst_ip == destination_ip:
            frontend_observed = True

        # LB VIP → backend (exact match or subnet)
        if f.src_ip == destination_ip:
            if f.dst_ip in backend_ips:
                backend_observed = True
            elif any(_ip_in_subnet(f.dst_ip, net) for net in backend_nets):
                backend_observed = True

    return {
        "lb_frontend_observed": frontend_observed,
        "lb_backend_observed":  backend_observed,
    }


def _detect_backend_response_quality(
    lb_vip: str,
    flows,
    roles: Dict[str, Any],
) -> Dict[str, Any]:
    """
    For flows already known to reach a backend (LB VIP → backend), determine
    whether the backend replied and how fast.

    Args:
        lb_vip:  The load balancer VIP (destination_ip from the outer context).
        flows:   All flows — iterable of FlowRecord objects.
        roles:   Dict with optional backend_ips / backend_subnets lists.

    Returns:
        {
            "backend_response_observed": bool,    # any backend→LB flow exists
            "backend_response_delay_ms": float|None,  # LB→be first_seen to be→LB first_seen
        }

    Note: delay is None when either direction's first_seen is missing or negative.
    """
    backend_ips  = roles.get("backend_ips", []) or []
    backend_nets = roles.get("backend_subnets", []) or []

    def _is_backend(ip: str) -> bool:
        if ip in backend_ips:
            return True
        return any(_ip_in_subnet(ip, net) for net in backend_nets)

    lb_to_be_ts: Optional[float] = None   # earliest LB→backend first_seen
    be_to_lb_ts: Optional[float] = None   # earliest backend→LB first_seen

    for f in flows:
        if f.src_ip == lb_vip and _is_backend(f.dst_ip):
            if lb_to_be_ts is None or f.first_seen < lb_to_be_ts:
                lb_to_be_ts = f.first_seen
        if _is_backend(f.src_ip) and f.dst_ip == lb_vip:
            if be_to_lb_ts is None or f.first_seen < be_to_lb_ts:
                be_to_lb_ts = f.first_seen

    backend_response_observed = be_to_lb_ts is not None

    delay_ms: Optional[float] = None
    if lb_to_be_ts is not None and be_to_lb_ts is not None:
        raw = (be_to_lb_ts - lb_to_be_ts) * 1000
        if raw >= 0:
            delay_ms = round(raw, 3)

    return {
        "backend_response_observed": backend_response_observed,
        "backend_response_delay_ms": delay_ms,
    }


def _detect_return_path_visibility(
    source_ip: str,
    destination_ip: str,
    flows,
    roles: Dict[str, Any],
    be_to_lb_ts: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Detect whether traffic returns from the LB VIP back toward the original client.

    Args:
        source_ip:        Original client IP.
        destination_ip:   The load balancer VIP.
        flows:            All flows — iterable of FlowRecord objects.
        roles:            Unused here; kept for API symmetry with sibling helpers.
        be_to_lb_ts:      Optional earliest backend→LB timestamp for delay computation.

    Returns:
        {
            "return_path_observed": bool,       # any LB VIP→client flow exists
            "return_path_delay_ms": float|None, # be→LB first_seen to LB→client first_seen
        }
    """
    lb_to_client_ts: Optional[float] = None

    for f in flows:
        if f.src_ip == destination_ip and f.dst_ip == source_ip:
            if lb_to_client_ts is None or f.first_seen < lb_to_client_ts:
                lb_to_client_ts = f.first_seen

    return_path_observed = lb_to_client_ts is not None

    delay_ms: Optional[float] = None
    if be_to_lb_ts is not None and lb_to_client_ts is not None:
        raw = (lb_to_client_ts - be_to_lb_ts) * 1000
        if raw >= 0:
            delay_ms = round(raw, 3)

    return {
        "return_path_observed": return_path_observed,
        "return_path_delay_ms": delay_ms,
    }


def _detect_firewall_path_interference(
    source_ip: str,
    destination_ip: str,
    flow_packets,
    roles: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Identify conservative packet-level evidence of firewall involvement.

    Inspects RST flags and known firewall IPs in the packet list.
    Does NOT invent certainty — all notes use hedged language.

    Args:
        source_ip:        Originating client IP.
        destination_ip:   Target IP (may be an LB VIP or backend).
        flow_packets:     Packets filtered for the client-facing flow.
        roles:            Dict with optional firewall_ips list.

    Returns:
        {
            "rst_observed":           bool,
            "rst_direction":          "server_to_client"|"client_to_server"|"unknown"|None,
            "firewall_evidence_notes": List[str],   # visibility/evidence notes
            "firewall_hypotheses":     List[str],   # alternative hypothesis strings
        }
    """
    firewall_ips = roles.get("firewall_ips", []) or []

    rst_observed   = False
    rst_direction  = None
    evidence_notes: List[str] = []
    fw_hypotheses:  List[str] = []

    for p in flow_packets:
        if not p.tcp_flags_rst:
            continue

        rst_observed = True

        # Determine direction of the first RST observed
        if rst_direction is None:
            if p.src_ip == destination_ip and p.dst_ip == source_ip:
                rst_direction = "server_to_client"
            elif p.src_ip == source_ip and p.dst_ip == destination_ip:
                rst_direction = "client_to_server"
            else:
                rst_direction = "unknown"

        # Direct firewall IP involvement in this RST packet
        if p.src_ip in firewall_ips or p.dst_ip in firewall_ips:
            fw_ip = p.src_ip if p.src_ip in firewall_ips else p.dst_ip
            evidence_notes.append(
                f"RST packet observed involving known firewall address {fw_ip} — "
                "may indicate active policy enforcement by the firewall."
            )

    if rst_observed and rst_direction is None:
        rst_direction = "unknown"

    return {
        "rst_observed":            rst_observed,
        "rst_direction":           rst_direction,
        "firewall_evidence_notes": evidence_notes,
        "firewall_hypotheses":     fw_hypotheses,
    }


# ── Failure-point → closing sentence map ─────────────────────────────────────
_FAILURE_CLOSING: Dict[str, str] = {
    "no_obvious_failure_detected":
        "No obvious failure was detected along the observed path.",
    "front_end_connection_failure":
        "The most likely issue is a connection failure before the traffic reached the service.",
    "connection_establishment_failure":
        "Connection establishment failed — the service may be unreachable or filtered on this path.",
    "no_server_response_after_connection":
        "The connection was established but no server response was observed — "
        "this may reflect a service issue or a capture visibility gap on the "
        "server-side response path.",
    "slow_connection_establishment":
        "Connection establishment appears slow, suggesting possible network latency or overload.",
    "backend_or_application_delay":
        "Timing suggests possible backend or application delay; verify whether "
        "this latency is within the normal baseline for this service before "
        "concluding there is a problem.",
}


def _compute_path_confidence(
    timing: Dict[str, Any],
    missing_visibility_notes: List[str],
    lb_vis: Optional[Dict[str, Any]] = None,
    bq: Optional[Dict[str, Any]] = None,
    rp: Optional[Dict[str, Any]] = None,
    fw: Optional[Dict[str, Any]] = None,
    path_impairments: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Penalty-based path analysis confidence scoring.

    Starts from 100 and subtracts for each signal gap or conflict.
    Returns {"path_confidence_score": int, "confidence_reasons": List[str]}.
    """
    score   = 100
    reasons: List[str] = []
    impairments = path_impairments or []
    frt = timing.get("first_response_time_ms")

    # Timing completeness
    if timing.get("connect_time_ms") is None:
        score -= 20
        reasons.append("Connection establishment not observed — SYN-ACK not confirmed.")

    if frt is None:
        score -= 15
        reasons.append("First server response not observed — server behaviour unclear.")

    # LB-specific gaps (only penalise when LB path was expected)
    if lb_vis is not None and not lb_vis["lb_backend_observed"]:
        score -= 10
        reasons.append("LB-to-backend forwarding not observed — backend reachability unknown.")

    # Backend response
    if bq is not None and not bq["backend_response_observed"]:
        score -= 15
        reasons.append("Backend response not observed — backend may be silent or unreachable.")

    # Return path
    if rp is not None and not rp["return_path_observed"]:
        score -= 10
        reasons.append("Return path visibility incomplete — LB-to-client flow not observed.")

    # Capture completeness — -5 per note, capped at -20
    if missing_visibility_notes:
        note_penalty = min(len(missing_visibility_notes) * 5, 20)
        score -= note_penalty
        reasons.append(
            f"Analysis based on partial capture ({len(missing_visibility_notes)} "
            "visibility gap(s)) — some path segments may be missing."
        )

    # Conflicting signals: RST present alongside observed backend response
    if (fw is not None and fw["rst_observed"]
            and bq is not None and bq["backend_response_observed"]):
        score -= 15
        reasons.append(
            "Conflicting signals: RST observed alongside backend response — "
            "cause of failure is ambiguous."
        )

    # RST involving firewall IP
    if fw is not None and fw["firewall_evidence_notes"]:
        reasons.append("RST observed involving a known firewall address.")

    # ── Impairment-specific confidence adjustments ────────────────────────────

    # Borderline backend delay (200–500 ms only) is a weak signal — many services
    # operate in this range normally.  Only apply when it's the sole impairment.
    if (
        impairments == ["backend_response_delay"]
        and frt is not None
        and 200 < frt <= 500
    ):
        score -= 15
        reasons.append(
            f"Backend delay of {frt:.0f} ms is in the borderline range (200–500 ms); "
            "this latency may be within normal operating range for this service."
        )

    # Return path absent without any other connectivity impairment most often
    # indicates a capture visibility gap rather than a genuine path failure.
    if impairments == ["return_path_problem"]:
        score -= 10
        reasons.append(
            "Return path absence is the only impairment — likely a capture "
            "visibility gap rather than an active path failure."
        )

    return {
        "path_confidence_score": max(0, min(100, score)),
        "confidence_reasons":    reasons,
    }


def _compose_path_narrative(
    source_ip: str,
    destination_ip: str,
    result: "PathAnalysisResult",
    roles: Optional[Dict[str, Any]] = None,
    lb_vis: Optional[Dict[str, Any]] = None,
    bq: Optional[Dict[str, Any]] = None,
    rp: Optional[Dict[str, Any]] = None,
    fw: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Compose a step-by-step human-readable narrative from existing analysis signals.

    Args:
        source_ip / destination_ip: Endpoint identifiers.
        result:   Fully populated PathAnalysisResult.
        roles:    Optional infrastructure role dict.
        lb_vis:   Output of _detect_lb_backend_visibility (or None).
        bq:       Output of _detect_backend_response_quality (or None).
        rp:       Output of _detect_return_path_visibility (or None).
        fw:       Output of _detect_firewall_path_interference (or None).

    Returns:
        {"path_steps": List[str], "path_summary": str}
    """
    steps: List[str] = []
    timing   = result.timing_breakdown
    state    = result.connection_state
    failure  = result.likely_failure_point
    lb_vips  = (roles or {}).get("load_balancer_vips", []) or []
    is_lb    = destination_ip in lb_vips

    # ── Step 1: opening ───────────────────────────────────────────────────────
    if state in (ConnectionState.NO_ATTEMPT, ConnectionState.UNKNOWN):
        steps.append(
            f"Traffic from {source_ip} toward {destination_ip} was observed, "
            "but connection establishment was incomplete or not confirmed."
        )
    else:
        steps.append(f"Client {source_ip} initiated traffic toward {destination_ip}.")

    # ── Step 2: connection establishment timing ───────────────────────────────
    ct = timing.get("connect_time_ms")
    if ct is None:
        steps.append("Connection establishment was not observed in this capture.")
    elif ct > 100:
        steps.append(
            f"Connection establishment completed in {ct:.1f} ms, "
            "which is slower than expected and may indicate network latency or server load."
        )
    else:
        steps.append(f"Connection was established successfully ({ct:.1f} ms).")

    # ── Step 3: load-balancer path (only when destination is a known LB VIP) ──
    if is_lb and lb_vis is not None:
        if lb_vis["lb_frontend_observed"]:
            steps.append("Traffic reached the load balancer frontend.")
        else:
            steps.append(
                "No client-to-LB frontend flow was observed — "
                "the load balancer may not have been reachable from this client."
            )

        if lb_vis["lb_backend_observed"]:
            steps.append(
                "The load balancer forwarded traffic to a backend host "
                "(LB-to-backend flow observed in capture)."
            )
        else:
            steps.append(
                "No LB-to-backend flow was observed — "
                "the load balancer may not have forwarded traffic to any backend, "
                "or this flow may not be visible at the current capture point."
            )

        # Backend response
        if bq is not None:
            if not bq["backend_response_observed"]:
                steps.append(
                    "No backend response to the load balancer was observed."
                )
            else:
                brd = bq["backend_response_delay_ms"]
                if brd is not None and brd > 200:
                    steps.append(
                        f"The backend responded to the load balancer, "
                        f"but took {brd:.1f} ms, suggesting application-level delay."
                    )
                else:
                    steps.append("The backend responded to the load balancer.")

        # Return path
        if rp is not None:
            if rp["return_path_observed"]:
                steps.append(
                    "Return traffic from the load balancer toward the client was observed."
                )
            else:
                steps.append(
                    "No return traffic from the load balancer toward the client was detected "
                    "— this may indicate a path interruption or a capture visibility gap at "
                    "this monitoring point."
                )

    # ── Step 4: firewall / RST evidence ──────────────────────────────────────
    if fw is not None and fw["rst_observed"]:
        direction = fw["rst_direction"] or "unknown"
        dir_label = {
            "server_to_client": "from server toward client",
            "client_to_server": "from client toward server",
        }.get(direction, "in an unknown direction")
        steps.append(
            f"A TCP reset (RST) was observed {dir_label}. "
            "RST may indicate an active policy rejection by a firewall or the server, "
            "but could also reflect normal application-level connection teardown; "
            "the specific cause cannot be confirmed from packet data alone."
        )
        if fw["firewall_evidence_notes"]:
            steps.append(
                "A RST packet was observed involving a known firewall address — "
                "firewall interference is possible but cannot be confirmed."
            )

    elif fw is not None and fw["firewall_evidence_notes"]:
        steps.append(
            "Firewall-related visibility notes were recorded; "
            "firewall involvement is possible but cannot be confirmed."
        )

    # ── Step 5: backend delay summary (non-LB path) ──────────────────────────
    if not is_lb:
        frt = timing.get("first_response_time_ms")
        if frt is not None and frt > 500:
            steps.append(
                f"The server response took {frt:.1f} ms after connection, "
                "which is notably elevated and suggests application-level delay."
            )
        elif frt is not None and frt > 200:
            steps.append(
                f"The server response took {frt:.1f} ms after connection — "
                "possible delay, though this may still be within the normal "
                "baseline for this application; verify before treating as a problem."
            )

    # ── Step 6: closing summary ───────────────────────────────────────────────
    closing = _FAILURE_CLOSING.get(
        failure,
        f"The analysis points to a possible issue at: {failure}." if failure else
        "The path analysis did not identify a specific failure point.",
    )
    if result.confidence_score < 65:
        closing += (
            " Note: analysis confidence is reduced — capture visibility may be "
            "incomplete or evidence is thin; treat conclusions as indicative."
        )
    steps.append(closing)

    return {
        "path_steps":   steps,
        "path_summary": closing,
    }


def _interpret_timing(timing: Dict[str, Any]) -> str:
    """
    Produce a plain-language timing interpretation from timing_breakdown values.

    Rules (applied in priority order):
    1. connect_time_ms is None
       → connection establishment was not observed.
    2. connect_time_ms present, first_response_time_ms is None
       → connection established but no server data observed.
    3. connect_time_ms > 100
       → connection establishment appears slower than expected.
    4. connect_time_ms <= 100, first_response_time_ms > 200
       → fast connect, delayed server response.
    5. connect_time_ms <= 100, first_response_time_ms <= 200
       → no obvious delay.
    Special: total < 100 ms AND no response → short failed attempt.
    """
    ct  = timing.get("connect_time_ms")
    frt = timing.get("first_response_time_ms")
    tot = timing.get("total_observed_latency_ms")

    if ct is None:
        if tot is not None and tot < 100 and frt is None:
            return (
                "A very short exchange was observed with no server response, "
                "suggesting a brief failed connection attempt."
            )
        return "Connection establishment was not observed or did not complete."

    if frt is None:
        return "Connection was established, but no server response data was observed."

    if ct > 100:
        return "Connection establishment appears slower than expected."

    if frt > 200:
        return (
            "Connection was established quickly, "
            "but the server response appears delayed."
        )

    return (
        "Connection establishment and first server response were observed "
        "with no obvious delay."
    )


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
        timing_interp = _interpret_timing(timing)

        # ── Failure domain (timing-based refinement) ──────────────────────────
        # Apply only for latency-specific domains; step_e owns connectivity failures.
        _TIMING_OVERRIDES = {
            "slow_connection_establishment",
            "backend_or_application_delay",
            "no_server_response_after_connection",
        }
        td_failure, td_hypotheses = _classify_failure_domain(timing)
        if td_failure in _TIMING_OVERRIDES and state != ConnectionState.DATA_OBSERVED:
            failure    = td_failure
            hypotheses = td_hypotheses

        # ── Role-aware enrichment ─────────────────────────────────────────────
        # Build a minimal stub so the helper can read destination_ip and failure.
        _stub = PathAnalysisResult(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol="unknown",
            connection_state=state,
            path_summary="",
            likely_failure_point=failure,
            alternative_hypotheses=hypotheses,
            missing_visibility_notes=[],   # enriched below after _visibility_notes()
        )
        _roles_dict = roles if isinstance(roles, dict) else None
        hypotheses, _role_vis = _classify_role_aware_failure_domain(_stub, _roles_dict)

        # Initialise per-layer context so downstream steps can reference them unconditionally.
        _lb_vis: Optional[Dict[str, Any]] = None
        _bq:     Optional[Dict[str, Any]] = None
        _rp:     Optional[Dict[str, Any]] = None

        # ── LB frontend/backend separation (only when destination is a known LB VIP) ──
        if _roles_dict and destination_ip in (_roles_dict.get("load_balancer_vips") or []):
            _lb_vis = _detect_lb_backend_visibility(  # noqa: F841 (used by narrative)
                source_ip, destination_ip, self._flows.values(), _roles_dict
            )
            if _lb_vis["lb_frontend_observed"] and not _lb_vis["lb_backend_observed"]:
                hypotheses = list(hypotheses) + [
                    "Load balancer frontend connection observed but no LB-to-backend flow detected — "
                    "possible backend forwarding misconfiguration or unhealthy backend pool.",
                    "Backend pool members may be failing health checks or are unreachable from the LB.",
                    "LB-to-backend forwarding flow may exist but not be captured at this monitoring "
                    "point — verify that the capture covers both LB interfaces.",
                ]

            # ── Backend response quality (only when LB reached a backend) ────
            if _lb_vis["lb_backend_observed"]:
                _bq = _detect_backend_response_quality(
                    destination_ip, self._flows.values(), _roles_dict
                )
                if not _bq["backend_response_observed"]:
                    hypotheses = list(hypotheses) + [
                        "Backend did not send a response to the load balancer.",
                        "Backend service may be down or refusing connections.",
                        "Return-path from backend to LB may not be visible at this capture point.",
                    ]
                else:
                    _brd = _bq["backend_response_delay_ms"]
                    if _brd is not None and _brd > 200:
                        hypotheses = list(hypotheses) + [
                            f"Backend response was slow ({_brd:.1f} ms from LB request to backend reply).",
                            "Application-level processing delay (e.g., database query, blocking I/O).",
                        ]

                    # ── Return-path visibility (backend replied; did LB return to client?) ──
                    _rp = _detect_return_path_visibility(
                        source_ip, destination_ip,
                        self._flows.values(), _roles_dict,
                    )
                    if not _rp["return_path_observed"]:
                        hypotheses = list(hypotheses) + [
                            "Capture point may not cover the LB-to-client path segment — "
                            "asymmetric routing or monitoring point location is a common "
                            "cause of missing return flows.",
                            "Backend response was observed but no return flow from LB to "
                            "client detected — possible return-path interruption between LB and client.",
                            "A firewall or intermediate device may be silently filtering return traffic.",
                        ]
                    else:
                        hypotheses = list(hypotheses) + [
                            "Return traffic from LB toward client was observed — "
                            "if the issue persists, investigate application-layer content or client-side behaviour.",
                        ]

        # ── Firewall path interference ────────────────────────────────────────
        _backend_resp_observed = bool(_bq and _bq["backend_response_observed"])
        _return_path_obs       = bool(_rp and _rp["return_path_observed"])
        _fw = _detect_firewall_path_interference(
            source_ip, destination_ip, relevant_packets, _roles_dict or {}
        )
        # Carry over any RST-on-known-firewall evidence notes.
        _fw_vis = list(_fw["firewall_evidence_notes"])
        hypotheses = list(hypotheses) + _fw["firewall_hypotheses"]

        # Rule 2: RST observed + return path absent + firewall IPs configured.
        if (_fw["rst_observed"]
                and not _return_path_obs
                and (_roles_dict or {}).get("firewall_ips")):
            hypotheses = list(hypotheses) + [
                "RST packet observed and no return path detected — "
                "could suggest a firewall is actively blocking or resetting return traffic.",
                "A firewall-generated reset may indicate traffic policy enforcement on this path.",
                "Intermediate filtering on the return path cannot be confirmed from this capture alone.",
            ]

        # Rule 3: backend replied, return path absent, no RST → silent drop.
        if _backend_resp_observed and not _return_path_obs and not _fw["rst_observed"]:
            hypotheses = list(hypotheses) + [
                "Backend response was observed but no RST and no return path detected — "
                "may indicate a silent drop on the return path.",
                "A firewall or intermediate device could be filtering return traffic silently.",
                "A capture visibility gap on the LB-to-client segment cannot be excluded.",
            ]

        # ── Confidence ────────────────────────────────────────────────────────
        conf_score, conf_reason = self._compute_confidence(
            relevant_packets, relevant_flows, syn_pkt, synack_pkt
        )

        # ── Visibility gaps ───────────────────────────────────────────────────
        visibility_notes = self._visibility_notes(
            relevant_packets, relevant_flows,
            syn_pkt, destination_port
        )
        visibility_notes.extend(_role_vis)    # role-based visibility notes
        visibility_notes.extend(_fw_vis)      # firewall evidence notes

        # ── Determine protocol ────────────────────────────────────────────────
        protocol = self._infer_protocol(relevant_packets, destination_port)

        # ── Return path ───────────────────────────────────────────────────────
        return_note = self._return_path_note(relevant_packets, source_ip, destination_ip)

        result = PathAnalysisResult(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            connection_state=state,
            path_summary=summary,
            hop_sequence=[source_ip, destination_ip],   # expanded by future topology layer
            timing_breakdown=timing,
            timing_interpretation=timing_interp,
            return_path_observation=return_note,
            likely_failure_point=failure,
            alternative_hypotheses=hypotheses,
            confidence_score=conf_score,
            confidence_reasoning=conf_reason,
            evidence_packets=[p.num for p in relevant_packets[:50]],
            evidence_flows=[f.key for f in relevant_flows],
            missing_visibility_notes=visibility_notes,
        )

        # ── Outcome / impairment model (computed first so confidence can use it) ──
        oi = _classify_outcome_and_impairments(
            state, timing,
            lb_vis=_lb_vis, bq=_bq, rp=_rp, fw=_fw,
        )
        result.connection_outcome  = oi["connection_outcome"]
        result.primary_impairment  = oi["primary_impairment"]
        result.path_impairments    = oi["path_impairments"]

        # ── Path confidence (uses impairment list for calibrated adjustments) ──
        pc = _compute_path_confidence(
            timing, visibility_notes,
            lb_vis=_lb_vis, bq=_bq, rp=_rp, fw=_fw,
            path_impairments=oi["path_impairments"],
        )
        result.path_confidence_score = pc["path_confidence_score"]
        result.confidence_reasons    = pc["confidence_reasons"]

        # ── Path narrative ────────────────────────────────────────────────────
        narrative = _compose_path_narrative(
            source_ip, destination_ip, result, _roles_dict,
            lb_vis=_lb_vis, bq=_bq, rp=_rp, fw=_fw,
        )
        result.path_steps = narrative["path_steps"]
        # path_summary keeps the step_e verdict; path_steps carries the full narrative.

        # ── Structured evidence ───────────────────────────────────────────────
        result.evidence_items = _build_evidence_items(
            source_ip, destination_ip, state, timing,
            oi["path_impairments"],
            relevant_packets, relevant_flows, self._flows.values(),
            roles=_roles_dict, lb_vis=_lb_vis, bq=_bq, rp=_rp, fw=_fw,
        )

        return result

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
