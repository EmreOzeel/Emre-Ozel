"""
Normalized intermediate data models for investigation-grade PCAP analysis.
All analyzers operate on these models, never on raw tshark output.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum
import hashlib


# ── Enumerations ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class HostRole(str, Enum):
    SERVER = "server"
    CLIENT = "client"
    GATEWAY = "gateway"
    DNS_RESOLVER = "dns_resolver"
    MAIL_SERVER = "mail_server"
    WEB_SERVER = "web_server"
    UNKNOWN = "unknown"


class TCPState(str, Enum):
    SYN_SENT = "syn_sent"
    ESTABLISHED = "established"
    FIN_CLOSED = "fin_closed"
    RESET = "reset"
    HALF_OPEN = "half_open"
    MID_STREAM = "mid_stream"


# ── Core packet / flow records ────────────────────────────────────────────────

@dataclass
class PacketRecord:
    """Normalized representation of a single packet."""
    num: int
    ts: float                    # epoch seconds
    frame_len: int
    protocol: str                # highest-layer protocol
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    ip_ttl: int = 0
    ip_proto: int = 0            # 6=TCP, 17=UDP, 1=ICMP
    # TCP
    tcp_stream: int = -1
    tcp_flags_syn: bool = False
    tcp_flags_ack: bool = False
    tcp_flags_fin: bool = False
    tcp_flags_rst: bool = False
    tcp_flags_psh: bool = False
    tcp_flags_urg: bool = False
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    tcp_payload_len: int = 0
    # tshark expert
    retransmission: bool = False
    dup_ack: bool = False
    out_of_order: bool = False
    fast_retransmit: bool = False
    zero_window: bool = False
    keep_alive: bool = False
    # Layer keys (set if layer is present)
    has_dns: bool = False
    has_http: bool = False
    has_tls: bool = False
    has_arp: bool = False
    has_icmp: bool = False
    has_dhcp: bool = False
    # Raw extras (protocol-specific fields kept as dict for analyzers)
    extras: Dict[str, str] = field(default_factory=dict)

    @property
    def flow_key(self) -> str:
        """Canonical bidirectional flow key."""
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)
        lo, hi = (a, b) if a <= b else (b, a)
        return f"{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}-{self.ip_proto}"


@dataclass
class FlowRecord:
    """Bidirectional network flow (5-tuple)."""
    key: str
    proto: int                    # 6=TCP, 17=UDP, 1=ICMP
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    # Timing
    first_seen: float = 0.0
    last_seen: float = 0.0
    # Volume
    fwd_packets: int = 0          # src→dst
    rev_packets: int = 0          # dst→src
    fwd_bytes: int = 0
    rev_bytes: int = 0
    # TCP specific
    tcp_stream: int = -1
    state: TCPState = TCPState.MID_STREAM
    # Quality
    retransmissions: int = 0
    dup_acks: int = 0
    out_of_order: int = 0
    zero_windows: int = 0
    rtt_samples: List[float] = field(default_factory=list)
    # Content markers
    has_dns: bool = False
    has_http: bool = False
    has_tls: bool = False
    # Packet refs
    packet_nums: List[int] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.rev_bytes

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.rev_packets

    @property
    def avg_rtt_ms(self) -> float:
        return (sum(self.rtt_samples) / len(self.rtt_samples) * 1000) if self.rtt_samples else 0.0


@dataclass
class SessionRecord:
    """TCP session with state machine tracking."""
    stream_id: int
    flow_key: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: TCPState = TCPState.MID_STREAM
    has_syn: bool = False
    has_synack: bool = False
    has_fin: bool = False
    has_rst: bool = False
    syn_ts: float = 0.0
    synack_ts: float = 0.0
    fin_ts: float = 0.0
    first_data_ts: float = 0.0
    last_ts: float = 0.0
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    retransmissions: int = 0
    dup_acks: int = 0
    zero_windows: int = 0
    out_of_order: int = 0
    fast_retransmits: int = 0
    packet_nums: List[int] = field(default_factory=list)

    @property
    def handshake_rtt_ms(self) -> float:
        if self.syn_ts and self.synack_ts:
            return (self.synack_ts - self.syn_ts) * 1000
        return 0.0

    @property
    def handshake_success(self) -> bool:
        return self.has_syn and self.has_synack


# ── Protocol transactions ────────────────────────────────────────────────────

@dataclass
class DnsTransaction:
    """Correlated DNS query + response."""
    txid: int
    query_pkt: int                # packet number of query
    response_pkt: int = 0         # 0 = unanswered
    ts_query: float = 0.0
    ts_response: float = 0.0
    client_ip: str = ""
    resolver_ip: str = ""
    qname: str = ""
    qtype: str = ""               # A, AAAA, MX, TXT, PTR, ...
    rcode: str = ""               # NOERROR, NXDOMAIN, SERVFAIL, ...
    answers: List[str] = field(default_factory=list)
    ttls: List[int] = field(default_factory=list)
    is_nxdomain: bool = False
    is_servfail: bool = False
    is_truncated: bool = False
    # DGA / tunneling indicators
    label_entropy: float = 0.0    # Shannon entropy of longest label
    label_length: int = 0         # length of longest label
    subdomain_depth: int = 0      # dots in qname
    # Computed
    rtt_ms: float = 0.0

    @property
    def answered(self) -> bool:
        return self.response_pkt > 0


@dataclass
class HttpTransaction:
    """Correlated HTTP request + response."""
    stream_id: int
    request_pkt: int
    response_pkt: int = 0
    ts_request: float = 0.0
    ts_response: float = 0.0
    client_ip: str = ""
    server_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    method: str = ""
    uri: str = ""
    host: str = ""
    user_agent: str = ""
    referrer: str = ""
    content_type_req: str = ""
    status_code: int = 0
    content_type_resp: str = ""
    resp_content_length: int = 0
    # Auth / cookie
    auth_header: str = ""
    cookie: str = ""
    set_cookie: str = ""
    # Redirects
    location: str = ""
    # Indicators
    latency_ms: float = 0.0


@dataclass
class TlsHandshake:
    """TLS handshake metadata."""
    stream_id: int
    client_pkt: int               # ClientHello packet number
    server_pkt: int = 0           # ServerHello packet number
    ts_client: float = 0.0
    ts_server: float = 0.0
    client_ip: str = ""
    server_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    sni: str = ""
    # Negotiated
    tls_version: str = ""         # TLSv1.2, TLSv1.3, ...
    cipher_suite: str = ""        # negotiated cipher
    alpn: str = ""                # h2, http/1.1, ...
    # Client Hello fields (for JA3)
    client_version: str = ""
    client_ciphers: List[str] = field(default_factory=list)
    client_extensions: List[str] = field(default_factory=list)
    client_curves: List[str] = field(default_factory=list)
    client_ec_formats: List[str] = field(default_factory=list)
    # Computed fingerprints
    ja3: str = ""                 # MD5 of JA3 string
    ja3s: str = ""                # MD5 of JA3S string
    # Alerts
    has_alert: bool = False
    alert_description: str = ""
    # Cert indicators
    cert_common_name: str = ""
    cert_issuer: str = ""
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_self_signed: bool = False
    cert_expired: bool = False
    cert_mismatch: bool = False   # SNI != cert CN


# ── Host profile ─────────────────────────────────────────────────────────────

@dataclass
class HostProfile:
    """Behavioral profile of a network host."""
    ip: str
    mac: str = ""
    # Traffic
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    # Connections
    unique_peers: int = 0
    unique_dst_ports: int = 0
    unique_src_ports: int = 0
    tcp_sessions_initiated: int = 0
    tcp_sessions_accepted: int = 0
    tcp_sessions_failed: int = 0
    # Protocol usage (protocol → frame count)
    protocols: Dict[str, int] = field(default_factory=dict)
    # Role inference
    role: HostRole = HostRole.UNKNOWN
    is_internal: bool = False
    # Peers
    top_peers: List[Tuple[str, int]] = field(default_factory=list)   # (ip, bytes)
    # Timing / beaconing
    connection_timestamps: List[float] = field(default_factory=list)
    periodic_interval_sec: float = 0.0    # > 0 if periodic behavior detected
    periodic_jitter: float = 0.0
    # Anomaly
    anomaly_score: float = 0.0            # 0.0 – 10.0
    suspicious_behaviors: List[str] = field(default_factory=list)
    # Service fingerprints
    open_ports: List[int] = field(default_factory=list)
    banner: str = ""
    os_guess: str = ""


# ── Timeline & findings ───────────────────────────────────────────────────────

@dataclass
class TimelineEvent:
    ts: float
    event_type: str               # dns_query, http_req, tls_hello, syn_scan, ...
    src_ip: str
    dst_ip: str
    label: str
    detail: str = ""
    severity: Severity = Severity.INFO
    flow_key: str = ""
    packet_num: int = 0
    protocol: str = ""


@dataclass
class Evidence:
    """Evidence bundle attached to a Finding."""
    packet_nums: List[int] = field(default_factory=list)
    flow_keys: List[str] = field(default_factory=list)
    host_ips: List[str] = field(default_factory=list)
    time_first: float = 0.0
    time_last: float = 0.0
    metrics: Dict[str, Any] = field(default_factory=dict)
    samples: List[str] = field(default_factory=list)   # human-readable examples


@dataclass
class MitreRef:
    tactic: str
    technique_id: str
    technique_name: str
    url: str = ""
    subtechnique_id: str = ""
    subtechnique_name: str = ""


@dataclass
class Finding:
    """Evidence-first security finding."""
    id: str
    severity: Severity
    confidence: Confidence
    score: float                  # 0.0 – 10.0
    category: str
    title: str
    description: str
    explanation: str
    possible_causes: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    affected_flows: List[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)
    mitre: List[MitreRef] = field(default_factory=list)
    rule_id: str = ""
    suppressed: bool = False
    tags: List[str] = field(default_factory=list)


# ── File info ─────────────────────────────────────────────────────────────────

@dataclass
class FileInfo:
    filename: str = ""
    file_size_bytes: int = 0
    total_packets: int = 0
    duration_sec: float = 0.0
    first_packet: str = ""
    last_packet: str = ""
    encapsulation: str = ""
    avg_packet_size: float = 0.0
    avg_packet_rate: float = 0.0
    avg_bit_rate: float = 0.0


# ── Top-level container ───────────────────────────────────────────────────────

@dataclass
class CaptureContext:
    """
    Central data container that flows through the entire analysis pipeline.
    Normalizer populates it; analyzers annotate it; correlator enriches it.
    """
    file_info: FileInfo = field(default_factory=FileInfo)
    # Normalized data
    packets: List[PacketRecord] = field(default_factory=list)
    flows: Dict[str, FlowRecord] = field(default_factory=dict)
    sessions: Dict[int, SessionRecord] = field(default_factory=dict)  # stream_id → session
    hosts: Dict[str, HostProfile] = field(default_factory=dict)
    # Protocol transactions
    dns_transactions: List[DnsTransaction] = field(default_factory=list)
    http_transactions: List[HttpTransaction] = field(default_factory=list)
    tls_handshakes: List[TlsHandshake] = field(default_factory=list)
    # Analysis results
    timeline: List[TimelineEvent] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    # Protocol statistics (from tshark -z io,phs)
    protocol_stats: Dict[str, int] = field(default_factory=dict)
    # Expert info from tshark
    expert_info: List[Dict] = field(default_factory=list)
    # TCP conversations from tshark -z conv,tcp
    tcp_conversations: List[Dict] = field(default_factory=list)
    # Generated narrative
    executive_summary: str = ""
    technical_summary: str = ""
    capture_story: str = ""
    host_stories: Dict[str, str] = field(default_factory=dict)
    flow_stories: Dict[str, str] = field(default_factory=dict)
    # Metadata
    packets_analyzed: int = 0
    analysis_time_sec: float = 0.0
