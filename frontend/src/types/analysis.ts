// ─── Primitive enums ──────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'
export type HandshakeStatus = 'complete' | 'failed' | 'mid_stream'
export type CloseBehavior = 'fin' | 'rst' | 'unknown'
export type AsymmetryType = 'balanced' | 'client_heavy' | 'server_heavy' | 'one_sided_send' | 'one_sided_recv'
export type CaptureQuality = 'good' | 'partial' | 'poor' | 'unknown'
export type HostRole = 'client' | 'server' | 'web_server' | 'dns_resolver' | 'mail_server' | 'gateway' | 'unknown'

// ─── Overview / file info ─────────────────────────────────────────────────────

export interface FileInfo {
  filename: string
  file_size_bytes: number
  total_packets: number
  duration_sec: number
  first_packet: string
  last_packet: string
  encapsulation: string
  avg_packet_size: number
  avg_packet_rate: number
  avg_bit_rate: number
}

export interface OverviewStats {
  file_info: FileInfo
  packets_analyzed: number
  analysis_time_sec: number
  issue_counts: {
    critical: number
    high: number
    medium: number
    warning: number
    total: number
  }
}

// ─── Capture quality / expert info ───────────────────────────────────────────

export interface CaptureAssessment {
  quality: CaptureQuality
  quality_label: string
  issues: string[]
  reliable: string[]
  low_confidence: string[]
  inferred: string[]
  observed: string[]
  midstream_count: number
  midstream_pct: number
  failed_handshake_count: number
  no_close_count: number
  total_sessions: number
}

export interface ExpertInfo {
  severity: string
  count: number
  message: string
}

// ─── Executive summary ────────────────────────────────────────────────────────

export type BulletSummary = string[]

// ─── Evidence & findings ──────────────────────────────────────────────────────

export interface Evidence {
  packet_nums: number[]
  flow_keys: string[]
  host_ips: string[]
  time_first: number
  time_last: number
  metrics: Record<string, unknown>
  samples: string[]
}

export interface MitreRef {
  tactic: string
  technique_id: string
  technique_name: string
  subtechnique_id: string
  url: string
}

export interface Finding {
  id: string
  severity: Severity
  confidence: Confidence
  score: number
  category: string
  title: string
  description: string
  explanation: string
  /** Why is the confidence level set to this value — explains signal strength. */
  confidence_note: string
  possible_causes: string[]
  recommended_actions: string[]
  affected_hosts: string[]
  affected_flows: string[]
  evidence: Evidence
  mitre: MitreRef[]
  rule_id: string
  suppressed: boolean
  tags: string[]
}

// ─── TCP sessions / conversations ─────────────────────────────────────────────

export interface TCPSession {
  stream_id: number
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  state: string
  has_syn: boolean
  has_synack: boolean
  has_fin: boolean
  has_rst: boolean
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
  retransmissions: number
  dup_acks: number
  zero_windows: number
  out_of_order: number
  handshake_rtt_ms: number
  duration_sec: number
  flow_key: string
  // Interpretation fields
  protocol_guess: string
  handshake_status: HandshakeStatus
  handshake_label: string
  close_behavior: CloseBehavior
  close_label: string
  confidence: Confidence
  confidence_note: string
  asymmetry_type: AsymmetryType
  asymmetry_note: string
  quality_notes: string[]
  interp_what: string
  interp_why: string
  interp_root_cause: string
  interp_check_next: string[]
}

export interface TCPStats {
  total_sessions: number
  retransmissions: number
  resets: number
  failed_handshakes: number
  midstream: number
  duplicate_acks: number
  zero_windows: number
  out_of_order: number
  sessions: TCPSession[]
}

// ─── Host profiles ────────────────────────────────────────────────────────────

export interface HostProfile {
  ip: string
  mac: string
  role: HostRole
  is_internal: boolean
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
  tcp_sessions_initiated: number
  tcp_sessions_accepted: number
  tcp_sessions_failed: number
  /** Fraction of initiated connections that succeeded (0–1). */
  connection_success_ratio: number
  unique_peers: number
  unique_dst_ports: number
  unique_src_ports: number
  protocols: Record<string, number>
  /** Protocol mix as percentages (protocol → %). */
  protocol_mix_pct: Record<string, number>
  top_peers: Array<{ ip: string; bytes: number }>
  /** Role inferred for each top peer (ip → role string). */
  peer_roles: Record<string, string>
  open_ports: number[]
  anomaly_score: number
  suspicious_behaviors: string[]
  periodic_interval_sec: number
  periodic_jitter: number
}

// ── Compare mode ──────────────────────────────────────────────────────────────

export interface CompareResult {
  file_comparison: {
    a: { filename: string; packets: number; duration_sec: number; size_bytes: number }
    b: { filename: string; packets: number; duration_sec: number; size_bytes: number }
  }
  issue_delta: {
    critical: number; high: number; total: number
    a_total: number; b_total: number
  }
  new_findings: Finding[]
  resolved_findings: Finding[]
  protocol_delta: Record<string, { a: number; b: number; change: string }>
  tcp_delta: {
    retransmissions: { a: number; b: number; change: string }
    zero_windows: { a: number; b: number }
    failed_handshakes: { a: number; b: number }
  }
  dns_delta?: { nxdomain: { a: number; b: number }; avg_rtt_ms: { a: number; b: number } }
  new_hosts: string[]
  removed_hosts: string[]
  comparison_summary: string
}

// ─── Protocol breakdown ───────────────────────────────────────────────────────

export interface ProtocolBreakdown {
  [protocol: string]: number
}

// ─── DNS ──────────────────────────────────────────────────────────────────────

export interface DnsStats {
  total_queries: number
  unique_domains: number
  nxdomain_count: number
  servfail_count: number
  avg_rtt_ms: number
  unanswered_count: number
  query_types: Record<string, number>
  top_queries: Array<{ domain: string; count: number }>
  nxdomains: Array<{ domain: string; count: number }>
  resolvers: Array<{ ip: string; count: number }>
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

export interface HttpStats {
  total_requests: number
  total_responses: number
  method_counts: Record<string, number>
  status_counts: Record<string, number>
  error_4xx: number
  error_5xx: number
  avg_latency_ms: number
  top_hosts: Array<{ host: string; count: number }>
  top_uris: Array<{ uri: string; count: number }>
  top_user_agents: Array<{ ua: string; count: number }>
}

// ─── TLS ──────────────────────────────────────────────────────────────────────

export interface TlsStats {
  total_streams: number
  unique_sni: number
  version_counts: Record<string, number>
  deprecated_count: number
  weak_cipher_count: number
  top_sni: Array<{ sni: string; count: number }>
  handshake_counts: Record<string, number>
  ja3_hashes: string[]
  ja3s_hashes: string[]
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

export interface TimelineEvent {
  ts: number
  type: string
  src_ip: string
  dst_ip: string
  label: string
  detail: string
  severity: Severity
  protocol: string
  packet_num: number
}

// ─── Top-level analysis response ─────────────────────────────────────────────

export interface AnalysisData {
  file_info: FileInfo
  packets_analyzed: number
  analysis_time_sec: number
  bullet_summary: BulletSummary
  capture_assessment: CaptureAssessment
  protocol_stats: ProtocolBreakdown
  tcp: TCPStats
  dns: DnsStats
  http: HttpStats
  tls: TlsStats
  hosts: HostProfile[]
  host_stories: Record<string, string>
  flow_stories: Record<string, string>
  all_issues: Finding[]
  all_findings: Finding[]
  suppressed_findings: Finding[]
  issue_counts: OverviewStats['issue_counts']
  timeline: TimelineEvent[]
  expert_info: ExpertInfo[]
  executive_summary: string
  technical_summary: string
  capture_story: string
  tcp_conversations: Record<string, unknown>[]
}

export interface AnalysisDetail {
  id: string
  filename: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  packet_count: number | null
  issue_count: number | null
  critical_count: number | null
  created_at: string | null
  started_at: string | null
  finished_at: string | null
  error: string | null
  data: AnalysisData | null
}
