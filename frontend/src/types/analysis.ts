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
  /** Evidence quality score 0–100. High = many packets + concrete metrics; low = thin / heuristic. */
  confidence_score: number
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

// ─── Sanity checks / trust score ─────────────────────────────────────────────

export interface SanityWarning {
  check_id: string
  severity: 'warning' | 'info'
  message: string
  detail: string
  related_finding: string | null
  affected_host: string | null
}

export interface TrustComponents {
  capture_completeness: number
  finding_quality: number
  contradiction_penalty: number
}

export interface LowConfidenceFinding {
  rule_id: string
  title: string
  severity: string
  confidence_score: number
  reason: string
}

export interface TrustScore {
  trust_score: number
  trust_label: string
  trust_reasons: string[]
  low_confidence_findings: LowConfidenceFinding[]
  components: TrustComponents
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
  /** Sanity check contradictions between findings and raw stats. */
  sanity_warnings: SanityWarning[]
  /** Overall analysis trust score. */
  trust: TrustScore
  decision_support: Record<string, unknown>
}

export interface AnalysisDetail extends AnalysisSummary {
  data: AnalysisData | null
}

export interface SuppressionRule {
  id: number
  scope: 'global' | 'user' | 'analysis'
  rule_id: string | null
  src_ip: string | null
  dst_ip: string | null
  analysis_id: string | null
  reason: string
  note: string | null
  is_active: boolean
  expires_at: string | null
  created_by: number | null
  created_at: string | null
}

export type TriageStatus = 'new' | 'acknowledged' | 'in_progress' | 'resolved' | 'false_positive'

export interface FindingTriage {
  id: number
  analysis_id: string
  finding_key: string
  status: TriageStatus
  note: string | null
  analyst_id: number | null
  created_at: string | null
  updated_at: string | null
}

// ─── Sharing scope (team workflow) ────────────────────────────────────────────

export type SharingScope = 'private' | 'team' | 'global'

/** Shared fields present on any team-aware object (presets, queries, notes). */
export interface SharedObjectMeta {
  scope: SharingScope
  team_id: number | null
  owner_user_id?: number | null
  created_by?: number | null
  updated_by?: number | null
  can_edit: boolean
}

// ─── Path Analysis Feedback ───────────────────────────────────────────────────

export type PathAnalysisFeedbackVerdict = 'correct' | 'partially_correct' | 'incorrect'

export interface PathAnalysisFeedback {
  id: number
  analysis_id: string
  source_ip: string
  destination_ip: string
  destination_port: number | null
  predicted_outcome: string
  predicted_impairment: string | null
  predicted_confidence: number
  verdict: PathAnalysisFeedbackVerdict
  analyst_note: string | null
  actual_root_cause: string | null
  misleading_step: string | null
  analyst_id: number | null
  scope: Extract<SharingScope, 'private' | 'team'>
  team_id: number | null
  can_edit: boolean
  created_at: string | null
  updated_at: string | null
}

export interface InvestigationNote extends SharedObjectMeta {
  id: number
  analysis_id: string
  source_ip: string
  destination_ip: string
  destination_port: number | null
  body: string
  scope: Extract<SharingScope, 'private' | 'team'>
  created_at: string | null
  updated_at: string | null
}

export interface PathAnalysisFeedbackSummary {
  total: number
  verdict_counts: { correct: number; partially_correct: number; incorrect: number }
  accuracy_rate: number | null
  by_predicted_impairment: Record<string, {
    total: number
    correct: number
    partially_correct: number
    incorrect: number
  }>
  overconfident: PathAnalysisFeedback[]
  weak_narratives: PathAnalysisFeedback[]
}

// ─── Investigation workflow ──────────────────────────────────────────────────

export type WorkflowState =
  | 'new'
  | 'in_progress'
  | 'needs_review'
  | 'resolved'
  | 'dismissed'

export interface WorkflowResponse {
  analysis_id: string
  workflow_state: WorkflowState
  assigned_user_id: number | null
  assignee_username: string | null
  workflow_updated_at: string | null
  workflow_updated_by: number | null
  owner_user_id: number
  can_edit_state: boolean
  can_assign: boolean
}

export interface UserPickerEntry {
  id: number
  username: string
  team_id: number | null
  is_admin: boolean
}

// ─── Notifications ───────────────────────────────────────────────────────────

export type NotificationType =
  | 'assignment'
  | 'review_required'
  | 'resolved'
  | 'feedback_alert'
  | 'mention'

export interface NotificationItem {
  id: number
  type: NotificationType
  analysis_id: string | null
  analysis_filename: string | null
  actor_user_id: number | null
  actor_username: string | null
  message: string
  read_at: string | null
  created_at: string | null
}

// ─── Work queue ──────────────────────────────────────────────────────────────

export type WorkQueueSectionKey =
  | 'needs_review'
  | 'recent_feedback_alerts'
  | 'assigned_to_me'
  | 'new_analyses'
  | 'unresolved_owned'
  | 'recent_resolved'

export interface WorkQueueItem {
  analysis_id: string
  filename: string
  status: string
  workflow_state: WorkflowState
  owner_user_id: number
  owner_username: string | null
  assigned_user_id: number | null
  assignee_username: string | null
  issue_count: number | null
  critical_count: number | null
  workflow_updated_at: string | null
  created_at: string | null
  primary_impairment: string | null
  path_confidence_score: number | null
  latest_feedback_verdict: string | null
  latest_feedback_at: string | null
  latest_notification_type: NotificationType | null
  latest_notification_at: string | null
}

export interface WorkQueueSection {
  key: WorkQueueSectionKey
  label: string
  priority: number
  count: number
  items: WorkQueueItem[]
}

export interface WorkQueueResponse {
  sections: WorkQueueSection[]
  total_open: number
  counts: Record<WorkQueueSectionKey, number>
}

export interface AnalysisSummary {
  id: string
  filename: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  packet_count: number | null
  issue_count: number | null
  critical_count: number | null
  current_stage: string | null
  progress_pct: number
  created_at: string | null
  started_at: string | null
  finished_at: string | null
  error: string | null
  // Investigation workflow fields (present on all list + detail responses)
  workflow_state?: WorkflowState | null
  assigned_user_id?: number | null
  assignee_username?: string | null
  workflow_updated_at?: string | null
  owner_user_id?: number | null
}
