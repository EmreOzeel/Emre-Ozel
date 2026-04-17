package causal_path

const CacheEngineVersion = "2.0.0-go"

// ConnectionState represents the observed TCP connection lifecycle state.
type ConnectionState string

const (
	StateNoAttempt        ConnectionState = "no_connection_attempt"
	StateNoResponse       ConnectionState = "connection_not_established"
	StateEstablishedNoData ConnectionState = "connection_established_no_data"
	StateDataObserved     ConnectionState = "application_level_interaction"
	StateUnknown          ConnectionState = "unknown"
)

// PathAnalysisResult is the full output of CausalPathEngine.Analyze().
type PathAnalysisResult struct {
	SourceIP        string  `json:"source_ip"`
	DestinationIP   string  `json:"destination_ip"`
	DestinationPort *int    `json:"destination_port"`
	Protocol        string  `json:"protocol"`

	ConnectionState   ConnectionState `json:"connection_state"`
	PathSummary       string          `json:"path_summary"`
	PathSteps         []string        `json:"path_steps"`

	HopSequence              []HopStep       `json:"hop_sequence"`
	FirewallObservation      HopObservation  `json:"firewall_observation"`
	LoadBalancerObservation  HopObservation  `json:"load_balancer_observation"`
	BackendObservation       HopObservation  `json:"backend_observation"`

	TimingBreakdown       map[string]interface{} `json:"timing_breakdown"`
	TimingInterpretation  string                 `json:"timing_interpretation"`

	ReturnPathObservation string `json:"return_path_observation"`

	ConnectionOutcome  string   `json:"connection_outcome"` // success/partial_success/failure/unknown
	PrimaryImpairment  string   `json:"primary_impairment"`
	PathImpairments    []string `json:"path_impairments"`

	LikelyFailurePoint    string   `json:"likely_failure_point"`
	AlternativeHypotheses []string `json:"alternative_hypotheses"`

	ConfidenceScore    int    `json:"confidence_score"`     // 0-100
	ConfidenceReasoning string `json:"confidence_reasoning"`

	PathConfidenceScore int      `json:"path_confidence_score"` // 0-100
	ConfidenceReasons   []string `json:"confidence_reasons"`

	EvidencePackets []int          `json:"evidence_packets"`
	EvidenceFlows   []string       `json:"evidence_flows"`
	EvidenceItems   []EvidenceItem `json:"evidence_items"`

	MissingVisibilityNotes []string `json:"missing_visibility_notes"`

	EngineVersion string `json:"engine_version"`
}

func (r *PathAnalysisResult) ToDict() map[string]interface{} {
	// JSON serialization via struct tags handles this.
	// This method exists for compatibility with cache storage.
	return map[string]interface{}{
		"source_ip":              r.SourceIP,
		"destination_ip":        r.DestinationIP,
		"destination_port":      r.DestinationPort,
		"protocol":              r.Protocol,
		"connection_state":      r.ConnectionState,
		"connection_outcome":    r.ConnectionOutcome,
		"primary_impairment":    r.PrimaryImpairment,
		"path_impairments":      r.PathImpairments,
		"path_summary":          r.PathSummary,
		"path_steps":            r.PathSteps,
		"timing_breakdown":      r.TimingBreakdown,
		"timing_interpretation": r.TimingInterpretation,
		"likely_failure_point":  r.LikelyFailurePoint,
		"confidence_score":      r.ConfidenceScore,
		"path_confidence_score": r.PathConfidenceScore,
		"confidence_reasons":    r.ConfidenceReasons,
		"evidence_items":        r.EvidenceItems,
		"hop_sequence":          r.HopSequence,
		"engine_version":        r.EngineVersion,
	}
}

type HopObservation struct {
	Role     string `json:"role"`
	IP       string `json:"ip"`
	Observed bool   `json:"observed"`
	Note     string `json:"note"`
}

type EvidenceItem struct {
	Type           string    `json:"type"`
	Summary        string    `json:"summary"`
	FlowID         string    `json:"flow_id,omitempty"`
	PacketRefs     []int     `json:"packet_refs"`
	Timestamps     []float64 `json:"timestamps"`
	SignalStrength string    `json:"signal_strength"` // high/medium/low
}

type HopStep struct {
	Step        string   `json:"step"`
	Src         string   `json:"src"`
	Dst         string   `json:"dst"`
	SourceRole  string   `json:"source_role"`
	DestRole    string   `json:"dest_role"`
	Timestamp   float64  `json:"ts"`
	Note        string   `json:"note,omitempty"`
	DelayMs     *float64 `json:"delay_ms,omitempty"`
	ThresholdMs *float64 `json:"threshold_ms,omitempty"`
}

// NormalizedPacket represents a single packet from the capture.
type NormalizedPacket struct {
	Num           int            `json:"num"`
	Time          float64        `json:"time"`          // seconds since epoch
	SrcIP         string         `json:"src_ip"`
	DstIP         string         `json:"dst_ip"`
	SrcPort       int            `json:"src_port"`
	DstPort       int            `json:"dst_port"`
	Protocol      string         `json:"protocol"`      // "TCP"/"UDP"/"ICMP"
	IPProto       int            `json:"ip_proto"`       // 6=TCP, 17=UDP, 1=ICMP
	Length        int            `json:"length"`
	TCPFlags      map[string]bool `json:"tcp_flags"`     // syn, ack, fin, rst, psh
	TCPPayloadLen int            `json:"tcp_payload_len"`
	FrameLen      int            `json:"frame_len"`
}

// Helper accessors for TCP flags
func (p *NormalizedPacket) IsSYN() bool    { return p.TCPFlags["syn"] && !p.TCPFlags["ack"] }
func (p *NormalizedPacket) IsSYNACK() bool { return p.TCPFlags["syn"] && p.TCPFlags["ack"] }
func (p *NormalizedPacket) IsRST() bool    { return p.TCPFlags["rst"] }
func (p *NormalizedPacket) IsACK() bool    { return p.TCPFlags["ack"] && !p.TCPFlags["syn"] && !p.TCPFlags["rst"] && !p.TCPFlags["fin"] }
func (p *NormalizedPacket) IsFIN() bool    { return p.TCPFlags["fin"] }
func (p *NormalizedPacket) HasPayload() bool { return p.TCPPayloadLen > 0 }

// FlowRecord summarizes a bidirectional flow from the analysis.
type FlowRecord struct {
	SrcIP    string   `json:"src_ip"`
	DstIP    string   `json:"dst_ip"`
	SrcPort  int      `json:"src_port"`
	DstPort  int      `json:"dst_port"`
	Protocol string   `json:"protocol"`
	Packets  []int    `json:"packets"`
	Findings []string `json:"findings"`
	FirstSeen float64 `json:"first_seen"`
}

// Finding represents a security/performance finding from analysis.
type Finding struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	PacketNums  []int  `json:"packet_nums"`
}

// TopologyRoles holds the user-supplied IP role hints.
type TopologyRoles struct {
	FirewallIPs      []string `json:"firewall_ips"`
	LoadBalancerVIPs []string `json:"load_balancer_vips"`
	BackendIPs       []string `json:"backend_ips"`
	BackendSubnets   []string `json:"backend_subnets"`
}

// Impairment priority order (index 0 = highest priority).
var impairmentPriority = []string{
	"connection_establishment_failure",
	"no_server_response",
	"firewall_interference",
	"return_path_problem",
	"lb_backend_issue",
	"backend_response_delay",
}

// failureClosing maps failure domain labels to closing sentences.
var failureClosing = map[string]string{
	"no_obvious_failure_detected":
		"No obvious failure was detected along the observed path.",
	"front_end_connection_failure":
		"The most likely issue is a connection failure before the traffic reached the service.",
	"connection_establishment_failure":
		"Connection establishment failed — the service may be unreachable or filtered on this path.",
	"no_server_response_after_connection":
		"The connection was established but no server response was observed — " +
			"this may reflect a service issue or a capture visibility gap on the " +
			"server-side response path.",
	"slow_connection_establishment":
		"Connection establishment appears slow, suggesting possible network latency or overload.",
	"backend_or_application_delay":
		"Timing suggests possible backend or application delay; verify whether " +
			"this latency is within the normal baseline for this service before " +
			"concluding there is a problem.",
}
