package causal_path

import (
	"sort"
)

// CausalPathEngine performs path analysis on a set of packets, flows, and findings.
type CausalPathEngine struct {
	packets  []NormalizedPacket
	flows    []FlowRecord
	findings []Finding
}

// NewEngine creates a CausalPathEngine from analysis data.
func NewEngine(packets []NormalizedPacket, flows []FlowRecord, findings []Finding) *CausalPathEngine {
	return &CausalPathEngine{packets: packets, flows: flows, findings: findings}
}

// Analyze performs causal path analysis between a source and destination IP.
func (e *CausalPathEngine) Analyze(
	srcIP, dstIP string,
	dstPort *int,
	rolesMap map[string]interface{},
) *PathAnalysisResult {
	roles := parseRoles(rolesMap)

	// Step A: Filter relevant traffic
	relevant := filterRelevant(e.packets, srcIP, dstIP, dstPort)

	// Sort by time
	sort.Slice(relevant, func(i, j int) bool {
		return relevant[i].Time < relevant[j].Time
	})

	// Step B: Find SYN
	syn := findSYN(relevant, srcIP, dstIP, dstPort)

	// Step C: Find SYN-ACK
	synack := findSYNACK(relevant, srcIP, dstIP, dstPort, syn)

	// Step D: Find data packets
	dataPackets := findDataPackets(relevant, srcIP, dstIP)

	// Step E: Classify connection state
	state := classifyState(syn, synack, dataPackets)

	// Protocol inference
	protocol := inferProtocol(relevant, dstPort)

	// Timing breakdown
	timing := computeTimingBreakdown(relevant, srcIP, dstIP, dstPort)
	timingInterp := interpretTiming(timing)

	// Hop sequence
	hops := buildHopSequence(relevant, srcIP, dstIP, dstPort, roles)

	// Impairment detection
	impairments, evidenceItems := detectImpairments(
		relevant, srcIP, dstIP, dstPort, roles, state, timing,
	)
	primaryImpairment := selectPrimaryImpairment(impairments)

	// Connection outcome derivation
	outcome := deriveOutcome(state, impairments)

	// Confidence scoring
	baseConf := computeBaseConfidence(relevant, syn != nil, synack != nil)
	visNotes := visibilityNotes(relevant, syn != nil, dstPort)

	var ctPtr, frtPtr *float64
	if ct, ok := timing["connect_time_ms"].(float64); ok {
		ctPtr = &ct
	}
	if frt, ok := timing["first_response_time_ms"].(float64); ok {
		frtPtr = &frt
	}

	// LB visibility for confidence scoring
	var lbVis map[string]bool
	if contains(roles.LoadBalancerVIPs, dstIP) {
		lbVis = detectLBBackendVisibility(srcIP, dstIP, relevant, roles)
	}

	fw := detectFirewallInterference(relevant, srcIP, dstIP, roles)

	pathConf, confReasons := computePathConfidence(
		ctPtr, frtPtr, lbVis, nil, nil, fw, impairments, visNotes,
	)

	// Failure domain & NLG
	failureDomain, hypotheses := classifyFailureDomain(timing)
	rpNote := returnPathNote(relevant, srcIP, dstIP)

	// Build result
	result := &PathAnalysisResult{
		SourceIP:        srcIP,
		DestinationIP:   dstIP,
		DestinationPort: dstPort,
		Protocol:        protocol,

		ConnectionState: state,
		ConnectionOutcome: outcome,
		PrimaryImpairment: primaryImpairment,
		PathImpairments:   impairments,

		HopSequence: hops,
		FirewallObservation: HopObservation{
			Role:     "firewall",
			Observed: fw["rst_observed"].(bool),
		},
		LoadBalancerObservation: HopObservation{
			Role:     "load_balancer",
			Observed: lbVis != nil && lbVis["lb_frontend_observed"],
		},
		BackendObservation: HopObservation{Role: "backend"},

		TimingBreakdown:      timing,
		TimingInterpretation: timingInterp,
		ReturnPathObservation: rpNote,

		LikelyFailurePoint:    failureDomain,
		AlternativeHypotheses: hypotheses,

		ConfidenceScore:     baseConf,
		PathConfidenceScore: pathConf,
		ConfidenceReasons:   confReasons,

		EvidenceItems:          evidenceItems,
		MissingVisibilityNotes: visNotes,

		EngineVersion: CacheEngineVersion,
	}

	// Generate NLG summary
	result.PathSummary = generatePathSummary(result)

	// Ensure non-nil slices for JSON serialization
	if result.PathImpairments == nil {
		result.PathImpairments = []string{}
	}
	if result.PathSteps == nil {
		result.PathSteps = []string{}
	}
	if result.HopSequence == nil {
		result.HopSequence = []HopStep{}
	}
	if result.EvidenceItems == nil {
		result.EvidenceItems = []EvidenceItem{}
	}
	if result.ConfidenceReasons == nil {
		result.ConfidenceReasons = []string{}
	}
	if result.MissingVisibilityNotes == nil {
		result.MissingVisibilityNotes = []string{}
	}
	if result.AlternativeHypotheses == nil {
		result.AlternativeHypotheses = []string{}
	}

	return result
}

// ── Pipeline helper functions ────────────────────────────────────────────────

// filterRelevant returns only packets between srcIP and dstIP.
func filterRelevant(packets []NormalizedPacket, srcIP, dstIP string, dstPort *int) []NormalizedPacket {
	var result []NormalizedPacket
	for _, p := range packets {
		match := (p.SrcIP == srcIP && p.DstIP == dstIP) || (p.SrcIP == dstIP && p.DstIP == srcIP)
		if !match {
			continue
		}
		if dstPort != nil {
			if p.DstPort != *dstPort && p.SrcPort != *dstPort {
				continue
			}
		}
		result = append(result, p)
	}
	return result
}

// findSYN returns the first SYN packet from client to server.
func findSYN(packets []NormalizedPacket, srcIP, dstIP string, dstPort *int) *NormalizedPacket {
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == srcIP && p.DstIP == dstIP && p.IsSYN() {
			if dstPort != nil && p.DstPort != *dstPort {
				continue
			}
			return p
		}
	}
	return nil
}

// findSYNACK returns the first SYN-ACK from server to client.
func findSYNACK(packets []NormalizedPacket, srcIP, dstIP string, dstPort *int, syn *NormalizedPacket) *NormalizedPacket {
	minTime := 0.0
	if syn != nil {
		minTime = syn.Time
	}
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == dstIP && p.DstIP == srcIP && p.IsSYNACK() && p.Time >= minTime {
			if dstPort != nil && p.SrcPort != *dstPort {
				continue
			}
			return p
		}
	}
	return nil
}

// findDataPackets returns packets with application data.
func findDataPackets(packets []NormalizedPacket, srcIP, dstIP string) []NormalizedPacket {
	var result []NormalizedPacket
	for _, p := range packets {
		if p.HasPayload() {
			result = append(result, p)
		} else if !p.IsSYN() && !p.IsFIN() && !p.IsRST() && !p.IsACK() && p.FrameLen > 54 {
			result = append(result, p)
		}
	}
	return result
}

// classifyState determines the connection lifecycle state.
func classifyState(syn, synack *NormalizedPacket, dataPackets []NormalizedPacket) ConnectionState {
	if syn == nil {
		return StateNoAttempt
	}
	if synack == nil {
		return StateNoResponse
	}
	if len(dataPackets) == 0 {
		return StateEstablishedNoData
	}
	return StateDataObserved
}

// deriveOutcome maps connection state and impairments to an outcome label.
func deriveOutcome(state ConnectionState, impairments []string) string {
	switch state {
	case StateDataObserved:
		for _, imp := range impairments {
			if imp == "return_path_problem" {
				return "partial_success"
			}
		}
		return "success"
	case StateEstablishedNoData:
		return "failure"
	case StateNoResponse:
		return "failure"
	case StateNoAttempt:
		return "unknown"
	default:
		return "unknown"
	}
}
