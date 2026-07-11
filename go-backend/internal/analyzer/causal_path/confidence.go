package causal_path

import "math"

// computeBaseConfidence calculates the initial confidence score based on
// packet availability and SYN/SYNACK detection.
func computeBaseConfidence(packets []NormalizedPacket, flowsFound, synFound, synackFound bool) int {
	n := len(packets)
	score := 50

	if n == 0 {
		return 10
	}
	if n < 5 {
		score -= 15
	} else if n >= 20 {
		score += 10
	}

	// Flow record bonus — only when an actual flow record exists for the pair
	// (mirrors Python _compute_confidence: `if flows: score += 5`).
	if flowsFound {
		score += 5
	}

	if synFound {
		score += 10
	} else {
		score -= 10
	}

	if synackFound {
		score += 10
	}

	if score < 10 {
		score = 10
	}
	if score > 95 {
		score = 95
	}
	return score
}

// computePathConfidence calculates the penalty-based path confidence score.
// It starts at 100 and deducts for visibility gaps and conflicting signals.
func computePathConfidence(
	connectTimeMs *float64,
	firstResponseTimeMs *float64,
	lbVis map[string]bool,         // lb_backend_observed, lb_frontend_observed
	bq map[string]interface{},      // backend_response_observed, backend_response_delay_ms
	rp map[string]interface{},      // return_path_observed
	fw map[string]interface{},      // rst_observed, firewall_evidence_notes
	impairments []string,
	visibilityNotes []string,
) (int, []string) {
	score := 100
	var reasons []string

	// Timing gaps
	if connectTimeMs == nil {
		score -= 20
		reasons = append(reasons, "Connection establishment not observed — SYN-ACK not confirmed.")
	}
	if firstResponseTimeMs == nil {
		score -= 15
		reasons = append(reasons, "First server response not observed — server behaviour unclear.")
	}

	// LB-specific gaps
	if lbVis != nil {
		if !lbVis["lb_backend_observed"] {
			score -= 10
			reasons = append(reasons, "LB-to-backend forwarding not observed — backend reachability unknown.")
		}
	}
	if bq != nil {
		if observed, ok := bq["backend_response_observed"].(bool); ok && !observed {
			score -= 15
			reasons = append(reasons, "Backend response not observed — backend may be silent or unreachable.")
		}
	}
	if rp != nil {
		if observed, ok := rp["return_path_observed"].(bool); ok && !observed {
			score -= 10
			reasons = append(reasons, "Return path visibility incomplete — LB-to-client flow not observed.")
		}
	}

	// Capture completeness
	if len(visibilityNotes) > 0 {
		penalty := len(visibilityNotes) * 5
		if penalty > 20 {
			penalty = 20
		}
		score -= penalty
		reasons = append(reasons, "Analysis based on partial capture — visibility gaps detected.")
	}

	// Conflicting signals
	if fw != nil {
		rstObserved, _ := fw["rst_observed"].(bool)
		if bq != nil {
			beObserved, _ := bq["backend_response_observed"].(bool)
			if rstObserved && beObserved {
				score -= 15
				reasons = append(reasons, "Conflicting signals: RST observed alongside backend response.")
			}
		}
		if notes, ok := fw["firewall_evidence_notes"].([]string); ok && len(notes) > 0 {
			reasons = append(reasons, "RST observed involving a known firewall address.")
		}
	}

	// Impairment-specific adjustments
	if len(impairments) == 1 && impairments[0] == "backend_response_delay" {
		if firstResponseTimeMs != nil && *firstResponseTimeMs > 200 && *firstResponseTimeMs <= 500 {
			score -= 15
			reasons = append(reasons, "Backend delay is in the borderline range (200–500 ms).")
		}
	}
	if len(impairments) == 1 && impairments[0] == "return_path_problem" {
		score -= 10
		reasons = append(reasons, "Return path absence is the only impairment — likely a capture visibility gap.")
	}

	// Clamp
	score = int(math.Max(0, math.Min(100, float64(score))))
	return score, reasons
}
