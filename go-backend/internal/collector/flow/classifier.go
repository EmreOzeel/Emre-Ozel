package flow

import (
	"math"
)

// FlowClassification holds the computed classification metadata for a flushed flow.
type FlowClassification struct {
	FlowType           string   `json:"flow_type"`
	ResetRatio         float64  `json:"reset_ratio"`
	DenyRatio          float64  `json:"deny_ratio"`
	BurstScore         float64  `json:"burst_score"`
	AsymmetricBehavior bool     `json:"asymmetric_behavior"`
	SuspiciousReasons  []string `json:"suspicious_reasons"`
}

// ClassifyFlow analyses an ActiveFlow and returns its classification.
func ClassifyFlow(f *ActiveFlow) FlowClassification {
	totalActions := f.AllowCount + f.DenyCount + f.DropCount + f.ResetCount + f.AlertCount
	if totalActions == 0 {
		totalActions = 1
	}

	resetRatio := float64(f.ResetCount) / float64(totalActions)
	denyRatio := float64(f.DenyCount+f.DropCount) / float64(totalActions)

	durSecs := f.LastSeen.Sub(f.FirstSeen).Seconds()
	if durSecs < 0.001 {
		durSecs = 0.001
	}
	burstScore := float64(f.EventCount) / durSecs

	// Asymmetric detection: large ratio between directions or one direction
	// effectively silent.
	maxDir := math.Max(float64(f.TotalBytesIn), float64(f.TotalBytesOut))
	minDir := math.Max(math.Min(float64(f.TotalBytesIn), float64(f.TotalBytesOut)), 1)
	asymmetric := (maxDir/minDir >= 10) || (maxDir > 1000 && minDir <= 1)

	totalBytes := f.TotalBytesIn + f.TotalBytesOut

	var flowType string
	var reasons []string

	// Classification order matters -- most specific first.
	switch {
	case f.AllowCount == 0 && f.DenyCount > 0 && f.ResetCount == 0 && totalBytes < 500 && durSecs < 5:
		flowType = "scanning"
		reasons = append(reasons, "zero_allow_short_denied")

	case f.AllowCount == 0 && (f.DenyCount+f.DropCount) > 0 && f.ResetCount == 0:
		flowType = "blocked"
		reasons = append(reasons, "all_denied_or_dropped")

	case f.ResetCount > 0 && (f.AllowCount > 0 || f.DenyCount > 0):
		flowType = "unstable"
		reasons = append(reasons, "reset_with_mixed_actions")

	case (f.ResetCount > 0 && f.AllowCount == 0) || f.AlertCount > 0 || (f.AllowCount > 0 && resetRatio > 0.3):
		flowType = "suspicious"
		if f.ResetCount > 0 && f.AllowCount == 0 {
			reasons = append(reasons, "reset_only")
		}
		if f.AlertCount > 0 {
			reasons = append(reasons, "alerts_present")
		}
		if resetRatio > 0.3 {
			reasons = append(reasons, "high_reset_ratio")
		}

	default:
		flowType = "normal"
	}

	// Ensure reasons is never nil so JSON serialisation produces [] not null.
	if reasons == nil {
		reasons = []string{}
	}

	return FlowClassification{
		FlowType:           flowType,
		ResetRatio:         resetRatio,
		DenyRatio:          denyRatio,
		BurstScore:         burstScore,
		AsymmetricBehavior: asymmetric,
		SuspiciousReasons:  reasons,
	}
}
