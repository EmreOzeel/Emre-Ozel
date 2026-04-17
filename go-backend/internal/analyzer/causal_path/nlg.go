package causal_path

import "fmt"

// generatePathSummary creates a one-sentence narrative for the result.
func generatePathSummary(r *PathAnalysisResult) string {
	port := ""
	if r.DestinationPort != nil {
		port = fmt.Sprintf(":%d", *r.DestinationPort)
	}
	src := r.SourceIP
	dst := r.DestinationIP + port

	switch r.PrimaryImpairment {
	case "no_server_response", "connection_establishment_failure":
		return fmt.Sprintf("No response received from %s. The connection appears to be silently dropped.", dst)
	case "firewall_interference":
		return fmt.Sprintf("Connection from %s to %s is being blocked by an intermediate device.", src, dst)
	case "connection_refused":
		return fmt.Sprintf("Connection actively refused by %s (TCP RST).", dst)
	case "tls_failure":
		return fmt.Sprintf("TLS handshake failed between %s and %s.", src, dst)
	case "backend_response_delay":
		delay := ""
		if frt, ok := r.TimingBreakdown["first_response_time_ms"].(float64); ok {
			delay = fmt.Sprintf(" (%.0fms average)", frt)
		}
		return fmt.Sprintf("Connection established but backend %s is responding slowly%s.", r.DestinationIP, delay)
	case "syn_timeout":
		return fmt.Sprintf("TCP SYN to %s timed out — destination unreachable or filtered.", dst)
	case "lb_backend_issue":
		return fmt.Sprintf("Load balancer accepted connection but backend forwarding failed for %s.", dst)
	case "return_path_problem":
		return fmt.Sprintf("Backend responded but return path to %s appears incomplete.", src)
	case "packet_loss":
		return fmt.Sprintf("Significant packet loss detected on path to %s.", r.DestinationIP)
	default:
		return fmt.Sprintf("Connection to %s appears normal.", dst)
	}
}

// classifyFailureDomain determines the failure domain from timing data.
func classifyFailureDomain(timing map[string]interface{}) (string, []string) {
	ct, ctOk := timing["connect_time_ms"].(float64)
	frt, frtOk := timing["first_response_time_ms"].(float64)
	tot, totOk := timing["total_observed_latency_ms"].(float64)

	if !ctOk {
		if totOk && tot < 100 {
			return "front_end_connection_failure", []string{
				"Traffic may be filtered before reaching the destination.",
				"Firewall or routing issue on the forward path.",
			}
		}
		return "connection_establishment_failure", []string{
			"Destination may be unreachable.",
			"Firewall may be silently dropping SYN packets.",
			"Destination service may not be listening.",
		}
	}

	if !frtOk {
		return "no_server_response_after_connection", []string{
			"Application may have crashed or hung after accepting connection.",
			"Backend service may be overloaded.",
			"Capture may lack visibility of server response path.",
		}
	}

	if ct > 100 {
		return "slow_connection_establishment", []string{
			"Network latency between client and server.",
			"Server under high load, slow to accept connections.",
		}
	}

	if frt > 200 {
		return "backend_or_application_delay", []string{
			"Application processing delay.",
			"Database or downstream service latency.",
			"Resource exhaustion on the server.",
		}
	}

	return "no_obvious_failure_detected", nil
}

// returnPathNote generates a return path observation string.
func returnPathNote(packets []NormalizedPacket, srcIP, dstIP string) string {
	fwd := 0
	rev := 0
	for _, p := range packets {
		if p.SrcIP == srcIP && p.DstIP == dstIP { fwd++ }
		if p.SrcIP == dstIP && p.DstIP == srcIP { rev++ }
	}

	if fwd == 0 && rev == 0 {
		return "No packets captured in either direction."
	}
	if rev == 0 {
		return fmt.Sprintf("Only forward traffic captured (%d packets %s→%s). Return path is invisible.", fwd, srcIP, dstIP)
	}
	if fwd == 0 {
		return fmt.Sprintf("Only return traffic captured (%d packets %s→%s). Forward path is invisible.", rev, dstIP, srcIP)
	}

	ratio := float64(rev) / float64(fwd)
	assessment := "symmetric."
	if ratio < 0.5 || ratio > 2.0 {
		assessment = "asymmetric — review capture position."
	}
	return fmt.Sprintf("%d packet(s) %s→%s, %d packet(s) %s→%s. Return ratio %.2fx — %s",
		fwd, srcIP, dstIP, rev, dstIP, srcIP, ratio, assessment)
}

// visibilityNotes collects notes about capture completeness.
func visibilityNotes(packets []NormalizedPacket, synFound bool, dstPort *int) []string {
	var notes []string
	if len(packets) == 0 {
		notes = append(notes, "No packets between this pair were found. Verify the capture covers the relevant timeframe.")
	}
	if !synFound && len(packets) > 0 {
		notes = append(notes, "Capture appears to be mid-stream (no SYN observed).")
	}
	if dstPort == nil {
		notes = append(notes, "No destination port specified. Results cover all ports between this pair.")
	}
	return notes
}
