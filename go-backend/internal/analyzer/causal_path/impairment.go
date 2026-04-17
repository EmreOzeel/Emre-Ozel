package causal_path

import "fmt"

// detectImpairments runs all impairment detection rules and returns
// the list of detected impairments plus evidence items.
func detectImpairments(
	packets []NormalizedPacket,
	srcIP, dstIP string,
	dstPort *int,
	roles *TopologyRoles,
	state ConnectionState,
	timing map[string]interface{},
) ([]string, []EvidenceItem) {
	var impairments []string
	var evidence []EvidenceItem

	frt, _ := timing["first_response_time_ms"].(float64)
	frtOk := false
	if _, ok := timing["first_response_time_ms"]; ok {
		frtOk = true
	}

	// Find SYN packet for evidence refs
	var synPkt *NormalizedPacket
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == srcIP && p.DstIP == dstIP && p.IsSYN() {
			if dstPort != nil && p.DstPort != *dstPort { continue }
			synPkt = p
			break
		}
	}

	// Rule 1: connection_establishment_failure
	if state == StateNoResponse || state == StateNoAttempt {
		impairments = append(impairments, "connection_establishment_failure")
		ev := EvidenceItem{
			Type:           "connection_establishment_failure",
			Summary:        "SYN packet observed from client but no SYN-ACK received.",
			SignalStrength: "medium",
		}
		if synPkt != nil {
			ev.PacketRefs = []int{synPkt.Num}
			ev.Timestamps = []float64{synPkt.Time}
			ev.SignalStrength = "high"
		}
		evidence = append(evidence, ev)
	}

	// Rule 2: no_server_response (handshake ok, no data)
	if state == StateEstablishedNoData {
		impairments = append(impairments, "no_server_response")
		evidence = append(evidence, EvidenceItem{
			Type:           "no_server_response",
			Summary:        "TCP handshake completed but no application data was observed.",
			SignalStrength: "high",
		})
	}

	// Rule 3: firewall_interference
	fw := detectFirewallInterference(packets, srcIP, dstIP, roles)
	if rstObserved, ok := fw["rst_observed"].(bool); ok && rstObserved {
		dir, _ := fw["rst_direction"].(string)
		notes, _ := fw["firewall_evidence_notes"].([]string)

		if len(notes) > 0 || dir == "server_to_client" {
			impairments = append(impairments, "firewall_interference")
			dirLabel := "in an unknown direction"
			if dir == "server_to_client" {
				dirLabel = "from server toward client"
			}
			summary := fmt.Sprintf("TCP RST packet observed %s.", dirLabel)
			if len(notes) > 0 {
				summary += " " + notes[0]
			}
			var rstRefs []int
			var rstTs []float64
			for i := range packets {
				p := &packets[i]
				if p.IsRST() {
					rstRefs = append(rstRefs, p.Num)
					rstTs = append(rstTs, p.Time)
					if len(rstRefs) >= 5 { break }
				}
			}
			strength := "medium"
			if len(notes) > 0 {
				strength = "high"
			}
			evidence = append(evidence, EvidenceItem{
				Type:           "firewall_interference",
				Summary:        summary,
				PacketRefs:     rstRefs,
				Timestamps:     rstTs,
				SignalStrength: strength,
			})
		}
	}

	// Rule 4: backend_response_delay
	if frtOk && frt > 200 {
		impairments = append(impairments, "backend_response_delay")
		strength := "medium"
		if frt > 500 {
			strength = "high"
		}
		evidence = append(evidence, EvidenceItem{
			Type:           "backend_response_delay",
			Summary:        fmt.Sprintf("Server first response observed %.1f ms after connection.", frt),
			SignalStrength: strength,
		})
	}

	// Rule 5: lb_backend_issue (only when LB VIP is destination)
	if roles != nil && contains(roles.LoadBalancerVIPs, dstIP) {
		lbVis := detectLBBackendVisibility(srcIP, dstIP, packets, roles)
		if lbVis["lb_frontend_observed"] && !lbVis["lb_backend_observed"] {
			impairments = append(impairments, "lb_backend_issue")
			evidence = append(evidence, EvidenceItem{
				Type:           "lb_backend_issue",
				Summary:        "Client-to-LB frontend flow was observed but no LB-to-backend forwarding detected.",
				SignalStrength: "medium",
			})
		}
	}

	// Rule 6: return_path_problem (only when LB path)
	if roles != nil && contains(roles.LoadBalancerVIPs, dstIP) {
		rp := detectReturnPathVisibility(srcIP, dstIP, packets, roles)
		if !rp["return_path_observed"] {
			impairments = append(impairments, "return_path_problem")
			evidence = append(evidence, EvidenceItem{
				Type:           "return_path_problem",
				Summary:        "Backend response was observed reaching the load balancer, but no return flow to client detected.",
				SignalStrength: "medium",
			})
		}
	}

	return impairments, evidence
}

// selectPrimaryImpairment returns the highest-priority impairment.
func selectPrimaryImpairment(impairments []string) string {
	for _, pri := range impairmentPriority {
		for _, imp := range impairments {
			if imp == pri {
				return imp
			}
		}
	}
	if len(impairments) > 0 {
		return impairments[0]
	}
	return "none"
}

// detectFirewallInterference checks for RST packets and firewall involvement.
func detectFirewallInterference(packets []NormalizedPacket, srcIP, dstIP string, roles *TopologyRoles) map[string]interface{} {
	result := map[string]interface{}{
		"rst_observed":           false,
		"rst_direction":          "",
		"firewall_evidence_notes": []string{},
		"firewall_hypotheses":    []string{},
	}

	var notes []string
	for _, p := range packets {
		if !p.IsRST() {
			continue
		}
		result["rst_observed"] = true

		// Determine direction
		if p.SrcIP == dstIP && p.DstIP == srcIP {
			result["rst_direction"] = "server_to_client"
		} else if p.SrcIP == srcIP && p.DstIP == dstIP {
			if result["rst_direction"] == "" {
				result["rst_direction"] = "client_to_server"
			}
		} else {
			if result["rst_direction"] == "" {
				result["rst_direction"] = "unknown"
			}
		}

		// Check firewall involvement
		if roles != nil {
			if contains(roles.FirewallIPs, p.SrcIP) {
				notes = append(notes, fmt.Sprintf("RST from known firewall %s", p.SrcIP))
			}
			if contains(roles.FirewallIPs, p.DstIP) {
				notes = append(notes, fmt.Sprintf("RST toward known firewall %s", p.DstIP))
			}
		}
	}
	result["firewall_evidence_notes"] = notes
	return result
}

// detectLBBackendVisibility checks for LB-to-backend packet flow.
func detectLBBackendVisibility(srcIP, dstIP string, packets []NormalizedPacket, roles *TopologyRoles) map[string]bool {
	frontendObserved := false
	backendObserved := false

	for _, p := range packets {
		if p.SrcIP == srcIP && p.DstIP == dstIP {
			frontendObserved = true
		}
		if p.SrcIP == dstIP {
			if contains(roles.BackendIPs, p.DstIP) {
				backendObserved = true
			}
			for _, subnet := range roles.BackendSubnets {
				if ipInSubnet(p.DstIP, subnet) {
					backendObserved = true
				}
			}
		}
	}

	return map[string]bool{
		"lb_frontend_observed": frontendObserved,
		"lb_backend_observed":  backendObserved,
	}
}

// detectReturnPathVisibility checks for LB→client return flow.
func detectReturnPathVisibility(srcIP, dstIP string, packets []NormalizedPacket, roles *TopologyRoles) map[string]bool {
	returnObserved := false
	for _, p := range packets {
		if p.SrcIP == dstIP && p.DstIP == srcIP {
			returnObserved = true
			break
		}
	}
	return map[string]bool{
		"return_path_observed": returnObserved,
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
