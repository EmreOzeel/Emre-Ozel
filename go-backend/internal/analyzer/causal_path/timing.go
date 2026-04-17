package causal_path

import "math"

// computeConnectTimeMs returns the TCP handshake time (SYN to SYN-ACK) in ms.
func computeConnectTimeMs(packets []NormalizedPacket, srcIP, dstIP string, dstPort *int) *float64 {
	// Find first SYN: src=srcIP, dst=dstIP, SYN=true, ACK=false
	var syn *NormalizedPacket
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == srcIP && p.DstIP == dstIP && p.IsSYN() {
			if dstPort != nil && p.DstPort != *dstPort {
				continue
			}
			syn = p
			break
		}
	}
	if syn == nil {
		return nil
	}

	// Find first SYN-ACK: src=dstIP, dst=srcIP, SYN+ACK=true
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == dstIP && p.DstIP == srcIP && p.IsSYNACK() && p.Time >= syn.Time {
			if dstPort != nil && p.SrcPort != *dstPort {
				continue
			}
			ms := math.Round((p.Time-syn.Time)*1000*1000) / 1000 // 3 decimals
			return &ms
		}
	}
	return nil
}

// computeFirstResponseTimeMs returns time from handshake completion to first server data.
func computeFirstResponseTimeMs(packets []NormalizedPacket, srcIP, dstIP string, dstPort *int) *float64 {
	// Step 1: Find SYN
	var syn *NormalizedPacket
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == srcIP && p.DstIP == dstIP && p.IsSYN() {
			if dstPort != nil && p.DstPort != *dstPort { continue }
			syn = p
			break
		}
	}
	if syn == nil { return nil }

	// Step 2: Find SYN-ACK
	var synack *NormalizedPacket
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == dstIP && p.DstIP == srcIP && p.IsSYNACK() && p.Time >= syn.Time {
			if dstPort != nil && p.SrcPort != *dstPort { continue }
			synack = p
			break
		}
	}
	if synack == nil { return nil }

	// Step 3: Find final ACK (handshake completion) — client→server, ACK only, no payload
	var finalAck *NormalizedPacket
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == srcIP && p.DstIP == dstIP && p.IsACK() && p.TCPPayloadLen == 0 && p.Time >= synack.Time {
			finalAck = p
			break
		}
	}
	if finalAck == nil { return nil }

	// Step 4: Find first server data — server→client, has payload
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == dstIP && p.DstIP == srcIP && p.HasPayload() && p.Time >= finalAck.Time {
			ms := math.Round((p.Time-finalAck.Time)*1000*1000) / 1000
			return &ms
		}
	}
	return nil
}

// computeTotalObservedLatencyMs returns (last - first) packet time in ms.
func computeTotalObservedLatencyMs(packets []NormalizedPacket) *float64 {
	if len(packets) == 0 {
		return nil
	}
	minT := packets[0].Time
	maxT := packets[0].Time
	for _, p := range packets[1:] {
		if p.Time < minT { minT = p.Time }
		if p.Time > maxT { maxT = p.Time }
	}
	ms := math.Round((maxT-minT)*1000*1000) / 1000
	return &ms
}

// computeTimingBreakdown computes all timing metrics.
func computeTimingBreakdown(packets []NormalizedPacket, srcIP, dstIP string, dstPort *int) map[string]interface{} {
	result := make(map[string]interface{})

	if ct := computeConnectTimeMs(packets, srcIP, dstIP, dstPort); ct != nil {
		result["connect_time_ms"] = *ct
	}
	if frt := computeFirstResponseTimeMs(packets, srcIP, dstIP, dstPort); frt != nil {
		result["first_response_time_ms"] = *frt
	}
	if tot := computeTotalObservedLatencyMs(packets); tot != nil {
		result["total_observed_latency_ms"] = *tot
	}

	return result
}

// interpretTiming generates a human-readable interpretation of timing data.
func interpretTiming(timing map[string]interface{}) string {
	ct, ctOk := timing["connect_time_ms"].(float64)
	frt, frtOk := timing["first_response_time_ms"].(float64)
	tot, totOk := timing["total_observed_latency_ms"].(float64)

	if !ctOk {
		if totOk && tot < 100 && !frtOk {
			return "A very short exchange was observed with no server response, suggesting a brief failed connection attempt."
		}
		return "Connection establishment was not observed or did not complete."
	}

	if !frtOk {
		return "Connection was established, but no server response data was observed."
	}

	if ct > 100 {
		return "Connection establishment appears slower than expected."
	}

	if frt > 200 {
		return "Connection was established quickly, but the server response appears delayed."
	}

	return "Connection establishment and first server response were observed with no obvious delay."
}
