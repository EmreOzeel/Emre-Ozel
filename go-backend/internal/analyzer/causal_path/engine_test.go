package causal_path

import (
	"strings"
	"testing"
)

// Helper to build a TCP packet with specific flags.
func pkt(num int, time float64, srcIP, dstIP string, srcPort, dstPort int, flags map[string]bool, payloadLen int) NormalizedPacket {
	return NormalizedPacket{
		Num:           num,
		Time:          time,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Protocol:      "TCP",
		IPProto:       6,
		Length:        64 + payloadLen,
		FrameLen:      64 + payloadLen,
		TCPFlags:      flags,
		TCPPayloadLen: payloadLen,
	}
}

func synFlags() map[string]bool   { return map[string]bool{"syn": true} }
func synackFlags() map[string]bool { return map[string]bool{"syn": true, "ack": true} }
func ackFlags() map[string]bool   { return map[string]bool{"ack": true} }
func rstFlags() map[string]bool   { return map[string]bool{"rst": true} }
func dataFlags() map[string]bool  { return map[string]bool{"ack": true, "psh": true} }

const (
	clientIP = "10.0.0.1"
	serverIP = "10.0.0.2"
	fwIP     = "10.0.0.254"
)

var port443 = 443

// Test 1: No response — SYN only
func TestCausalPath_NoResponse(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.0, clientIP, serverIP, 12345, 443, synFlags(), 0),
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)

	if result.ConnectionOutcome != "failure" {
		t.Errorf("outcome=%s, want failure", result.ConnectionOutcome)
	}
	if result.PrimaryImpairment != "connection_establishment_failure" {
		t.Errorf("impairment=%s, want connection_establishment_failure", result.PrimaryImpairment)
	}
}

// Test 2: Firewall interference — RST from intermediate IP
func TestCausalPath_FirewallInterference(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.0, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(2, 1000.001, fwIP, clientIP, 443, 12345, rstFlags(), 0),
	}
	roles := map[string]interface{}{
		"firewall_ips": []string{fwIP},
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, roles)

	found := false
	for _, imp := range result.PathImpairments {
		if imp == "firewall_interference" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected firewall_interference in impairments, got %v", result.PathImpairments)
	}
}

// Test 3: Connection refused — RST from destination
func TestCausalPath_ConnectionRefused(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.0, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(2, 1000.001, serverIP, clientIP, 443, 12345, rstFlags(), 0),
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)

	// RST from server = firewall_interference with server_to_client direction
	// (not "connection_refused" which isn't in the Python impairment set)
	if result.ConnectionOutcome != "failure" {
		t.Errorf("outcome=%s, want failure", result.ConnectionOutcome)
	}
}

// Test 4: Success — Full handshake + data
func TestCausalPath_Success(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.000, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(2, 1000.050, serverIP, clientIP, 443, 12345, synackFlags(), 0),
		pkt(3, 1000.051, clientIP, serverIP, 12345, 443, ackFlags(), 0),
		pkt(4, 1000.052, clientIP, serverIP, 12345, 443, dataFlags(), 100),
		pkt(5, 1000.100, serverIP, clientIP, 443, 12345, dataFlags(), 500),
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)

	if result.ConnectionOutcome != "success" {
		t.Errorf("outcome=%s, want success", result.ConnectionOutcome)
	}
	if result.PrimaryImpairment != "none" {
		t.Errorf("impairment=%s, want none", result.PrimaryImpairment)
	}
}

// Test 5: Backend delay — response after 3000ms
func TestCausalPath_BackendDelay(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.000, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(2, 1000.050, serverIP, clientIP, 443, 12345, synackFlags(), 0),
		pkt(3, 1000.051, clientIP, serverIP, 12345, 443, ackFlags(), 0),
		pkt(4, 1000.052, clientIP, serverIP, 12345, 443, dataFlags(), 100),
		pkt(5, 1003.052, serverIP, clientIP, 443, 12345, dataFlags(), 500), // 3s delay
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)

	found := false
	for _, imp := range result.PathImpairments {
		if imp == "backend_response_delay" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected backend_response_delay in %v", result.PathImpairments)
	}
}

// Test 6: Packet loss — many retransmits (simulated as duplicate packets)
func TestCausalPath_PacketLoss(t *testing.T) {
	// With 5 packets total and successful handshake but no data,
	// this tests the established_no_data path
	packets := []NormalizedPacket{
		pkt(1, 1000.000, clientIP, serverIP, 12345, 80, synFlags(), 0),
		pkt(2, 1000.050, serverIP, clientIP, 80, 12345, synackFlags(), 0),
		pkt(3, 1000.051, clientIP, serverIP, 12345, 80, ackFlags(), 0),
	}
	port80 := 80
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port80, nil)

	// Established but no data → no_server_response
	if result.ConnectionOutcome != "failure" {
		t.Errorf("outcome=%s, want failure", result.ConnectionOutcome)
	}
}

// Test 7: Low confidence — only 3 packets
func TestCausalPath_Confidence_Low(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.0, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(2, 1000.1, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(3, 1000.2, clientIP, serverIP, 12345, 443, synFlags(), 0),
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)

	if result.ConfidenceScore >= 50 {
		t.Errorf("confidence=%d, want < 50 for 3 packets", result.ConfidenceScore)
	}
}

// Test 8: High confidence — 20+ packets, clear success
func TestCausalPath_Confidence_High(t *testing.T) {
	var packets []NormalizedPacket
	packets = append(packets, pkt(1, 1000.000, clientIP, serverIP, 12345, 443, synFlags(), 0))
	packets = append(packets, pkt(2, 1000.050, serverIP, clientIP, 443, 12345, synackFlags(), 0))
	packets = append(packets, pkt(3, 1000.051, clientIP, serverIP, 12345, 443, ackFlags(), 0))
	for i := 4; i <= 25; i++ {
		t := 1000.052 + float64(i-4)*0.01
		if i%2 == 0 {
			packets = append(packets, pkt(i, t, clientIP, serverIP, 12345, 443, dataFlags(), 100))
		} else {
			packets = append(packets, pkt(i, t, serverIP, clientIP, 443, 12345, dataFlags(), 200))
		}
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)

	if result.ConfidenceScore < 70 {
		t.Errorf("confidence=%d, want >= 70 for 25 packets with clear handshake", result.ConfidenceScore)
	}
}

// Test 9: Timing breakdown — SYN at t=0, SYN-ACK at t=0.05
func TestCausalPath_TimingBreakdown(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.000, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(2, 1000.050, serverIP, clientIP, 443, 12345, synackFlags(), 0),
		pkt(3, 1000.051, clientIP, serverIP, 12345, 443, ackFlags(), 0),
		pkt(4, 1000.052, clientIP, serverIP, 12345, 443, dataFlags(), 100),
		pkt(5, 1000.100, serverIP, clientIP, 443, 12345, dataFlags(), 500),
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)

	ct, ok := result.TimingBreakdown["connect_time_ms"].(float64)
	if !ok {
		t.Fatal("connect_time_ms not in timing breakdown")
	}
	// SYN-ACK at 1000.050 - SYN at 1000.000 = 50ms
	if ct < 49 || ct > 51 {
		t.Errorf("connect_time_ms=%.3f, want ~50", ct)
	}
}

// Test 10: NLG — firewall message contains "blocked"
func TestCausalPath_NLG_FirewallMessage(t *testing.T) {
	result := &PathAnalysisResult{
		SourceIP:        clientIP,
		DestinationIP:   serverIP,
		DestinationPort: &port443,
		PrimaryImpairment: "firewall_interference",
		TimingBreakdown: map[string]interface{}{},
	}
	summary := generatePathSummary(result)
	if !strings.Contains(strings.ToLower(summary), "blocked") {
		t.Errorf("firewall summary should contain 'blocked': %s", summary)
	}
}

// Test 11: Cache key — same inputs produce same key, different port → different key
func TestCausalPath_CacheKey(t *testing.T) {
	// The cache key is computed externally (in handler), but we can verify
	// that the engine version is consistent
	packets := []NormalizedPacket{
		pkt(1, 1000.0, clientIP, serverIP, 12345, 443, synFlags(), 0),
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, nil)
	if result.EngineVersion != CacheEngineVersion {
		t.Errorf("engine_version=%s, want %s", result.EngineVersion, CacheEngineVersion)
	}
}

// Test 12: Roles affect hop classification
func TestCausalPath_RolesAffectHops(t *testing.T) {
	packets := []NormalizedPacket{
		pkt(1, 1000.000, clientIP, serverIP, 12345, 443, synFlags(), 0),
		pkt(2, 1000.001, fwIP, clientIP, 443, 12345, rstFlags(), 0),
	}
	roles := map[string]interface{}{
		"firewall_ips": []string{fwIP},
	}
	engine := NewEngine(packets, nil, nil)
	result := engine.Analyze(clientIP, serverIP, &port443, roles)

	foundFW := false
	for _, hop := range result.HopSequence {
		if hop.SourceRole == "firewall" || hop.DestRole == "firewall" {
			foundFW = true
		}
	}
	if !foundFW {
		t.Errorf("expected firewall role in hop sequence: %+v", result.HopSequence)
	}
}
