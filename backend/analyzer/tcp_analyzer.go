package analyzer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"pcap-analyzer/models"
)

// TCPFlow tracks state for a single TCP connection
type TCPFlow struct {
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	SYNTime    *time.Time
	SYNACKSeen bool
	ACKSeen    bool
	RSTCount   int
	Retransmissions int
	SeqNums    map[uint32]int // seq -> count
	FirstSeen  time.Time
	LastSeen   time.Time
	BytesSent  int64
}

// TCPState holds all TCP tracking data
type TCPState struct {
	flows        map[string]*TCPFlow
	synCountPerSrc map[string]int // srcIP -> unacknowledged SYN count
	rstPerSrc    map[string]int  // srcIP -> RST count
	synTime      map[string]time.Time // flowKey -> first SYN time
}

func newTCPState() *TCPState {
	return &TCPState{
		flows:          make(map[string]*TCPFlow),
		synCountPerSrc: make(map[string]int),
		rstPerSrc:      make(map[string]int),
		synTime:        make(map[string]time.Time),
	}
}

func flowKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	// Canonical key (smaller IP first to track bidirectional)
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}

func analyzeTCP(packet gopacket.Packet, state *analysisState) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	ts := packet.Metadata().Timestamp
	key := flowKey(srcIP, dstIP, srcPort, dstPort)

	s := state.tcpState

	// Get or create flow
	flow, exists := s.flows[key]
	if !exists {
		flow = &TCPFlow{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			SeqNums:   make(map[uint32]int),
			FirstSeen: ts,
		}
		s.flows[key] = flow
	}
	flow.LastSeen = ts

	payloadLen := int64(len(tcp.Payload))
	flow.BytesSent += payloadLen

	// Track SYN - SYN without ACK means new connection attempt
	if tcp.SYN && !tcp.ACK {
		t := ts
		flow.SYNTime = &t
		s.synCountPerSrc[srcIP]++
		s.synTime[key] = ts
	}

	// SYN-ACK
	if tcp.SYN && tcp.ACK {
		flow.SYNACKSeen = true
		// Reduce unacknowledged SYN count for destination (they responded)
		if s.synCountPerSrc[dstIP] > 0 {
			s.synCountPerSrc[dstIP]--
		}
	}

	// Track RST packets
	if tcp.RST {
		flow.RSTCount++
		s.rstPerSrc[srcIP]++
	}

	// Retransmission detection: same seq number with payload seen more than once
	if payloadLen > 0 && tcp.Seq > 0 {
		flow.SeqNums[tcp.Seq]++
		if flow.SeqNums[tcp.Seq] > 1 {
			flow.Retransmissions++
		}
	}
}

func finalizeTCP(s *TCPState) []models.Finding {
	var findings []models.Finding

	// 1. High retransmission flows
	for key, flow := range s.flows {
		_ = key
		if flow.Retransmissions >= 5 {
			severity := "warning"
			if flow.Retransmissions >= 20 {
				severity = "critical"
			}
			first := flow.FirstSeen
			last := flow.LastSeen
			findings = append(findings, models.Finding{
				Severity:    severity,
				Category:    "tcp",
				Title:       "High TCP Retransmissions Detected",
				Description: fmt.Sprintf("Flow %s:%d → %s:%d has %d retransmitted packets, indicating packet loss or congestion.", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Retransmissions),
				Details: map[string]interface{}{
					"retransmissions": flow.Retransmissions,
					"flow":            fmt.Sprintf("%s:%d → %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort),
				},
				SrcIP:       flow.SrcIP,
				DstIP:       flow.DstIP,
				SrcPort:     int(flow.SrcPort),
				DstPort:     int(flow.DstPort),
				PacketCount: flow.Retransmissions,
				FirstSeen:   &first,
				LastSeen:    &last,
			})
		}
	}

	// 2. SYN flood detection: many SYNs from one source without completing handshake
	for srcIP, synCount := range s.synCountPerSrc {
		if synCount >= 20 {
			severity := "warning"
			if synCount >= 50 {
				severity = "critical"
			}
			findings = append(findings, models.Finding{
				Severity:    severity,
				Category:    "tcp",
				Title:       "Possible SYN Flood Attack",
				Description: fmt.Sprintf("Source IP %s sent %d SYN packets without completing the TCP handshake, which may indicate a SYN flood DoS attack.", srcIP, synCount),
				Details: map[string]interface{}{
					"unanswered_syns": synCount,
				},
				SrcIP:       srcIP,
				PacketCount: synCount,
			})
		}
	}

	// 3. RST flood detection
	for srcIP, rstCount := range s.rstPerSrc {
		if rstCount >= 10 {
			severity := "warning"
			if rstCount >= 30 {
				severity = "critical"
			}
			findings = append(findings, models.Finding{
				Severity:    severity,
				Category:    "tcp",
				Title:       "TCP RST Flood Detected",
				Description: fmt.Sprintf("Source IP %s sent %d TCP RST packets. This can indicate a connection reset attack or misconfigured host.", srcIP, rstCount),
				Details: map[string]interface{}{
					"rst_count": rstCount,
				},
				SrcIP:       srcIP,
				PacketCount: rstCount,
			})
		}
	}

	// 4. Incomplete TCP handshakes (SYN but no SYN-ACK within the capture)
	incompleteSYNs := 0
	for _, flow := range s.flows {
		if flow.SYNTime != nil && !flow.SYNACKSeen {
			incompleteSYNs++
		}
	}
	if incompleteSYNs >= 10 {
		findings = append(findings, models.Finding{
			Severity:    "warning",
			Category:    "tcp",
			Title:       "Many Incomplete TCP Handshakes",
			Description: fmt.Sprintf("%d TCP connections had SYN packets but no SYN-ACK response. Possible port scan, firewall blocking, or server unavailability.", incompleteSYNs),
			Details: map[string]interface{}{
				"incomplete_handshakes": incompleteSYNs,
			},
			PacketCount: incompleteSYNs,
		})
	}

	// 5. Info: summary of TCP flows
	totalFlows := len(s.flows)
	if totalFlows > 0 {
		totalRetrans := 0
		for _, flow := range s.flows {
			totalRetrans += flow.Retransmissions
		}
		findings = append(findings, models.Finding{
			Severity:    "info",
			Category:    "tcp",
			Title:       "TCP Traffic Summary",
			Description: fmt.Sprintf("Captured %d unique TCP flows with a total of %d retransmitted packets.", totalFlows, totalRetrans),
			Details: map[string]interface{}{
				"total_flows":          totalFlows,
				"total_retransmissions": totalRetrans,
			},
		})
	}

	return findings
}
