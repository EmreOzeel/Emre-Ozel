package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"pcap-analyzer/models"
)

const (
	maxConnections  = 500 // max connections to track
	maxStepsPerConn = 150 // max steps per connection (to keep JSON size sane)
)

// rawPacket stores minimal per-packet info for a connection
type rawPacket struct {
	ts         time.Time
	srcIP      string
	dstIP      string
	srcPort    uint16
	dstPort    uint16
	syn        bool
	ack        bool
	fin        bool
	rst        bool
	psh        bool
	urg        bool
	seq        uint32
	ackNum     uint32
	payloadLen int
}

// connRecord accumulates packets for one TCP flow
type connRecord struct {
	clientIP   string
	serverIP   string
	clientPort uint16
	serverPort uint16
	packets    []rawPacket
	startTime  time.Time
	// direction key: "clientIP:clientPort-serverIP:serverPort"
}

// ConnectionState holds all connection tracking data
type ConnectionState struct {
	// canonical key → record; key is always client:port-server:port
	records map[string]*connRecord
	// limit total tracked connections
	order []string
}

func newConnectionState() *ConnectionState {
	return &ConnectionState{
		records: make(map[string]*connRecord),
	}
}

// canonicalKey returns a stable key for a flow, with the SYN initiator first.
// For non-SYN packets we look up which side is the client.
func (cs *ConnectionState) canonicalKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	k1 := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	k2 := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
	if _, ok := cs.records[k1]; ok {
		return k1
	}
	if _, ok := cs.records[k2]; ok {
		return k2
	}
	return "" // unknown
}

func analyzeConnections(packet gopacket.Packet, state *analysisState) {
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
	cs := state.connState

	pkt := rawPacket{
		ts:         ts,
		srcIP:      srcIP,
		dstIP:      dstIP,
		srcPort:    srcPort,
		dstPort:    dstPort,
		syn:        tcp.SYN,
		ack:        tcp.ACK,
		fin:        tcp.FIN,
		rst:        tcp.RST,
		psh:        tcp.PSH,
		urg:        tcp.URG,
		seq:        tcp.Seq,
		ackNum:     tcp.Ack,
		payloadLen: len(tcp.Payload),
	}

	// SYN-only packet = new connection; register the initiator as client
	if tcp.SYN && !tcp.ACK {
		key := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
		if _, exists := cs.records[key]; !exists {
			if len(cs.records) >= maxConnections {
				return // cap reached
			}
			cs.records[key] = &connRecord{
				clientIP:   srcIP,
				serverIP:   dstIP,
				clientPort: srcPort,
				serverPort: dstPort,
				startTime:  ts,
			}
			cs.order = append(cs.order, key)
		}
		cs.records[key].packets = append(cs.records[key].packets, pkt)
		return
	}

	// For other packets, find the existing record
	key := cs.canonicalKey(srcIP, dstIP, srcPort, dstPort)
	if key == "" {
		return // no matching connection
	}
	cs.records[key].packets = append(cs.records[key].packets, pkt)
}

func finalizeConnections(cs *ConnectionState) []models.TCPConnection {
	result := make([]models.TCPConnection, 0, len(cs.records))

	for i, key := range cs.order {
		rec := cs.records[key]
		if len(rec.packets) == 0 {
			continue
		}

		conn := buildConnection(i+1, rec)
		result = append(result, conn)
	}

	// Sort by start time
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartTime == nil {
			return false
		}
		if result[j].StartTime == nil {
			return true
		}
		return result[i].StartTime.Before(*result[j].StartTime)
	})

	// Re-assign sequential IDs after sort
	for i := range result {
		result[i].ID = i + 1
	}

	return result
}

func buildConnection(id int, rec *connRecord) models.TCPConnection {
	conn := models.TCPConnection{
		ID:         id,
		ClientIP:   rec.clientIP,
		ServerIP:   rec.serverIP,
		ClientPort: int(rec.clientPort),
		ServerPort: int(rec.serverPort),
	}

	if len(rec.packets) > 0 {
		t := rec.packets[0].ts
		conn.StartTime = &t
	}

	// Determine state and build steps
	hasSYN := false
	hasSYNACK := false
	hasACKAfterHandshake := false
	hasFIN := false
	hasRST := false

	steps := make([]models.ConnectionStep, 0, len(rec.packets))
	stepCount := 0

	for _, pkt := range rec.packets {
		if stepCount >= maxStepsPerConn {
			break
		}

		isClient := pkt.srcIP == rec.clientIP && pkt.srcPort == rec.clientPort
		direction := "→"
		if !isClient {
			direction = "←"
		}

		flags := buildFlagsString(pkt)
		desc := describePacket(pkt, hasSYN, hasSYNACK)

		relTime := 0.0
		if conn.StartTime != nil {
			relTime = pkt.ts.Sub(*conn.StartTime).Seconds()
		}

		step := models.ConnectionStep{
			RelTimeSec:  relTime,
			Direction:   direction,
			Flags:       flags,
			SeqNum:      pkt.seq,
			AckNum:      pkt.ackNum,
			PayloadLen:  pkt.payloadLen,
			Description: desc,
		}
		steps = append(steps, step)
		stepCount++

		// Track state
		if pkt.syn && !pkt.ack {
			hasSYN = true
		}
		if pkt.syn && pkt.ack {
			hasSYNACK = true
		}
		if pkt.ack && !pkt.syn && hasSYNACK && !hasACKAfterHandshake {
			hasACKAfterHandshake = true
		}
		if pkt.fin {
			hasFIN = true
		}
		if pkt.rst {
			hasRST = true
		}

		// Track bytes
		if isClient {
			conn.BytesClient += int64(pkt.payloadLen)
		} else {
			conn.BytesServer += int64(pkt.payloadLen)
		}
	}

	conn.PacketCount = len(rec.packets)
	conn.Steps = steps

	// Calculate duration
	if conn.StartTime != nil && len(rec.packets) > 0 {
		last := rec.packets[len(rec.packets)-1].ts
		conn.DurationSec = last.Sub(*conn.StartTime).Seconds()
	}

	// Determine connection state
	conn.State = determineState(hasSYN, hasSYNACK, hasACKAfterHandshake, hasFIN, hasRST)

	return conn
}

func buildFlagsString(p rawPacket) string {
	var flags []string
	if p.syn {
		flags = append(flags, "SYN")
	}
	if p.ack {
		flags = append(flags, "ACK")
	}
	if p.fin {
		flags = append(flags, "FIN")
	}
	if p.rst {
		flags = append(flags, "RST")
	}
	if p.psh {
		flags = append(flags, "PSH")
	}
	if p.urg {
		flags = append(flags, "URG")
	}
	if len(flags) == 0 {
		return "—"
	}
	return strings.Join(flags, "+")
}

func describePacket(p rawPacket, hasSYN, hasSYNACK bool) string {
	switch {
	case p.syn && !p.ack:
		return fmt.Sprintf("Connection Request — %s:%d → %s:%d", p.srcIP, p.srcPort, p.dstIP, p.dstPort)
	case p.syn && p.ack:
		return fmt.Sprintf("Connection Accepted — %s:%d → %s:%d", p.srcIP, p.srcPort, p.dstIP, p.dstPort)
	case p.rst && p.ack:
		return "Connection Reset (RST+ACK)"
	case p.rst:
		return "Connection Reset (RST) — abrupt termination"
	case p.fin && p.ack && p.psh && p.payloadLen > 0:
		return fmt.Sprintf("Data + Close Request (FIN+PSH+ACK) — %d bytes", p.payloadLen)
	case p.fin && p.ack:
		return "Close Request (FIN+ACK) — graceful teardown"
	case p.fin:
		return "Close Request (FIN)"
	case p.ack && !p.syn && !p.fin && !p.rst && !hasSYNACK:
		return "Acknowledgment (handshake completing)"
	case p.psh && p.ack && p.payloadLen > 0:
		return fmt.Sprintf("Data Transfer (PSH+ACK) — %d bytes", p.payloadLen)
	case p.ack && p.payloadLen > 0:
		return fmt.Sprintf("Data Transfer (ACK) — %d bytes", p.payloadLen)
	case p.ack && p.payloadLen == 0 && hasSYNACK:
		return "Acknowledgment (ACK)"
	default:
		if p.payloadLen > 0 {
			return fmt.Sprintf("Data — %d bytes", p.payloadLen)
		}
		return "Control packet"
	}
}

func determineState(syn, synack, ackAfter, fin, rst bool) string {
	if rst {
		return "reset"
	}
	if syn && synack && ackAfter && fin {
		return "fin-closed"
	}
	if syn && synack && ackAfter {
		return "established"
	}
	if syn && !synack {
		return "half-open"
	}
	if syn && synack && !ackAfter {
		return "syn-ack-sent"
	}
	return "unknown"
}
