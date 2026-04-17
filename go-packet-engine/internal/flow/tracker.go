package flow

import (
	"sync"
	"time"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/parser"
)

// FlowKey uniquely identifies a bidirectional flow.
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// Flow tracks aggregated metadata for a network flow.
type Flow struct {
	Key         FlowKey
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount int
	BytesIn     int64
	BytesOut    int64
	SYNCount    int
	RSTCount    int
	FINCount    int
	DNSQueries  []string
	SNIs        []string
	HTTPHosts   []string
	Action      string // derived: "allow"/"reset"/"fin_closed"
}

// FlowTracker maintains in-memory flow state.
type FlowTracker struct {
	flows   map[FlowKey]*Flow
	mu      sync.RWMutex
	timeout time.Duration
}

// NewFlowTracker creates a tracker with the given idle timeout.
func NewFlowTracker(timeout time.Duration) *FlowTracker {
	return &FlowTracker{
		flows:   make(map[FlowKey]*Flow),
		timeout: timeout,
	}
}

const maxListPerFlow = 10

// Update creates or updates a flow with data from the parsed packet.
func (t *FlowTracker) Update(pkt *parser.ParsedPacket) {
	key := FlowKey{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: pkt.Protocol,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	f, ok := t.flows[key]
	if !ok {
		f = &Flow{
			Key:       key,
			FirstSeen: pkt.Timestamp,
			Action:    "allow",
		}
		t.flows[key] = f
	}

	f.LastSeen = pkt.Timestamp
	f.PacketCount++
	f.BytesIn += int64(pkt.PayloadSize)

	// TCP flags
	if pkt.TCPFlags.SYN {
		f.SYNCount++
	}
	if pkt.TCPFlags.RST {
		f.RSTCount++
		f.Action = "reset"
	}
	if pkt.TCPFlags.FIN {
		f.FINCount++
		if f.Action != "reset" {
			f.Action = "fin_closed"
		}
	}

	// DNS
	if pkt.DNSInfo != nil && pkt.DNSInfo.Domain != "" && len(f.DNSQueries) < maxListPerFlow {
		if !contains(f.DNSQueries, pkt.DNSInfo.Domain) {
			f.DNSQueries = append(f.DNSQueries, pkt.DNSInfo.Domain)
		}
	}

	// TLS SNI
	if pkt.TLSInfo != nil && pkt.TLSInfo.SNI != "" && len(f.SNIs) < maxListPerFlow {
		if !contains(f.SNIs, pkt.TLSInfo.SNI) {
			f.SNIs = append(f.SNIs, pkt.TLSInfo.SNI)
		}
	}

	// HTTP Host
	if pkt.HTTPInfo != nil && pkt.HTTPInfo.Host != "" && len(f.HTTPHosts) < maxListPerFlow {
		if !contains(f.HTTPHosts, pkt.HTTPInfo.Host) {
			f.HTTPHosts = append(f.HTTPHosts, pkt.HTTPInfo.Host)
		}
	}
}

// FlushExpired removes and returns flows that have been idle longer than timeout.
func (t *FlowTracker) FlushExpired(now time.Time) []*Flow {
	cutoff := now.Add(-t.timeout)
	var expired []*Flow

	t.mu.Lock()
	defer t.mu.Unlock()

	for key, f := range t.flows {
		if f.LastSeen.Before(cutoff) {
			expired = append(expired, f)
			delete(t.flows, key)
		}
	}
	return expired
}

// Stats returns a summary of tracker state.
func (t *FlowTracker) Stats() map[string]int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return map[string]int{
		"active_flows": len(t.flows),
	}
}

func contains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}
