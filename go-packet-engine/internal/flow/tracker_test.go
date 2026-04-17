package flow

import (
	"testing"
	"time"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/parser"
)

func makePacket(srcIP, dstIP string, srcPort, dstPort uint16, ts time.Time) *parser.ParsedPacket {
	return &parser.ParsedPacket{
		Timestamp:   ts,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    "TCP",
		PayloadSize: 100,
	}
}

func TestNewFlowCreated(t *testing.T) {
	tracker := NewFlowTracker(60 * time.Second)
	now := time.Now()

	pkt := makePacket("10.0.0.1", "10.0.0.2", 12345, 80, now)
	tracker.Update(pkt)

	stats := tracker.Stats()
	if stats["active_flows"] != 1 {
		t.Errorf("expected 1 active flow, got %d", stats["active_flows"])
	}
}

func TestExistingFlowUpdated(t *testing.T) {
	tracker := NewFlowTracker(60 * time.Second)
	now := time.Now()

	pkt1 := makePacket("10.0.0.1", "10.0.0.2", 12345, 80, now)
	pkt2 := makePacket("10.0.0.1", "10.0.0.2", 12345, 80, now.Add(time.Second))
	pkt2.PayloadSize = 200

	tracker.Update(pkt1)
	tracker.Update(pkt2)

	stats := tracker.Stats()
	if stats["active_flows"] != 1 {
		t.Errorf("expected 1 active flow, got %d", stats["active_flows"])
	}

	// Flush everything to inspect the flow
	expired := tracker.FlushExpired(now.Add(5 * time.Minute))
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired flow, got %d", len(expired))
	}
	f := expired[0]
	if f.PacketCount != 2 {
		t.Errorf("expected 2 packets, got %d", f.PacketCount)
	}
	if f.BytesIn != 300 {
		t.Errorf("expected 300 bytes, got %d", f.BytesIn)
	}
}

func TestFlushExpiredReturnsOldFlows(t *testing.T) {
	tracker := NewFlowTracker(10 * time.Second)
	now := time.Now()

	pkt := makePacket("10.0.0.1", "10.0.0.2", 12345, 80, now.Add(-30*time.Second))
	tracker.Update(pkt)

	expired := tracker.FlushExpired(now)
	if len(expired) != 1 {
		t.Errorf("expected 1 expired flow, got %d", len(expired))
	}

	stats := tracker.Stats()
	if stats["active_flows"] != 0 {
		t.Errorf("expected 0 active flows after flush, got %d", stats["active_flows"])
	}
}

func TestFlushExpiredKeepsActiveFlows(t *testing.T) {
	tracker := NewFlowTracker(60 * time.Second)
	now := time.Now()

	pkt := makePacket("10.0.0.1", "10.0.0.2", 12345, 80, now)
	tracker.Update(pkt)

	expired := tracker.FlushExpired(now)
	if len(expired) != 0 {
		t.Errorf("expected 0 expired flows, got %d", len(expired))
	}

	stats := tracker.Stats()
	if stats["active_flows"] != 1 {
		t.Errorf("expected 1 active flow, got %d", stats["active_flows"])
	}
}

func TestStatsReturnsActiveCount(t *testing.T) {
	tracker := NewFlowTracker(60 * time.Second)
	now := time.Now()

	for i := 0; i < 5; i++ {
		pkt := makePacket("10.0.0.1", "10.0.0.2", uint16(10000+i), 80, now)
		tracker.Update(pkt)
	}

	stats := tracker.Stats()
	if stats["active_flows"] != 5 {
		t.Errorf("expected 5 active flows, got %d", stats["active_flows"])
	}
}
