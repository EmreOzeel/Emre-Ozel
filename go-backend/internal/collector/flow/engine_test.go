package flow

import (
	"testing"
	"time"
)

func makeEvent(srcIP, dstIP string, srcPort, dstPort int, proto, action string, bytesIn, bytesOut int) map[string]interface{} {
	return map[string]interface{}{
		"source_ip":        srcIP,
		"destination_ip":   dstIP,
		"source_port":      srcPort,
		"destination_port": dstPort,
		"protocol":         proto,
		"action":           action,
		"bytes_in":         bytesIn,
		"bytes_out":        bytesOut,
		"event_time":       time.Now().UTC(),
	}
}

func TestFlowEngine_NewFlow(t *testing.T) {
	e := NewEngine(60)
	ev := makeEvent("10.0.0.1", "10.0.0.2", 12345, 80, "TCP", "allow", 100, 200)
	e.ProcessEvent(ev)

	stats := e.Stats()
	if stats["active_flows"] != 1 {
		t.Errorf("expected 1 active flow, got %v", stats["active_flows"])
	}
}

func TestFlowEngine_UpdateExistingFlow(t *testing.T) {
	e := NewEngine(60)
	ev1 := makeEvent("10.0.0.1", "10.0.0.2", 12345, 80, "TCP", "allow", 100, 200)
	ev2 := makeEvent("10.0.0.1", "10.0.0.2", 12345, 80, "TCP", "allow", 50, 100)
	e.ProcessEvent(ev1)
	e.ProcessEvent(ev2)

	stats := e.Stats()
	if stats["active_flows"] != 1 {
		t.Errorf("expected 1 flow (updated), got %v", stats["active_flows"])
	}

	// Check the flow accumulated bytes
	e.mu.Lock()
	key := MakeFlowKey(ev1)
	f := e.flows[key]
	e.mu.Unlock()
	if f.EventCount != 2 {
		t.Errorf("expected 2 events, got %d", f.EventCount)
	}
	if f.TotalBytesIn != 150 {
		t.Errorf("expected bytes_in=150, got %d", f.TotalBytesIn)
	}
}

func TestFlowEngine_DifferentPortsSeparateFlows(t *testing.T) {
	e := NewEngine(60)
	e.ProcessEvent(makeEvent("10.0.0.1", "10.0.0.2", 12345, 80, "TCP", "allow", 100, 0))
	e.ProcessEvent(makeEvent("10.0.0.1", "10.0.0.2", 12345, 443, "TCP", "allow", 100, 0))

	stats := e.Stats()
	if stats["active_flows"] != 2 {
		t.Errorf("expected 2 flows (different dst ports), got %v", stats["active_flows"])
	}
}

func TestFlowEngine_DifferentProtocolsSeparateFlows(t *testing.T) {
	e := NewEngine(60)
	e.ProcessEvent(makeEvent("10.0.0.1", "10.0.0.2", 12345, 80, "TCP", "allow", 100, 0))
	e.ProcessEvent(makeEvent("10.0.0.1", "10.0.0.2", 12345, 80, "UDP", "allow", 100, 0))

	stats := e.Stats()
	if stats["active_flows"] != 2 {
		t.Errorf("expected 2 flows (different protocols), got %v", stats["active_flows"])
	}
}

func TestFlowEngine_FlushExpired(t *testing.T) {
	e := NewEngine(60)
	now := time.Now().UTC()
	oldTime := now.Add(-120 * time.Second)

	old := map[string]interface{}{
		"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
		"source_port": 1111, "destination_port": 80, "protocol": "TCP",
		"action": "allow", "event_time": oldTime,
	}
	recent := map[string]interface{}{
		"source_ip": "10.0.0.3", "destination_ip": "10.0.0.4",
		"source_port": 2222, "destination_port": 443, "protocol": "TCP",
		"action": "allow", "event_time": now,
	}

	e.ProcessEvent(old)
	e.ProcessEvent(recent)

	flushed := e.FlushExpired(now)

	if len(flushed) != 1 {
		t.Fatalf("expected 1 flushed flow, got %d", len(flushed))
	}
	if flushed[0]["source_ip"] != "10.0.0.1" {
		t.Errorf("expected flushed flow from 10.0.0.1, got %v", flushed[0]["source_ip"])
	}

	// Recent flow should still be active
	stats := e.Stats()
	if stats["active_flows"] != 1 {
		t.Errorf("expected 1 active flow remaining, got %v", stats["active_flows"])
	}
}

func TestFlowEngine_FlushExpired_State_Allow(t *testing.T) {
	e := NewEngine(1) // 1 second timeout
	ev := map[string]interface{}{
		"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
		"source_port": 1234, "destination_port": 80, "protocol": "TCP",
		"action": "allow", "event_time": time.Now().UTC().Add(-5 * time.Second),
	}
	e.ProcessEvent(ev)
	flushed := e.FlushExpired(time.Now().UTC())
	if len(flushed) != 1 || flushed[0]["state"] != "completed" {
		t.Errorf("expected state=completed, got %v", flushed)
	}
}

func TestFlowEngine_FlushExpired_State_Deny(t *testing.T) {
	e := NewEngine(1)
	ev := map[string]interface{}{
		"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
		"source_port": 1234, "destination_port": 80, "protocol": "TCP",
		"action": "deny", "event_time": time.Now().UTC().Add(-5 * time.Second),
	}
	e.ProcessEvent(ev)
	flushed := e.FlushExpired(time.Now().UTC())
	if len(flushed) != 1 || flushed[0]["state"] != "denied" {
		t.Errorf("expected state=denied, got %v", flushed)
	}
}

func TestFlowEngine_FlushExpired_State_Reset(t *testing.T) {
	e := NewEngine(1)
	ev := map[string]interface{}{
		"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
		"source_port": 1234, "destination_port": 80, "protocol": "TCP",
		"action": "reset", "event_time": time.Now().UTC().Add(-5 * time.Second),
	}
	e.ProcessEvent(ev)
	flushed := e.FlushExpired(time.Now().UTC())
	if len(flushed) != 1 || flushed[0]["state"] != "reset" {
		t.Errorf("expected state=reset, got %v", flushed)
	}
}

func TestFlowEngine_Stats(t *testing.T) {
	e := NewEngine(60)
	for i := 0; i < 3; i++ {
		e.ProcessEvent(makeEvent("10.0.0.1", "10.0.0.2", 10000+i, 80, "TCP", "allow", 100, 0))
	}
	stats := e.Stats()
	if stats["active_flows"] != 3 {
		t.Errorf("expected 3 active flows, got %v", stats["active_flows"])
	}
}
