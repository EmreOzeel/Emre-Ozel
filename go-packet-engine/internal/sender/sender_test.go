package sender

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/flow"
)

func TestBatchFlushOnSize(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		json.Unmarshal(body, &payload)
		events, ok := payload["events"].([]interface{})
		if ok {
			received.Add(int32(len(events)))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"accepted": 2}`))
	}))
	defer server.Close()

	s := New(server.URL, "test-token", 2) // batch size = 2

	event1 := map[string]interface{}{"source_ip": "1.1.1.1"}
	event2 := map[string]interface{}{"source_ip": "2.2.2.2"}

	s.Add(event1)
	// batch should not have flushed yet
	if s.BatchLen() != 1 {
		t.Errorf("expected batch len 1, got %d", s.BatchLen())
	}

	s.Add(event2)
	// batch should have auto-flushed
	// Give a small moment for the HTTP request to complete
	time.Sleep(50 * time.Millisecond)

	if got := received.Load(); got != 2 {
		t.Errorf("expected 2 events received by server, got %d", got)
	}
}

func TestFlushSendsCorrectPayload(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer server.Close()

	s := New(server.URL, "my-secret-token", 100)

	f := &flow.Flow{
		Key: flow.FlowKey{
			SrcIP:    "10.0.0.1",
			DstIP:    "10.0.0.2",
			SrcPort:  12345,
			DstPort:  443,
			Protocol: "TCP",
		},
		FirstSeen:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:    time.Date(2025, 1, 1, 0, 0, 10, 0, time.UTC),
		PacketCount: 42,
		BytesIn:     5000,
		Action:      "allow",
		SNIs:        []string{"example.com"},
	}

	event := s.FlowToEvent(f)
	s.Add(event)
	s.Flush(context.Background())

	if receivedAuth != "Bearer my-secret-token" {
		t.Errorf("expected Bearer auth header, got %q", receivedAuth)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	events, ok := payload["events"].([]interface{})
	if !ok || len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", payload["events"])
	}

	ev := events[0].(map[string]interface{})
	if ev["source_ip"] != "10.0.0.1" {
		t.Errorf("expected source_ip 10.0.0.1, got %v", ev["source_ip"])
	}
	if ev["device_type"] != "packet_engine" {
		t.Errorf("expected device_type packet_engine, got %v", ev["device_type"])
	}
}
