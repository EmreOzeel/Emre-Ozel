package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/flow"
)

// Sender batches events and POSTs them to the Python backend.
type Sender struct {
	backendURL string
	token      string
	client     *http.Client
	batch      []map[string]interface{}
	mu         sync.Mutex
	batchSize  int
	hostname   string
}

// New creates a Sender targeting the given backend URL.
func New(backendURL, token string, batchSize int) *Sender {
	hostname, _ := os.Hostname()
	return &Sender{
		backendURL: backendURL,
		token:      token,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		batchSize: batchSize,
		hostname:  hostname,
	}
}

// Add appends an event to the batch. Flushes immediately if batch is full.
func (s *Sender) Add(event map[string]interface{}) {
	s.mu.Lock()
	s.batch = append(s.batch, event)
	if len(s.batch) >= s.batchSize {
		batch := s.batch
		s.batch = nil
		s.mu.Unlock()
		if err := s.send(context.Background(), batch); err != nil {
			log.Printf("[sender] flush error: %v", err)
		}
		return
	}
	s.mu.Unlock()
}

// Flush sends all buffered events to the backend.
func (s *Sender) Flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.batch
	s.batch = nil
	s.mu.Unlock()

	err := s.send(ctx, batch)
	if err != nil {
		// Retry once
		log.Printf("[sender] first attempt failed: %v, retrying...", err)
		err = s.send(ctx, batch)
		if err != nil {
			// Re-queue on final failure
			s.mu.Lock()
			s.batch = append(batch, s.batch...)
			s.mu.Unlock()
			return err
		}
	}
	return nil
}

// FlowToEvent converts a completed Flow into an event map for the backend.
func (s *Sender) FlowToEvent(f *flow.Flow) map[string]interface{} {
	return map[string]interface{}{
		"source_ip":        f.Key.SrcIP,
		"destination_ip":   f.Key.DstIP,
		"source_port":      f.Key.SrcPort,
		"destination_port": f.Key.DstPort,
		"protocol":         f.Key.Protocol,
		"first_seen":       f.FirstSeen.Format(time.RFC3339),
		"last_seen":        f.LastSeen.Format(time.RFC3339),
		"duration_ms":      f.LastSeen.Sub(f.FirstSeen).Milliseconds(),
		"packet_count":     f.PacketCount,
		"bytes_in":         f.BytesIn,
		"bytes_out":        f.BytesOut,
		"action":           f.Action,
		"dns_queries":      f.DNSQueries,
		"sni":              f.SNIs,
		"http_hosts":       f.HTTPHosts,
		"device_type":      "packet_engine",
		"parser_id":        "gopacket",
		"source_id":        s.hostname,
	}
}

// BatchLen returns the current number of buffered events.
func (s *Sender) BatchLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batch)
}

// SendAlert POSTs a single alert to the backend's packet-alerts endpoint.
// The alertData map should contain: timestamp, src_ip, dst_ip, dst_port,
// protocol, alert_type, message, value, threshold.
func (s *Sender) SendAlert(ctx context.Context, alertData map[string]interface{}) error {
	body, err := json.Marshal(alertData)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	url := s.backendURL + "/api/ingest/packet-alerts"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
	}
	return nil
}

func (s *Sender) send(ctx context.Context, batch []map[string]interface{}) error {
	body, err := json.Marshal(map[string]interface{}{
		"events": batch,
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := s.backendURL + "/api/ingest/packet-events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
	}

	return nil
}
