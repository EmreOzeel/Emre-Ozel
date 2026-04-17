package collector

import (
	"log"
	"sync"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/collector/flow"
	"github.com/emreozeel/pcap-analyzer/backend/internal/collector/intelligence"
	"github.com/emreozeel/pcap-analyzer/backend/internal/collector/parsers"
	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

// Service is the collector orchestrator. It owns the pipeline, flow engine,
// and background loops for flushing, pattern scanning, and retention.
type Service struct {
	cfg        *config.Config
	db         *gorm.DB
	pipeline   *Pipeline
	flowEngine *flow.Engine
	running    bool
	mu         sync.Mutex
	stopCh     chan struct{}
}

// NewService creates a new collector service.
func NewService(cfg *config.Config, db *gorm.DB) *Service {
	return &Service{cfg: cfg, db: db, stopCh: make(chan struct{})}
}

// Start initialises parsers, pipeline, flow engine, and background goroutines.
func (s *Service) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}

	// Register parsers (order matters: most specific first)
	parsers.ClearRegistry()
	parsers.Register(&parsers.PaloAltoParser{})
	parsers.Register(&parsers.FortiGateParser{})
	parsers.Register(&parsers.GenericKVParser{})

	// Create pipeline
	s.pipeline = NewPipeline(s.cfg.CollectorSourceID, s.cfg.CollectorDeviceRole)

	// Create flow engine with 60-second idle timeout
	s.flowEngine = flow.NewEngine(60)

	s.running = true

	// Start retention loop
	go s.retentionLoop()

	log.Println("[collector] started")
}

// Stop shuts down the collector service and its background loops.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false
	close(s.stopCh)
	log.Println("[collector] stopped")
}

// Stats returns a snapshot of collector-level counters for the status API.
func (s *Service) Stats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := map[string]interface{}{
		"running":     s.running,
		"syslog_port": s.cfg.SyslogPort,
		"source_id":   s.cfg.CollectorSourceID,
	}
	if s.pipeline != nil {
		result["pipeline_stats"] = map[string]int64{
			"received": s.pipeline.Stats.Received,
			"parsed":   s.pipeline.Stats.Parsed,
			"dropped":  s.pipeline.Stats.Dropped,
		}
	}
	if s.flowEngine != nil {
		for k, v := range s.flowEngine.Stats() {
			result[k] = v
		}
	}
	return result
}

// ProcessLine feeds a single raw log line through the pipeline and flow engine.
func (s *Service) ProcessLine(line string) {
	if !s.running || s.pipeline == nil {
		return
	}
	event := s.pipeline.ProcessLine(line)
	if event == nil {
		return
	}

	// Feed to flow engine
	if s.flowEngine != nil {
		eventMap := eventToMap(event)
		s.flowEngine.ProcessEvent(eventMap)
	}

	s.pipeline.Buffer(event)
}

// retentionLoop runs periodic tasks: buffer flush, flow flush, pattern
// scanning, and retention sweeps.
func (s *Service) retentionLoop() {
	ticker := time.NewTicker(time.Duration(s.cfg.CollectorFlushInterval * float64(time.Second)))
	defer ticker.Stop()

	tick := 0
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			tick++

			// Every tick: flush pipeline buffer
			s.pipeline.Flush(s.db)

			// Every tick: flush expired flows
			s.flushFlows()

			// Every 2 ticks: scan patterns
			if tick%2 == 0 {
				intelligence.ScanPatterns(s.db)
			}

			// Every 60 ticks: retention sweep
			if tick%60 == 0 {
				s.retentionSweep()
			}
		}
	}
}

// flushFlows expires idle flows from the engine and persists them as LiveFlow rows.
func (s *Service) flushFlows() {
	if s.flowEngine == nil {
		return
	}
	expired := s.flowEngine.FlushExpired(time.Now().UTC())
	if len(expired) == 0 {
		return
	}

	var flows []models.LiveFlow
	for _, fd := range expired {
		f := mapToLiveFlow(fd)
		flows = append(flows, f)
	}
	s.db.Create(&flows)
}

// retentionSweep deletes events and flows older than the configured retention window.
func (s *Service) retentionSweep() {
	cutoff := time.Now().UTC().AddDate(0, 0, -s.cfg.RetentionDays)
	s.db.Where("event_time < ?", cutoff).Delete(&models.LiveEvent{})
	s.db.Where("first_seen < ?", cutoff).Delete(&models.LiveFlow{})
	log.Printf("[collector] retention sweep: deleted events/flows older than %d days", s.cfg.RetentionDays)
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

// eventToMap converts a LiveEvent to a map suitable for the flow engine.
func eventToMap(e *models.LiveEvent) map[string]interface{} {
	m := map[string]interface{}{
		"source_ip":      e.SourceIP,
		"destination_ip": e.DestinationIP,
		"action":         e.Action,
		"event_time":     e.EventTime,
		"source_id":      e.SourceID,
		"device_type":    e.DeviceType,
		"parser_id":      e.ParserID,
	}

	if e.DeviceRole != nil {
		m["device_role"] = *e.DeviceRole
	}
	if e.Protocol != nil {
		m["protocol"] = *e.Protocol
	}
	if e.SourcePort != nil {
		m["source_port"] = *e.SourcePort
	}
	if e.DestinationPort != nil {
		m["destination_port"] = *e.DestinationPort
	}
	if e.BytesIn != nil {
		m["bytes_in"] = *e.BytesIn
	}
	if e.BytesOut != nil {
		m["bytes_out"] = *e.BytesOut
	}
	if e.PacketsIn != nil {
		m["packets_in"] = *e.PacketsIn
	}
	if e.PacketsOut != nil {
		m["packets_out"] = *e.PacketsOut
	}
	if e.DurationMs != nil {
		m["duration_ms"] = *e.DurationMs
	}
	if e.Reason != nil {
		m["reason"] = *e.Reason
	}
	if e.Application != nil {
		m["application"] = *e.Application
	}
	if e.Service != nil {
		m["service"] = *e.Service
	}
	if e.NatSourceIP != nil {
		m["nat_source_ip"] = *e.NatSourceIP
	}
	if e.NatDestinationIP != nil {
		m["nat_destination_ip"] = *e.NatDestinationIP
	}
	if e.NatSourcePort != nil {
		m["nat_source_port"] = *e.NatSourcePort
	}
	if e.NatDestinationPort != nil {
		m["nat_destination_port"] = *e.NatDestinationPort
	}
	if e.BackendIP != nil {
		m["backend_ip"] = *e.BackendIP
	}
	if e.BackendPort != nil {
		m["backend_port"] = *e.BackendPort
	}

	return m
}

// mapToLiveFlow converts a flushed flow map from the engine into a LiveFlow model.
func mapToLiveFlow(fd map[string]interface{}) models.LiveFlow {
	f := models.LiveFlow{
		SourceIP:      mapStr(fd, "source_ip"),
		DestinationIP: mapStr(fd, "destination_ip"),
		SourceID:      mapStr(fd, "source_id"),
		DeviceType:    mapStr(fd, "device_type"),
		ParserID:      mapStr(fd, "parser_id"),
		EventCount:    mapInt(fd, "event_count"),
		TotalBytesIn:  mapInt(fd, "total_bytes_in"),
		TotalBytesOut: mapInt(fd, "total_bytes_out"),
		TotalPacketsIn:  mapInt(fd, "total_pkts_in"),
		TotalPacketsOut: mapInt(fd, "total_pkts_out"),
		AllowCount:    mapInt(fd, "allow_count"),
		DenyCount:     mapInt(fd, "deny_count"),
		DropCount:     mapInt(fd, "drop_count"),
		ResetCount:    mapInt(fd, "reset_count"),
		AlertCount:    mapInt(fd, "alert_count"),
		RawEventCount: mapInt(fd, "event_count"),
		State:         mapStr(fd, "state"),
	}

	// Optional pointer fields
	setPtr(&f.DeviceRole, fd, "device_role")
	setPtr(&f.Protocol, fd, "protocol")
	setPtr(&f.Application, fd, "last_application")
	setPtr(&f.Service, fd, "last_service")
	setPtr(&f.ActionSummary, fd, "action_summary")
	setPtr(&f.ReasonSummary, fd, "last_reason")
	setPtr(&f.NatSourceIP, fd, "nat_source_ip")
	setPtr(&f.NatDestinationIP, fd, "nat_destination_ip")
	setPtr(&f.BackendIP, fd, "backend_ip")
	setPtr(&f.FlowType, fd, "flow_type")
	setPtr(&f.SuspiciousReasons, fd, "suspicious_reasons")

	// Port fields
	setIntPtr(&f.SourcePort, fd, "source_port")
	setIntPtr(&f.DestinationPort, fd, "destination_port")
	setIntPtr(&f.NatSourcePort, fd, "nat_source_port")
	setIntPtr(&f.NatDestinationPort, fd, "nat_destination_port")
	setIntPtr(&f.BackendPort, fd, "backend_port")

	// Duration
	if v, ok := fd["duration_ms"]; ok {
		switch n := v.(type) {
		case int64:
			d := int(n)
			f.DurationMs = &d
		case int:
			f.DurationMs = &n
		case float64:
			d := int(n)
			f.DurationMs = &d
		}
	}

	// Float fields
	setFloatPtr(&f.ResetRatio, fd, "reset_ratio")
	setFloatPtr(&f.DenyRatio, fd, "deny_ratio")
	setFloatPtr(&f.BurstScore, fd, "burst_score")

	// Bool fields
	if v, ok := fd["asymmetric_behavior"]; ok {
		if b, ok := v.(bool); ok {
			f.AsymmetricBehavior = &b
		}
	}

	// Timestamps
	f.FirstSeen = parseTimeField(fd, "first_seen")
	f.LastSeen = parseTimeField(fd, "last_seen")
	if f.FirstSeen.IsZero() {
		f.FirstSeen = time.Now().UTC()
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = time.Now().UTC()
	}

	return f
}

// ---------------------------------------------------------------------------
// Map access helpers
// ---------------------------------------------------------------------------

func mapStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func mapInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

func setPtr(target **string, m map[string]interface{}, key string) {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			cp := s
			*target = &cp
		}
	}
}

func setIntPtr(target **int, m map[string]interface{}, key string) {
	if v, ok := m[key]; ok {
		var n int
		switch val := v.(type) {
		case int:
			n = val
		case int64:
			n = int(val)
		case float64:
			n = int(val)
		default:
			return
		}
		if n != 0 {
			cp := n
			*target = &cp
		}
	}
}

func setFloatPtr(target **float64, m map[string]interface{}, key string) {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			cp := val
			*target = &cp
		case float32:
			cp := float64(val)
			*target = &cp
		case int:
			cp := float64(val)
			*target = &cp
		}
	}
}

func parseTimeField(m map[string]interface{}, key string) time.Time {
	v, ok := m[key]
	if !ok {
		return time.Time{}
	}
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
		} {
			if parsed, err := time.Parse(layout, t); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}
