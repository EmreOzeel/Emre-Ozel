package collector

import (
	"strings"
	"sync"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/collector/parsers"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

const (
	rawLineMax = 2000
	pgIntMax   = 2147483647
)

// PipelineStats tracks basic counters for observability.
type PipelineStats struct {
	Received int64
	Parsed   int64
	Dropped  int64
}

// Pipeline receives raw syslog lines, detects the parser, normalises the
// output, and buffers LiveEvent rows for batch insertion.
type Pipeline struct {
	SourceID   string
	DeviceRole string
	buffer     []models.LiveEvent
	webBuffer  []models.WebTransaction
	mu         sync.Mutex
	Stats      PipelineStats
}

// NewPipeline creates a pipeline bound to a specific source.
func NewPipeline(sourceID, deviceRole string) *Pipeline {
	return &Pipeline{SourceID: sourceID, DeviceRole: deviceRole}
}

// ProcessLine parses a single raw log line and returns a LiveEvent, or nil
// if the line could not be parsed.
func (p *Pipeline) ProcessLine(line string) *models.LiveEvent {
	p.Stats.Received++
	if strings.TrimSpace(line) == "" {
		p.Stats.Dropped++
		return nil
	}
	clean := parsers.StripSyslogPriority(line)
	parser := parsers.Detect(clean)
	if parser == nil {
		p.Stats.Dropped++
		return nil
	}
	parsed, err := parser.Parse(clean)
	if err != nil || parsed == nil {
		p.Stats.Dropped++
		return nil
	}
	event := p.normalize(parsed, parser, line)
	p.Stats.Parsed++

	// URL filtering logs additionally produce a WebTransaction row.
	// It is buffered here (not by the caller) because the web fields live
	// in the parsed map, which is not part of the returned LiveEvent.
	if wt := p.webTransactionFrom(parsed, event); wt != nil {
		p.mu.Lock()
		p.webBuffer = append(p.webBuffer, *wt)
		p.mu.Unlock()
	}

	return event
}

// webTransactionFrom builds a WebTransaction from a parsed URL-filtering log
// map plus its normalised LiveEvent. Returns nil when the line is not a web
// transaction (no "url" field).
func (p *Pipeline) webTransactionFrom(parsed map[string]interface{}, event *models.LiveEvent) *models.WebTransaction {
	url, ok := parsed["url"].(string)
	if !ok || url == "" {
		return nil
	}

	urlCopy := url
	action := event.Action
	wt := &models.WebTransaction{
		SourceID:        event.SourceID,
		DeviceType:      event.DeviceType,
		SourceIP:        event.SourceIP,
		DestinationIP:   event.DestinationIP,
		URL:             &urlCopy,
		Action:          &action,
		TransactionTime: event.EventTime,
	}

	// Ports / bytes / duration come from the already-normalised event.
	if event.SourcePort != nil {
		v := *event.SourcePort
		wt.SourcePort = &v
	}
	if event.DestinationPort != nil {
		v := *event.DestinationPort
		wt.DestinationPort = &v
	}
	if event.BytesIn != nil {
		wt.BytesIn = *event.BytesIn
	}
	if event.BytesOut != nil {
		wt.BytesOut = *event.BytesOut
	}
	if event.DurationMs != nil {
		v := *event.DurationMs
		wt.DurationMs = &v
	}

	// Web-specific optional fields from the parsed map.
	setOptStr(parsed, "host", &wt.Host)
	setOptStr(parsed, "http_method", &wt.Method)
	setOptStr(parsed, "user_agent", &wt.UserAgent)
	setOptStr(parsed, "content_type", &wt.ContentType)
	setOptStr(parsed, "referer", &wt.Referer)
	setOptStr(parsed, "url_category", &wt.Category)
	setOptInt(parsed, "status_code", &wt.StatusCode)

	return wt
}

// normalize converts a parser output map into a LiveEvent struct.
func (p *Pipeline) normalize(parsed map[string]interface{}, parser parsers.Parser, rawLine string) *models.LiveEvent {
	now := time.Now().UTC()

	// Truncate raw line
	rl := rawLine
	if len(rl) > rawLineMax {
		rl = rl[:rawLineMax]
	}

	event := &models.LiveEvent{
		SourceID:   p.SourceID,
		DeviceType: parser.DeviceType(),
		DeviceRole: &p.DeviceRole,
		ParserID:   parser.ParserID(),
		ReceivedAt: now,
		RawLine:    &rl,
	}

	// event_time
	if et, ok := parsed["event_time"]; ok {
		if t, ok := et.(time.Time); ok {
			event.EventTime = t
		}
	}
	if event.EventTime.IsZero() {
		event.EventTime = now
	}

	// Required string fields
	event.SourceIP = getStr(parsed, "source_ip", "0.0.0.0")
	event.DestinationIP = getStr(parsed, "destination_ip", "0.0.0.0")
	event.Action = getStr(parsed, "action", "unknown")

	// Optional strings
	setOptStr(parsed, "protocol", &event.Protocol)
	setOptStr(parsed, "reason", &event.Reason)
	setOptStr(parsed, "nat_source_ip", &event.NatSourceIP)
	setOptStr(parsed, "nat_destination_ip", &event.NatDestinationIP)
	setOptStr(parsed, "application", &event.Application)
	setOptStr(parsed, "service", &event.Service)
	setOptStr(parsed, "backend_ip", &event.BackendIP)
	setOptStr(parsed, "health_status", &event.HealthStatus)

	// Int fields (capped at pgIntMax)
	setOptInt(parsed, "source_port", &event.SourcePort)
	setOptInt(parsed, "destination_port", &event.DestinationPort)
	setOptInt(parsed, "bytes_in", &event.BytesIn)
	setOptInt(parsed, "bytes_out", &event.BytesOut)
	setOptInt(parsed, "packets_in", &event.PacketsIn)
	setOptInt(parsed, "packets_out", &event.PacketsOut)
	setOptInt(parsed, "duration_ms", &event.DurationMs)
	setOptInt(parsed, "nat_source_port", &event.NatSourcePort)
	setOptInt(parsed, "nat_destination_port", &event.NatDestinationPort)
	setOptInt(parsed, "backend_port", &event.BackendPort)

	// Float fields
	setOptFloat(parsed, "response_time_ms", &event.ResponseTimeMs)

	return event
}

// Buffer appends an event to the internal batch buffer (thread-safe).
func (p *Pipeline) Buffer(event *models.LiveEvent) {
	p.mu.Lock()
	p.buffer = append(p.buffer, *event)
	p.mu.Unlock()
}

// Flush writes all buffered events (and web transactions) to the database
// and returns the number of events written.
func (p *Pipeline) Flush(db *gorm.DB) int {
	p.mu.Lock()
	buf := p.buffer
	webBuf := p.webBuffer
	p.buffer = nil
	p.webBuffer = nil
	p.mu.Unlock()

	if len(webBuf) > 0 {
		db.Create(&webBuf)
	}

	if len(buf) == 0 {
		return 0
	}

	result := db.Create(&buf)
	if result.Error != nil {
		return 0
	}
	return len(buf)
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

func getStr(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return def
}

func setOptStr(m map[string]interface{}, key string, target **string) {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			cp := s
			*target = &cp
		}
	}
}

func setOptInt(m map[string]interface{}, key string, target **int) {
	v, ok := m[key]
	if !ok {
		return
	}
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
	if n > pgIntMax {
		n = pgIntMax
	}
	if n < 0 {
		n = 0
	}
	cp := n
	*target = &cp
}

func setOptFloat(m map[string]interface{}, key string, target **float64) {
	v, ok := m[key]
	if !ok {
		return
	}
	switch val := v.(type) {
	case float64:
		cp := val
		*target = &cp
	case int:
		cp := float64(val)
		*target = &cp
	}
}
