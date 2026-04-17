package flow

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const MaxActiveFlows = 50000

// FlowKey uniquely identifies a bidirectional network flow.
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Protocol string
}

// ActiveFlow tracks the accumulated state of a single flow while it is active.
type ActiveFlow struct {
	Key        FlowKey
	SourceID   string
	DeviceType string
	DeviceRole string
	ParserID   string

	FirstSeen time.Time
	LastSeen  time.Time
	EventCount int

	TotalBytesIn  int64
	TotalBytesOut int64
	TotalPktsIn   int
	TotalPktsOut  int

	AllowCount int
	DenyCount  int
	DropCount  int
	ResetCount int
	AlertCount int

	LastReason      string
	LastApplication string
	LastService     string

	NatSrcIP    string
	NatDstIP    string
	NatSrcPort  int
	NatDstPort  int
	BackendIP   string
	BackendPort int
}

// Engine aggregates raw events into flows, flushes expired ones, and provides
// classification metadata on each flushed flow.
type Engine struct {
	TimeoutSeconds int
	flows          map[FlowKey]*ActiveFlow
	mu             sync.Mutex
	totalCreated   int64
	totalFlushed   int64
}

// NewEngine returns an initialised flow engine with the given idle timeout.
func NewEngine(timeoutSeconds int) *Engine {
	return &Engine{
		TimeoutSeconds: timeoutSeconds,
		flows:          make(map[FlowKey]*ActiveFlow),
	}
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

// MakeFlowKey derives a FlowKey from a raw event map.
func MakeFlowKey(event map[string]interface{}) FlowKey {
	return FlowKey{
		SrcIP:    getStr(event, "source_ip"),
		DstIP:    getStr(event, "destination_ip"),
		SrcPort:  getInt(event, "source_port"),
		DstPort:  getInt(event, "destination_port"),
		Protocol: strings.ToUpper(getStr(event, "protocol")),
	}
}

// ---------------------------------------------------------------------------
// Event processing
// ---------------------------------------------------------------------------

// ProcessEvent ingests a single parsed event into the flow table.  It returns
// nil on success or an error if the event is unusable.
func (e *Engine) ProcessEvent(event map[string]interface{}) error {
	key := MakeFlowKey(event)
	if key.SrcIP == "" || key.DstIP == "" {
		return nil // skip events without endpoints
	}

	eventTime := getTime(event, "event_time")
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	f, exists := e.flows[key]
	if !exists {
		f = &ActiveFlow{
			Key:       key,
			FirstSeen: eventTime,
			LastSeen:  eventTime,
		}
		e.flows[key] = f
		e.totalCreated++
	}

	// Timestamps: widen the window.
	if eventTime.Before(f.FirstSeen) {
		f.FirstSeen = eventTime
	}
	if eventTime.After(f.LastSeen) {
		f.LastSeen = eventTime
	}

	f.EventCount++

	// Metadata (first-write if empty, otherwise always overwrite).
	if s := getStr(event, "source_id"); s != "" {
		f.SourceID = s
	}
	if s := getStr(event, "device_type"); s != "" {
		f.DeviceType = s
	}
	if s := getStr(event, "device_role"); s != "" {
		f.DeviceRole = s
	}
	if s := getStr(event, "parser_id"); s != "" {
		f.ParserID = s
	}

	// Byte / packet counters.
	f.TotalBytesIn += getInt64(event, "bytes_in")
	f.TotalBytesOut += getInt64(event, "bytes_out")
	f.TotalPktsIn += getInt(event, "packets_in")
	f.TotalPktsOut += getInt(event, "packets_out")

	// Action counters.
	action := strings.ToLower(getStr(event, "action"))
	switch action {
	case "allow", "accept", "permit":
		f.AllowCount++
	case "deny", "reject":
		f.DenyCount++
	case "drop":
		f.DropCount++
	case "reset", "rst":
		f.ResetCount++
	case "alert":
		f.AlertCount++
	}

	// Last-write-wins fields.
	if s := getStr(event, "reason"); s != "" {
		f.LastReason = s
	}
	if s := getStr(event, "application"); s != "" {
		f.LastApplication = s
	}
	if s := getStr(event, "service"); s != "" {
		f.LastService = s
	}

	// NAT fields.
	if s := getStr(event, "nat_source_ip"); s != "" {
		f.NatSrcIP = s
	}
	if s := getStr(event, "nat_destination_ip"); s != "" {
		f.NatDstIP = s
	}
	if v := getInt(event, "nat_source_port"); v != 0 {
		f.NatSrcPort = v
	}
	if v := getInt(event, "nat_destination_port"); v != 0 {
		f.NatDstPort = v
	}
	if s := getStr(event, "backend_ip"); s != "" {
		f.BackendIP = s
	}
	if v := getInt(event, "backend_port"); v != 0 {
		f.BackendPort = v
	}

	return nil
}

// ---------------------------------------------------------------------------
// Flushing
// ---------------------------------------------------------------------------

// FlushExpired removes idle flows from the table and returns their serialised
// representations.  If the active flow count exceeds MaxActiveFlows the oldest
// flows are force-evicted first.
func (e *Engine) FlushExpired(now time.Time) []map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()

	cutoff := now.Add(-time.Duration(e.TimeoutSeconds) * time.Second)

	var expired []*ActiveFlow
	for _, f := range e.flows {
		if !f.LastSeen.After(cutoff) {
			expired = append(expired, f)
		}
	}

	// Force-evict oldest flows if the table is over capacity.
	if len(e.flows) > MaxActiveFlows {
		overflow := len(e.flows) - MaxActiveFlows

		// Collect all flows, sort by LastSeen ascending.
		all := make([]*ActiveFlow, 0, len(e.flows))
		for _, f := range e.flows {
			all = append(all, f)
		}
		sort.Slice(all, func(i, j int) bool {
			return all[i].LastSeen.Before(all[j].LastSeen)
		})

		// Build set of already-expired keys to avoid duplicates.
		expiredSet := make(map[FlowKey]struct{}, len(expired))
		for _, f := range expired {
			expiredSet[f.Key] = struct{}{}
		}
		for i := 0; i < overflow && i < len(all); i++ {
			if _, already := expiredSet[all[i].Key]; !already {
				expired = append(expired, all[i])
			}
		}
	}

	results := make([]map[string]interface{}, 0, len(expired))
	for _, f := range expired {
		results = append(results, f.toDict())
		delete(e.flows, f.Key)
		e.totalFlushed++
	}

	return results
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

func (f *ActiveFlow) toDict() map[string]interface{} {
	durationMs := f.LastSeen.Sub(f.FirstSeen).Milliseconds()
	state := f.DeriveState()
	actionSummary := f.DeriveActionSummary()
	cls := ClassifyFlow(f)

	m := map[string]interface{}{
		"source_ip":       f.Key.SrcIP,
		"destination_ip":  f.Key.DstIP,
		"source_port":     f.Key.SrcPort,
		"destination_port": f.Key.DstPort,
		"protocol":        f.Key.Protocol,

		"source_id":   f.SourceID,
		"device_type": f.DeviceType,
		"device_role": f.DeviceRole,
		"parser_id":   f.ParserID,

		"first_seen":  f.FirstSeen.UTC().Format(time.RFC3339Nano),
		"last_seen":   f.LastSeen.UTC().Format(time.RFC3339Nano),
		"event_count": f.EventCount,
		"duration_ms": durationMs,

		"total_bytes_in":  f.TotalBytesIn,
		"total_bytes_out": f.TotalBytesOut,
		"total_pkts_in":   f.TotalPktsIn,
		"total_pkts_out":  f.TotalPktsOut,

		"allow_count": f.AllowCount,
		"deny_count":  f.DenyCount,
		"drop_count":  f.DropCount,
		"reset_count": f.ResetCount,
		"alert_count": f.AlertCount,

		"last_reason":      f.LastReason,
		"last_application": f.LastApplication,
		"last_service":     f.LastService,

		"nat_source_ip":        f.NatSrcIP,
		"nat_destination_ip":   f.NatDstIP,
		"nat_source_port":      f.NatSrcPort,
		"nat_destination_port": f.NatDstPort,
		"backend_ip":           f.BackendIP,
		"backend_port":         f.BackendPort,

		"state":          state,
		"action_summary": actionSummary,

		"flow_type":           cls.FlowType,
		"reset_ratio":         cls.ResetRatio,
		"deny_ratio":          cls.DenyRatio,
		"burst_score":         cls.BurstScore,
		"asymmetric_behavior": cls.AsymmetricBehavior,
		"suspicious_reasons":  cls.SuspiciousReasons,
	}
	return m
}

// ---------------------------------------------------------------------------
// State derivation
// ---------------------------------------------------------------------------

// DeriveState returns a human-readable state label for the flow.
func (f *ActiveFlow) DeriveState() string {
	switch {
	case f.ResetCount > 0:
		return "reset"
	case f.DenyCount > 0 && f.AllowCount == 0:
		return "denied"
	case f.DropCount > 0 && f.AllowCount == 0:
		return "dropped"
	case f.AllowCount > 0:
		return "completed"
	default:
		return "expired"
	}
}

// DeriveActionSummary returns a summary label describing the mix of actions.
func (f *ActiveFlow) DeriveActionSummary() string {
	if f.ResetCount > 0 {
		return "reset_seen"
	}
	total := f.AllowCount + f.DenyCount + f.DropCount + f.AlertCount
	if total == 0 {
		return "unknown"
	}
	if f.DenyCount > 0 && f.AllowCount > 0 {
		return "mixed"
	}
	half := total / 2
	if f.DenyCount > half {
		return "mostly_deny"
	}
	if f.AllowCount > half {
		return "mostly_allow"
	}
	return "mixed"
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

// Stats returns a snapshot of engine-level counters.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]interface{}{
		"active_flows":  len(e.flows),
		"total_created": e.totalCreated,
		"total_flushed": e.totalFlushed,
	}
}

// ---------------------------------------------------------------------------
// Map-access helpers
// ---------------------------------------------------------------------------

func getStr(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprintf("%v", s)
	}
}

func getInt(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
		return int(n)
	default:
		return 0
	}
}

func getInt64(m map[string]interface{}, key string) int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	default:
		return 0
	}
}

func getTime(m map[string]interface{}, key string) time.Time {
	v, ok := m[key]
	if !ok || v == nil {
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
