package stream

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/parser"
)

const (
	windowDuration = 60 * time.Second
	alertChanSize  = 256
)

// Alert represents a streaming analysis alert to send to the backend.
type Alert struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	DstPort   uint16
	Protocol  string
	AlertType string  // "threshold_exceeded" / "dns_anomaly" / "tls_anomaly"
	Message   string
	Value     float64 // the metric value that triggered
	Threshold float64 // the configured threshold
}

// WatchRule defines thresholds for a target IP:port to monitor.
type WatchRule struct {
	TargetIP   string  `json:"target_ip"`
	TargetPort uint16  `json:"target_port"` // 0 = any port
	Protocol   string  `json:"protocol"`    // "" = any
	MaxPPS     float64 `json:"max_pps"`     // packets per second, 0 = disabled
	MaxBPS     float64 `json:"max_bps"`     // bytes per second, 0 = disabled
	MaxConns   int     `json:"max_conns"`   // distinct source IPs, 0 = disabled

	// internal state
	window  []windowSample
	connSet map[string]bool
}

type windowSample struct {
	ts      time.Time
	packets int
	bytes   int64
}

// StreamAnalyzer performs real-time threshold and anomaly analysis on packets.
type StreamAnalyzer struct {
	alerts    chan Alert
	watchlist map[string]*WatchRule // "ip:port" → rule
	mu        sync.RWMutex

	// DNS anomaly tracking: per-server NXDOMAIN rate
	dnsStats   map[string]*dnsWindow
	dnsMu      sync.Mutex
}

type dnsWindow struct {
	total    int
	nxdomain int
	samples  []dnsEvent
}

type dnsEvent struct {
	ts        time.Time
	nxdomain  bool
}

// NewStreamAnalyzer creates a new StreamAnalyzer.
func NewStreamAnalyzer() *StreamAnalyzer {
	return &StreamAnalyzer{
		alerts:    make(chan Alert, alertChanSize),
		watchlist: make(map[string]*WatchRule),
		dnsStats:  make(map[string]*dnsWindow),
	}
}

func watchKey(ip string, port uint16) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

// AddWatch registers a watch rule.
func (a *StreamAnalyzer) AddWatch(rule WatchRule) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := rule
	r.window = nil
	r.connSet = make(map[string]bool)
	a.watchlist[watchKey(rule.TargetIP, rule.TargetPort)] = &r
}

// RemoveWatch removes a watch rule by IP and port.
func (a *StreamAnalyzer) RemoveWatch(ip string, port uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.watchlist, watchKey(ip, port))
}

// ListWatches returns a copy of all active watch rules.
func (a *StreamAnalyzer) ListWatches() []WatchRule {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]WatchRule, 0, len(a.watchlist))
	for _, r := range a.watchlist {
		result = append(result, WatchRule{
			TargetIP:   r.TargetIP,
			TargetPort: r.TargetPort,
			Protocol:   r.Protocol,
			MaxPPS:     r.MaxPPS,
			MaxBPS:     r.MaxBPS,
			MaxConns:   r.MaxConns,
		})
	}
	return result
}

// Alerts returns a read-only channel of alerts.
func (a *StreamAnalyzer) Alerts() <-chan Alert {
	return a.alerts
}

// Analyze processes a parsed packet through all watch rules and anomaly checks.
func (a *StreamAnalyzer) Analyze(pkt *parser.ParsedPacket) {
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	a.analyzeWatchRules(pkt, now)
	a.analyzeDNS(pkt, now)
	a.analyzeTLS(pkt, now)
}

func (a *StreamAnalyzer) analyzeWatchRules(pkt *parser.ParsedPacket, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, rule := range a.watchlist {
		if !ruleMatches(rule, pkt) {
			continue
		}

		// Trim old samples outside window
		cutoff := now.Add(-windowDuration)
		trimmed := rule.window[:0]
		for _, s := range rule.window {
			if !s.ts.Before(cutoff) {
				trimmed = append(trimmed, s)
			}
		}
		rule.window = trimmed

		// Add current sample
		rule.window = append(rule.window, windowSample{
			ts:      now,
			packets: 1,
			bytes:   int64(pkt.PayloadSize),
		})

		// Track distinct source IPs
		if rule.connSet == nil {
			rule.connSet = make(map[string]bool)
		}
		rule.connSet[pkt.SrcIP] = true

		// Compute rates over the window
		elapsed := windowSeconds(rule.window)
		if elapsed < 1 {
			continue
		}

		var totalPkts int
		var totalBytes int64
		for _, s := range rule.window {
			totalPkts += s.packets
			totalBytes += s.bytes
		}
		pps := float64(totalPkts) / elapsed
		bps := float64(totalBytes) / elapsed

		// Check thresholds
		if rule.MaxPPS > 0 && pps > rule.MaxPPS {
			a.emitAlert(Alert{
				Timestamp: now,
				SrcIP:     pkt.SrcIP,
				DstIP:     rule.TargetIP,
				DstPort:   rule.TargetPort,
				Protocol:  pkt.Protocol,
				AlertType: "threshold_exceeded",
				Message:   fmt.Sprintf("PPS %.1f exceeds threshold %.1f for %s:%d", pps, rule.MaxPPS, rule.TargetIP, rule.TargetPort),
				Value:     pps,
				Threshold: rule.MaxPPS,
			})
		}
		if rule.MaxBPS > 0 && bps > rule.MaxBPS {
			a.emitAlert(Alert{
				Timestamp: now,
				SrcIP:     pkt.SrcIP,
				DstIP:     rule.TargetIP,
				DstPort:   rule.TargetPort,
				Protocol:  pkt.Protocol,
				AlertType: "threshold_exceeded",
				Message:   fmt.Sprintf("BPS %.1f exceeds threshold %.1f for %s:%d", bps, rule.MaxBPS, rule.TargetIP, rule.TargetPort),
				Value:     bps,
				Threshold: rule.MaxBPS,
			})
		}
		if rule.MaxConns > 0 && len(rule.connSet) > rule.MaxConns {
			a.emitAlert(Alert{
				Timestamp: now,
				SrcIP:     pkt.SrcIP,
				DstIP:     rule.TargetIP,
				DstPort:   rule.TargetPort,
				Protocol:  pkt.Protocol,
				AlertType: "threshold_exceeded",
				Message:   fmt.Sprintf("Distinct sources %d exceeds threshold %d for %s:%d", len(rule.connSet), rule.MaxConns, rule.TargetIP, rule.TargetPort),
				Value:     float64(len(rule.connSet)),
				Threshold: float64(rule.MaxConns),
			})
		}
	}
}

func (a *StreamAnalyzer) analyzeDNS(pkt *parser.ParsedPacket, now time.Time) {
	if pkt.DNSInfo == nil || pkt.DNSInfo.IsQuery {
		return
	}

	serverKey := pkt.SrcIP
	isNX := pkt.DNSInfo.RCode == "NXDomain"

	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()

	w, ok := a.dnsStats[serverKey]
	if !ok {
		w = &dnsWindow{}
		a.dnsStats[serverKey] = w
	}

	// Trim old entries
	cutoff := now.Add(-windowDuration)
	trimmed := w.samples[:0]
	total := 0
	nxCount := 0
	for _, e := range w.samples {
		if !e.ts.Before(cutoff) {
			trimmed = append(trimmed, e)
			total++
			if e.nxdomain {
				nxCount++
			}
		}
	}

	// Add current
	trimmed = append(trimmed, dnsEvent{ts: now, nxdomain: isNX})
	total++
	if isNX {
		nxCount++
	}

	w.samples = trimmed
	w.total = total
	w.nxdomain = nxCount

	// Check NXDOMAIN rate > 50% with minimum sample size
	if total >= 10 && float64(nxCount)/float64(total) > 0.5 {
		rate := float64(nxCount) / float64(total) * 100
		a.emitAlert(Alert{
			Timestamp: now,
			SrcIP:     pkt.DstIP, // the client that queried
			DstIP:     pkt.SrcIP, // the DNS server
			Protocol:  pkt.Protocol,
			AlertType: "dns_anomaly",
			Message:   fmt.Sprintf("NXDOMAIN rate %.0f%% (%d/%d) from DNS server %s in last 60s", rate, nxCount, total, serverKey),
			Value:     rate,
			Threshold: 50,
		})
	}
}

func (a *StreamAnalyzer) analyzeTLS(pkt *parser.ParsedPacket, now time.Time) {
	if pkt.TLSInfo == nil || !pkt.TLSInfo.IsClientHello || pkt.TLSInfo.SNI == "" {
		return
	}

	sni := pkt.TLSInfo.SNI
	// Check if SNI looks like an IP address instead of a hostname
	if net.ParseIP(sni) != nil {
		a.emitAlert(Alert{
			Timestamp: now,
			SrcIP:     pkt.SrcIP,
			DstIP:     pkt.DstIP,
			DstPort:   pkt.DstPort,
			Protocol:  pkt.Protocol,
			AlertType: "tls_anomaly",
			Message:   fmt.Sprintf("TLS ClientHello SNI contains IP address %q instead of hostname (src=%s dst=%s:%d)", sni, pkt.SrcIP, pkt.DstIP, pkt.DstPort),
			Value:     1,
			Threshold: 0,
		})
	}
}

func (a *StreamAnalyzer) emitAlert(alert Alert) {
	select {
	case a.alerts <- alert:
	default:
		// Channel full — drop oldest to make room
		select {
		case <-a.alerts:
		default:
		}
		a.alerts <- alert
	}
}

func ruleMatches(rule *WatchRule, pkt *parser.ParsedPacket) bool {
	if pkt.DstIP != rule.TargetIP && pkt.SrcIP != rule.TargetIP {
		return false
	}
	if rule.TargetPort != 0 && pkt.DstPort != rule.TargetPort && pkt.SrcPort != rule.TargetPort {
		return false
	}
	if rule.Protocol != "" && pkt.Protocol != rule.Protocol {
		return false
	}
	return true
}

func windowSeconds(samples []windowSample) float64 {
	if len(samples) < 2 {
		return 0
	}
	first := samples[0].ts
	last := samples[len(samples)-1].ts
	d := last.Sub(first).Seconds()
	if d < 1 {
		return 1
	}
	return d
}
