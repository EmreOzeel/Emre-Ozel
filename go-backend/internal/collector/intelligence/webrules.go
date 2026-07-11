package intelligence

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

// Behavior types produced by the web rules scanner.
const (
	BehaviorWebPolicyBurst   = "web_policy_burst"
	BehaviorWebRiskyCategory = "web_risky_category"
	BehaviorWebHostSpread    = "web_host_spread"
)

// Default thresholds for the web incident rules. Each can be overridden via
// the environment variables documented in LoadWebRuleConfig.
const (
	DefaultWebBurstThreshold          = 10
	DefaultWebBurstWindowMinutes      = 5
	DefaultWebHostSpreadThreshold     = 30
	DefaultWebHostSpreadWindowMinutes = 5
)

// DefaultWebRiskyCategories are URL categories that create an incident on the
// first matching transaction (all lowercase; matching is case-insensitive).
var DefaultWebRiskyCategories = []string{
	"malware",
	"phishing",
	"command-and-control",
	"c2",
	"hacking",
	"proxy-avoidance-and-anonymizers",
	"grayware",
}

// webDeniedActionSQL matches web transactions whose action indicates the
// request was denied/blocked/dropped (covers normalized "deny"/"drop" as well
// as raw PAN-OS values such as "block-url" or "block-continue").
const webDeniedActionSQL = "(LOWER(action) LIKE 'deny%' OR LOWER(action) LIKE 'block%' OR LOWER(action) LIKE 'drop%')"

// webNotSuppressedSQL excludes transactions hidden by suppression rules.
const webNotSuppressedSQL = "(suppressed IS NULL OR suppressed = ?)"

// WebRuleConfig holds thresholds for the web incident rules.
type WebRuleConfig struct {
	BurstThreshold          int
	BurstWindowMinutes      int
	HostSpreadThreshold     int
	HostSpreadWindowMinutes int
	RiskyCategories         []string // lowercase
}

// LoadWebRuleConfig builds the rule configuration from environment variables,
// falling back to package defaults:
//
//	WEB_RULE_BURST_THRESHOLD        (default 10)
//	WEB_RULE_BURST_WINDOW_MIN       (default 5)
//	WEB_RULE_HOST_SPREAD_THRESHOLD  (default 30)
//	WEB_RULE_HOST_SPREAD_WINDOW_MIN (default 5)
//	WEB_RULE_RISKY_CATEGORIES       (comma-separated, default DefaultWebRiskyCategories)
func LoadWebRuleConfig() WebRuleConfig {
	return WebRuleConfig{
		BurstThreshold:          webEnvInt("WEB_RULE_BURST_THRESHOLD", DefaultWebBurstThreshold),
		BurstWindowMinutes:      webEnvInt("WEB_RULE_BURST_WINDOW_MIN", DefaultWebBurstWindowMinutes),
		HostSpreadThreshold:     webEnvInt("WEB_RULE_HOST_SPREAD_THRESHOLD", DefaultWebHostSpreadThreshold),
		HostSpreadWindowMinutes: webEnvInt("WEB_RULE_HOST_SPREAD_WINDOW_MIN", DefaultWebHostSpreadWindowMinutes),
		RiskyCategories:         webEnvList("WEB_RULE_RISKY_CATEGORIES", DefaultWebRiskyCategories),
	}
}

// WebRuleScanner periodically evaluates web_transactions against suspicious
// web behavior rules and creates/updates LiveIncidents. It keeps an in-memory
// cursor (lastScan) so the same transactions are not re-processed every tick.
type WebRuleScanner struct {
	cfg      WebRuleConfig
	mu       sync.Mutex
	lastScan time.Time
}

// NewWebRuleScanner creates a scanner with configuration from the environment.
func NewWebRuleScanner() *WebRuleScanner {
	return &WebRuleScanner{cfg: LoadWebRuleConfig()}
}

// NewWebRuleScannerWithConfig creates a scanner with an explicit configuration
// (primarily for tests).
func NewWebRuleScannerWithConfig(cfg WebRuleConfig) *WebRuleScanner {
	return &WebRuleScanner{cfg: cfg}
}

// Scan runs all web incident rules once. Only sources that produced new
// transactions since the previous scan are evaluated, which prevents the same
// rows from generating repeated incident updates. Returns created/updated
// incident counts.
func (s *WebRuleScanner) Scan(db *gorm.DB) (created, updated int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	maxWindow := s.cfg.BurstWindowMinutes
	if s.cfg.HostSpreadWindowMinutes > maxWindow {
		maxWindow = s.cfg.HostSpreadWindowMinutes
	}

	newSince := s.lastScan
	if newSince.IsZero() {
		// First scan: only look back over the widest rule window.
		newSince = now.Add(-time.Duration(maxWindow) * time.Minute)
	}
	s.lastScan = now

	// Cursor gate: which sources have new transactions since the last scan?
	var activeIPs []string
	db.Model(&models.WebTransaction{}).
		Where("created_at > ?", newSince).
		Distinct().
		Pluck("source_ip", &activeIPs)

	if len(activeIPs) == 0 {
		return 0, 0
	}

	c, u := s.scanRiskyCategories(db, now, newSince)
	created += c
	updated += u

	c, u = s.scanPolicyBurst(db, now, activeIPs)
	created += c
	updated += u

	c, u = s.scanHostSpread(db, now, activeIPs)
	created += c
	updated += u

	return created, updated
}

// scanPolicyBurst (R1): a source with >= BurstThreshold denied/blocked/dropped
// web transactions inside the burst window becomes a medium incident.
func (s *WebRuleScanner) scanPolicyBurst(db *gorm.DB, now time.Time, activeIPs []string) (created, updated int) {
	windowStart := now.Add(-time.Duration(s.cfg.BurstWindowMinutes) * time.Minute)

	type row struct {
		SourceIP      string
		Total         int64
		DistinctHosts int64
		DistinctDsts  int64
	}

	var rows []row
	db.Model(&models.WebTransaction{}).
		Select("source_ip, count(*) as total, count(distinct host) as distinct_hosts, count(distinct destination_ip) as distinct_dsts").
		Where("transaction_time >= ? AND source_ip IN ?", windowStart, activeIPs).
		Where(webDeniedActionSQL).
		Where(webNotSuppressedSQL, false).
		Group("source_ip").
		Having("count(*) >= ?", s.cfg.BurstThreshold).
		Find(&rows)

	for _, r := range rows {
		topHosts := s.topWebColumn(db, "host", r.SourceIP, windowStart, true)
		topDsts := s.topWebColumn(db, "destination_ip", r.SourceIP, windowStart, true)

		summary := fmt.Sprintf("web_policy_burst: %d denied web requests to %d host(s) in %dm",
			r.Total, r.DistinctHosts, s.cfg.BurstWindowMinutes)
		if len(topHosts) > 0 {
			summary += fmt.Sprintf("; top host: %s", topHosts[0])
		}

		if s.upsertWebIncident(db, webIncidentDetails{
			SourceIP:     r.SourceIP,
			BehaviorType: BehaviorWebPolicyBurst,
			Severity:     "medium",
			Summary:      summary,
			EventCount:   int(r.Total),
			TopHosts:     topHosts,
			TopDstIPs:    topDsts,
			DistinctDsts: int(r.DistinctDsts),
		}) {
			created++
		} else {
			updated++
		}
	}

	return created, updated
}

// scanRiskyCategories (R2): any new transaction whose URL category is in the
// risky list creates a high severity incident, even a single one.
func (s *WebRuleScanner) scanRiskyCategories(db *gorm.DB, now, newSince time.Time) (created, updated int) {
	type row struct {
		SourceIP      string
		DestinationIP string
		Host          *string
		Category      *string
	}

	var rows []row
	db.Model(&models.WebTransaction{}).
		Select("source_ip, destination_ip, host, category").
		Where("created_at > ? AND category IS NOT NULL AND LOWER(category) IN ?", newSince, s.cfg.RiskyCategories).
		Where(webNotSuppressedSQL, false).
		Find(&rows)

	type agg struct {
		count int
		hosts map[string]bool
		dsts  map[string]bool
		cats  map[string]bool
	}

	bySource := map[string]*agg{}
	for _, r := range rows {
		a := bySource[r.SourceIP]
		if a == nil {
			a = &agg{hosts: map[string]bool{}, dsts: map[string]bool{}, cats: map[string]bool{}}
			bySource[r.SourceIP] = a
		}
		a.count++
		if r.Host != nil && *r.Host != "" {
			a.hosts[*r.Host] = true
		}
		if r.DestinationIP != "" {
			a.dsts[r.DestinationIP] = true
		}
		if r.Category != nil && *r.Category != "" {
			a.cats[strings.ToLower(*r.Category)] = true
		}
	}

	for sourceIP, a := range bySource {
		hosts := sortedKeysWeb(a.hosts)
		cats := sortedKeysWeb(a.cats)
		dsts := sortedKeysWeb(a.dsts)

		summary := fmt.Sprintf("web_risky_category: %d request(s) to risky categories (%s)",
			a.count, strings.Join(cats, ", "))
		if len(hosts) > 0 {
			summary += "; hosts: " + strings.Join(limitStringsWeb(hosts, 5), ", ")
		}

		if s.upsertWebIncident(db, webIncidentDetails{
			SourceIP:     sourceIP,
			BehaviorType: BehaviorWebRiskyCategory,
			Severity:     "high",
			Summary:      summary,
			EventCount:   a.count,
			TopHosts:     limitStringsWeb(hosts, 5),
			TopDstIPs:    limitStringsWeb(dsts, 5),
			DistinctDsts: len(dsts),
		}) {
			created++
		} else {
			updated++
		}
	}

	return created, updated
}

// scanHostSpread (R3): a source that contacts >= HostSpreadThreshold distinct
// hosts inside the spread window becomes a medium incident (possible
// beaconing or web scanning).
func (s *WebRuleScanner) scanHostSpread(db *gorm.DB, now time.Time, activeIPs []string) (created, updated int) {
	windowStart := now.Add(-time.Duration(s.cfg.HostSpreadWindowMinutes) * time.Minute)

	type row struct {
		SourceIP      string
		DistinctHosts int64
		Total         int64
		DistinctDsts  int64
	}

	var rows []row
	db.Model(&models.WebTransaction{}).
		Select("source_ip, count(distinct host) as distinct_hosts, count(*) as total, count(distinct destination_ip) as distinct_dsts").
		Where("transaction_time >= ? AND source_ip IN ? AND host IS NOT NULL AND host <> ''", windowStart, activeIPs).
		Where(webNotSuppressedSQL, false).
		Group("source_ip").
		Having("count(distinct host) >= ?", s.cfg.HostSpreadThreshold).
		Find(&rows)

	for _, r := range rows {
		topHosts := s.topWebColumn(db, "host", r.SourceIP, windowStart, false)
		topDsts := s.topWebColumn(db, "destination_ip", r.SourceIP, windowStart, false)

		summary := fmt.Sprintf("web_host_spread: requests to %d distinct hosts (%d requests) in %dm; possible beaconing or web scanning",
			r.DistinctHosts, r.Total, s.cfg.HostSpreadWindowMinutes)

		if s.upsertWebIncident(db, webIncidentDetails{
			SourceIP:     r.SourceIP,
			BehaviorType: BehaviorWebHostSpread,
			Severity:     "medium",
			Summary:      summary,
			EventCount:   int(r.Total),
			TopHosts:     topHosts,
			TopDstIPs:    topDsts,
			DistinctDsts: int(r.DistinctDsts),
		}) {
			created++
		} else {
			updated++
		}
	}

	return created, updated
}

// webIncidentDetails carries the fields used to create or refresh an incident.
type webIncidentDetails struct {
	SourceIP     string
	BehaviorType string
	Severity     string
	Summary      string
	EventCount   int
	TopHosts     []string
	TopDstIPs    []string
	DistinctDsts int
}

// upsertWebIncident applies the same dedup pattern as UpsertIncidents: if an
// open/investigating incident exists for the same source_ip + behavior_type
// within the merge window, it is refreshed; otherwise a new one is created.
// Returns true when a new incident was created.
func (s *WebRuleScanner) upsertWebIncident(db *gorm.DB, d webIncidentDetails) bool {
	now := time.Now().UTC()
	mergeWindow := now.Add(-MergeWindowMinutes * time.Minute)

	if d.EventCount < 1 {
		d.EventCount = 1
	}

	summary := d.Summary
	var targetSummary *string
	if len(d.TopHosts) > 0 {
		ts := "top hosts: " + strings.Join(limitStringsWeb(d.TopHosts, 5), ", ")
		targetSummary = &ts
	}
	var topDstJSON *string
	if len(d.TopDstIPs) > 0 {
		if b, err := json.Marshal(limitStringsWeb(d.TopDstIPs, 5)); err == nil {
			j := string(b)
			topDstJSON = &j
		}
	}
	var distinctDsts *int
	if d.DistinctDsts > 0 {
		v := d.DistinctDsts
		distinctDsts = &v
	}

	// Try to find an existing open/investigating incident within merge window
	var existing models.LiveIncident
	err := db.Where(
		"source_ip = ? AND behavior_type = ? AND status IN (?,?) AND last_seen >= ?",
		d.SourceIP, d.BehaviorType, "open", "investigating", mergeWindow,
	).Order("last_seen desc").First(&existing).Error

	if err == nil {
		// Update existing incident
		existing.LastSeen = now
		existing.EventCount++
		existing.Summary = &summary
		if targetSummary != nil {
			existing.TargetSummary = targetSummary
		}
		if topDstJSON != nil {
			existing.TopDestinationIPs = topDstJSON
		}
		if distinctDsts != nil {
			existing.TotalDistinctDestinations = distinctDsts
		}

		// Never downgrade severity
		if sevRank[d.Severity] > sevRank[existing.Severity] {
			existing.Severity = d.Severity
		}

		db.Save(&existing)
		return false
	}

	// Create new incident
	incident := models.LiveIncident{
		SourceIP:                  d.SourceIP,
		BehaviorType:              d.BehaviorType,
		Severity:                  d.Severity,
		Status:                    "open",
		FirstSeen:                 now,
		LastSeen:                  now,
		EventCount:                d.EventCount,
		Summary:                   &summary,
		TargetSummary:             targetSummary,
		TopDestinationIPs:         topDstJSON,
		TotalDistinctDestinations: distinctDsts,
	}
	db.Create(&incident)

	// Notify admin for medium+ severity (same pattern as UpsertIncidents)
	if sevRank[d.Severity] >= sevRank["medium"] {
		notif := models.Notification{
			UserID:  AdminUserID,
			Type:    "drift_detected",
			Message: fmt.Sprintf("[AUTO] New %s incident: %s from %s", d.Severity, d.BehaviorType, d.SourceIP),
		}
		db.Create(&notif)
	}

	return true
}

// topWebColumn returns up to 5 most frequent non-empty values of a column for
// a source within the window, optionally restricted to denied transactions.
func (s *WebRuleScanner) topWebColumn(db *gorm.DB, column, sourceIP string, since time.Time, deniedOnly bool) []string {
	q := db.Model(&models.WebTransaction{}).
		Select(column).
		Where("transaction_time >= ? AND source_ip = ?", since, sourceIP).
		Where(column+" IS NOT NULL AND "+column+" <> ''").
		Where(webNotSuppressedSQL, false)
	if deniedOnly {
		q = q.Where(webDeniedActionSQL)
	}

	var vals []string
	q.Group(column).Order("count(*) desc").Limit(5).Pluck(column, &vals)
	return vals
}

// ---------------------------------------------------------------------------
// Env / small helpers
// ---------------------------------------------------------------------------

func webEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func webEnvList(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return append([]string(nil), fallback...)
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), fallback...)
	}
	return out
}

func sortedKeysWeb(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func limitStringsWeb(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
