package intelligence

import (
	"fmt"
	"testing"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupWebRulesDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	db.AutoMigrate(&models.WebTransaction{}, &models.LiveIncident{}, &models.Notification{}, &models.User{})
	// Create admin user (id=1)
	db.Create(&models.User{Username: "admin", HashedPassword: "x", IsAdmin: true})
	return db
}

// seedWebTx inserts one web transaction. Empty host/category/action are
// stored as NULL. when is used for both transaction_time and created_at so
// the scanner cursor behaves deterministically.
func seedWebTx(t *testing.T, db *gorm.DB, srcIP, dstIP, host, category, action string, when time.Time) {
	t.Helper()
	tx := models.WebTransaction{
		SourceID:        "test",
		DeviceType:      "firewall",
		SourceIP:        srcIP,
		DestinationIP:   dstIP,
		TransactionTime: when,
		CreatedAt:       when,
	}
	if host != "" {
		h := host
		tx.Host = &h
	}
	if category != "" {
		c := category
		tx.Category = &c
	}
	if action != "" {
		a := action
		tx.Action = &a
	}
	if err := db.Create(&tx).Error; err != nil {
		t.Fatalf("failed to seed web transaction: %v", err)
	}
}

func countIncidents(t *testing.T, db *gorm.DB, behaviorType string) int64 {
	t.Helper()
	var count int64
	q := db.Model(&models.LiveIncident{})
	if behaviorType != "" {
		q = q.Where("behavior_type = ?", behaviorType)
	}
	q.Count(&count)
	return count
}

func firstIncident(t *testing.T, db *gorm.DB, behaviorType string) models.LiveIncident {
	t.Helper()
	var inc models.LiveIncident
	if err := db.Where("behavior_type = ?", behaviorType).First(&inc).Error; err != nil {
		t.Fatalf("expected %s incident, got error: %v", behaviorType, err)
	}
	return inc
}

// ---------------------------------------------------------------------------
// R1: web_policy_burst
// ---------------------------------------------------------------------------

func TestWebRules_PolicyBurst_Positive(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	// 12 denied requests (>= default threshold 10) to 3 hosts within 5 min
	for i := 0; i < 12; i++ {
		host := fmt.Sprintf("blocked%d.example.com", i%3)
		seedWebTx(t, db, "192.168.1.50", "203.0.113.10", host, "", "deny", now.Add(-2*time.Minute))
	}

	scanner := NewWebRuleScanner()
	created, _ := scanner.Scan(db)

	if created != 1 {
		t.Errorf("expected 1 created incident, got %d", created)
	}
	inc := firstIncident(t, db, BehaviorWebPolicyBurst)
	if inc.SourceIP != "192.168.1.50" {
		t.Errorf("expected source_ip 192.168.1.50, got %s", inc.SourceIP)
	}
	if inc.Severity != "medium" {
		t.Errorf("expected severity medium, got %s", inc.Severity)
	}
	if inc.Status != "open" {
		t.Errorf("expected status open, got %s", inc.Status)
	}
	if inc.EventCount != 12 {
		t.Errorf("expected event_count 12, got %d", inc.EventCount)
	}
	if inc.Summary == nil || *inc.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestWebRules_PolicyBurst_BlockActionVariants(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	// Raw PAN-OS style actions should also match (block-url, drop, deny)
	actions := []string{"block-url", "block-continue", "drop", "deny"}
	for i := 0; i < 12; i++ {
		seedWebTx(t, db, "192.168.1.51", "203.0.113.10", "bad.example.com", "", actions[i%len(actions)], now.Add(-1*time.Minute))
	}

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	if n := countIncidents(t, db, BehaviorWebPolicyBurst); n != 1 {
		t.Errorf("expected 1 web_policy_burst incident, got %d", n)
	}
}

func TestWebRules_PolicyBurst_BelowThreshold(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	// Only 9 denied (< 10); the 5 allowed must not count
	for i := 0; i < 9; i++ {
		seedWebTx(t, db, "192.168.1.60", "203.0.113.10", "site.example.com", "", "deny", now.Add(-2*time.Minute))
	}
	for i := 0; i < 5; i++ {
		seedWebTx(t, db, "192.168.1.60", "203.0.113.10", "ok.example.com", "", "allow", now.Add(-2*time.Minute))
	}

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	if n := countIncidents(t, db, BehaviorWebPolicyBurst); n != 0 {
		t.Errorf("expected 0 incidents below threshold, got %d", n)
	}
}

func TestWebRules_PolicyBurst_EnvOverride(t *testing.T) {
	t.Setenv("WEB_RULE_BURST_THRESHOLD", "3")

	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	for i := 0; i < 3; i++ {
		seedWebTx(t, db, "192.168.1.70", "203.0.113.10", "site.example.com", "", "deny", now.Add(-1*time.Minute))
	}

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	if n := countIncidents(t, db, BehaviorWebPolicyBurst); n != 1 {
		t.Errorf("expected 1 incident with lowered threshold, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// R2: web_risky_category
// ---------------------------------------------------------------------------

func TestWebRules_RiskyCategory_SingleTransaction(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	// A single malware-category transaction is enough
	seedWebTx(t, db, "10.0.0.5", "198.51.100.7", "evil.example.com", "malware", "allow", now.Add(-1*time.Minute))

	scanner := NewWebRuleScanner()
	created, _ := scanner.Scan(db)

	if created != 1 {
		t.Errorf("expected 1 created incident, got %d", created)
	}
	inc := firstIncident(t, db, BehaviorWebRiskyCategory)
	if inc.Severity != "high" {
		t.Errorf("expected severity high, got %s", inc.Severity)
	}
	if inc.SourceIP != "10.0.0.5" {
		t.Errorf("expected source_ip 10.0.0.5, got %s", inc.SourceIP)
	}

	// medium+ severity must produce an admin notification
	var notifCount int64
	db.Model(&models.Notification{}).Count(&notifCount)
	if notifCount < 1 {
		t.Errorf("expected notification for high severity incident, got %d", notifCount)
	}
}

func TestWebRules_RiskyCategory_CaseInsensitive(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	seedWebTx(t, db, "10.0.0.6", "198.51.100.7", "c2.example.com", "Command-And-Control", "alert", now.Add(-1*time.Minute))

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	if n := countIncidents(t, db, BehaviorWebRiskyCategory); n != 1 {
		t.Errorf("expected 1 incident for mixed-case category, got %d", n)
	}
}

func TestWebRules_RiskyCategory_SafeCategory(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	seedWebTx(t, db, "10.0.0.7", "198.51.100.7", "news.example.com", "news", "allow", now.Add(-1*time.Minute))
	seedWebTx(t, db, "10.0.0.7", "198.51.100.8", "shop.example.com", "shopping", "allow", now.Add(-1*time.Minute))

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	if n := countIncidents(t, db, ""); n != 0 {
		t.Errorf("expected 0 incidents for safe categories, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// R3: web_host_spread
// ---------------------------------------------------------------------------

func TestWebRules_HostSpread_Positive(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	// 30 distinct hosts (>= default threshold 30) within 5 min
	for i := 0; i < 30; i++ {
		host := fmt.Sprintf("host%02d.example.com", i)
		dst := fmt.Sprintf("198.51.100.%d", i+1)
		seedWebTx(t, db, "172.16.0.9", dst, host, "", "allow", now.Add(-3*time.Minute))
	}

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	inc := firstIncident(t, db, BehaviorWebHostSpread)
	if inc.Severity != "medium" {
		t.Errorf("expected severity medium, got %s", inc.Severity)
	}
	if inc.TotalDistinctDestinations == nil || *inc.TotalDistinctDestinations != 30 {
		t.Errorf("expected 30 distinct destinations, got %v", inc.TotalDistinctDestinations)
	}
	if inc.TopDestinationIPs == nil || *inc.TopDestinationIPs == "" {
		t.Error("expected top_destination_ips to be populated")
	}
}

func TestWebRules_HostSpread_BelowThreshold(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	// Only 20 distinct hosts (< 30)
	for i := 0; i < 20; i++ {
		host := fmt.Sprintf("host%02d.example.com", i)
		seedWebTx(t, db, "172.16.0.10", "198.51.100.99", host, "", "allow", now.Add(-3*time.Minute))
	}

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	if n := countIncidents(t, db, BehaviorWebHostSpread); n != 0 {
		t.Errorf("expected 0 incidents below host spread threshold, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// Dedup + cursor behavior
// ---------------------------------------------------------------------------

func TestWebRules_Dedup_SecondScanNoNewIncident(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	seedWebTx(t, db, "10.0.0.20", "198.51.100.20", "phish.example.com", "phishing", "deny", now.Add(-1*time.Minute))

	scanner := NewWebRuleScanner()
	created, updated := scanner.Scan(db)
	if created != 1 || updated != 0 {
		t.Fatalf("first scan: expected created=1 updated=0, got created=%d updated=%d", created, updated)
	}

	// Second scan without new transactions: cursor must prevent re-processing
	created, updated = scanner.Scan(db)
	if created != 0 || updated != 0 {
		t.Errorf("second scan: expected created=0 updated=0, got created=%d updated=%d", created, updated)
	}
	if n := countIncidents(t, db, BehaviorWebRiskyCategory); n != 1 {
		t.Errorf("expected 1 incident after second scan, got %d", n)
	}
	inc := firstIncident(t, db, BehaviorWebRiskyCategory)
	if inc.EventCount != 1 {
		t.Errorf("expected event_count still 1 after no-op scan, got %d", inc.EventCount)
	}

	// New risky transaction after the cursor: incident is updated, not duplicated
	seedWebTx(t, db, "10.0.0.20", "198.51.100.21", "phish2.example.com", "phishing", "deny", time.Now().UTC().Add(2*time.Second))

	created, updated = scanner.Scan(db)
	if created != 0 || updated != 1 {
		t.Errorf("third scan: expected created=0 updated=1, got created=%d updated=%d", created, updated)
	}
	if n := countIncidents(t, db, BehaviorWebRiskyCategory); n != 1 {
		t.Errorf("expected still 1 incident after merge, got %d", n)
	}
	inc = firstIncident(t, db, BehaviorWebRiskyCategory)
	if inc.EventCount != 2 {
		t.Errorf("expected event_count 2 after merge, got %d", inc.EventCount)
	}
}

func TestWebRules_Dedup_BurstNotDuplicatedAcrossScans(t *testing.T) {
	db := setupWebRulesDB(t)
	now := time.Now().UTC()

	for i := 0; i < 12; i++ {
		seedWebTx(t, db, "192.168.2.5", "203.0.113.44", "blocked.example.com", "", "deny", now.Add(-2*time.Minute))
	}

	scanner := NewWebRuleScanner()
	scanner.Scan(db)

	// One more denied request arrives; the burst window still contains the
	// old rows, but the existing incident must be merged, not duplicated.
	seedWebTx(t, db, "192.168.2.5", "203.0.113.44", "blocked.example.com", "", "deny", time.Now().UTC().Add(2*time.Second))
	created, updated := scanner.Scan(db)

	if created != 0 {
		t.Errorf("expected 0 created on second scan, got %d", created)
	}
	if updated != 1 {
		t.Errorf("expected 1 updated on second scan, got %d", updated)
	}
	if n := countIncidents(t, db, BehaviorWebPolicyBurst); n != 1 {
		t.Errorf("expected 1 web_policy_burst incident total, got %d", n)
	}
}
