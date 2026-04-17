package intelligence

import (
	"testing"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupBridgeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	db.AutoMigrate(&models.LiveFlow{}, &models.Notification{}, &models.User{})
	// Create admin user (id=1)
	db.Create(&models.User{Username: "admin", HashedPassword: "x", IsAdmin: true})
	return db
}

func seedFlows(db *gorm.DB, srcIP string, count int, state, flowType string) {
	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		f := models.LiveFlow{
			SourceID:      "test",
			DeviceType:    "firewall",
			ParserID:      "test",
			SourceIP:      srcIP,
			DestinationIP: "10.0.0." + string(rune('1'+i)),
			State:         state,
			FlowType:      &flowType,
			FirstSeen:     now.Add(-5 * time.Minute),
			LastSeen:      now,
			EventCount:    1,
		}
		db.Create(&f)
	}
}

func countNotifications(db *gorm.DB) int64 {
	var count int64
	db.Model(&models.Notification{}).Count(&count)
	return count
}

func TestBridge_BlockedFlowSpike(t *testing.T) {
	db := setupBridgeDB(t)
	seedFlows(db, "192.168.1.100", 6, "denied", "blocked")

	ScanPatterns(db)

	if n := countNotifications(db); n < 1 {
		t.Errorf("expected notification for blocked flow spike, got %d", n)
	}
}

func TestBridge_NoAlert_BelowThreshold(t *testing.T) {
	db := setupBridgeDB(t)
	seedFlows(db, "192.168.1.200", 4, "denied", "blocked") // below threshold of 5

	ScanPatterns(db)

	if n := countNotifications(db); n != 0 {
		t.Errorf("expected 0 notifications below threshold, got %d", n)
	}
}

func TestBridge_ScanningFlowType(t *testing.T) {
	db := setupBridgeDB(t)
	scanning := "scanning"
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		db.Create(&models.LiveFlow{
			SourceID:      "test",
			DeviceType:    "firewall",
			ParserID:      "test",
			SourceIP:      "10.10.10.1",
			DestinationIP: "10.0.0." + string(rune('1'+i)),
			State:         "denied",
			FlowType:      &scanning,
			FirstSeen:     now.Add(-3 * time.Minute),
			LastSeen:      now,
			EventCount:    1,
		})
	}

	ScanPatterns(db)

	if n := countNotifications(db); n < 1 {
		t.Errorf("expected notification for scanning flows, got %d", n)
	}
}

func TestBridge_PortScan(t *testing.T) {
	db := setupBridgeDB(t)
	now := time.Now().UTC()
	scanning := "scanning"
	for i := 0; i < 11; i++ {
		db.Create(&models.LiveFlow{
			SourceID:      "test",
			DeviceType:    "firewall",
			ParserID:      "test",
			SourceIP:      "10.50.50.1",
			DestinationIP: "10.0.0." + string(rune('A'+i)),
			State:         "denied",
			FlowType:      &scanning,
			FirstSeen:     now.Add(-3 * time.Minute),
			LastSeen:      now,
			EventCount:    1,
		})
	}

	ScanPatterns(db)

	if n := countNotifications(db); n < 1 {
		t.Errorf("expected notification for port scan, got %d", n)
	}
}

func TestBridge_RepeatedReset(t *testing.T) {
	db := setupBridgeDB(t)
	unstable := "unstable"
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		db.Create(&models.LiveFlow{
			SourceID:      "test",
			DeviceType:    "firewall",
			ParserID:      "test",
			SourceIP:      "10.99.99.1",
			DestinationIP: "10.0.0.1",
			State:         "reset",
			FlowType:      &unstable,
			FirstSeen:     now.Add(-3 * time.Minute),
			LastSeen:      now,
			EventCount:    1,
		})
	}

	ScanPatterns(db)

	if n := countNotifications(db); n < 1 {
		t.Errorf("expected notification for repeated reset, got %d", n)
	}
}
