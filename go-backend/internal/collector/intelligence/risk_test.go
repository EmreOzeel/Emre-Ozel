package intelligence

import (
	"testing"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupRiskDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	db.AutoMigrate(&models.LiveFlow{})
	return db
}

func seedRiskFlows(db *gorm.DB, srcIP string, allowCount, denyCount, resetCount int) {
	now := time.Now().UTC()
	for i := 0; i < allowCount+denyCount+resetCount; i++ {
		f := models.LiveFlow{
			SourceID:      "test",
			DeviceType:    "firewall",
			ParserID:      "test",
			SourceIP:      srcIP,
			DestinationIP: "10.0.0.1",
			FirstSeen:     now.Add(-5 * time.Minute),
			LastSeen:      now,
			EventCount:    1,
		}
		if i < denyCount {
			f.DenyCount = 1
		} else if i < denyCount+resetCount {
			f.ResetCount = 1
		} else {
			f.AllowCount = 1
		}
		db.Create(&f)
	}
}

func TestRisk_HighDenyRate(t *testing.T) {
	db := setupRiskDB(t)
	seedRiskFlows(db, "192.168.1.50", 1, 3, 0) // 3 deny, 1 allow

	scores := ComputeLiveRiskScores(db)
	if len(scores) == 0 {
		t.Fatal("expected at least 1 risk score")
	}
	found := false
	for _, s := range scores {
		if s["source_ip"] == "192.168.1.50" {
			found = true
			drivers, _ := s["drivers"].([]string)
			hasDriver := false
			for _, d := range drivers {
				if d == "high_deny_ratio" {
					hasDriver = true
				}
			}
			if !hasDriver {
				t.Errorf("expected high_deny_ratio driver, got %v", drivers)
			}
		}
	}
	if !found {
		t.Error("IP 192.168.1.50 not found in risk scores")
	}
}

func TestRisk_BelowMinFlows(t *testing.T) {
	db := setupRiskDB(t)
	// Only 1 flow — below minimum of 2
	seedRiskFlows(db, "10.0.0.99", 1, 0, 0)

	scores := ComputeLiveRiskScores(db)
	for _, s := range scores {
		if s["source_ip"] == "10.0.0.99" {
			t.Error("IP with only 1 flow should be excluded")
		}
	}
}

func TestRisk_ScoreCapped(t *testing.T) {
	db := setupRiskDB(t)
	// Lots of deny+reset flows → should still be capped at 100
	seedRiskFlows(db, "10.0.0.88", 0, 50, 50)

	scores := ComputeLiveRiskScores(db)
	for _, s := range scores {
		if s["source_ip"] == "10.0.0.88" {
			score, _ := s["risk_score"].(int)
			if score > 100 {
				t.Errorf("score=%d, should be capped at 100", score)
			}
		}
	}
}
