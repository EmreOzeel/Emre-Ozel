package models

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAutoMigrate(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	err = db.AutoMigrate(
		&Team{},
		&User{},
		&Analysis{},
		&SuppressionRule{},
		&TelemetryEvent{},
		&FindingTriage{},
		&PathAnalysisSavedQuery{},
		&PathAnalysisRolePreset{},
		&PathAnalysisCache{},
		&PathAnalysisFeedback{},
		&InvestigationNote{},
		&MonitoredPath{},
		&MonitorSuppression{},
		&MonitorOutcome{},
		&MonitoredPathRun{},
		&Notification{},
		&LiveEvent{},
		&LiveFlow{},
		&LiveIncident{},
		&AttackSession{},
		&IPBaseline{},
		&Asset{},
		&ThreatIndicator{},
		&ThreatFeed{},
		&CorrelationRule{},
		&GeoIPCache{},
		&WebTransaction{},
	)
	if err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	// Verify we can create and read a user
	user := User{Username: "test", HashedPassword: "x", IsAdmin: false}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if user.ID == 0 {
		t.Error("expected non-zero user ID after create")
	}
}

func TestWebTransactionCreate(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&WebTransaction{}); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	host := "www.example.com"
	url := "https://www.example.com/index.html"
	method := "GET"
	status := 200
	wt := WebTransaction{
		SourceID:        "src-1",
		DeviceType:      "firewall",
		SourceIP:        "10.0.0.1",
		DestinationIP:   "203.0.113.10",
		Host:            &host,
		URL:             &url,
		Method:          &method,
		StatusCode:      &status,
		BytesIn:         100,
		BytesOut:        200,
		TransactionTime: time.Now().UTC(),
	}
	if err := db.Create(&wt).Error; err != nil {
		t.Fatalf("failed to create web transaction: %v", err)
	}
	if wt.ID == 0 {
		t.Error("expected non-zero web transaction ID after create")
	}

	var loaded WebTransaction
	if err := db.First(&loaded, wt.ID).Error; err != nil {
		t.Fatalf("failed to load web transaction: %v", err)
	}
	if loaded.Host == nil || *loaded.Host != host {
		t.Errorf("unexpected host: %v", loaded.Host)
	}
	if loaded.StatusCode == nil || *loaded.StatusCode != 200 {
		t.Errorf("unexpected status code: %v", loaded.StatusCode)
	}
	if loaded.TableName() != "web_transactions" {
		t.Errorf("unexpected table name: %s", loaded.TableName())
	}
}
