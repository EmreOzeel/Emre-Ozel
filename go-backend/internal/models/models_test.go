package models

import (
	"testing"

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
