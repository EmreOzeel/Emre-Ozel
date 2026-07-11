package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/emreozeel/pcap-analyzer/backend/internal/api/handlers"
	"github.com/emreozeel/pcap-analyzer/backend/internal/api/router"
	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"github.com/emreozeel/pcap-analyzer/backend/internal/database"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

const testPacketToken = "test-packet-token"

// ingestRouter builds a router whose config carries the given packet-engine
// token (empty token exercises the "not configured" branch).
func ingestRouter(t *testing.T, packetToken string) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg := &config.Config{
		JWTSecret:         "test-secret-key-for-ingest",
		JWTExpireHours:    24,
		UploadDir:         t.TempDir(),
		MaxUploadMB:       100,
		AllowedOrigins:    "*",
		PacketEngineToken: packetToken,
	}
	auth.Init(cfg)
	database.DB = db

	h := handlers.New(db, cfg)
	return router.Setup(db, cfg, h), db
}

func postIngest(t *testing.T, r *gin.Engine, path, token string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Valid events are stored as LiveEvent rows with the documented defaults.
func TestIngestPacketEvents_Accepts(t *testing.T) {
	r, db := ingestRouter(t, testPacketToken)

	payload := map[string]interface{}{
		"events": []map[string]interface{}{
			{
				"source_id": "engine-1", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
				"source_port": 12345, "destination_port": 443, "protocol": "TCP",
				"first_seen": "2026-04-15T12:00:00Z", "duration_ms": 250,
				"packet_count": 10, "bytes_in": 500, "bytes_out": 1500, "action": "allow",
			},
			{"source_ip": "10.0.0.3", "destination_ip": "10.0.0.4"}, // minimal -> defaults
		},
	}

	w := postIngest(t, r, "/api/ingest/packet-events", testPacketToken, payload)
	if w.Code != 200 {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["accepted"].(float64) != 2 {
		t.Errorf("accepted=%v, want 2", resp["accepted"])
	}

	var count int64
	db.Model(&models.LiveEvent{}).Count(&count)
	if count != 2 {
		t.Fatalf("db rows=%d, want 2", count)
	}

	var first models.LiveEvent
	db.Where("source_ip = ?", "10.0.0.1").First(&first)
	if first.SourceID != "engine-1" || first.DeviceType != "packet_engine" || first.ParserID != "gopacket" {
		t.Errorf("defaults wrong: source_id=%q device_type=%q parser_id=%q", first.SourceID, first.DeviceType, first.ParserID)
	}
	if first.DeviceRole == nil || *first.DeviceRole != "span" {
		t.Errorf("device_role want span, got %v", first.DeviceRole)
	}
	if first.DestinationPort == nil || *first.DestinationPort != 443 {
		t.Errorf("destination_port want 443, got %v", first.DestinationPort)
	}
	if first.PacketsIn == nil || *first.PacketsIn != 10 {
		t.Errorf("packets_in want 10, got %v", first.PacketsIn)
	}
	if !first.EventTime.Equal(time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("event_time not parsed from first_seen: %v", first.EventTime)
	}

	var second models.LiveEvent
	db.Where("source_ip = ?", "10.0.0.3").First(&second)
	if second.SourceID != "packet_engine" || second.Action != "allow" {
		t.Errorf("defaults wrong: source_id=%q action=%q", second.SourceID, second.Action)
	}
	if second.SourcePort != nil {
		t.Errorf("absent source_port should be nil, got %v", *second.SourcePort)
	}
}

func TestIngestPacketEvents_WrongToken(t *testing.T) {
	r, _ := ingestRouter(t, testPacketToken)
	w := postIngest(t, r, "/api/ingest/packet-events", "bad-token",
		map[string]interface{}{"events": []map[string]interface{}{}})
	if w.Code != 401 {
		t.Errorf("wrong token: got %d, want 401", w.Code)
	}
}

func TestIngestPacketEvents_MissingToken(t *testing.T) {
	r, _ := ingestRouter(t, testPacketToken)
	w := postIngest(t, r, "/api/ingest/packet-events", "",
		map[string]interface{}{"events": []map[string]interface{}{}})
	if w.Code != 401 {
		t.Errorf("missing token: got %d, want 401", w.Code)
	}
}

func TestIngest_NotConfigured(t *testing.T) {
	r, _ := ingestRouter(t, "") // token unset -> 503
	w := postIngest(t, r, "/api/ingest/packet-events", "anything",
		map[string]interface{}{"events": []map[string]interface{}{}})
	if w.Code != 503 {
		t.Errorf("not configured: got %d, want 503", w.Code)
	}
}

// An alert creates an admin notification and annotates the open incident.
func TestIngestPacketAlert(t *testing.T) {
	r, db := ingestRouter(t, testPacketToken)

	now := time.Now().UTC()
	db.Create(&models.LiveIncident{
		SourceIP: "10.9.9.9", BehaviorType: "port_scan", Status: "open",
		FirstSeen: now, LastSeen: now,
	})

	alert := map[string]interface{}{
		"timestamp": now.Format(time.RFC3339), "src_ip": "10.9.9.9",
		"dst_ip": "10.9.9.1", "dst_port": 22, "protocol": "TCP",
		"alert_type": "rate_spike", "message": "connection rate exceeded",
		"value": 120.0, "threshold": 50.0,
	}

	w := postIngest(t, r, "/api/ingest/packet-alerts", testPacketToken, alert)
	if w.Code != 200 {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["accepted"] != true {
		t.Errorf("accepted=%v, want true", resp["accepted"])
	}

	var notif models.Notification
	if err := db.Where("user_id = ? AND type = ?", 1, "drift_detected").First(&notif).Error; err != nil {
		t.Fatalf("notification not created: %v", err)
	}
	if notif.Message == "" || notif.Message[:14] != "[STREAM ALERT]" {
		t.Errorf("unexpected notification message: %q", notif.Message)
	}

	var inc models.LiveIncident
	db.Where("source_ip = ?", "10.9.9.9").First(&inc)
	if inc.LastActivitySummary == nil || *inc.LastActivitySummary == "" {
		t.Errorf("incident last_activity_summary not updated")
	}
}
