package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

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

func setupTestRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	// Migrate all models
	db.AutoMigrate(models.AllModels()...)

	cfg := &config.Config{
		JWTSecret:      "test-secret-key-for-handler-tests",
		JWTExpireHours: 24,
		UploadDir:      t.TempDir(),
		MaxUploadMB:    100,
		AllowedOrigins: "*",
	}

	auth.Init(cfg)
	database.DB = db

	// Seed admin user
	hash, _ := auth.HashPassword("admin123")
	db.Create(&models.User{Username: "admin", HashedPassword: hash, IsAdmin: true})

	h := handlers.New(db, cfg)
	r := router.Setup(db, cfg, h)

	return r, db
}

func getAdminToken(t *testing.T, r *gin.Engine) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin123",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp["access_token"].(string)
}

// Test 1: POST /api/auth/login success
func TestLoginSuccess(t *testing.T) {
	r, _ := setupTestRouter(t)

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin123",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("expected access_token in response")
	}
}

// Test 2: POST /api/auth/login wrong password -> 401
func TestLoginWrongPassword(t *testing.T) {
	r, _ := setupTestRouter(t)

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// Test 3: GET /api/auth/me without token -> 401
func TestMeWithoutToken(t *testing.T) {
	r, _ := setupTestRouter(t)

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// Test 4: GET /api/auth/me with valid token -> 200
func TestMeWithToken(t *testing.T) {
	r, _ := setupTestRouter(t)
	token := getAdminToken(t, r)

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["username"] != "admin" {
		t.Errorf("expected username 'admin', got %v", resp["username"])
	}
}

// Test 5: GET /api/health -> 200
func TestHealth(t *testing.T) {
	r, _ := setupTestRouter(t)

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// Test 6: POST /api/analyses without auth -> 401
func TestCreateAnalysisNoAuth(t *testing.T) {
	r, _ := setupTestRouter(t)

	req := httptest.NewRequest("POST", "/api/analyses", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// Test 7: GET /api/live-events without auth -> 401
func TestLiveEventsNoAuth(t *testing.T) {
	r, _ := setupTestRouter(t)

	req := httptest.NewRequest("GET", "/api/live-events", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// Test 8: GET /api/live-incidents without auth -> 401
func TestLiveIncidentsNoAuth(t *testing.T) {
	r, _ := setupTestRouter(t)

	req := httptest.NewRequest("GET", "/api/live-incidents", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── Workflow tests ───────────────────────────────────────────────────────────

func createTestAnalysis(t *testing.T, db *gorm.DB, userID uint) string {
	t.Helper()
	id := "test-analysis-" + t.Name()
	a := models.Analysis{
		ID:            id,
		UserID:        userID,
		Filename:      "test.pcap",
		Status:        "completed",
		WorkflowState: "new",
	}
	db.Create(&a)
	return id
}

// Test 9: GET workflow returns correct shape
func TestGetWorkflowState(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	aID := createTestAnalysis(t, db, 1)

	req := httptest.NewRequest("GET", "/api/analyses/"+aID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["workflow_state"] != "new" {
		t.Errorf("expected workflow_state 'new', got %v", resp["workflow_state"])
	}
}

// Test 10: PUT workflow/state transitions correctly
func TestWorkflowStateTransition(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	aID := createTestAnalysis(t, db, 1)

	body, _ := json.Marshal(map[string]string{"workflow_state": "in_progress"})
	req := httptest.NewRequest("PUT", "/api/analyses/"+aID+"/workflow", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["workflow_state"] != "in_progress" {
		t.Errorf("expected 'in_progress', got %v", resp["workflow_state"])
	}
}

// Test 11: PUT workflow/state by non-owner returns 403
func TestWorkflowStateByNonOwner(t *testing.T) {
	r, db := setupTestRouter(t)

	// Create a second user
	hash, _ := auth.HashPassword("user2pass")
	user2 := models.User{Username: "user2", HashedPassword: hash, IsAdmin: false}
	db.Create(&user2)

	// Create analysis owned by admin (ID=1)
	aID := createTestAnalysis(t, db, 1)

	// Login as user2
	loginBody, _ := json.Marshal(map[string]string{"username": "user2", "password": "user2pass"})
	loginReq := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)
	var loginResp map[string]interface{}
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)
	user2Token := loginResp["access_token"].(string)

	body, _ := json.Marshal(map[string]string{"workflow_state": "resolved"})
	req := httptest.NewRequest("PUT", "/api/analyses/"+aID+"/workflow", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+user2Token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// Test 12: PUT workflow/assignee by non-owner returns 403
func TestAssignByNonOwner(t *testing.T) {
	r, db := setupTestRouter(t)

	hash, _ := auth.HashPassword("user3pass")
	user3 := models.User{Username: "user3", HashedPassword: hash, IsAdmin: false}
	db.Create(&user3)

	aID := createTestAnalysis(t, db, 1)

	loginBody, _ := json.Marshal(map[string]string{"username": "user3", "password": "user3pass"})
	loginReq := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)
	var loginResp map[string]interface{}
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)
	user3Token := loginResp["access_token"].(string)

	body, _ := json.Marshal(map[string]uint{"user_id": 1})
	req := httptest.NewRequest("PUT", "/api/analyses/"+aID+"/assign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+user3Token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Monitoring tests ─────────────────────────────────────────────────────────

// Test 13: POST /path-monitors creates monitor
func TestCreateMonitor(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	// Create prerequisites
	aID := createTestAnalysis(t, db, 1)
	sq := models.PathAnalysisSavedQuery{
		OwnerUserID: 1, Name: "test-query",
		SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2",
	}
	db.Create(&sq)

	body, _ := json.Marshal(map[string]interface{}{
		"saved_query_id":            sq.ID,
		"analysis_id":              aID,
		"schedule_interval_minutes": 30,
		"enabled":                  true,
	})
	req := httptest.NewRequest("POST", "/api/path-monitors", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

// Test 14: GET /path-monitors/:id/history returns runs
func TestMonitorHistory(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	// Create monitor
	m := models.MonitoredPath{
		SavedQueryID: 1, AnalysisID: "a1", OwnerUserID: 1,
		ScheduleIntervalMinutes: 60, Enabled: true,
	}
	db.Create(&m)

	// Create some runs
	db.Create(&models.MonitoredPathRun{
		MonitoredPathID: m.ID, ConnectionOutcome: "success",
		PathConfidenceScore: 85, DriftSeverity: "none",
	})

	req := httptest.NewRequest("GET", "/api/path-monitors/"+uintToStr(m.ID)+"/history", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// Test 15: POST /path-monitors/:id/outcomes creates outcome
func TestCreateOutcome(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	m := models.MonitoredPath{
		SavedQueryID: 1, AnalysisID: "a1", OwnerUserID: 1,
		ScheduleIntervalMinutes: 60, Enabled: true,
	}
	db.Create(&m)

	body, _ := json.Marshal(map[string]string{
		"outcome": "false_positive",
		"note":    "Testing outcome creation",
	})
	req := httptest.NewRequest("POST", "/api/path-monitors/"+uintToStr(m.ID)+"/outcomes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

// Test 16: GET /api/work-queue returns 5 sections
func TestWorkQueue(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	// Create analyses in different states
	db.Create(&models.Analysis{ID: "wq-new", UserID: 1, Filename: "a.pcap", Status: "completed", WorkflowState: "new"})
	db.Create(&models.Analysis{ID: "wq-prog", UserID: 1, Filename: "b.pcap", Status: "completed", WorkflowState: "in_progress"})

	req := httptest.NewRequest("GET", "/api/work-queue", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	sections := resp["sections"].(map[string]interface{})
	if sections["needs_review"] == nil || sections["assigned_to_me"] == nil ||
		sections["new_analyses"] == nil || sections["unresolved"] == nil ||
		sections["recent_resolved"] == nil {
		t.Error("expected all 5 sections in work queue response")
	}
}

// ── Dashboard tests ──────────────────────────────────────────────────────────

// Test 17: GET /api/dashboard/summary returns all keys
func TestDashboardSummaryKeys(t *testing.T) {
	r, _ := setupTestRouter(t)
	token := getAdminToken(t, r)

	req := httptest.NewRequest("GET", "/api/dashboard/summary", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	requiredKeys := []string{"collector", "live_events", "risk_scores", "auto_detections", "work_queue", "analyses"}
	for _, k := range requiredKeys {
		if resp[k] == nil {
			t.Errorf("missing key %q in dashboard summary", k)
		}
	}
}

// Test 18: dashboard analyses.pending count correct
func TestDashboardPendingCount(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	db.Create(&models.Analysis{ID: "dash-p1", UserID: 1, Filename: "a.pcap", Status: "pending", WorkflowState: "new"})
	db.Create(&models.Analysis{ID: "dash-p2", UserID: 1, Filename: "b.pcap", Status: "pending", WorkflowState: "new"})
	db.Create(&models.Analysis{ID: "dash-c1", UserID: 1, Filename: "c.pcap", Status: "completed", WorkflowState: "new"})

	req := httptest.NewRequest("GET", "/api/dashboard/summary", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	analyses := resp["analyses"].(map[string]interface{})
	pending := analyses["pending"].(float64)
	if pending != 2 {
		t.Errorf("expected 2 pending analyses, got %.0f", pending)
	}
}

func uintToStr(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}
