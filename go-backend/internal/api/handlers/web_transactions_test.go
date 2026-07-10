package handlers_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

func seedWebTransactions(t *testing.T, db *gorm.DB) []models.WebTransaction {
	t.Helper()

	strPtr := func(s string) *string { return &s }
	intPtr := func(n int) *int { return &n }
	now := time.Now().UTC()

	txs := []models.WebTransaction{
		{
			SourceID: "src-1", DeviceType: "firewall",
			SourceIP: "10.0.0.1", DestinationIP: "203.0.113.10",
			Host: strPtr("www.example.com"), URL: strPtr("https://www.example.com/index.html"),
			Method: strPtr("GET"), StatusCode: intPtr(200), Action: strPtr("allow"),
			Category: strPtr("business"), DurationMs: intPtr(100),
			BytesIn: 500, BytesOut: 100,
			TransactionTime: now.Add(-2 * time.Minute),
		},
		{
			SourceID: "src-1", DeviceType: "firewall",
			SourceIP: "10.0.0.2", DestinationIP: "203.0.113.20",
			Host: strPtr("evil.example.net"), URL: strPtr("http://evil.example.net/malware.exe"),
			Method: strPtr("GET"), StatusCode: intPtr(403), Action: strPtr("deny"),
			Category: strPtr("malware-sites"), DurationMs: intPtr(300),
			BytesIn: 0, BytesOut: 50,
			TransactionTime: now.Add(-1 * time.Minute),
		},
		{
			SourceID: "src-1", DeviceType: "firewall",
			SourceIP: "10.0.0.1", DestinationIP: "203.0.113.30",
			Host: strPtr("api.example.org"), URL: strPtr("https://api.example.org/v1/data"),
			Method: strPtr("POST"), StatusCode: intPtr(200), Action: strPtr("allow"),
			Category: strPtr("computer-and-internet-info"),
			BytesIn:  1000, BytesOut: 2000,
			TransactionTime: now,
		},
	}
	if err := db.Create(&txs).Error; err != nil {
		t.Fatalf("failed to seed web transactions: %v", err)
	}
	return txs
}

func getJSON(t *testing.T, r *gin.Engine, token, path string, wantStatus int) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != wantStatus {
		t.Fatalf("GET %s: got %d, want %d: %s", path, w.Code, wantStatus, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp
}

// GET /api/web-transactions returns the standard list shape.
func TestListWebTransactionsShape(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)
	seedWebTransactions(t, db)

	resp := getJSON(t, r, token, "/api/web-transactions?limit=10", 200)

	for _, k := range []string{"total", "offset", "limit", "transactions"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("missing key %q in response", k)
		}
	}
	if resp["total"].(float64) != 3 {
		t.Errorf("expected total=3, got %v", resp["total"])
	}
	arr, ok := resp["transactions"].([]interface{})
	if !ok {
		t.Fatal("transactions is not an array")
	}
	if len(arr) != 3 {
		t.Errorf("expected 3 transactions, got %d", len(arr))
	}
}

// Filters: source_ip, host, method, status_code, action, category, search.
func TestListWebTransactionsFilters(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)
	seedWebTransactions(t, db)

	tests := []struct {
		query     string
		wantTotal float64
	}{
		{"source_ip=10.0.0.1", 2},
		{"destination_ip=203.0.113.20", 1},
		{"host=evil.example.net", 1},
		{"method=POST", 1},
		{"status_code=200", 2},
		{"action=deny", 1},
		{"category=malware-sites", 1},
		{"search=MALWARE.EXE", 1}, // case-insensitive URL search
		{"search=example", 3},
		{"search=no-such-url", 0},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			resp := getJSON(t, r, token, "/api/web-transactions?"+tt.query, 200)
			if resp["total"].(float64) != tt.wantTotal {
				t.Errorf("query %q: total=%v, want %v", tt.query, resp["total"], tt.wantTotal)
			}
		})
	}
}

// Time range filters.
func TestListWebTransactionsTimeRange(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)
	seedWebTransactions(t, db)

	// Only the most recent transaction is within the last 30 seconds.
	start := time.Now().UTC().Add(-30 * time.Second).Format(time.RFC3339)
	resp := getJSON(t, r, token, "/api/web-transactions?start_time="+start, 200)
	if resp["total"].(float64) != 1 {
		t.Errorf("expected total=1 with start_time filter, got %v", resp["total"])
	}

	// end_time in the past excludes everything.
	end := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	resp = getJSON(t, r, token, "/api/web-transactions?end_time="+end, 200)
	if resp["total"].(float64) != 0 {
		t.Errorf("expected total=0 with past end_time filter, got %v", resp["total"])
	}
}

// GET /api/web-transactions/:id returns single transaction; unknown id -> 404.
func TestGetWebTransaction(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)
	txs := seedWebTransactions(t, db)

	resp := getJSON(t, r, token, "/api/web-transactions/"+uintToStr(txs[0].ID), 200)
	if resp["source_ip"] != "10.0.0.1" {
		t.Errorf("expected source_ip=10.0.0.1, got %v", resp["source_ip"])
	}
	if resp["host"] != "www.example.com" {
		t.Errorf("expected host=www.example.com, got %v", resp["host"])
	}

	getJSON(t, r, token, "/api/web-transactions/999999", 404)
}

// GET /api/web-transactions/stats returns all stat keys with correct values.
func TestWebTransactionStats(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)
	seedWebTransactions(t, db)

	resp := getJSON(t, r, token, "/api/web-transactions/stats", 200)

	for _, k := range []string{"total", "top_hosts", "status_code_counts", "top_source_ips", "avg_duration_ms"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("missing key %q in stats response", k)
		}
	}
	if resp["total"].(float64) != 3 {
		t.Errorf("expected total=3, got %v", resp["total"])
	}

	statusCounts, ok := resp["status_code_counts"].(map[string]interface{})
	if !ok {
		t.Fatal("status_code_counts is not an object")
	}
	if statusCounts["200"].(float64) != 2 {
		t.Errorf("expected 2 transactions with status 200, got %v", statusCounts["200"])
	}
	if statusCounts["403"].(float64) != 1 {
		t.Errorf("expected 1 transaction with status 403, got %v", statusCounts["403"])
	}

	// avg over 100 and 300 (third row has NULL duration) = 200.
	if resp["avg_duration_ms"].(float64) != 200 {
		t.Errorf("expected avg_duration_ms=200, got %v", resp["avg_duration_ms"])
	}
}

// All web-transaction endpoints require auth.
func TestWebTransactionsNoAuth(t *testing.T) {
	r, _ := setupTestRouter(t)

	for _, path := range []string{
		"/api/web-transactions",
		"/api/web-transactions/stats",
		"/api/web-transactions/1",
	} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Errorf("GET %s without token: got %d, want 401", path, w.Code)
		}
	}
}
