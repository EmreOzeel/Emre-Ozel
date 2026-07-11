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

// seedWebTransactionsForAnalytics seeds transactions at fixed, known times
// relative to base for deterministic timeseries/top assertions.
//
// Layout (base = bucket boundary, 5m interval):
//   - base+1m: a.example.com, 10.0.0.1, business, allow, dur 100, in 500, out 100
//   - base+2m: a.example.com, 10.0.0.2, malware-sites, block-url, dur nil, in 0, out 50
//   - base+3m: host nil, 10.0.0.3, category nil, deny, dur 200, in 10, out 20
//   - base+7m: b.example.com, 10.0.0.1, business, allow, dur 300, in 1000, out 2000
func seedWebTransactionsForAnalytics(t *testing.T, db *gorm.DB, base time.Time) {
	t.Helper()

	strPtr := func(s string) *string { return &s }
	intPtr := func(n int) *int { return &n }

	txs := []models.WebTransaction{
		{
			SourceID: "src-1", DeviceType: "firewall",
			SourceIP: "10.0.0.1", DestinationIP: "203.0.113.10",
			Host: strPtr("a.example.com"), Category: strPtr("business"),
			Action: strPtr("allow"), DurationMs: intPtr(100),
			BytesIn: 500, BytesOut: 100,
			TransactionTime: base.Add(1 * time.Minute),
		},
		{
			SourceID: "src-1", DeviceType: "firewall",
			SourceIP: "10.0.0.2", DestinationIP: "203.0.113.20",
			Host: strPtr("a.example.com"), Category: strPtr("malware-sites"),
			Action: strPtr("block-url"),
			BytesIn: 0, BytesOut: 50,
			TransactionTime: base.Add(2 * time.Minute),
		},
		{
			SourceID: "src-1", DeviceType: "firewall",
			SourceIP: "10.0.0.3", DestinationIP: "203.0.113.30",
			Action: strPtr("deny"), DurationMs: intPtr(200),
			BytesIn: 10, BytesOut: 20,
			TransactionTime: base.Add(3 * time.Minute),
		},
		{
			SourceID: "src-1", DeviceType: "firewall",
			SourceIP: "10.0.0.1", DestinationIP: "203.0.113.40",
			Host: strPtr("b.example.com"), Category: strPtr("business"),
			Action: strPtr("allow"), DurationMs: intPtr(300),
			BytesIn: 1000, BytesOut: 2000,
			TransactionTime: base.Add(7 * time.Minute),
		},
	}
	if err := db.Create(&txs).Error; err != nil {
		t.Fatalf("failed to seed analytics web transactions: %v", err)
	}
}

// GET /api/web-transactions/timeseries buckets correctly and zero-fills
// empty buckets.
func TestWebTransactionTimeseries(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	base := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	seedWebTransactionsForAnalytics(t, db, base)

	path := "/api/web-transactions/timeseries?interval=5m" +
		"&start_time=" + base.Format(time.RFC3339) +
		"&end_time=" + base.Add(15*time.Minute).Format(time.RFC3339)
	resp := getJSON(t, r, token, path, 200)

	for _, k := range []string{"interval", "start_time", "end_time", "series"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("missing key %q in timeseries response", k)
		}
	}
	if resp["interval"] != "5m" {
		t.Errorf("expected interval=5m, got %v", resp["interval"])
	}

	series, ok := resp["series"].([]interface{})
	if !ok {
		t.Fatal("series is not an array")
	}
	if len(series) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(series))
	}

	// Bucket 0 [base, base+5m): 3 transactions, 2 denied (block-url + deny),
	// avg duration over 100 and 200 = 150.
	b0 := series[0].(map[string]interface{})
	if b0["bucket"] != base.Format(time.RFC3339) {
		t.Errorf("bucket 0 timestamp = %v, want %v", b0["bucket"], base.Format(time.RFC3339))
	}
	if b0["count"].(float64) != 3 {
		t.Errorf("bucket 0 count = %v, want 3", b0["count"])
	}
	if b0["denied_count"].(float64) != 2 {
		t.Errorf("bucket 0 denied_count = %v, want 2", b0["denied_count"])
	}
	if b0["avg_duration_ms"].(float64) != 150 {
		t.Errorf("bucket 0 avg_duration_ms = %v, want 150", b0["avg_duration_ms"])
	}
	if b0["bytes_in"].(float64) != 510 {
		t.Errorf("bucket 0 bytes_in = %v, want 510", b0["bytes_in"])
	}
	if b0["bytes_out"].(float64) != 170 {
		t.Errorf("bucket 0 bytes_out = %v, want 170", b0["bytes_out"])
	}

	// Bucket 1 [base+5m, base+10m): a single allowed transaction.
	b1 := series[1].(map[string]interface{})
	if b1["bucket"] != base.Add(5*time.Minute).Format(time.RFC3339) {
		t.Errorf("bucket 1 timestamp = %v, want %v", b1["bucket"], base.Add(5*time.Minute).Format(time.RFC3339))
	}
	if b1["count"].(float64) != 1 {
		t.Errorf("bucket 1 count = %v, want 1", b1["count"])
	}
	if b1["denied_count"].(float64) != 0 {
		t.Errorf("bucket 1 denied_count = %v, want 0", b1["denied_count"])
	}
	if b1["avg_duration_ms"].(float64) != 300 {
		t.Errorf("bucket 1 avg_duration_ms = %v, want 300", b1["avg_duration_ms"])
	}

	// Bucket 2 [base+10m, base+15m): empty, zero-filled with null avg.
	b2 := series[2].(map[string]interface{})
	if b2["count"].(float64) != 0 {
		t.Errorf("bucket 2 count = %v, want 0", b2["count"])
	}
	if b2["denied_count"].(float64) != 0 {
		t.Errorf("bucket 2 denied_count = %v, want 0", b2["denied_count"])
	}
	if b2["avg_duration_ms"] != nil {
		t.Errorf("bucket 2 avg_duration_ms = %v, want null", b2["avg_duration_ms"])
	}
	if b2["bytes_in"].(float64) != 0 || b2["bytes_out"].(float64) != 0 {
		t.Errorf("bucket 2 bytes = %v/%v, want 0/0", b2["bytes_in"], b2["bytes_out"])
	}
}

// Timeseries respects the shared optional filters.
func TestWebTransactionTimeseriesFilters(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	base := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	seedWebTransactionsForAnalytics(t, db, base)

	path := "/api/web-transactions/timeseries?interval=5m&source_ip=10.0.0.1" +
		"&start_time=" + base.Format(time.RFC3339) +
		"&end_time=" + base.Add(15*time.Minute).Format(time.RFC3339)
	resp := getJSON(t, r, token, path, 200)

	series := resp["series"].([]interface{})
	if len(series) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(series))
	}
	b0 := series[0].(map[string]interface{})
	b1 := series[1].(map[string]interface{})
	if b0["count"].(float64) != 1 || b1["count"].(float64) != 1 {
		t.Errorf("filtered counts = %v/%v, want 1/1", b0["count"], b1["count"])
	}
}

// Timeseries input validation: bad interval, bad times, too many buckets.
func TestWebTransactionTimeseriesValidation(t *testing.T) {
	r, _ := setupTestRouter(t)
	token := getAdminToken(t, r)

	// Unsupported interval.
	getJSON(t, r, token, "/api/web-transactions/timeseries?interval=2m", 400)

	// Unparsable time params.
	getJSON(t, r, token, "/api/web-transactions/timeseries?start_time=not-a-time", 400)
	getJSON(t, r, token, "/api/web-transactions/timeseries?end_time=not-a-time", 400)

	// start_time must be before end_time.
	getJSON(t, r, token,
		"/api/web-transactions/timeseries?start_time=2026-01-10T10:00:00Z&end_time=2026-01-10T09:00:00Z", 400)

	// 9 days at 5m = 2592 buckets, over the ~1000 cap.
	getJSON(t, r, token,
		"/api/web-transactions/timeseries?interval=5m&start_time=2026-01-01T00:00:00Z&end_time=2026-01-10T00:00:00Z", 400)

	// Same range is fine at 1h (216 buckets).
	resp := getJSON(t, r, token,
		"/api/web-transactions/timeseries?interval=1h&start_time=2026-01-01T00:00:00Z&end_time=2026-01-10T00:00:00Z", 200)
	if len(resp["series"].([]interface{})) != 216 {
		t.Errorf("expected 216 buckets, got %d", len(resp["series"].([]interface{})))
	}
}

// GET /api/web-transactions/top aggregates per dimension, excludes NULL keys
// and honors limit.
func TestWebTransactionTop(t *testing.T) {
	r, db := setupTestRouter(t)
	token := getAdminToken(t, r)

	base := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	seedWebTransactionsForAnalytics(t, db, base)

	rangeQuery := "&start_time=" + base.Format(time.RFC3339) +
		"&end_time=" + base.Add(time.Hour).Format(time.RFC3339)

	// Default dimension is host; NULL hosts are excluded.
	resp := getJSON(t, r, token, "/api/web-transactions/top?limit=10"+rangeQuery, 200)
	if resp["dimension"] != "host" {
		t.Errorf("expected dimension=host, got %v", resp["dimension"])
	}
	items, ok := resp["items"].([]interface{})
	if !ok {
		t.Fatal("items is not an array")
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 host items (NULL host excluded), got %d", len(items))
	}
	first := items[0].(map[string]interface{})
	if first["key"] != "a.example.com" {
		t.Errorf("top host = %v, want a.example.com", first["key"])
	}
	if first["count"].(float64) != 2 {
		t.Errorf("top host count = %v, want 2", first["count"])
	}
	if first["denied_count"].(float64) != 1 {
		t.Errorf("top host denied_count = %v, want 1", first["denied_count"])
	}
	// bytes_total for a.example.com: (500+100) + (0+50) = 650.
	if first["bytes_total"].(float64) != 650 {
		t.Errorf("top host bytes_total = %v, want 650", first["bytes_total"])
	}

	// dimension=category: NULL categories excluded.
	resp = getJSON(t, r, token, "/api/web-transactions/top?dimension=category"+rangeQuery, 200)
	items = resp["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("expected 2 category items, got %d", len(items))
	}
	if items[0].(map[string]interface{})["key"] != "business" {
		t.Errorf("top category = %v, want business", items[0].(map[string]interface{})["key"])
	}

	// dimension=source_ip: all three sources present, 10.0.0.1 first.
	resp = getJSON(t, r, token, "/api/web-transactions/top?dimension=source_ip"+rangeQuery, 200)
	items = resp["items"].([]interface{})
	if len(items) != 3 {
		t.Fatalf("expected 3 source_ip items, got %d", len(items))
	}
	topIP := items[0].(map[string]interface{})
	if topIP["key"] != "10.0.0.1" || topIP["count"].(float64) != 2 {
		t.Errorf("top source_ip = %v (count %v), want 10.0.0.1 (count 2)", topIP["key"], topIP["count"])
	}

	// limit is honored.
	resp = getJSON(t, r, token, "/api/web-transactions/top?dimension=source_ip&limit=1"+rangeQuery, 200)
	if len(resp["items"].([]interface{})) != 1 {
		t.Errorf("expected 1 item with limit=1, got %d", len(resp["items"].([]interface{})))
	}

	// Unknown dimension is rejected.
	getJSON(t, r, token, "/api/web-transactions/top?dimension=bogus", 400)
}

// All web-transaction endpoints require auth.
func TestWebTransactionsNoAuth(t *testing.T) {
	r, _ := setupTestRouter(t)

	for _, path := range []string{
		"/api/web-transactions",
		"/api/web-transactions/stats",
		"/api/web-transactions/timeseries",
		"/api/web-transactions/top",
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
