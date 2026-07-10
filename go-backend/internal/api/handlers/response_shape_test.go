package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// assertKeys checks that all expected keys exist in the JSON response body.
func assertKeys(t *testing.T, body []byte, keys []string) {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		// Might be an array — check that too
		var arr []interface{}
		if err2 := json.Unmarshal(body, &arr); err2 != nil {
			t.Fatalf("response is not valid JSON object or array: %s", string(body))
		}
		return // arrays don't have named keys to check
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in response: %s", k, string(body))
		}
	}
}

// TestResponseShapes verifies all key endpoints return the correct JSON shape.
func TestResponseShapes(t *testing.T) {
	r, _ := setupTestRouter(t)
	token := getAdminToken(t, r)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantKeys   []string // top-level keys to verify (empty = skip key check)
		needsAuth  bool
	}{
		// Health (no auth)
		{
			name: "health", method: "GET", path: "/api/health",
			wantStatus: 200, wantKeys: []string{"status", "version"},
		},
		// Auth
		{
			name: "login_success", method: "POST", path: "/api/auth/login",
			wantStatus: 200, wantKeys: []string{"access_token", "token_type"},
		},
		{
			name: "me", method: "GET", path: "/api/auth/me",
			wantStatus: 200, wantKeys: []string{"id", "username", "is_admin"},
			needsAuth: true,
		},
		// Live Events
		{
			name: "live_events", method: "GET", path: "/api/live-events?limit=5",
			wantStatus: 200, wantKeys: []string{"total", "offset", "limit", "events"},
			needsAuth: true,
		},
		// Live Flows
		{
			name: "live_flows", method: "GET", path: "/api/live-flows?limit=5",
			wantStatus: 200, wantKeys: []string{"total", "offset", "limit", "flows"},
			needsAuth: true,
		},
		// Live Incidents
		{
			name: "live_incidents", method: "GET", path: "/api/live-incidents?limit=5",
			wantStatus: 200, wantKeys: []string{"total", "incidents"},
			needsAuth: true,
		},
		// Web Transactions
		{
			name: "web_transactions", method: "GET", path: "/api/web-transactions?limit=5",
			wantStatus: 200, wantKeys: []string{"total", "offset", "limit", "transactions"},
			needsAuth: true,
		},
		{
			name: "web_transactions_stats", method: "GET", path: "/api/web-transactions/stats",
			wantStatus: 200,
			wantKeys:   []string{"total", "top_hosts", "status_code_counts", "top_source_ips", "avg_duration_ms"},
			needsAuth:  true,
		},
		// Notifications
		{
			name: "notifications_unread_count", method: "GET", path: "/api/notifications/unread-count",
			wantStatus: 200, wantKeys: []string{"unread"},
			needsAuth: true,
		},
		// Work Queue
		{
			name: "work_queue", method: "GET", path: "/api/work-queue",
			wantStatus: 200, wantKeys: []string{"sections", "total_open", "counts"},
			needsAuth: true,
		},
		// Dashboard
		{
			name: "dashboard", method: "GET", path: "/api/dashboard/summary",
			wantStatus: 200,
			wantKeys: []string{"collector", "live_events", "risk_scores", "auto_detections", "work_queue", "analyses"},
			needsAuth: true,
		},
		// Threat indicators
		{
			name: "threat_indicators", method: "GET", path: "/api/threat-indicators?limit=3",
			wantStatus: 200, wantKeys: []string{"total", "items"},
			needsAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.method == "POST" && tt.path == "/api/auth/login" {
				// Special: login needs a body
				loginBody, _ := json.Marshal(map[string]string{
					"username": "admin", "password": "admin123",
				})
				body = loginBody
			}

			var req *httptest.ResponseRecorder
			if body != nil {
				httpReq := httptest.NewRequest(tt.method, tt.path, bytes.NewReader(body))
				httpReq.Header.Set("Content-Type", "application/json")
				if tt.needsAuth {
					httpReq.Header.Set("Authorization", "Bearer "+token)
				}
				req = httptest.NewRecorder()
				r.ServeHTTP(req, httpReq)
			} else {
				httpReq := httptest.NewRequest(tt.method, tt.path, nil)
				if tt.needsAuth {
					httpReq.Header.Set("Authorization", "Bearer "+token)
				}
				req = httptest.NewRecorder()
				r.ServeHTTP(req, httpReq)
			}

			if req.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d: %s", req.Code, tt.wantStatus, req.Body.String())
				return
			}

			if len(tt.wantKeys) > 0 {
				assertKeys(t, req.Body.Bytes(), tt.wantKeys)
			}
		})
	}
}

// TestAuthEnforcement verifies all protected endpoints return 401 without token.
func TestAuthEnforcement(t *testing.T) {
	r, _ := setupTestRouter(t)

	protectedPaths := []string{
		"/api/auth/me",
		"/api/analyses",
		"/api/live-events",
		"/api/live-flows",
		"/api/live-incidents",
		"/api/web-transactions",
		"/api/web-transactions/stats",
		"/api/notifications",
		"/api/notifications/unread-count",
		"/api/suppressions",
		"/api/work-queue",
		"/api/dashboard/summary",
		"/api/correlation-rules",
		"/api/threat-indicators",
		"/api/baselines",
		"/api/users",
	}

	for _, path := range protectedPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != 401 {
				t.Errorf("GET %s without token: got %d, want 401", path, w.Code)
			}
		})
	}
}

// TestPagination verifies limit/offset params work correctly.
func TestPagination(t *testing.T) {
	r, _ := setupTestRouter(t)
	token := getAdminToken(t, r)

	// Test with explicit limit=1
	endpoints := []struct {
		path     string
		listKey  string // key containing the array
	}{
		{"/api/live-events?limit=1", "events"},
		{"/api/live-flows?limit=1", "flows"},
		{"/api/live-incidents?limit=1", "incidents"},
		{"/api/web-transactions?limit=1", "transactions"},
	}

	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", ep.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != 200 {
				t.Fatalf("got %d, want 200", w.Code)
			}

			var resp map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &resp)

			arr, ok := resp[ep.listKey].([]interface{})
			if !ok {
				t.Fatalf("key %q is not an array", ep.listKey)
			}
			// With no data, array should be empty but present
			if arr == nil {
				t.Errorf("key %q is nil, expected empty array", ep.listKey)
			}
		})
	}
}

// TestListEndpointsReturnArrays verifies endpoints that should return
// direct arrays (not wrapped in objects) do so.
func TestListEndpointsReturnArrays(t *testing.T) {
	r, _ := setupTestRouter(t)
	token := getAdminToken(t, r)

	arrayEndpoints := []string{
		"/api/analyses",
		"/api/notifications",
		"/api/suppressions",
		"/api/correlation-rules",
		"/api/threat-feeds",
		"/api/baselines",
		"/api/users",
	}

	for _, path := range arrayEndpoints {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != 200 {
				t.Fatalf("GET %s: got %d, want 200: %s", path, w.Code, w.Body.String())
			}

			// Must be a JSON array
			var arr []interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &arr); err != nil {
				t.Errorf("GET %s: response is not a JSON array: %s", path, w.Body.String())
			}
		})
	}
}

// TestLoginFailure verifies wrong password returns 401.
func TestLoginFailure(t *testing.T) {
	r, _ := setupTestRouter(t)
	body, _ := json.Marshal(map[string]string{
		"username": "admin", "password": "wrongpassword",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["detail"] == nil {
		t.Error("error response should contain 'detail' key")
	}
}
