package parsers

import (
	"testing"
)

// Realistic TRAFFIC line: 36+ comma-separated fields.
// Fields: [0]=serial, [1]=timestamp, [2]=?, [3]=TRAFFIC, [7]=src, [8]=dst,
// [9]=natSrc, [10]=natDst, [11]=rule, [14]=app, [24]=sport, [25]=dport,
// [26]=natSport, [27]=natDport, [29]=proto, [30]=action, [31]=bytesSent,
// [32]=bytesRecv, [33]=durSec, [34]=pktsSent, [35]=pktsRecv
var paTrafficLine = "1,2026/04/15 11:26:33,0123456789,TRAFFIC,end,2049,2026/04/15 11:26:33,10.1.1.100,203.0.113.50,172.16.0.1,203.0.113.50,Allow-Web,,,web-browsing,vsys1,trust,untrust,ae1.100,ae2.200,Log-Forward,2026/04/15 11:26:33,12345,1,54321,443,54321,443,0x400000,tcp,allow,5678,12345,60,35,25,0x0,0,0,0,policy-route,0,0,0,0"

// THREAT line
var paThreatLine = "1,2026/04/15 12:00:00,0123456789,THREAT,vulnerability,2049,2026/04/15 12:00:00,10.1.1.100,203.0.113.50,172.16.0.1,203.0.113.50,Allow-Web,,,suspicious-app,vsys1,trust,untrust,ae1.100,ae2.200,Log-Forward,2026/04/15 12:00:00,67890,1,54321,443,54321,443,0x400000,CVE-2024-1234,alert,0,0,0,0,0,web-attacks,high,client-to-server,unused,unused,unused"

func TestPaloAltoCanParse_Traffic(t *testing.T) {
	p := &PaloAltoParser{}
	if !p.CanParse(paTrafficLine) {
		t.Error("CanParse should return true for TRAFFIC line")
	}
}

func TestPaloAltoCanParse_Threat(t *testing.T) {
	p := &PaloAltoParser{}
	if !p.CanParse(paThreatLine) {
		t.Error("CanParse should return true for THREAT line")
	}
}

func TestPaloAltoCanParse_Rejects_NonPA(t *testing.T) {
	p := &PaloAltoParser{}
	line := `date=2026-04-13 time=10:00:00 srcip=1.2.3.4 dstip=5.6.7.8 action=allow`
	if p.CanParse(line) {
		t.Error("CanParse should return false for FortiGate-style line")
	}
}

func TestPaloAltoTraffic_FieldExtraction(t *testing.T) {
	p := &PaloAltoParser{}
	result, err := p.Parse(paTrafficLine)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if result == nil {
		t.Fatal("Parse returned nil for valid TRAFFIC line")
	}

	// Source / destination
	assertStr(t, result, "source_ip", "10.1.1.100")
	assertStr(t, result, "destination_ip", "203.0.113.50")

	// Ports
	assertInt(t, result, "source_port", 54321)
	assertInt(t, result, "destination_port", 443)

	// Protocol
	assertStr(t, result, "protocol", "TCP")

	// Action
	assertStr(t, result, "action", "allow")

	// Bytes (field 31=sent=bytes_out, field 32=recv=bytes_in)
	assertInt(t, result, "bytes_out", 5678)
	assertInt(t, result, "bytes_in", 12345)

	// Duration (60 seconds * 1000 = 60000ms)
	assertInt(t, result, "duration_ms", 60000)

	// Application
	assertStr(t, result, "application", "web-browsing")

	// NAT source IP (172.16.0.1 != 10.1.1.100, so should be set)
	assertStr(t, result, "nat_source_ip", "172.16.0.1")
}

func TestPaloAltoThreat_FieldExtraction(t *testing.T) {
	p := &PaloAltoParser{}
	result, err := p.Parse(paThreatLine)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if result == nil {
		t.Fatal("Parse returned nil for valid THREAT line")
	}

	// reason = threat_id (field 29)
	assertStr(t, result, "reason", "CVE-2024-1234")

	// action = normalizeThreatAction("alert") = "alert"
	assertStr(t, result, "action", "alert")

	// application = category (field 35)
	assertStr(t, result, "application", "web-attacks")

	// health_status = mapSeverity("high") = "high"
	assertStr(t, result, "health_status", "high")

	// service = direction (field 39)
	assertStr(t, result, "service", "client-to-server")
}

func TestPaloAltoAction_Normalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		threat   bool // use threat action normalizer
	}{
		{"allow", "allow", false},
		{"deny", "deny", false},
		{"drop", "drop", false},
		{"drop-all-packets", "drop", false},
		{"reset-both", "reset", false},
		{"reset-both", "deny", true},  // THREAT normalizer
		{"alert", "alert", true},
		{"block", "deny", true},
	}
	for _, tt := range tests {
		var got string
		if tt.threat {
			got = normalizeThreatAction(tt.input)
		} else {
			got = normalizeAction(tt.input)
		}
		if got != tt.expected {
			t.Errorf("normalize(%q, threat=%v) = %q, want %q", tt.input, tt.threat, got, tt.expected)
		}
	}
}

func TestPaloAlto_MalformedLine(t *testing.T) {
	p := &PaloAltoParser{}
	// Only 10 fields — well under 36 minimum
	line := "1,2026/04/15 11:00:00,serial,TRAFFIC,end,2049,ts,10.0.0.1,10.0.0.2,0.0.0.0"
	result, _ := p.Parse(line)
	if result != nil {
		t.Error("Parse should return nil for line with < 36 fields")
	}
}

// ── test helpers ──

func assertStr(t *testing.T, m map[string]interface{}, key, want string) {
	t.Helper()
	got, _ := m[key].(string)
	if got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
}

func assertInt(t *testing.T, m map[string]interface{}, key string, want int) {
	t.Helper()
	got, ok := m[key].(int)
	if !ok {
		t.Errorf("%s not an int (got %T: %v)", key, m[key], m[key])
		return
	}
	if got != want {
		t.Errorf("%s = %d, want %d", key, got, want)
	}
}
