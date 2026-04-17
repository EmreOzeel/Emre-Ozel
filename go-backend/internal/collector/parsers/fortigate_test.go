package parsers

import "testing"

var fgLine = `date=2026-04-13 time=10:00:00 devname=FGT logid=0000 srcip=192.168.1.10 dstip=8.8.8.8 srcport=45678 dstport=53 proto=17 action=accept sentbyte=200 rcvdbyte=500 policyname=LAN-to-WAN app=DNS service=DNS duration=5`

func TestFortiGateCanParse_WithLogID(t *testing.T) {
	p := &FortiGateParser{}
	if !p.CanParse(fgLine) {
		t.Error("CanParse should return true for FortiGate line with logid=")
	}
}

func TestFortiGateCanParse_WithDevname(t *testing.T) {
	p := &FortiGateParser{}
	line := `devname=FG100D srcip=10.0.0.1 dstip=10.0.0.2 action=allow`
	if !p.CanParse(line) {
		t.Error("CanParse should return true for line with devname=")
	}
}

func TestFortiGateCanParse_Rejects_PA_Line(t *testing.T) {
	p := &FortiGateParser{}
	if p.CanParse(paTrafficLine) {
		t.Error("CanParse should return false for PA CSV line")
	}
}

func TestFortiGate_FieldExtraction(t *testing.T) {
	p := &FortiGateParser{}
	result, err := p.Parse(fgLine)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if result == nil {
		t.Fatal("Parse returned nil")
	}

	assertStr(t, result, "source_ip", "192.168.1.10")
	assertStr(t, result, "destination_ip", "8.8.8.8")
	assertInt(t, result, "source_port", 45678)
	assertInt(t, result, "destination_port", 53)
	assertStr(t, result, "protocol", "UDP") // proto=17 → UDP
	assertStr(t, result, "action", "allow") // accept → allow
	assertInt(t, result, "bytes_out", 200)  // sentbyte
	assertInt(t, result, "bytes_in", 500)   // rcvdbyte
	assertStr(t, result, "reason", "LAN-to-WAN")
	assertStr(t, result, "application", "DNS")
	assertInt(t, result, "duration_ms", 5000) // 5 sec * 1000
}

func TestFortiGate_ProtocolMapping(t *testing.T) {
	tests := []struct {
		proto string
		want  string
	}{
		{"6", "TCP"},
		{"17", "UDP"},
		{"1", "ICMP"},
	}
	for _, tt := range tests {
		line := `logid=0001 srcip=1.1.1.1 dstip=2.2.2.2 proto=` + tt.proto + ` action=allow`
		p := &FortiGateParser{}
		result, _ := p.Parse(line)
		if result == nil {
			t.Fatalf("Parse returned nil for proto=%s", tt.proto)
		}
		assertStr(t, result, "protocol", tt.want)
	}
}

func TestFortiGate_ActionNormalization(t *testing.T) {
	tests := []struct{ input, want string }{
		{"accept", "allow"},
		{"deny", "deny"},
		{"drop", "drop"},
		{"reject", "deny"},
		{"pass", "allow"},
	}
	for _, tt := range tests {
		got := fgNormalizeAction(tt.input)
		if got != tt.want {
			t.Errorf("fgNormalizeAction(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
