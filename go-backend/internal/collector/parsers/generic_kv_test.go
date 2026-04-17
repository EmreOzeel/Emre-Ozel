package parsers

import "testing"

func TestGenericKV_CanParse_ValidLine(t *testing.T) {
	p := &GenericKVParser{}
	line := `src=10.0.0.1 dst=10.0.0.2 action=allow sport=1234 dport=80`
	if !p.CanParse(line) {
		t.Error("CanParse should return true for valid KV line")
	}
}

func TestGenericKV_CanParse_Rejects_Insufficient_KV(t *testing.T) {
	p := &GenericKVParser{}
	line := `hello world no kv pairs`
	if p.CanParse(line) {
		t.Error("CanParse should return false for line without KV pairs")
	}
}

func TestGenericKV_FieldMapping(t *testing.T) {
	p := &GenericKVParser{}
	line := `srcip=10.0.0.1 dstip=10.0.0.2 action=allow sport=1234 dport=80 proto=TCP`
	result, err := p.Parse(line)
	if err != nil || result == nil {
		t.Fatal("Parse returned nil or error")
	}
	assertStr(t, result, "source_ip", "10.0.0.1")
	assertStr(t, result, "destination_ip", "10.0.0.2")
	assertInt(t, result, "source_port", 1234)
	assertInt(t, result, "destination_port", 80)
	assertStr(t, result, "protocol", "TCP")
}

func TestGenericKV_ActionNormalization(t *testing.T) {
	tests := []struct{ input, want string }{
		{"accept", "allow"},
		{"permit", "allow"},
		{"block", "deny"},
		{"discard", "drop"},
	}
	for _, tt := range tests {
		got := gkvNormalizeAction(tt.input)
		if got != tt.want {
			t.Errorf("gkvNormalizeAction(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenericKV_QuotedValues(t *testing.T) {
	p := &GenericKVParser{}
	line := `src="10.0.0.1" dst="10.0.0.2" action="allow"`
	result, _ := p.Parse(line)
	if result == nil {
		t.Fatal("Parse returned nil for quoted values")
	}
	assertStr(t, result, "source_ip", "10.0.0.1")
	assertStr(t, result, "destination_ip", "10.0.0.2")
	assertStr(t, result, "action", "allow")
}

func TestGenericKV_MissingRequiredFields(t *testing.T) {
	p := &GenericKVParser{}
	// Has src and dst but no action — CanParse should return false
	line := `src=10.0.0.1 dst=10.0.0.2 proto=TCP sport=1234`
	if p.CanParse(line) {
		t.Error("CanParse should return false when action is missing")
	}
}
