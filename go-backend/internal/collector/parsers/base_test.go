package parsers

import "testing"

func TestRegistry_RegisterAndDetect(t *testing.T) {
	ClearRegistry()
	Register(&PaloAltoParser{})

	p := Detect(paTrafficLine)
	if p == nil {
		t.Fatal("Detect returned nil for PA line")
	}
	if p.ParserID() != "paloalto" {
		t.Errorf("expected paloalto parser, got %s", p.ParserID())
	}
}

func TestRegistry_Priority(t *testing.T) {
	ClearRegistry()
	Register(&PaloAltoParser{})
	Register(&GenericKVParser{})

	// PA line should match PA parser first (not KV)
	p := Detect(paTrafficLine)
	if p == nil || p.ParserID() != "paloalto" {
		t.Errorf("expected paloalto parser for PA line, got %v", p)
	}
}

func TestRegistry_FallsBackToKV(t *testing.T) {
	ClearRegistry()
	Register(&PaloAltoParser{})
	Register(&GenericKVParser{})

	line := `src=10.0.0.1 dst=10.0.0.2 action=allow`
	p := Detect(line)
	if p == nil {
		t.Fatal("Detect returned nil for KV line")
	}
	if p.ParserID() != "generic_kv" {
		t.Errorf("expected generic_kv, got %s", p.ParserID())
	}
}

func TestStripSyslogPriority(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<134>actual message", "actual message"},
		{"no priority", "no priority"},
		{"<abc>not numeric", "<abc>not numeric"},
		{"<14>short", "short"},
	}
	for _, tt := range tests {
		got := StripSyslogPriority(tt.input)
		if got != tt.want {
			t.Errorf("StripSyslogPriority(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
