package collector

import (
	"testing"

	"github.com/emreozeel/pcap-analyzer/backend/internal/collector/parsers"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Realistic PA TRAFFIC line for pipeline testing
var testPALine = "1,2026/04/15 11:26:33,0123456789,TRAFFIC,end,2049,2026/04/15 11:26:33,10.1.1.100,203.0.113.50,172.16.0.1,203.0.113.50,Allow-Web,,,web-browsing,vsys1,trust,untrust,ae1.100,ae2.200,Log-Forward,2026/04/15 11:26:33,12345,1,54321,443,54321,443,0x400000,tcp,allow,5678,12345,60,35,25,0x0,0,0,0,policy-route,0,0,0,0"

func setupPipeline() *Pipeline {
	parsers.ClearRegistry()
	parsers.Register(&parsers.PaloAltoParser{})
	parsers.Register(&parsers.FortiGateParser{})
	parsers.Register(&parsers.GenericKVParser{})
	return NewPipeline("test-source", "perimeter")
}

func TestPipeline_ProcessLine_PA(t *testing.T) {
	p := setupPipeline()
	event := p.ProcessLine(testPALine)
	if event == nil {
		t.Fatal("ProcessLine returned nil for valid PA line")
	}
	if event.SourceIP != "10.1.1.100" {
		t.Errorf("expected source_ip=10.1.1.100, got %s", event.SourceIP)
	}
	if event.Action != "allow" {
		t.Errorf("expected action=allow, got %s", event.Action)
	}
	if event.ParserID != "paloalto" {
		t.Errorf("expected parser_id=paloalto, got %s", event.ParserID)
	}
}

func TestPipeline_ProcessLine_Empty(t *testing.T) {
	p := setupPipeline()
	if p.ProcessLine("") != nil {
		t.Error("expected nil for empty line")
	}
	if p.ProcessLine("   ") != nil {
		t.Error("expected nil for whitespace-only line")
	}
}

func TestPipeline_ProcessLine_Garbage(t *testing.T) {
	p := setupPipeline()
	if p.ProcessLine("this is just random text with no structure") != nil {
		t.Error("expected nil for garbage line")
	}
}

func TestPipeline_Stats_Increment(t *testing.T) {
	p := setupPipeline()
	fgLine := `date=2026-04-13 time=10:00:00 logid=0001 srcip=1.1.1.1 dstip=2.2.2.2 action=allow`
	kvLine := `src=3.3.3.3 dst=4.4.4.4 action=deny`

	p.ProcessLine(testPALine) // valid PA
	p.ProcessLine(fgLine)      // valid FG
	p.ProcessLine(kvLine)      // valid KV
	p.ProcessLine("garbage1")  // dropped
	p.ProcessLine("garbage2")  // dropped

	if p.Stats.Received != 5 {
		t.Errorf("received=%d, want 5", p.Stats.Received)
	}
	if p.Stats.Parsed != 3 {
		t.Errorf("parsed=%d, want 3", p.Stats.Parsed)
	}
	if p.Stats.Dropped != 2 {
		t.Errorf("dropped=%d, want 2", p.Stats.Dropped)
	}
}

func TestPipeline_Buffer_And_Flush(t *testing.T) {
	p := setupPipeline()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	db.AutoMigrate(&models.LiveEvent{})

	// Process and buffer 3 events
	lines := []string{
		testPALine,
		`date=2026-04-13 time=10:00:00 logid=0001 srcip=1.1.1.1 dstip=2.2.2.2 action=allow`,
		`src=3.3.3.3 dst=4.4.4.4 action=deny`,
	}
	for _, line := range lines {
		ev := p.ProcessLine(line)
		if ev != nil {
			p.Buffer(ev)
		}
	}

	// Flush to DB
	count := p.Flush(db)
	if count != 3 {
		t.Errorf("Flush returned %d, want 3", count)
	}

	// Verify DB
	var total int64
	db.Model(&models.LiveEvent{}).Count(&total)
	if total != 3 {
		t.Errorf("expected 3 rows in live_events, got %d", total)
	}
}
