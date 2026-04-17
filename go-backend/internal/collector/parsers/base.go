package parsers

import (
	"strings"
)

// Parser is the interface every log-line parser must satisfy.
type Parser interface {
	CanParse(line string) bool
	Parse(line string) (map[string]interface{}, error)
	ParserID() string
	DeviceType() string
}

var registry []Parser

// Register adds a parser to the global detection registry.
func Register(p Parser) {
	registry = append(registry, p)
}

// Detect returns the first registered parser whose CanParse returns true,
// guarded so that a panicking parser cannot crash the pipeline.
func Detect(line string) Parser {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	for _, p := range registry {
		matched := false
		func() {
			defer func() { recover() }()
			matched = p.CanParse(line)
		}()
		if matched {
			return p
		}
	}
	return nil
}

// ClearRegistry removes all registered parsers (useful in tests).
func ClearRegistry() {
	registry = nil
}

// StripSyslogPriority removes RFC 3164/5424 priority prefix like "<134>"
// and optionally the BSD-style syslog header that follows.
func StripSyslogPriority(line string) string {
	if len(line) < 3 || line[0] != '<' {
		return line
	}
	end := strings.IndexByte(line, '>')
	if end < 2 || end > 4 {
		return line
	}
	// Check that content between < > is numeric
	for i := 1; i < end; i++ {
		if line[i] < '0' || line[i] > '9' {
			return line
		}
	}
	rest := line[end+1:]
	return stripRFC3164Header(rest)
}

var months = map[string]bool{
	"Jan": true, "Feb": true, "Mar": true, "Apr": true,
	"May": true, "Jun": true, "Jul": true, "Aug": true,
	"Sep": true, "Oct": true, "Nov": true, "Dec": true,
}

// stripRFC3164Header strips "Mon DD HH:MM:SS hostname " from front of line.
func stripRFC3164Header(line string) string {
	if len(line) < 16 {
		return line
	}
	if !months[line[:3]] {
		return line
	}
	// Pattern: "Mon DD HH:MM:SS hostname msg"
	// Find space after timestamp (position ~15)
	spaceAfterTS := -1
	for i := 15; i < len(line) && i < 20; i++ {
		if line[i] == ' ' {
			spaceAfterTS = i
			break
		}
	}
	if spaceAfterTS < 0 {
		return line
	}
	// Find space after hostname
	rest := line[spaceAfterTS+1:]
	spaceAfterHost := strings.IndexByte(rest, ' ')
	if spaceAfterHost < 0 {
		return line
	}
	return rest[spaceAfterHost+1:]
}
