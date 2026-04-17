package parsers

import (
	"strconv"
	"strings"
	"time"
)

func init() {
	Register(&GenericKVParser{})
}

// GenericKVParser handles arbitrary key=value log lines that contain
// at least source, destination, and action fields.
type GenericKVParser struct{}

func (p *GenericKVParser) ParserID() string  { return "generic_kv" }
func (p *GenericKVParser) DeviceType() string { return "unknown" }

// srcAliases are the KV keys that signal a source IP is present.
var srcAliases = []string{"src", "srcip", "src_ip", "source"}

// dstAliases are the KV keys that signal a destination IP is present.
var dstAliases = []string{"dst", "dstip", "dst_ip", "destination"}

// actAliases are the KV keys that signal an action is present.
var actAliases = []string{"action", "act"}

func (p *GenericKVParser) CanParse(line string) bool {
	check := line
	if len(check) > 500 {
		check = check[:500]
	}

	// Need at least 3 kv pairs
	matches := fgKVRe.FindAllStringSubmatch(check, -1)
	if len(matches) < 3 {
		return false
	}

	kv := make(map[string]bool, len(matches))
	for _, m := range matches {
		kv[strings.ToLower(m[1])] = true
	}

	hasSrc := anyKeyPresent(kv, srcAliases)
	hasDst := anyKeyPresent(kv, dstAliases)
	hasAct := anyKeyPresent(kv, actAliases)

	return hasSrc && hasDst && hasAct
}

func anyKeyPresent(kv map[string]bool, keys []string) bool {
	for _, k := range keys {
		if kv[k] {
			return true
		}
	}
	return false
}

// aliasMap maps raw KV keys to normalised output field names.
var aliasMap = map[string]string{
	// Source / destination
	"src":         "source_ip",
	"srcip":       "source_ip",
	"src_ip":      "source_ip",
	"source":      "source_ip",
	"dst":         "destination_ip",
	"dstip":       "destination_ip",
	"dst_ip":      "destination_ip",
	"destination": "destination_ip",
	// Ports
	"sport":    "source_port",
	"srcport":  "source_port",
	"src_port": "source_port",
	"dport":    "destination_port",
	"dstport":  "destination_port",
	"dst_port": "destination_port",
	// Protocol / action
	"proto":    "protocol",
	"protocol": "protocol",
	"action":   "action",
	"act":      "action",
	// Bytes / packets
	"sentbyte":       "bytes_out",
	"bytes_sent":     "bytes_out",
	"bytesout":       "bytes_out",
	"rcvdbyte":       "bytes_in",
	"bytes_received": "bytes_in",
	"bytesin":        "bytes_in",
	"sentpkt":        "packets_out",
	"rcvdpkt":        "packets_in",
	// Duration
	"duration": "duration_ms",
	"elapsed":  "duration_ms",
	// NAT
	"transip":  "nat_source_ip",
	"transsip": "nat_source_ip",
	"nat_src":  "nat_source_ip",
	"transdip": "nat_destination_ip",
	"nat_dst":  "nat_destination_ip",
	"tranport": "nat_source_port",
	"transsp":  "nat_source_port",
	"transdp":  "nat_destination_port",
	// Application / service / policy
	"app":         "application",
	"appname":     "application",
	"application": "application",
	"service":     "service",
	"policyname":  "reason",
	"policy":      "reason",
	"rule":        "reason",
	"rulename":    "reason",
	// Time (internal prefixed keys consumed by timestamp builder)
	"date":      "_date",
	"time":      "_time",
	"eventtime": "_eventtime",
	"timestamp": "_timestamp",
	"start":     "_timestamp",
}

// intFields lists output fields that must be stored as int.
var intFields = map[string]bool{
	"source_port":          true,
	"destination_port":     true,
	"bytes_in":             true,
	"bytes_out":            true,
	"packets_in":           true,
	"packets_out":          true,
	"duration_ms":          true,
	"nat_source_port":      true,
	"nat_destination_port": true,
}

func (p *GenericKVParser) Parse(line string) (map[string]interface{}, error) {
	rawKV := extractKV(line) // reuses fortigate.go helper
	if len(rawKV) == 0 {
		return nil, nil
	}

	m := make(map[string]interface{})
	internal := make(map[string]string) // for _date, _time, etc.

	for rawKey, rawVal := range rawKV {
		outKey, ok := aliasMap[rawKey]
		if !ok {
			continue
		}
		// Internal keys (prefixed with _) are consumed below for timestamp.
		if strings.HasPrefix(outKey, "_") {
			internal[outKey] = rawVal
			continue
		}
		// Skip if already set (first alias wins).
		if _, already := m[outKey]; already {
			continue
		}
		if intFields[outKey] {
			if n, err := strconv.Atoi(rawVal); err == nil {
				// Duration heuristic: if raw key was "duration" and value < 1000,
				// treat as seconds and convert to ms.
				if outKey == "duration_ms" && rawKey == "duration" && n < 1000 {
					n = n * 1000
				}
				if n > pgIntMax {
					n = pgIntMax
				}
				if n < 0 {
					n = 0
				}
				m[outKey] = n
			}
		} else {
			m[outKey] = rawVal
		}
	}

	// Protocol normalisation
	if proto, ok := m["protocol"].(string); ok {
		if mapped, found := fgProtoMap[proto]; found {
			m["protocol"] = mapped
		} else {
			m["protocol"] = strings.ToUpper(proto)
		}
	}

	// Action normalisation
	if act, ok := m["action"].(string); ok {
		m["action"] = gkvNormalizeAction(act)
	} else {
		m["action"] = "unknown"
	}

	// Timestamp
	m["event_time"] = gkvParseTime(internal)

	return m, nil
}

// gkvNormalizeAction maps generic action strings to canonical form.
func gkvNormalizeAction(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	switch low {
	case "accept", "allow", "pass", "permit", "allowed":
		return "allow"
	case "deny", "denied", "block", "blocked", "reject":
		return "deny"
	case "drop", "dropped", "discard":
		return "drop"
	}
	if strings.HasPrefix(low, "reset") {
		return "reset"
	}
	if low == "" {
		return "unknown"
	}
	return low
}

// gkvParseTime builds an event timestamp from internal KV fields.
func gkvParseTime(internal map[string]string) time.Time {
	// Try date + time combination
	dateStr := internal["_date"]
	timeStr := internal["_time"]
	if dateStr != "" && timeStr != "" {
		combined := dateStr + " " + timeStr
		for _, layout := range []string{
			"2006-01-02 15:04:05",
			"2006/01/02 15:04:05",
			"2006-01-02 15:04:05.000",
		} {
			if t, err := time.Parse(layout, combined); err == nil {
				return t.UTC()
			}
		}
	}

	// Fallback: epoch
	for _, key := range []string{"_eventtime", "_timestamp"} {
		if raw := internal[key]; raw != "" {
			if epoch, err := strconv.ParseInt(raw, 10, 64); err == nil {
				switch {
				case epoch > 1e18:
					return time.Unix(0, epoch).UTC()
				case epoch > 1e15:
					return time.Unix(0, epoch*1000).UTC()
				default:
					return time.Unix(epoch, 0).UTC()
				}
			}
		}
	}

	return time.Now().UTC()
}
