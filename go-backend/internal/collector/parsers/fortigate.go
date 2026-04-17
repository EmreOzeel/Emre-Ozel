package parsers

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var fgKVRe = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)`)

var fgProtoMap = map[string]string{
	"1":  "ICMP",
	"6":  "TCP",
	"17": "UDP",
	"47": "GRE",
	"50": "ESP",
	"51": "AH",
	"58": "ICMPv6",
	"89": "OSPF",
}

func init() {
	Register(&FortiGateParser{})
}

// FortiGateParser handles FortiOS key=value syslog lines.
type FortiGateParser struct{}

func (p *FortiGateParser) ParserID() string  { return "fortigate" }
func (p *FortiGateParser) DeviceType() string { return "firewall" }

func (p *FortiGateParser) CanParse(line string) bool {
	check := line
	if len(check) > 500 {
		check = check[:500]
	}
	low := strings.ToLower(check)
	hasIdent := strings.Contains(low, "logid=") || strings.Contains(low, "devname=")
	hasAddr := strings.Contains(low, "srcip=") || strings.Contains(low, "src=")
	return hasIdent && hasAddr
}

func (p *FortiGateParser) Parse(line string) (map[string]interface{}, error) {
	kv := extractKV(line)
	if len(kv) == 0 {
		return nil, nil
	}

	m := make(map[string]interface{})

	// Source / destination
	m["source_ip"] = firstOf(kv, "srcip", "src")
	m["destination_ip"] = firstOf(kv, "dstip", "dst")

	setKVInt(m, "source_port", kv, "srcport")
	setKVInt(m, "destination_port", kv, "dstport")

	// Protocol
	if proto := firstOf(kv, "proto", "protocol"); proto != "" {
		if mapped, ok := fgProtoMap[proto]; ok {
			m["protocol"] = mapped
		} else {
			m["protocol"] = strings.ToUpper(proto)
		}
	}

	// Action
	if act := firstOf(kv, "action", "act"); act != "" {
		m["action"] = fgNormalizeAction(act)
	} else {
		m["action"] = "unknown"
	}

	// Reason / policy
	if reason := firstOf(kv, "policyname", "policy"); reason != "" {
		m["reason"] = reason
	}

	// Bytes / packets
	setKVInt(m, "bytes_out", kv, "sentbyte")
	setKVInt(m, "bytes_in", kv, "rcvdbyte")
	setKVInt(m, "packets_out", kv, "sentpkt")
	setKVInt(m, "packets_in", kv, "rcvdpkt")

	// Application / service
	if app := firstOf(kv, "app", "appname"); app != "" {
		m["application"] = app
	}
	if svc := kv["service"]; svc != "" {
		m["service"] = svc
	}

	// Duration (seconds → ms)
	if dur := kv["duration"]; dur != "" {
		if n, err := strconv.Atoi(dur); err == nil {
			ms := n * 1000
			if ms > pgIntMax {
				ms = pgIntMax
			}
			m["duration_ms"] = ms
		}
	}

	// NAT
	fgExtractNAT(m, kv)

	// Timestamp
	m["event_time"] = fgParseTime(kv)

	return m, nil
}

// extractKV parses key=value pairs from a line.
func extractKV(line string) map[string]string {
	matches := fgKVRe.FindAllStringSubmatch(line, -1)
	kv := make(map[string]string, len(matches))
	for _, match := range matches {
		key := strings.ToLower(match[1])
		val := match[2]
		// Strip surrounding quotes
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		kv[key] = val
	}
	return kv
}

// firstOf returns the value of the first non-empty key found.
func firstOf(kv map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := kv[k]; v != "" {
			return v
		}
	}
	return ""
}

// setKVInt reads a value from kv, parses it as int, and stores it.
func setKVInt(m map[string]interface{}, outKey string, kv map[string]string, kvKeys ...string) {
	for _, k := range kvKeys {
		if raw := kv[k]; raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				if n > pgIntMax {
					n = pgIntMax
				}
				if n < 0 {
					n = 0
				}
				m[outKey] = n
				return
			}
		}
	}
}

// fgExtractNAT sets NAT fields only when they differ from original IPs.
func fgExtractNAT(m map[string]interface{}, kv map[string]string) {
	srcIP, _ := m["source_ip"].(string)
	dstIP, _ := m["destination_ip"].(string)

	natSrc := firstOf(kv, "transip", "transsip")
	if natSrc != "" && natSrc != "0.0.0.0" && natSrc != srcIP {
		m["nat_source_ip"] = natSrc
		setKVInt(m, "nat_source_port", kv, "transport", "transsp")
	}

	natDst := kv["transdip"]
	if natDst != "" && natDst != "0.0.0.0" && natDst != dstIP {
		m["nat_destination_ip"] = natDst
		setKVInt(m, "nat_destination_port", kv, "transdp")
	}
}

// fgParseTime tries to build a timestamp from FortiGate fields.
func fgParseTime(kv map[string]string) time.Time {
	// Try combining date= and time= fields
	dateStr := kv["date"]
	timeStr := kv["time"]
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

	// Fallback: epoch seconds
	for _, key := range []string{"eventtime", "timestamp"} {
		if raw := kv[key]; raw != "" {
			if epoch, err := strconv.ParseInt(raw, 10, 64); err == nil {
				// FortiOS sometimes sends nanoseconds or microseconds
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

// fgNormalizeAction maps FortiGate action strings to canonical form.
func fgNormalizeAction(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	switch low {
	case "accept", "allow", "pass", "permit":
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
