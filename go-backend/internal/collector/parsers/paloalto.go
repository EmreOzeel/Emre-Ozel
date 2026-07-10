package parsers

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var paPrefixRe = regexp.MustCompile(`^\d+,\d{4}/`)

const pgIntMax = 2147483647

func init() {
	Register(&PaloAltoParser{})
}

// PaloAltoParser handles PAN-OS CSV syslog (TRAFFIC and THREAT types).
type PaloAltoParser struct{}

func (p *PaloAltoParser) ParserID() string  { return "paloalto" }
func (p *PaloAltoParser) DeviceType() string { return "firewall" }

func (p *PaloAltoParser) CanParse(line string) bool {
	check := line
	if len(check) > 20 {
		check = check[:20]
	}
	if !paPrefixRe.MatchString(check) {
		return false
	}
	parts := strings.SplitN(line, ",", 6)
	if len(parts) < 5 {
		return false
	}
	lt := parts[3]
	return lt == "TRAFFIC" || lt == "THREAT"
}

func (p *PaloAltoParser) Parse(line string) (map[string]interface{}, error) {
	fields := strings.Split(line, ",")
	if len(fields) < 36 {
		return nil, nil
	}

	eventTime := parsePATime(fields[1])
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	logType := fields[3]
	if logType == "TRAFFIC" {
		return parseTraffic(fields, eventTime), nil
	}
	if logType == "THREAT" {
		m := parseThreat(fields, eventTime)
		// URL Filtering logs are THREAT logs with subtype "url".
		// Augment (never replace) the THREAT output with web fields so the
		// existing LiveEvent production stays untouched.
		if strings.EqualFold(strings.TrimSpace(fields[4]), "url") {
			augmentURLFiltering(m, fields)
		}
		return m, nil
	}
	return nil, nil
}

// parseTraffic builds a normalised map from a PAN-OS TRAFFIC log line.
func parseTraffic(f []string, eventTime time.Time) map[string]interface{} {
	m := map[string]interface{}{
		"event_time":     eventTime,
		"source_ip":      f[7],
		"destination_ip": f[8],
	}

	setIntField(m, "source_port", f[24])
	setIntField(m, "destination_port", f[25])

	if f[29] != "" {
		m["protocol"] = strings.ToUpper(f[29])
	}

	m["action"] = normalizeAction(f[30])

	setIntField(m, "bytes_out", f[31])
	setIntField(m, "bytes_in", f[32])

	// Duration: PAN-OS reports seconds; convert to ms, cap at pgIntMax.
	if dur, err := strconv.Atoi(f[33]); err == nil {
		ms := dur * 1000
		if ms > pgIntMax {
			ms = pgIntMax
		}
		m["duration_ms"] = ms
	}

	setIntField(m, "packets_out", f[34])
	setIntField(m, "packets_in", f[35])

	if f[14] != "" {
		m["application"] = f[14]
	}
	if f[11] != "" {
		m["reason"] = f[11]
	}

	extractNAT(m, f)
	return m
}

// parseThreat builds a normalised map from a PAN-OS THREAT log line.
func parseThreat(f []string, eventTime time.Time) map[string]interface{} {
	m := map[string]interface{}{
		"event_time":     eventTime,
		"source_ip":      f[7],
		"destination_ip": f[8],
	}

	setIntField(m, "source_port", f[24])
	setIntField(m, "destination_port", f[25])

	if f[29] != "" {
		m["reason"] = f[29] // threat_id
	}

	m["action"] = normalizeThreatAction(f[30])

	if len(f) > 36 && f[36] != "" {
		m["application"] = f[36] // category
	}

	if len(f) > 37 && f[37] != "" {
		m["health_status"] = mapSeverity(f[37]) // severity
	}

	if len(f) > 38 && f[38] != "" {
		m["service"] = f[38] // direction
	}

	if f[29] != "" {
		m["protocol"] = strings.ToUpper(f[29])
	}

	extractNAT(m, f)
	return m
}

// augmentURLFiltering adds web-transaction fields from a PAN-OS URL Filtering
// log (THREAT subtype "url") on top of the standard THREAT map.
// Field positions follow the PAN-OS URL log layout:
// [31]=misc (the URL, often quoted), [35]=category, [41]=content type,
// [46]=user agent, [49]=referer, [56]=HTTP method. Trailing fields are only
// read when present so shorter lines still parse.
func augmentURLFiltering(m map[string]interface{}, f []string) {
	m["log_subtype"] = "url"

	if url := trimQuotes(f[31]); url != "" {
		m["url"] = url
		if host := hostFromURL(url); host != "" {
			m["host"] = host
		}
	}
	if len(f) > 35 {
		if cat := trimQuotes(f[35]); cat != "" {
			m["url_category"] = cat
		}
	}
	if len(f) > 41 {
		if ct := trimQuotes(f[41]); ct != "" {
			m["content_type"] = ct
		}
	}
	if len(f) > 46 {
		if ua := trimQuotes(f[46]); ua != "" {
			m["user_agent"] = ua
		}
	}
	if len(f) > 49 {
		if ref := trimQuotes(f[49]); ref != "" {
			m["referer"] = ref
		}
	}
	if len(f) > 56 {
		if method := trimQuotes(f[56]); method != "" && method != "unknown" {
			m["http_method"] = strings.ToUpper(method)
		}
	}
}

// trimQuotes strips surrounding double quotes and whitespace from a CSV field.
func trimQuotes(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"`)
}

// hostFromURL extracts the host portion from a URL that may or may not
// include a scheme, path, or port.
func hostFromURL(url string) string {
	host := url
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	if idx := strings.IndexByte(host, '/'); idx >= 0 {
		host = host[:idx]
	}
	// Strip port (IPv4/hostname only; leave bracketed IPv6 untouched).
	if !strings.HasPrefix(host, "[") {
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
	}
	return host
}

// extractNAT populates NAT fields only when they differ from the original IPs.
func extractNAT(m map[string]interface{}, f []string) {
	if len(f) < 27 {
		return
	}

	srcIP, _ := m["source_ip"].(string)
	dstIP, _ := m["destination_ip"].(string)

	natSrc := f[9]
	natDst := f[10]

	if natSrc != "" && natSrc != "0.0.0.0" && natSrc != srcIP {
		m["nat_source_ip"] = natSrc
		if len(f) > 26 {
			setIntField(m, "nat_source_port", f[26])
		}
	}

	if natDst != "" && natDst != "0.0.0.0" && natDst != dstIP {
		m["nat_destination_ip"] = natDst
		if len(f) > 27 {
			setIntField(m, "nat_destination_port", f[27])
		}
	}
}

// normalizeAction maps PAN-OS TRAFFIC actions to canonical form.
func normalizeAction(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	switch low {
	case "allow", "allowed":
		return "allow"
	case "deny", "denied":
		return "deny"
	case "drop", "dropped", "drop-all-packets":
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

// normalizeThreatAction maps PAN-OS THREAT actions to canonical form.
func normalizeThreatAction(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	switch low {
	case "alert":
		return "alert"
	case "allow", "allowed":
		return "allow"
	case "block", "blocked":
		return "deny"
	case "deny", "denied":
		return "deny"
	case "drop", "dropped", "drop-all-packets":
		return "drop"
	}
	if strings.HasPrefix(low, "reset") {
		return "deny"
	}
	if low == "" {
		return "unknown"
	}
	return low
}

var severityMap = map[string]string{
	"critical":      "critical",
	"high":          "high",
	"medium":        "medium",
	"low":           "low",
	"informational": "info",
}

func mapSeverity(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	if v, ok := severityMap[low]; ok {
		return v
	}
	return low
}

// parsePATime tries the two common PAN-OS timestamp formats.
func parsePATime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if t, err := time.Parse("2006/01/02 15:04:05", raw); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("2006/01/02 15:04:05.000000", raw); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// setIntField parses a string as int and stores it in the map, capped at pgIntMax.
func setIntField(m map[string]interface{}, key, val string) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return
	}
	if n > pgIntMax {
		n = pgIntMax
	}
	if n < 0 {
		n = 0
	}
	m[key] = n
}
