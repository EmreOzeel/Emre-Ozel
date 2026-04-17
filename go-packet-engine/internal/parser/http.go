package parser

import (
	"strconv"
	"strings"
)

// ParseHTTP performs a simple line-based parse of HTTP/1.x request or response.
// Returns nil if the payload does not look like HTTP.
func ParseHTTP(payload []byte) *HTTPInfo {
	if len(payload) < 10 {
		return nil
	}

	text := string(payload)
	lines := strings.SplitN(text, "\r\n", 32)
	if len(lines) == 0 {
		return nil
	}

	first := lines[0]

	// Try request: "METHOD path HTTP/1.x"
	if isHTTPMethod(first) {
		return parseHTTPRequest(first, lines[1:])
	}

	// Try response: "HTTP/1.x STATUS ..."
	if strings.HasPrefix(first, "HTTP/") {
		return parseHTTPResponse(first)
	}

	return nil
}

func isHTTPMethod(line string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT "}
	for _, m := range methods {
		if strings.HasPrefix(line, m) {
			return true
		}
	}
	return false
}

func parseHTTPRequest(firstLine string, headers []string) *HTTPInfo {
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return nil
	}

	info := &HTTPInfo{
		Method: parts[0],
		Path:   parts[1],
	}

	for _, h := range headers {
		if h == "" {
			break
		}
		lower := strings.ToLower(h)
		if strings.HasPrefix(lower, "host:") {
			info.Host = strings.TrimSpace(h[5:])
		} else if strings.HasPrefix(lower, "user-agent:") {
			info.UserAgent = strings.TrimSpace(h[11:])
		}
	}

	return info
}

func parseHTTPResponse(firstLine string) *HTTPInfo {
	// "HTTP/1.1 200 OK"
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return nil
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}
	return &HTTPInfo{StatusCode: code}
}
