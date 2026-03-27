package analyzer

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"pcap-analyzer/models"
)

type HTTPFlow struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Method   string
	Path     string
	Host     string
	Status   int
	HasAuth  bool // Basic auth header
	HasCreds bool // Potential plaintext credentials in body
	ReqTime  time.Time
	RespTime time.Time
}

type HTTPState struct {
	// error status codes: code -> count
	statusCodes map[int]int

	// cleartext HTTP traffic count (port 80)
	cleartextCount int
	cleartextHosts map[string]struct{}

	// suspicious user agents
	suspiciousUA map[string]int

	// basic auth over HTTP
	basicAuthHTTP []basicAuthRecord

	// HTTP flows with errors
	errorFlows []HTTPFlow

	// HTTP methods
	methods map[string]int

	// Slow responses (time between req and response > 5s)
	slowResponses int
}

type basicAuthRecord struct {
	Host    string
	SrcIP   string
	DstIP   string
	DstPort uint16
}

var suspiciousAgents = []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab",
	"dirbuster", "gobuster", "hydra", "medusa",
	"metasploit", "python-requests/2", "curl/", "wget/",
	"scrapy", "burpsuite",
}

func newHTTPState() *HTTPState {
	return &HTTPState{
		statusCodes:    make(map[int]int),
		cleartextHosts: make(map[string]struct{}),
		suspiciousUA:   make(map[string]int),
		methods:        make(map[string]int),
	}
}

func analyzeHTTP(packet gopacket.Packet, state *analysisState) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	payload := tcp.Payload
	if len(payload) < 8 {
		return
	}

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}
	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()
	ts := packet.Metadata().Timestamp
	s := state.httpState

	dstPort := uint16(tcp.DstPort)
	srcPort := uint16(tcp.SrcPort)

	// Detect HTTP requests
	firstLine := string(payload[:min(len(payload), 10)])
	isRequest := strings.HasPrefix(firstLine, "GET ") ||
		strings.HasPrefix(firstLine, "POST ") ||
		strings.HasPrefix(firstLine, "PUT ") ||
		strings.HasPrefix(firstLine, "DELETE ") ||
		strings.HasPrefix(firstLine, "HEAD ") ||
		strings.HasPrefix(firstLine, "OPTIONS ") ||
		strings.HasPrefix(firstLine, "PATCH ")

	isResponse := strings.HasPrefix(firstLine, "HTTP/")

	if isRequest {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
		if err != nil {
			return
		}
		defer req.Body.Close()

		// Track method
		s.methods[req.Method]++

		// Cleartext HTTP detection
		if dstPort == 80 || dstPort == 8080 || dstPort == 8000 {
			s.cleartextCount++
			if req.Host != "" {
				s.cleartextHosts[req.Host] = struct{}{}
			}

			// Basic auth over HTTP
			if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
				s.basicAuthHTTP = append(s.basicAuthHTTP, basicAuthRecord{
					Host:    req.Host,
					SrcIP:   srcIP,
					DstIP:   dstIP,
					DstPort: dstPort,
				})
			}
		}

		// Suspicious user agents
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		for _, agent := range suspiciousAgents {
			if strings.Contains(ua, agent) {
				s.suspiciousUA[agent]++
				break
			}
		}

		// Check for credentials in POST body (basic heuristic)
		body := make([]byte, 512)
		n, _ := req.Body.Read(body)
		bodyStr := strings.ToLower(string(body[:n]))
		if strings.Contains(bodyStr, "password=") || strings.Contains(bodyStr, "passwd=") ||
			strings.Contains(bodyStr, "pass=") || strings.Contains(bodyStr, "pwd=") {
			if dstPort == 80 || dstPort == 8080 {
				s.basicAuthHTTP = append(s.basicAuthHTTP, basicAuthRecord{
					Host:    req.Host,
					SrcIP:   srcIP,
					DstIP:   dstIP,
					DstPort: dstPort,
				})
			}
		}

		_ = ts
		_ = srcPort
	}

	if isResponse {
		// Parse status code from first line: "HTTP/1.1 404 Not Found"
		parts := strings.SplitN(string(payload[:min(len(payload), 100)]), " ", 3)
		if len(parts) >= 2 {
			var statusCode int
			fmt.Sscanf(parts[1], "%d", &statusCode)
			if statusCode >= 100 && statusCode < 600 {
				s.statusCodes[statusCode]++
				if statusCode >= 400 {
					s.errorFlows = append(s.errorFlows, HTTPFlow{
						SrcIP:   srcIP,
						DstIP:   dstIP,
						SrcPort: srcPort,
						DstPort: dstPort,
						Status:  statusCode,
						ReqTime: ts,
					})
				}
			}
		}
	}
}

func finalizeHTTP(s *HTTPState) []models.Finding {
	var findings []models.Finding

	// 1. HTTP error codes summary
	error4xx := 0
	error5xx := 0
	for code, count := range s.statusCodes {
		if code >= 400 && code < 500 {
			error4xx += count
		} else if code >= 500 {
			error5xx += count
		}
	}

	if error5xx >= 5 {
		severity := "warning"
		if error5xx >= 20 {
			severity = "critical"
		}
		// Find which 5xx codes
		codesDetail := make(map[string]int)
		for code, count := range s.statusCodes {
			if code >= 500 {
				codesDetail[fmt.Sprintf("%d", code)] = count
			}
		}
		findings = append(findings, models.Finding{
			Severity:    severity,
			Category:    "http",
			Title:       "High Number of HTTP 5xx Server Errors",
			Description: fmt.Sprintf("%d HTTP server-side error responses (5xx) detected. This indicates server crashes, application bugs, or resource exhaustion.", error5xx),
			Details: map[string]interface{}{
				"total_5xx":   error5xx,
				"error_codes": codesDetail,
			},
			PacketCount: error5xx,
		})
	}

	if error4xx >= 20 {
		severity := "warning"
		if error4xx >= 100 {
			severity = "critical"
		}
		codesDetail := make(map[string]int)
		for code, count := range s.statusCodes {
			if code >= 400 && code < 500 {
				codesDetail[fmt.Sprintf("%d", code)] = count
			}
		}
		findings = append(findings, models.Finding{
			Severity:    severity,
			Category:    "http",
			Title:       "High Number of HTTP 4xx Client Errors",
			Description: fmt.Sprintf("%d HTTP client-side error responses (4xx) detected. Frequent 404s may indicate directory traversal or scanning attempts.", error4xx),
			Details: map[string]interface{}{
				"total_4xx":   error4xx,
				"error_codes": codesDetail,
			},
			PacketCount: error4xx,
		})
	}

	// 2. Unencrypted HTTP traffic
	if s.cleartextCount >= 10 {
		severity := "warning"
		if s.cleartextCount >= 100 {
			severity = "critical"
		}
		hosts := make([]string, 0, 5)
		for h := range s.cleartextHosts {
			hosts = append(hosts, h)
			if len(hosts) >= 5 {
				break
			}
		}
		findings = append(findings, models.Finding{
			Severity:    severity,
			Category:    "http",
			Title:       "Unencrypted HTTP Traffic Detected",
			Description: fmt.Sprintf("%d HTTP (plaintext) requests were captured. Sensitive data transmitted over plain HTTP can be intercepted. Use HTTPS instead.", s.cleartextCount),
			Details: map[string]interface{}{
				"request_count": s.cleartextCount,
				"unique_hosts":  len(s.cleartextHosts),
				"example_hosts": hosts,
			},
			PacketCount: s.cleartextCount,
		})
	}

	// 3. Credentials over HTTP
	if len(s.basicAuthHTTP) > 0 {
		// Deduplicate by host
		seen := make(map[string]struct{})
		unique := make([]basicAuthRecord, 0)
		for _, r := range s.basicAuthHTTP {
			key := r.Host + r.SrcIP
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				unique = append(unique, r)
			}
		}
		examples := make([]string, 0, 3)
		for _, r := range unique {
			if len(examples) >= 3 {
				break
			}
			examples = append(examples, fmt.Sprintf("%s → %s:%d", r.SrcIP, r.DstIP, r.DstPort))
		}
		findings = append(findings, models.Finding{
			Severity:    "critical",
			Category:    "http",
			Title:       "Credentials Transmitted Over Plaintext HTTP",
			Description: fmt.Sprintf("%d instances of authentication credentials (Basic Auth or form passwords) sent over unencrypted HTTP. These credentials can be trivially intercepted.", len(unique)),
			Details: map[string]interface{}{
				"credential_flows": len(unique),
				"examples":         examples,
			},
			PacketCount: len(s.basicAuthHTTP),
		})
	}

	// 4. Suspicious user agents (scanning tools)
	if len(s.suspiciousUA) > 0 {
		toolList := make([]string, 0, len(s.suspiciousUA))
		for tool, count := range s.suspiciousUA {
			toolList = append(toolList, fmt.Sprintf("%s (%d reqs)", tool, count))
		}
		findings = append(findings, models.Finding{
			Severity:    "critical",
			Category:    "http",
			Title:       "Security Tool User-Agents Detected",
			Description: fmt.Sprintf("HTTP requests with user agents matching known security/scanning tools were detected: %s. This indicates active scanning or exploitation attempts.", strings.Join(toolList, ", ")),
			Details: map[string]interface{}{
				"tools_detected": s.suspiciousUA,
			},
		})
	}

	// 5. HTTP traffic info summary
	if len(s.statusCodes) > 0 || s.cleartextCount > 0 {
		totalHTTP := 0
		for _, c := range s.statusCodes {
			totalHTTP += c
		}
		findings = append(findings, models.Finding{
			Severity:    "info",
			Category:    "http",
			Title:       "HTTP Traffic Summary",
			Description: fmt.Sprintf("Captured %d HTTP responses: %d client errors (4xx), %d server errors (5xx). %d unencrypted HTTP requests detected.", totalHTTP, error4xx, error5xx, s.cleartextCount),
			Details: map[string]interface{}{
				"total_responses":   totalHTTP,
				"4xx_errors":        error4xx,
				"5xx_errors":        error5xx,
				"http_requests":     s.cleartextCount,
				"status_code_breakdown": s.statusCodes,
				"http_methods":      s.methods,
			},
			PacketCount: totalHTTP,
		})
	}

	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
