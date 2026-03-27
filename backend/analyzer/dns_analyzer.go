package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"pcap-analyzer/models"
)

type DNSQueryRecord struct {
	Name      string
	QueryTime time.Time
	Answered  bool
	RCode     layers.DNSResponseCode
	RTT       time.Duration
}

type DNSState struct {
	// txID+srcIP -> query record (for matching requests to responses)
	pendingQueries map[string]*DNSQueryRecord

	// NXDOMAIN counts per domain
	nxdomainDomains map[string]int

	// Total failed queries per src
	failedPerSrc map[string]int

	// DNS query rate per src
	queryCount   map[string]int
	queryFirst   map[string]time.Time
	queryLast    map[string]time.Time

	// Subdomain lengths (for tunneling detection)
	longSubdomains map[string]int // domain -> count of queries with very long subdomains

	// All NXDOMAINs
	nxdomainList []string

	// Slow DNS (RTT > 2s)
	slowDNS []slowDNSRecord
}

type slowDNSRecord struct {
	Domain  string
	RTT     time.Duration
	SrcIP   string
}

func newDNSState() *DNSState {
	return &DNSState{
		pendingQueries:  make(map[string]*DNSQueryRecord),
		nxdomainDomains: make(map[string]int),
		failedPerSrc:    make(map[string]int),
		queryCount:      make(map[string]int),
		queryFirst:      make(map[string]time.Time),
		queryLast:       make(map[string]time.Time),
		longSubdomains:  make(map[string]int),
	}
}

func analyzeDNS(packet gopacket.Packet, state *analysisState) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}
	srcIP := netLayer.NetworkFlow().Src().String()
	ts := packet.Metadata().Timestamp
	s := state.dnsState

	if !dns.QR { // Query
		// Count queries per source
		s.queryCount[srcIP]++
		if _, ok := s.queryFirst[srcIP]; !ok {
			s.queryFirst[srcIP] = ts
		}
		s.queryLast[srcIP] = ts

		for _, q := range dns.Questions {
			qName := string(q.Name)

			// Check for long subdomain labels (potential DNS tunneling)
			labels := strings.Split(qName, ".")
			for _, label := range labels {
				if len(label) > 30 {
					s.longSubdomains[qName]++
					break
				}
			}

			key := fmt.Sprintf("%d-%s", dns.ID, srcIP)
			s.pendingQueries[key] = &DNSQueryRecord{
				Name:      qName,
				QueryTime: ts,
			}
		}
	} else { // Response
		dstIP := netLayer.NetworkFlow().Dst().String()
		key := fmt.Sprintf("%d-%s", dns.ID, dstIP)

		if record, ok := s.pendingQueries[key]; ok {
			record.Answered = true
			record.RCode = dns.ResponseCode
			record.RTT = ts.Sub(record.QueryTime)
			delete(s.pendingQueries, key)

			// NXDOMAIN
			if dns.ResponseCode == layers.DNSResponseCodeNXDomain {
				s.nxdomainDomains[record.Name]++
				s.failedPerSrc[dstIP]++
				s.nxdomainList = append(s.nxdomainList, record.Name)
			}

			// SERVFAIL
			if dns.ResponseCode == layers.DNSResponseCodeServFail {
				s.failedPerSrc[dstIP]++
			}

			// Slow DNS response (>2 seconds)
			if record.RTT > 2*time.Second {
				s.slowDNS = append(s.slowDNS, slowDNSRecord{
					Domain: record.Name,
					RTT:    record.RTT,
					SrcIP:  dstIP,
				})
			}
		}
	}
}

func finalizeDNS(s *DNSState) []models.Finding {
	var findings []models.Finding

	// 1. NXDOMAIN flood / failed DNS queries
	totalNXDomain := 0
	for _, c := range s.nxdomainDomains {
		totalNXDomain += c
	}
	if totalNXDomain >= 10 {
		// Top NXDOMAIN domains
		type domainCount struct {
			domain string
			count  int
		}
		var sorted []domainCount
		for d, c := range s.nxdomainDomains {
			sorted = append(sorted, domainCount{d, c})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })
		topDomains := make([]string, 0, 5)
		for i := 0; i < len(sorted) && i < 5; i++ {
			topDomains = append(topDomains, fmt.Sprintf("%s (%d)", sorted[i].domain, sorted[i].count))
		}

		severity := "warning"
		if totalNXDomain >= 50 {
			severity = "critical"
		}
		findings = append(findings, models.Finding{
			Severity:    severity,
			Category:    "dns",
			Title:       "High Number of NXDOMAIN Responses",
			Description: fmt.Sprintf("%d DNS queries resulted in NXDOMAIN (Non-Existent Domain). This could indicate malware beaconing to dead C2 servers, DGA (Domain Generation Algorithm) activity, or misconfigured applications.", totalNXDomain),
			Details: map[string]interface{}{
				"total_nxdomain": totalNXDomain,
				"unique_domains": len(s.nxdomainDomains),
				"top_domains":    topDomains,
			},
			PacketCount: totalNXDomain,
		})
	}

	// 2. DNS tunneling detection (long subdomain labels)
	if len(s.longSubdomains) >= 3 {
		exampleDomains := make([]string, 0, 5)
		for d := range s.longSubdomains {
			exampleDomains = append(exampleDomains, d)
			if len(exampleDomains) >= 5 {
				break
			}
		}
		findings = append(findings, models.Finding{
			Severity:    "critical",
			Category:    "dns",
			Title:       "Possible DNS Tunneling Detected",
			Description: fmt.Sprintf("%d DNS queries contain unusually long subdomain labels (>30 chars), which is a common characteristic of DNS tunneling — used to exfiltrate data or establish covert C2 channels.", len(s.longSubdomains)),
			Details: map[string]interface{}{
				"suspicious_query_count": len(s.longSubdomains),
				"example_domains":        exampleDomains,
			},
			PacketCount: len(s.longSubdomains),
		})
	}

	// 3. High DNS query rate (potential DNS amplification/flood)
	for srcIP, count := range s.queryCount {
		first := s.queryFirst[srcIP]
		last := s.queryLast[srcIP]
		durationSec := last.Sub(first).Seconds()
		if durationSec < 1 {
			durationSec = 1
		}
		qps := float64(count) / durationSec
		if qps >= 50 {
			severity := "warning"
			if qps >= 200 {
				severity = "critical"
			}
			findings = append(findings, models.Finding{
				Severity:    severity,
				Category:    "dns",
				Title:       "Abnormally High DNS Query Rate",
				Description: fmt.Sprintf("Source IP %s sent DNS queries at %.1f queries/second (%d total). This may indicate a DNS flood or automated reconnaissance.", srcIP, qps, count),
				Details: map[string]interface{}{
					"total_queries":   count,
					"queries_per_sec": fmt.Sprintf("%.1f", qps),
				},
				SrcIP:       srcIP,
				PacketCount: count,
				FirstSeen:   &first,
				LastSeen:    &last,
			})
		}
	}

	// 4. Slow DNS responses
	if len(s.slowDNS) >= 3 {
		maxRTT := time.Duration(0)
		for _, r := range s.slowDNS {
			if r.RTT > maxRTT {
				maxRTT = r.RTT
			}
		}
		exampleDomains := make([]string, 0, 3)
		for _, r := range s.slowDNS {
			exampleDomains = append(exampleDomains, fmt.Sprintf("%s (%.0fms)", r.Domain, float64(r.RTT.Milliseconds())))
			if len(exampleDomains) >= 3 {
				break
			}
		}
		findings = append(findings, models.Finding{
			Severity:    "warning",
			Category:    "dns",
			Title:       "Slow DNS Responses Detected",
			Description: fmt.Sprintf("%d DNS queries had response times exceeding 2 seconds (max: %s). Slow DNS can degrade application performance significantly.", len(s.slowDNS), maxRTT.Round(time.Millisecond)),
			Details: map[string]interface{}{
				"slow_query_count": len(s.slowDNS),
				"max_rtt_ms":       maxRTT.Milliseconds(),
				"examples":         exampleDomains,
			},
			PacketCount: len(s.slowDNS),
		})
	}

	// 5. Info: DNS summary
	totalQueries := 0
	for _, c := range s.queryCount {
		totalQueries += c
	}
	if totalQueries > 0 {
		findings = append(findings, models.Finding{
			Severity:    "info",
			Category:    "dns",
			Title:       "DNS Traffic Summary",
			Description: fmt.Sprintf("Captured %d DNS queries from %d sources. %d queries resulted in NXDOMAIN.", totalQueries, len(s.queryCount), totalNXDomain),
			Details: map[string]interface{}{
				"total_queries": totalQueries,
				"unique_clients": len(s.queryCount),
				"nxdomain_count": totalNXDomain,
			},
			PacketCount: totalQueries,
		})
	}

	return findings
}
