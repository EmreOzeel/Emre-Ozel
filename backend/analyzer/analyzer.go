package analyzer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"pcap-analyzer/models"
)

// State shared across all analyzers during a single-pass analysis
type analysisState struct {
	// General stats
	totalPackets  int
	totalBytes    int64
	firstTime     *time.Time
	lastTime      *time.Time
	uniqueIPs     map[string]struct{}
	protocols     map[string]int
	ipBytes       map[string]int64 // srcIP -> total bytes sent

	// TCP state
	tcpState *TCPState

	// Security state
	secState *SecurityState

	// DNS state
	dnsState *DNSState

	// HTTP state
	httpState *HTTPState

	// Connection flow state
	connState *ConnectionState
}

// newPacketSource opens a pcap or pcapng file using the pure-Go pcapgo reader
// (no libpcap / CGO required).
func newPacketSource(r io.Reader, filePath string) (*gopacket.PacketSource, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".pcapng" {
		ng, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pcapng file: %w", err)
		}
		src := gopacket.NewPacketSource(ng, ng.LinkType())
		return src, nil
	}
	// .pcap or .cap
	pcapReader, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pcap file: %w", err)
	}
	src := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
	return src, nil
}

// Analyze opens a PCAP file and runs all analysis modules
func Analyze(filePath string) (*models.AnalysisResult, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer f.Close()

	packetSource, err := newPacketSource(f, filePath)
	if err != nil {
		return nil, err
	}

	state := &analysisState{
		uniqueIPs: make(map[string]struct{}),
		protocols: make(map[string]int),
		ipBytes:   make(map[string]int64),
		tcpState:  newTCPState(),
		secState:  newSecurityState(),
		dnsState:  newDNSState(),
		httpState: newHTTPState(),
		connState: newConnectionState(),
	}

	packetSource.NoCopy = true

	for packet := range packetSource.Packets() {
		state.totalPackets++
		captureLen := int64(len(packet.Data()))
		state.totalBytes += captureLen

		ts := packet.Metadata().Timestamp
		if state.firstTime == nil {
			t := ts
			state.firstTime = &t
		}
		t := ts
		state.lastTime = &t

		// Track protocol
		trackProtocols(packet, state)

		// Run analyzers
		analyzeTCP(packet, state)
		analyzeSecurity(packet, state)
		analyzeDNS(packet, state)
		analyzeHTTP(packet, state)
		analyzeConnections(packet, state)
	}

	findings := collectFindings(state)

	// Assign sequential IDs
	for i := range findings {
		findings[i].ID = i + 1
	}

	// Sort findings by severity: critical first, then warning, then info
	sort.SliceStable(findings, func(i, j int) bool {
		return severityOrder(findings[i].Severity) < severityOrder(findings[j].Severity)
	})

	summary := buildSummary(state, findings)

	connections := finalizeConnections(state.connState)

	return &models.AnalysisResult{
		Summary:     summary,
		Findings:    findings,
		Connections: connections,
	}, nil
}

func trackProtocols(packet gopacket.Packet, state *analysisState) {
	// Network layer
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		switch netLayer.LayerType() {
		case layers.LayerTypeIPv4:
			ip4, _ := netLayer.(*layers.IPv4)
			state.protocols["IPv4"]++
			srcIP := ip4.SrcIP.String()
			dstIP := ip4.DstIP.String()
			state.uniqueIPs[srcIP] = struct{}{}
			state.uniqueIPs[dstIP] = struct{}{}
			state.ipBytes[srcIP] += int64(ip4.Length)
		case layers.LayerTypeIPv6:
			ip6, _ := netLayer.(*layers.IPv6)
			state.protocols["IPv6"]++
			srcIP := ip6.SrcIP.String()
			dstIP := ip6.DstIP.String()
			state.uniqueIPs[srcIP] = struct{}{}
			state.uniqueIPs[dstIP] = struct{}{}
			state.ipBytes[srcIP] += int64(ip6.Length)
		}
	}

	// Transport layer
	if transLayer := packet.TransportLayer(); transLayer != nil {
		switch transLayer.LayerType() {
		case layers.LayerTypeTCP:
			state.protocols["TCP"]++
		case layers.LayerTypeUDP:
			state.protocols["UDP"]++
		}
	}

	// Application layer hints
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) >= 4 {
			p := string(payload[:4])
			switch {
			case p == "HTTP" || p[:3] == "GET" || p[:4] == "POST":
				state.protocols["HTTP"]++
			case p == "\x16\x03\x01" || p == "\x16\x03\x03":
				state.protocols["TLS"]++
			}
		}
	}

	// ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		state.protocols["ARP"]++
	}

	// ICMP
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		state.protocols["ICMP"]++
	}
}

func collectFindings(state *analysisState) []models.Finding {
	var findings []models.Finding
	findings = append(findings, finalizeTCP(state.tcpState)...)
	findings = append(findings, finalizeSecurity(state.secState)...)
	findings = append(findings, finalizeDNS(state.dnsState)...)
	findings = append(findings, finalizeHTTP(state.httpState)...)
	return findings
}

func buildSummary(state *analysisState, findings []models.Finding) models.Summary {
	var critical, warning, info int
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "warning":
			warning++
		case "info":
			info++
		}
	}

	var durationSec float64
	if state.firstTime != nil && state.lastTime != nil {
		durationSec = state.lastTime.Sub(*state.firstTime).Seconds()
	}

	// Top talkers (top 5 by bytes)
	type ipBytes struct {
		ip    string
		bytes int64
	}
	var talkers []ipBytes
	for ip, b := range state.ipBytes {
		talkers = append(talkers, ipBytes{ip, b})
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].bytes > talkers[j].bytes
	})
	topN := 5
	if len(talkers) < topN {
		topN = len(talkers)
	}
	topTalkers := make([]models.TopTalker, topN)
	for i := 0; i < topN; i++ {
		topTalkers[i] = models.TopTalker{IP: talkers[i].ip, Bytes: talkers[i].bytes}
	}

	return models.Summary{
		TotalPackets:  state.totalPackets,
		TotalBytes:    state.totalBytes,
		DurationSec:   durationSec,
		StartTime:     state.firstTime,
		EndTime:       state.lastTime,
		UniqueIPs:     len(state.uniqueIPs),
		Protocols:     state.protocols,
		CriticalCount: critical,
		WarningCount:  warning,
		InfoCount:     info,
		TopTalkers:    topTalkers,
	}
}

func severityOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}
