package analyzer

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"pcap-analyzer/models"
)

type PortScanState struct {
	Ports     map[uint16]struct{}
	FirstSeen time.Time
	LastSeen  time.Time
	SYNCount  int
}

type SecurityState struct {
	// Port scan: srcIP -> dstIP -> ports targeted
	portScans map[string]map[string]*PortScanState

	// ARP spoofing: IP -> set of MACs claiming that IP
	arpTable map[string]map[string]struct{}

	// ICMP flood: srcIP -> count
	icmpCount map[string]int
	icmpFirst map[string]time.Time
	icmpLast  map[string]time.Time

	// Large data transfers: srcIP -> total bytes
	largeTransfer map[string]int64

	// UDP flood: srcIP -> count
	udpCount  map[string]int
	udpFirst  map[string]time.Time
	udpLast   map[string]time.Time

	// Null/Xmas TCP scans (unusual TCP flag combinations)
	nullScanSrc map[string]int
	xmasScanSrc map[string]int
}

func newSecurityState() *SecurityState {
	return &SecurityState{
		portScans:     make(map[string]map[string]*PortScanState),
		arpTable:      make(map[string]map[string]struct{}),
		icmpCount:     make(map[string]int),
		icmpFirst:     make(map[string]time.Time),
		icmpLast:      make(map[string]time.Time),
		largeTransfer: make(map[string]int64),
		udpCount:      make(map[string]int),
		udpFirst:      make(map[string]time.Time),
		udpLast:       make(map[string]time.Time),
		nullScanSrc:   make(map[string]int),
		xmasScanSrc:   make(map[string]int),
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"fc00::/7",
		"::1/128",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func analyzeSecurity(packet gopacket.Packet, state *analysisState) {
	s := state.secState
	ts := packet.Metadata().Timestamp

	// ARP spoofing detection
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPReply {
			senderIP := net.IP(arp.SourceProtAddress).String()
			senderMAC := net.HardwareAddr(arp.SourceHwAddress).String()
			if s.arpTable[senderIP] == nil {
				s.arpTable[senderIP] = make(map[string]struct{})
			}
			s.arpTable[senderIP][senderMAC] = struct{}{}
		}
	}

	// ICMP flood
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				srcIP := netLayer.NetworkFlow().Src().String()
				s.icmpCount[srcIP]++
				if _, ok := s.icmpFirst[srcIP]; !ok {
					s.icmpFirst[srcIP] = ts
				}
				s.icmpLast[srcIP] = ts
			}
		}
	}

	// TCP port scan & null/xmas scan detection
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			return
		}
		srcIP := netLayer.NetworkFlow().Src().String()
		dstIP := netLayer.NetworkFlow().Dst().String()

		// Track large data transfers for non-private IPs
		if !isPrivateIP(dstIP) {
			s.largeTransfer[srcIP] += int64(len(tcp.Payload))
		}

		// Null scan: all flags are 0
		if !tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG {
			s.nullScanSrc[srcIP]++
		}

		// Xmas scan: FIN + PSH + URG set
		if tcp.FIN && tcp.PSH && tcp.URG {
			s.xmasScanSrc[srcIP]++
		}

		// Port scan: SYN only packets to multiple ports
		if tcp.SYN && !tcp.ACK {
			dstPort := uint16(tcp.DstPort)
			if s.portScans[srcIP] == nil {
				s.portScans[srcIP] = make(map[string]*PortScanState)
			}
			if s.portScans[srcIP][dstIP] == nil {
				s.portScans[srcIP][dstIP] = &PortScanState{
					Ports:     make(map[uint16]struct{}),
					FirstSeen: ts,
				}
			}
			ps := s.portScans[srcIP][dstIP]
			ps.Ports[dstPort] = struct{}{}
			ps.SYNCount++
			ps.LastSeen = ts
		}
	}

	// UDP flood detection
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			srcIP := netLayer.NetworkFlow().Src().String()
			s.udpCount[srcIP]++
			if _, ok := s.udpFirst[srcIP]; !ok {
				s.udpFirst[srcIP] = ts
			}
			s.udpLast[srcIP] = ts
		}
	}
}

func finalizeSecurity(s *SecurityState) []models.Finding {
	var findings []models.Finding

	// 1. ARP spoofing
	for ip, macs := range s.arpTable {
		if len(macs) > 1 {
			macList := make([]string, 0, len(macs))
			for m := range macs {
				macList = append(macList, m)
			}
			findings = append(findings, models.Finding{
				Severity:    "critical",
				Category:    "security",
				Title:       "ARP Spoofing Detected",
				Description: fmt.Sprintf("IP address %s is claimed by %d different MAC addresses: %v. This is a strong indicator of ARP spoofing / Man-in-the-Middle attack.", ip, len(macs), macList),
				Details: map[string]interface{}{
					"ip":   ip,
					"macs": macList,
				},
				DstIP: ip,
			})
		}
	}

	// 2. Port scan detection (>15 distinct ports targeted by same src→dst pair)
	for srcIP, dstMap := range s.portScans {
		for dstIP, ps := range dstMap {
			portCount := len(ps.Ports)
			if portCount >= 15 {
				severity := "warning"
				if portCount >= 50 {
					severity = "critical"
				}
				// Get sample ports
				samplePorts := make([]int, 0, 10)
				for p := range ps.Ports {
					samplePorts = append(samplePorts, int(p))
					if len(samplePorts) >= 10 {
						break
					}
				}
				sort.Ints(samplePorts)

				first := ps.FirstSeen
				last := ps.LastSeen
				findings = append(findings, models.Finding{
					Severity:    severity,
					Category:    "security",
					Title:       "Port Scan Detected",
					Description: fmt.Sprintf("Source IP %s targeted %d different ports on %s, indicating a port scanning activity.", srcIP, portCount, dstIP),
					Details: map[string]interface{}{
						"ports_scanned": portCount,
						"sample_ports":  samplePorts,
						"syn_count":     ps.SYNCount,
					},
					SrcIP:       srcIP,
					DstIP:       dstIP,
					PacketCount: ps.SYNCount,
					FirstSeen:   &first,
					LastSeen:    &last,
				})
			}
		}
	}

	// 3. ICMP flood
	for srcIP, count := range s.icmpCount {
		if count >= 100 {
			severity := "warning"
			if count >= 500 {
				severity = "critical"
			}
			first := s.icmpFirst[srcIP]
			last := s.icmpLast[srcIP]
			durationSec := last.Sub(first).Seconds()
			pps := 0.0
			if durationSec > 0 {
				pps = float64(count) / durationSec
			}
			findings = append(findings, models.Finding{
				Severity:    severity,
				Category:    "security",
				Title:       "ICMP Flood Detected",
				Description: fmt.Sprintf("Source IP %s sent %d ICMP Echo Requests (%.1f packets/sec). This may be a ping flood DoS attack.", srcIP, count, pps),
				Details: map[string]interface{}{
					"icmp_count":       count,
					"packets_per_sec":  fmt.Sprintf("%.1f", pps),
					"duration_seconds": fmt.Sprintf("%.1f", durationSec),
				},
				SrcIP:       srcIP,
				PacketCount: count,
				FirstSeen:   &first,
				LastSeen:    &last,
			})
		}
	}

	// 4. Large data exfiltration (>50MB sent to external IPs)
	const exfilThreshold = 50 * 1024 * 1024 // 50MB
	for srcIP, bytes := range s.largeTransfer {
		if bytes >= exfilThreshold {
			severity := "warning"
			if bytes >= 200*1024*1024 {
				severity = "critical"
			}
			findings = append(findings, models.Finding{
				Severity:    severity,
				Category:    "security",
				Title:       "Large Data Transfer to External IP",
				Description: fmt.Sprintf("Source IP %s transferred %.1f MB to external destinations. This may indicate data exfiltration.", srcIP, float64(bytes)/1024/1024),
				Details: map[string]interface{}{
					"bytes_transferred": bytes,
					"mb_transferred":    fmt.Sprintf("%.1f", float64(bytes)/1024/1024),
				},
				SrcIP: srcIP,
			})
		}
	}

	// 5. Null scan
	for srcIP, count := range s.nullScanSrc {
		if count >= 5 {
			findings = append(findings, models.Finding{
				Severity:    "critical",
				Category:    "security",
				Title:       "TCP Null Scan Detected",
				Description: fmt.Sprintf("Source IP %s sent %d TCP packets with no flags set (Null Scan). This is a stealthy port scanning technique used to bypass certain firewalls.", srcIP, count),
				Details: map[string]interface{}{
					"packet_count": count,
				},
				SrcIP:       srcIP,
				PacketCount: count,
			})
		}
	}

	// 6. Xmas scan
	for srcIP, count := range s.xmasScanSrc {
		if count >= 5 {
			findings = append(findings, models.Finding{
				Severity:    "critical",
				Category:    "security",
				Title:       "TCP Xmas Scan Detected",
				Description: fmt.Sprintf("Source IP %s sent %d TCP packets with FIN+PSH+URG flags (Xmas Scan). This is a stealthy port scanning technique.", srcIP, count),
				Details: map[string]interface{}{
					"packet_count": count,
				},
				SrcIP:       srcIP,
				PacketCount: count,
			})
		}
	}

	// 7. UDP flood
	for srcIP, count := range s.udpCount {
		if count >= 500 {
			severity := "warning"
			if count >= 2000 {
				severity = "critical"
			}
			first := s.udpFirst[srcIP]
			last := s.udpLast[srcIP]
			durationSec := last.Sub(first).Seconds()
			pps := 0.0
			if durationSec > 0 {
				pps = float64(count) / durationSec
			}
			findings = append(findings, models.Finding{
				Severity:    severity,
				Category:    "security",
				Title:       "UDP Flood Detected",
				Description: fmt.Sprintf("Source IP %s sent %d UDP packets (%.1f packets/sec). This may indicate a UDP flood attack.", srcIP, count, pps),
				Details: map[string]interface{}{
					"udp_count":       count,
					"packets_per_sec": fmt.Sprintf("%.1f", pps),
				},
				SrcIP:       srcIP,
				PacketCount: count,
				FirstSeen:   &first,
				LastSeen:    &last,
			})
		}
	}

	return findings
}
