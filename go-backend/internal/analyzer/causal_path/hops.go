package causal_path

import (
	"fmt"
	"net"
)

const slowBackendThresholdMs = 500.0

// classifyIPRole determines the network role of an IP address using topology hints.
// Priority: firewall > load_balancer > backend (exact) > backend (subnet) > unknown
func classifyIPRole(ip string, roles *TopologyRoles) string {
	if roles == nil {
		return "unknown"
	}
	for _, fwIP := range roles.FirewallIPs {
		if ip == fwIP {
			return "firewall"
		}
	}
	for _, lbIP := range roles.LoadBalancerVIPs {
		if ip == lbIP {
			return "load_balancer"
		}
	}
	for _, beIP := range roles.BackendIPs {
		if ip == beIP {
			return "backend"
		}
	}
	for _, subnet := range roles.BackendSubnets {
		if ipInSubnet(ip, subnet) {
			return "backend"
		}
	}
	return "unknown"
}

// ipInSubnet checks if an IP falls within a CIDR subnet.
func ipInSubnet(ip, cidr string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(parsedIP)
}

// buildHopSequence constructs an ordered sequence of network hops from packet data.
func buildHopSequence(
	packets []NormalizedPacket,
	srcIP, dstIP string,
	dstPort *int,
	roles *TopologyRoles,
) []HopStep {
	var steps []HopStep

	// Find SYN
	var syn *NormalizedPacket
	for i := range packets {
		p := &packets[i]
		if p.SrcIP == srcIP && p.DstIP == dstIP && p.IsSYN() {
			if dstPort != nil && p.DstPort != *dstPort {
				continue
			}
			syn = p
			break
		}
	}

	// Step: client_initiated
	if syn != nil {
		steps = append(steps, HopStep{
			Step:       "client_initiated",
			Src:        srcIP,
			Dst:        dstIP,
			SourceRole: classifyIPRole(srcIP, roles),
			DestRole:   classifyIPRole(dstIP, roles),
			Timestamp:  syn.Time,
		})
	}

	// Find SYN-ACK
	var synack *NormalizedPacket
	if syn != nil {
		for i := range packets {
			p := &packets[i]
			if p.SrcIP == dstIP && p.DstIP == srcIP && p.IsSYNACK() && p.Time >= syn.Time {
				if dstPort != nil && p.SrcPort != *dstPort {
					continue
				}
				synack = p
				break
			}
		}
	}

	if synack != nil {
		steps = append(steps, HopStep{
			Step:       "connection_established",
			Src:        dstIP,
			Dst:        srcIP,
			SourceRole: classifyIPRole(dstIP, roles),
			DestRole:   classifyIPRole(srcIP, roles),
			Timestamp:  synack.Time,
		})
	} else if syn != nil {
		steps = append(steps, HopStep{
			Step:       "connection_failed",
			Src:        srcIP,
			Dst:        dstIP,
			SourceRole: classifyIPRole(srcIP, roles),
			DestRole:   classifyIPRole(dstIP, roles),
			Timestamp:  syn.Time,
			Note:       "No SYN-ACK received",
		})
	}

	// Check for RST from intermediate IPs (firewall)
	for i := range packets {
		p := &packets[i]
		if p.IsRST() {
			if p.SrcIP != srcIP && p.SrcIP != dstIP {
				// RST from intermediate hop
				note := fmt.Sprintf("RST from intermediate IP %s", p.SrcIP)
				fwRole := classifyIPRole(p.SrcIP, roles)
				if fwRole == "firewall" {
					steps = append(steps, HopStep{
						Step:       "firewall_reset_observed",
						Src:        p.SrcIP,
						Dst:        p.DstIP,
						SourceRole: fwRole,
						DestRole:   classifyIPRole(p.DstIP, roles),
						Timestamp:  p.Time,
						Note:       note,
					})
				}
			}
		}
	}

	// Check for firewall pass-through (SYN-ACK after traversing firewall)
	if synack != nil && roles != nil {
		for _, fwIP := range roles.FirewallIPs {
			// If we see packets going through a firewall IP
			for i := range packets {
				p := &packets[i]
				if (p.SrcIP == fwIP || p.DstIP == fwIP) && p.Time < synack.Time {
					steps = append(steps, HopStep{
						Step:       "firewall_pass_observed",
						Src:        p.SrcIP,
						Dst:        p.DstIP,
						SourceRole: classifyIPRole(p.SrcIP, roles),
						DestRole:   classifyIPRole(p.DstIP, roles),
						Timestamp:  p.Time,
					})
					break // one per firewall IP
				}
			}
		}
	}

	// Check for LB frontend connection
	if roles != nil {
		for _, lbIP := range roles.LoadBalancerVIPs {
			if dstIP == lbIP && synack != nil {
				steps = append(steps, HopStep{
					Step:       "lb_frontend_connection_observed",
					Src:        srcIP,
					Dst:        lbIP,
					SourceRole: "client",
					DestRole:   "load_balancer",
					Timestamp:  synack.Time,
				})
			}
		}
	}

	// Check for backend response delay
	if synack != nil {
		frt := computeFirstResponseTimeMs(packets, srcIP, dstIP, dstPort)
		if frt != nil && *frt > slowBackendThresholdMs {
			threshold := slowBackendThresholdMs
			steps = append(steps, HopStep{
				Step:        "backend_response_slow",
				Src:         dstIP,
				Dst:         srcIP,
				SourceRole:  classifyIPRole(dstIP, roles),
				DestRole:    classifyIPRole(srcIP, roles),
				Timestamp:   synack.Time,
				DelayMs:     frt,
				ThresholdMs: &threshold,
				Note:        fmt.Sprintf("Response delay %.1fms exceeds %.0fms threshold", *frt, threshold),
			})
		}
	}

	return steps
}

// parseRoles converts a generic map to TopologyRoles.
func parseRoles(roles map[string]interface{}) *TopologyRoles {
	if roles == nil {
		return &TopologyRoles{}
	}
	tr := &TopologyRoles{}
	tr.FirewallIPs = toStringSlice(roles["firewall_ips"])
	tr.LoadBalancerVIPs = toStringSlice(roles["load_balancer_vips"])
	tr.BackendIPs = toStringSlice(roles["backend_ips"])
	tr.BackendSubnets = toStringSlice(roles["backend_subnets"])
	return tr
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// inferProtocol determines the dominant protocol from packets.
// Ties are broken by first appearance in the capture so the result is
// deterministic (Go map iteration order is randomized).
func inferProtocol(packets []NormalizedPacket, port *int) string {
	counts := make(map[int]int)
	var order []int
	for _, p := range packets {
		if _, seen := counts[p.IPProto]; !seen {
			order = append(order, p.IPProto)
		}
		counts[p.IPProto]++
	}
	if len(counts) == 0 {
		return "unknown"
	}
	maxProto := 0
	maxCount := 0
	for _, proto := range order {
		if counts[proto] > maxCount {
			maxProto = proto
			maxCount = counts[proto]
		}
	}
	switch maxProto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("proto/%d", maxProto)
	}
}
