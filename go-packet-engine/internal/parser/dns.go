package parser

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseDNS extracts DNS query/response info from a packet.
func ParseDNS(pkt gopacket.Packet) *ParsedPacket {
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}
	dns, _ := dnsLayer.(*layers.DNS)

	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return nil
	}

	var srcIP, dstIP string
	switch nl := netLayer.(type) {
	case *layers.IPv4:
		srcIP = nl.SrcIP.String()
		dstIP = nl.DstIP.String()
	case *layers.IPv6:
		srcIP = nl.SrcIP.String()
		dstIP = nl.DstIP.String()
	default:
		return nil
	}

	var srcPort, dstPort uint16
	var proto string

	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		proto = "UDP"
	} else if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "TCP"
	}

	info := &DNSInfo{
		QueryID: dns.ID,
		IsQuery: !dns.QR,
		RCode:   dns.ResponseCode.String(),
	}

	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		info.Domain = string(q.Name)
		info.QueryType = dnsQueryTypeString(q.Type)
	}

	for _, a := range dns.Answers {
		info.Answers = append(info.Answers, dnsAnswerString(a))
	}

	return &ParsedPacket{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  proto,
		DNSInfo:   info,
	}
}

func dnsQueryTypeString(t layers.DNSType) string {
	switch t {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func dnsAnswerString(a layers.DNSResourceRecord) string {
	switch a.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		if a.IP != nil {
			return a.IP.String()
		}
	case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
		return string(a.CNAME)
	case layers.DNSTypeMX:
		return string(a.MX.Name)
	case layers.DNSTypeTXT:
		var parts []string
		for _, txt := range a.TXTs {
			parts = append(parts, string(txt))
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprintf("%v", a.Data)
}
