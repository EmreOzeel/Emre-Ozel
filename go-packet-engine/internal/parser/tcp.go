package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseTCP extracts metadata from a TCP packet including flags, and
// optionally detects TLS ClientHello or HTTP in the payload.
func ParseTCP(pkt gopacket.Packet) *ParsedPacket {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return nil
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, _ := tcpLayer.(*layers.TCP)

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

	p := &ParsedPacket{
		Timestamp:   pkt.Metadata().Timestamp,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     uint16(tcp.SrcPort),
		DstPort:     uint16(tcp.DstPort),
		Protocol:    "TCP",
		PayloadSize: len(tcp.Payload),
		TCPFlags: TCPFlags{
			SYN: tcp.SYN,
			ACK: tcp.ACK,
			FIN: tcp.FIN,
			RST: tcp.RST,
			PSH: tcp.PSH,
		},
	}

	payload := tcp.Payload
	if len(payload) == 0 {
		return p
	}

	// Detect TLS record (content type 0x16 = Handshake)
	if len(payload) >= 5 && payload[0] == 0x16 {
		if info := ParseTLSClientHello(payload); info != nil {
			p.TLSInfo = info
		}
	}

	// Detect HTTP request/response
	if info := ParseHTTP(payload); info != nil {
		p.HTTPInfo = info
	}

	return p
}
