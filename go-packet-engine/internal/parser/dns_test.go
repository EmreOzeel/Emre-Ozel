package parser

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildDNSPacket(isQuery bool, domain string, answers []string) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{8, 8, 8, 8},
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		IHL:      5,
	}
	udp := &layers.UDP{
		SrcPort: 54321,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	dns := &layers.DNS{
		ID: 0x1234,
		QR: !isQuery,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
	if !isQuery {
		dns.ResponseCode = layers.DNSResponseCodeNoErr
		for _, a := range answers {
			dns.Answers = append(dns.Answers, layers.DNSResourceRecord{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    []byte{1, 2, 3, 4}, // simplified
			})
			_ = a
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		panic(err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestParseDNSQuery(t *testing.T) {
	pkt := buildDNSPacket(true, "example.com", nil)
	parsed := ParseDNS(pkt)

	if parsed == nil {
		t.Fatal("expected parsed packet, got nil")
	}
	if parsed.DNSInfo == nil {
		t.Fatal("expected DNSInfo, got nil")
	}
	if !parsed.DNSInfo.IsQuery {
		t.Error("expected IsQuery=true")
	}
	if parsed.DNSInfo.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", parsed.DNSInfo.Domain)
	}
	if parsed.DNSInfo.QueryType != "A" {
		t.Errorf("expected query type 'A', got %q", parsed.DNSInfo.QueryType)
	}
	if parsed.SrcIP != "10.0.0.1" {
		t.Errorf("expected src IP 10.0.0.1, got %s", parsed.SrcIP)
	}
}

func TestParseDNSResponse(t *testing.T) {
	pkt := buildDNSPacket(false, "example.com", []string{"1.2.3.4"})
	parsed := ParseDNS(pkt)

	if parsed == nil {
		t.Fatal("expected parsed packet, got nil")
	}
	if parsed.DNSInfo == nil {
		t.Fatal("expected DNSInfo, got nil")
	}
	if parsed.DNSInfo.IsQuery {
		t.Error("expected IsQuery=false for response")
	}
	if len(parsed.DNSInfo.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(parsed.DNSInfo.Answers))
	}
}
