package parser

import "time"

// ParsedPacket holds metadata extracted from a raw packet.
type ParsedPacket struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string // "TCP" / "UDP" / "ICMP"
	PayloadSize int
	TCPFlags    TCPFlags
	DNSInfo     *DNSInfo
	TLSInfo     *TLSInfo
	HTTPInfo    *HTTPInfo
}

// TCPFlags represents the key TCP control flags.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
}

// DNSInfo holds parsed DNS query/response data.
type DNSInfo struct {
	QueryID   uint16
	IsQuery   bool
	Domain    string
	QueryType string // "A", "AAAA", "MX", etc.
	RCode     string // "NOERROR", "NXDOMAIN", etc.
	Answers   []string
}

// TLSInfo holds parsed TLS ClientHello data.
type TLSInfo struct {
	IsClientHello bool
	SNI           string
	Version       string // "TLS 1.0", "TLS 1.2", "TLS 1.3"
}

// HTTPInfo holds parsed HTTP request/response data.
type HTTPInfo struct {
	Method     string
	Host       string
	Path       string
	StatusCode int
	UserAgent  string
}
