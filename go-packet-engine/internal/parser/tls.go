package parser

import "encoding/binary"

// ParseTLSClientHello parses a TLS record to extract ClientHello SNI and version.
// Returns nil if the payload is not a TLS ClientHello.
func ParseTLSClientHello(payload []byte) *TLSInfo {
	// Minimum TLS record: 5 bytes header + 4 bytes handshake header + content
	if len(payload) < 11 {
		return nil
	}

	// TLS record header
	contentType := payload[0]
	if contentType != 0x16 { // Handshake
		return nil
	}

	recordVersion := binary.BigEndian.Uint16(payload[1:3])
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return nil
	}

	handshake := payload[5 : 5+recordLen]
	if len(handshake) < 4 {
		return nil
	}

	// Handshake header
	hsType := handshake[0]
	if hsType != 0x01 { // ClientHello
		return nil
	}

	info := &TLSInfo{IsClientHello: true}

	// Detect version from record layer as fallback
	info.Version = tlsVersionString(recordVersion)

	// Parse ClientHello body to find extensions
	// Skip: handshake header (4) + client version (2) + random (32) = 38
	if len(handshake) < 38 {
		return info
	}
	pos := 38

	// Session ID
	if pos >= len(handshake) {
		return info
	}
	sessIDLen := int(handshake[pos])
	pos += 1 + sessIDLen

	// Cipher suites
	if pos+2 > len(handshake) {
		return info
	}
	csLen := int(binary.BigEndian.Uint16(handshake[pos:]))
	pos += 2 + csLen

	// Compression methods
	if pos >= len(handshake) {
		return info
	}
	compLen := int(handshake[pos])
	pos += 1 + compLen

	// Extensions
	if pos+2 > len(handshake) {
		return info
	}
	extLen := int(binary.BigEndian.Uint16(handshake[pos:]))
	pos += 2

	end := pos + extLen
	if end > len(handshake) {
		end = len(handshake)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(handshake[pos:])
		extDataLen := int(binary.BigEndian.Uint16(handshake[pos+2:]))
		pos += 4

		if pos+extDataLen > end {
			break
		}
		extData := handshake[pos : pos+extDataLen]

		switch extType {
		case 0x0000: // server_name
			info.SNI = parseSNI(extData)
		case 0x002b: // supported_versions
			if v := parseSupportedVersions(extData); v != "" {
				info.Version = v
			}
		}

		pos += extDataLen
	}

	return info
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// server_name_list length (2 bytes)
	// server_name_type (1 byte, must be 0x00 = hostname)
	// host_name length (2 bytes)
	nameType := data[2]
	if nameType != 0x00 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseSupportedVersions(data []byte) string {
	if len(data) < 1 {
		return ""
	}
	listLen := int(data[0])
	if listLen < 2 || 1+listLen > len(data) {
		return ""
	}
	// Pick the highest (first) version
	ver := binary.BigEndian.Uint16(data[1:3])
	return tlsVersionString(ver)
}

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	case 0x0300:
		return "SSL 3.0"
	default:
		return "unknown"
	}
}
