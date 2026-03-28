"""TLS/SSL handshake analysis — SNI, versions, cipher suites, certificate issues."""
from collections import defaultdict
from typing import List, Dict, Any

# TLS version names
TLS_VERSIONS = {
    "0x0300": "SSLv3", "0x0301": "TLSv1.0", "0x0302": "TLSv1.1",
    "0x0303": "TLSv1.2", "0x0304": "TLSv1.3",
    "769": "TLSv1.0", "770": "TLSv1.1", "771": "TLSv1.2", "772": "TLSv1.3",
}

# Handshake types
HANDSHAKE_TYPES = {
    "1": "ClientHello", "2": "ServerHello", "11": "Certificate",
    "12": "ServerKeyExchange", "13": "CertificateRequest",
    "14": "ServerHelloDone", "15": "CertificateVerify",
    "16": "ClientKeyExchange", "20": "Finished",
}

# Weak/deprecated cipher suites (partial list of known weak ones)
WEAK_CIPHERS = {
    "0x0005", "0x0004", "0x0003", "0x0002", "0x0001",   # RC4
    "0x002f", "0x0035",                                   # AES-CBC w/ RSA (no PFS)
    "0x000a", "0x0009", "0x0008", "0x0007",              # DES/3DES
    "0xff80", "0xff81", "0xff82", "0xff83",               # GOST
    "0x0000",                                             # NULL
    "0x0006", "0x000b", "0x000c", "0x000d",              # Export/NULL suites
}

DEPRECATED_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1"}


def analyze(packets: List[Dict]) -> Dict[str, Any]:
    sni_counts: Dict[str, int] = defaultdict(int)
    version_counts: Dict[str, int] = defaultdict(int)
    cipher_counts: Dict[str, int] = defaultdict(int)
    handshake_counts: Dict[str, int] = defaultdict(int)

    # Per-stream TLS state
    streams: Dict[str, Dict] = {}
    issues = []
    timeline_events = []

    weak_cipher_uses = []
    deprecated_version_uses = []

    for pkt in packets:
        if "tls.handshake.type" not in pkt and "tls.record.version" not in pkt:
            continue

        ts_str = pkt.get("frame.time_epoch", "0")
        try:
            ts = float(ts_str)
        except ValueError:
            ts = 0.0

        src_ip = pkt.get("ip.src", pkt.get("ipv6.src", ""))
        dst_ip = pkt.get("ip.dst", pkt.get("ipv6.dst", ""))
        stream = pkt.get("tcp.stream", "")

        hs_type_raw = pkt.get("tls.handshake.type", "")
        sni = pkt.get("tls.handshake.extensions_server_name", "")
        version_raw = pkt.get("tls.handshake.version", pkt.get("tls.record.version", ""))
        cipher_raw = pkt.get("tls.handshake.ciphersuite", "")

        version = TLS_VERSIONS.get(version_raw, version_raw)
        hs_type = HANDSHAKE_TYPES.get(hs_type_raw, hs_type_raw)

        if hs_type:
            handshake_counts[hs_type] += 1

        if sni:
            sni_counts[sni] += 1

        if version and version not in ("", version_raw if not version_raw.startswith("TLS") else ""):
            version_counts[version] += 1

        if cipher_raw:
            cipher_counts[cipher_raw] += 1

        # Init stream state
        if stream and stream not in streams:
            streams[stream] = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "sni": "", "version": "", "cipher": "",
                "has_client_hello": False, "has_server_hello": False,
                "ts": ts,
            }

        if stream:
            st = streams[stream]
            if sni:
                st["sni"] = sni
            if version:
                st["version"] = version
            if cipher_raw:
                st["cipher"] = cipher_raw
            if hs_type == "ClientHello":
                st["has_client_hello"] = True
            if hs_type == "ServerHello":
                st["has_server_hello"] = True

        # Track deprecated versions
        if version in DEPRECATED_VERSIONS:
            deprecated_version_uses.append({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "version": version, "sni": sni, "ts": ts,
            })
            version_counts[version] = version_counts.get(version, 0) + 1

        # Track weak ciphers
        if cipher_raw and cipher_raw.lower() in WEAK_CIPHERS:
            weak_cipher_uses.append({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "cipher": cipher_raw, "sni": sni, "ts": ts,
            })

        # Timeline
        if hs_type == "ClientHello":
            timeline_events.append({
                "ts": ts, "type": "tls_client_hello",
                "label": f"TLS ClientHello → {sni or dst_ip}",
                "detail": f"{src_ip} → {dst_ip}: TLS ClientHello SNI={sni or 'N/A'}",
                "severity": "info",
            })
        elif hs_type == "ServerHello":
            timeline_events.append({
                "ts": ts, "type": "tls_server_hello",
                "label": f"TLS ServerHello ({version})",
                "detail": f"{src_ip} → {dst_ip}: TLS ServerHello version={version}",
                "severity": "warning" if version in DEPRECATED_VERSIONS else "info",
            })

    # Build issues
    deprecated_count = sum(v for k, v in version_counts.items() if k in DEPRECATED_VERSIONS)
    if deprecated_count >= 5:
        deprecated_list = [k for k in version_counts if k in DEPRECATED_VERSIONS]
        issues.append({
            "severity": "critical", "category": "tls",
            "title": f"Deprecated TLS Versions in Use ({deprecated_count} connections)",
            "description": (
                f"{deprecated_count} TLS connections used deprecated protocol versions: "
                f"{', '.join(deprecated_list)}. "
                "SSLv3, TLSv1.0, and TLSv1.1 are vulnerable to known attacks (POODLE, BEAST) "
                "and have been deprecated by RFC 8996. Upgrade to TLSv1.2 minimum, prefer TLSv1.3."
            ),
            "count": deprecated_count,
            "deprecated_versions": deprecated_list,
        })

    if weak_cipher_uses:
        unique_ciphers = list({w["cipher"] for w in weak_cipher_uses})
        issues.append({
            "severity": "warning", "category": "tls",
            "title": f"Weak Cipher Suites Negotiated ({len(weak_cipher_uses)} connections)",
            "description": (
                f"{len(weak_cipher_uses)} TLS connections used weak or deprecated cipher suites "
                f"including: {', '.join(unique_ciphers[:3])}. "
                "Weak ciphers may be vulnerable to decryption attacks. "
                "Use AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with PFS (ECDHE key exchange)."
            ),
            "count": len(weak_cipher_uses),
        })

    # Check for unencrypted streams on port 443 (missing TLS)
    cleartext_on_443 = sum(
        1 for pkt in packets
        if (pkt.get("tcp.dstport") == "443" or pkt.get("tcp.srcport") == "443")
        and "tls.handshake.type" not in pkt
        and "http.request.method" in pkt
    )
    if cleartext_on_443 > 0:
        issues.append({
            "severity": "critical", "category": "tls",
            "title": "Cleartext HTTP Detected on Port 443",
            "description": (
                f"{cleartext_on_443} plaintext HTTP packets detected on TCP port 443. "
                "This may indicate a TLS stripping attack (SSLstrip) or misconfigured service "
                "that should be using HTTPS."
            ),
            "count": cleartext_on_443,
        })

    # Summarize streams
    stream_list = [
        {
            "stream": k,
            "src_ip": v["src_ip"],
            "dst_ip": v["dst_ip"],
            "sni": v["sni"],
            "version": v["version"],
            "cipher": v["cipher"],
        }
        for k, v in streams.items()
        if v["has_client_hello"] or v["has_server_hello"]
    ]

    top_sni = sorted(sni_counts.items(), key=lambda x: -x[1])[:30]

    return {
        "total_tls_streams": len(stream_list),
        "unique_sni": len(sni_counts),
        "version_counts": dict(version_counts),
        "handshake_counts": dict(handshake_counts),
        "top_sni": [{"sni": s, "count": c} for s, c in top_sni],
        "deprecated_version_count": deprecated_count,
        "weak_cipher_count": len(weak_cipher_uses),
        "streams": stream_list[:200],
        "issues": issues,
        "timeline_events": timeline_events[:300],
    }
