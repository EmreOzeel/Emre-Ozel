"""
Low-level tshark CLI wrapper.
Returns raw dicts from capinfos / tshark -z / tshark -T fields.
Nothing above this layer touches subprocess output.
"""
import dataclasses
import logging
import subprocess
import re
import io
from typing import List, Dict, Any, Optional

log = logging.getLogger(__name__)


# ── Field list extracted for every packet ─────────────────────────────────────
# Ordered; index is used to map to field name.
PACKET_FIELDS: List[str] = [
    # Frame
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    # IP
    "ip.src", "ip.dst", "ip.ttl", "ip.proto",
    "ipv6.src", "ipv6.dst", "ipv6.hlim",
    # TCP
    "tcp.stream", "tcp.srcport", "tcp.dstport",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin",
    "tcp.flags.rst", "tcp.flags.psh", "tcp.flags.urg",
    "tcp.seq", "tcp.ack", "tcp.window_size_value",
    "tcp.len",
    # TCP analysis expert
    "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order", "tcp.analysis.fast_retransmission",
    "tcp.analysis.zero_window", "tcp.analysis.keep_alive",
    # TCP RTT
    "tcp.analysis.ack_rtt",
    # UDP
    "udp.srcport", "udp.dstport",
    # ICMP
    "icmp.type", "icmp.code",
    # ARP
    "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "arp.src.hw_mac", "arp.dst.hw_mac",
    # DNS
    "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type",
    "dns.flags.rcode", "dns.a", "dns.aaaa", "dns.cname",
    "dns.resp.ttl", "dns.count.queries", "dns.count.answers",
    "dns.flags.truncated",
    # DNS timing
    "dns.time",
    # HTTP (request)
    "http.request.method", "http.request.uri", "http.host",
    "http.user_agent", "http.referer", "http.authorization",
    "http.cookie", "http.content_type",
    "http.request_number",
    # HTTP (response)
    "http.response.code", "http.content_type",
    "http.content_length", "http.location",
    "http.set_cookie",
    # HTTP2
    "http2.header.name", "http2.header.value",
    # TLS
    "tls.handshake.type", "tls.handshake.version",
    "tls.record.version",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite",
    # TLS ClientHello fields for JA3
    "tls.handshake.ciphersuites",
    "tls.handshake.extension.type",
    "tls.handshake.extensions_supported_group",
    "tls.handshake.extensions_ec_point_format",
    # TLS ServerHello for JA3S
    "tls.handshake.extensions_alpn_str",
    # TLS alerts / cert
    "tls.alert_message.desc",
    "tls.handshake.certificate",
    "x509sat.uTF8String",
    # DHCP
    "dhcp.option.dhcp", "dhcp.ip.your", "dhcp.hw.mac_addr",
    # SMTP
    "smtp.req.command",
    # FTP
    "ftp.request.command", "ftp.response.code",
    # SSH
    "ssh.protocol",
    # SMB2
    "smb2.cmd",
    # RDP
    "rdp.neg_req.selectedProtocol",
    # Kerberos
    "kerberos.msg_type",
    # NTP
    "ntp.mode", "ntp.stratum",
    # SNMP
    "snmp.version",
    # QUIC
    "quic.version",
    # SIP
    "sip.Method", "sip.Status-Code",
    # LDAP
    "ldap.requestName",
]

_FIELD_SEP = "\t"   # tab — tshark default, guaranteed to work across all versions


@dataclasses.dataclass
class PacketParseResult:
    """Diagnostic result returned by get_packets()."""
    packets: List[Dict[str, str]]
    raw_line_count: int          # total non-empty lines tshark produced
    malformed_line_count: int    # lines with 1–3 fields (possible sep/format failure)
    fields_used: List[str]       # final field list after any invalid-field removal
    invalid_fields_removed: List[str]  # fields rejected by this tshark version
    attempts: int                # extraction attempts (>1 means retry happened)


def check_tshark() -> None:
    """
    Verify tshark is installed and functional.
    Logs tshark binary path and version string on success.
    Raises RuntimeError with install instructions if not available.
    """
    import shutil
    path = shutil.which("tshark")
    if path is None:
        raise RuntimeError(
            "tshark is required for packet analysis but was not found on this system.\n"
            "Install it with:\n"
            "  apt-get update && apt-get install -y tshark wireshark-common\n"
            "Then restart the backend container."
        )
    result = subprocess.run(
        ["tshark", "--version"], capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"tshark is installed but failed to execute (exit code {result.returncode}).\n"
            "Try reinstalling: apt-get install --reinstall tshark wireshark-common"
        )
    version_line = (result.stdout or "").splitlines()[0] if result.stdout else "(unknown version)"
    log.info("[tshark] path=%s  version=%s", path, version_line)
    print(f"[tshark] check_tshark: path={path}  version={version_line}")


def _run(cmd: List[str], timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        if result.returncode != 0 and result.stderr:
            print(f"[tshark] cmd={cmd[0]} rc={result.returncode} stderr={result.stderr[:200]}")
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[tshark] TIMEOUT: {' '.join(cmd[:4])}")
        return ""
    except FileNotFoundError:
        raise RuntimeError("tshark not found. Install wireshark-cli.")


def get_file_info(path: str) -> Dict[str, Any]:
    """Run capinfos to get capture metadata."""
    out = _run(["capinfos", "-c", "-d", "-e", "-u", "-a", "-o", "-s", "-y", path])
    info: Dict[str, Any] = {}
    patterns = {
        "total_packets": r"Number of packets:\s+(\d+)",
        "duration_sec": r"Capture duration:\s+([\d.]+)",
        "file_size_bytes": r"File size:\s+([\d,]+)",
        "first_packet": r"First packet time:\s+(.+)",
        "last_packet": r"Last packet time:\s+(.+)",
        "encapsulation": r"Data link type:\s+(.+)",
        "avg_packet_size": r"Average packet size:\s+([\d.]+)",
        "avg_packet_rate": r"Average packet rate:\s+([\d.]+)",
        "avg_bit_rate": r"Average bit rate:\s+([\d.]+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, out, re.I)
        if m:
            v = m.group(1).strip()
            if key in ("total_packets",):
                info[key] = int(v)
            elif key in ("duration_sec", "file_size_bytes", "avg_packet_size",
                         "avg_packet_rate", "avg_bit_rate"):
                try:
                    info[key] = float(v.replace(",", "").split()[0])
                except ValueError:
                    info[key] = 0.0
            else:
                info[key] = v
    return info


def get_protocol_hierarchy(path: str) -> Dict[str, int]:
    """Parse tshark -z io,phs output into {protocol: frame_count}.
    Handles both tshark output formats:
      Old: '  tcp  1234  123456 bytes'
      New: '  tcp  frames:1234 bytes:123456'
    """
    out = _run(["tshark", "-q", "-z", "io,phs", "-r", path])
    result: Dict[str, int] = {}
    for line in out.splitlines():
        # New format: "  tcp   frames:1234 bytes:..."
        m = re.match(r"\s+([\w.]+)\s+frames:(\d+)", line)
        if m:
            result[m.group(1).lower()] = int(m.group(2))
            continue
        # Old format: "  tcp   1234   123456"
        m = re.match(r"\s+([\w.]+)\s+(\d+)\s+", line)
        if m:
            result[m.group(1).lower()] = int(m.group(2))
    return result


def get_ip_endpoints(path: str) -> List[Dict]:
    """Parse tshark -z endpoints,ip into list of endpoint dicts."""
    out = _run(["tshark", "-q", "-z", "endpoints,ip", "-r", path])
    endpoints = []
    in_table = False
    for line in out.splitlines():
        if "Endpoint" in line and "IP" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if re.match(r"^=+$", line.strip()):
            continue
        parts = line.split()
        if len(parts) >= 5:
            try:
                endpoints.append({
                    "ip": parts[0],
                    "packets": int(parts[1]),
                    "bytes": int(parts[2]),
                    "tx_packets": int(parts[3]),
                    "tx_bytes": int(parts[4]),
                    "rx_packets": int(parts[5]) if len(parts) > 5 else 0,
                    "rx_bytes": int(parts[6]) if len(parts) > 6 else 0,
                })
            except (ValueError, IndexError):
                pass
    return sorted(endpoints, key=lambda x: -x["bytes"])[:100]


def get_tcp_conversations(path: str) -> List[Dict]:
    """Parse tshark -z conv,tcp into list of conversation dicts."""
    out = _run(["tshark", "-q", "-z", "conv,tcp", "-r", path])
    convs = []
    in_table = False
    for line in out.splitlines():
        if "TCP Conversations" in line:
            in_table = True
            continue
        if not in_table:
            continue
        m = re.match(
            r"(\S+):(\d+)\s+<->\s+(\S+):(\d+)\s+"
            r"(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)",
            line.strip(),
        )
        if m:
            convs.append({
                "src_ip": m.group(1), "src_port": int(m.group(2)),
                "dst_ip": m.group(3), "dst_port": int(m.group(4)),
                "frames_fwd": int(m.group(5)), "bytes_fwd": int(m.group(6)),
                "frames_rev": int(m.group(7)), "bytes_rev": int(m.group(8)),
                "packets": int(m.group(9)), "bytes": int(m.group(10)),
                "duration": float(m.group(11)),
            })
    return sorted(convs, key=lambda x: -x["bytes"])[:100]


def get_expert_info(path: str) -> List[Dict]:
    """Run tshark -z expert and parse severity + message."""
    out = _run(["tshark", "-q", "-z", "expert,warn", "-r", path])
    items: List[Dict] = []
    counts: Dict[str, Dict] = {}
    for line in out.splitlines():
        m = re.match(r"^\s+(Error|Warning|Note|Chat)\s+(.+?)\s+(\d+)", line, re.I)
        if m:
            msg = m.group(2).strip()
            if msg not in counts:
                counts[msg] = {"severity": m.group(1).lower(), "message": msg, "count": 0}
            counts[msg]["count"] += int(m.group(3))
    return sorted(counts.values(), key=lambda x: -x["count"])[:50]


def get_packets(path: str, max_packets: int = 50_000) -> PacketParseResult:
    """
    Extract per-packet fields using tshark -T fields.
    Auto-detects and removes invalid field names so one bad field never
    silences the entire capture.

    Returns a PacketParseResult with parsed packets plus extraction diagnostics
    (raw line count, malformed line count, invalid fields removed, attempt count).
    Callers should inspect these diagnostics to decide whether the extraction is
    reliable enough to proceed with analysis.
    """
    fields = list(PACKET_FIELDS)
    all_invalid_removed: List[str] = []
    attempts = 0

    for attempt in range(4):
        attempts = attempt + 1
        cmd = [
            "tshark", "-r", path,
            "-c", str(max_packets),
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=f",
            "-E", "aggregator=|",
        ]
        for f in fields:
            cmd += ["-e", f]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180, check=False,
        )

        stderr = result.stderr or ""

        # Parse invalid field names from tshark stderr and retry without them
        if "aren't valid" in stderr or "are not valid" in stderr:
            invalid: set = set()
            in_block = False
            for line in stderr.splitlines():
                if "aren't valid" in line or "are not valid" in line:
                    in_block = True
                    continue
                if in_block:
                    candidate = line.strip()
                    if not candidate:
                        break
                    if re.match(r'^[\w.]+$', candidate):
                        invalid.add(candidate)
            if invalid:
                log.warning("[tshark] attempt %d: removing %d invalid fields: %s",
                            attempts, len(invalid), sorted(invalid))
                print(f"[tshark] attempt {attempts}: removing {len(invalid)} invalid fields: {sorted(invalid)}")
                all_invalid_removed.extend(sorted(invalid))
                fields = [f for f in fields if f not in invalid]
                continue  # retry with cleaned field list

        # Non-zero exit without invalid-field error = root warning or other issue;
        # stdout may still contain packet data so fall through.
        if result.returncode != 0 and result.stdout.strip():
            log.warning("[tshark] rc=%d but stdout has data — continuing", result.returncode)

        out = result.stdout
        break
    else:
        out = ""

    lines = [ln for ln in out.splitlines() if ln]   # strip blank lines
    raw_line_count = len(lines)
    malformed_line_count = 0
    packets: List[Dict[str, str]] = []

    for line in lines:
        values = line.split(_FIELD_SEP)
        if len(values) < 4:
            # Line has too few fields — separator mismatch or tshark format change
            malformed_line_count += 1
            continue
        d: Dict[str, str] = {}
        for i, val in enumerate(values):
            if i < len(fields) and val:
                d[fields[i]] = val
        if d:
            packets.append(d)

    log.info(
        "[tshark] get_packets: raw_lines=%d malformed=%d parsed=%d fields=%d attempts=%d invalid_removed=%s",
        raw_line_count, malformed_line_count, len(packets), len(fields), attempts, all_invalid_removed,
    )
    print(
        f"[tshark] get_packets: raw_lines={raw_line_count} malformed={malformed_line_count} "
        f"parsed={len(packets)} fields={len(fields)} attempts={attempts}"
    )

    return PacketParseResult(
        packets=packets,
        raw_line_count=raw_line_count,
        malformed_line_count=malformed_line_count,
        fields_used=list(fields),
        invalid_fields_removed=sorted(set(all_invalid_removed)),
        attempts=attempts,
    )
