"""
tshark wrapper — runs tshark as subprocess and returns structured packet data.
Two-phase approach:
  Phase 1: statistics (fast, handles any size)
  Phase 2: per-packet fields (capped at MAX_PACKETS)
"""

import re
import subprocess
from typing import Any, Dict, List

MAX_PACKETS = 50_000   # hard cap for detail pass
TSHARK_TIMEOUT = 180   # seconds


def _run(cmd: List[str]) -> str:
    """Run tshark and return stdout. Raises on fatal errors."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=TSHARK_TIMEOUT)
        return r.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        raise RuntimeError("tshark timed out (file may be too large)")
    except FileNotFoundError:
        raise RuntimeError("tshark not found — install wireshark-common")


# ─── Phase 1: fast statistics via -z ──────────────────────────────────────────

def get_file_info(path: str) -> Dict[str, Any]:
    """capinfos: total packets, bytes, duration."""
    out = _run(["capinfos", "-M", "-T", path])
    info: Dict[str, Any] = {}
    for line in out.splitlines():
        if "Number of packets" in line:
            m = re.search(r"(\d[\d,]+)", line)
            if m:
                info["total_packets"] = int(m.group(1).replace(",", ""))
        elif "File size" in line:
            m = re.search(r"([\d,]+)", line)
            if m:
                info["file_size_bytes"] = int(m.group(1).replace(",", ""))
        elif "Capture duration" in line:
            m = re.search(r"([\d.]+)", line)
            if m:
                info["duration_sec"] = float(m.group(1))
        elif "First packet time" in line:
            info["first_packet"] = line.split(":", 1)[-1].strip()
        elif "Last packet time" in line:
            info["last_packet"] = line.split(":", 1)[-1].strip()
    return info


def get_protocol_hierarchy(path: str) -> Dict[str, int]:
    """Protocol distribution from io,phs."""
    out = _run(["tshark", "-r", path, "-q", "-z", "io,phs"])
    protos: Dict[str, int] = {}
    for line in out.splitlines():
        m = re.match(r"\s+([\w.]+)\s+frames:(\d+)", line)
        if m:
            name = m.group(1).upper().split(".")[-1]
            count = int(m.group(2))
            if name not in ("FRAME", "ETH", "ETHERTYPE", "DATA-TEXT-LINES", "DATA"):
                protos[name] = protos.get(name, 0) + count
    # merge TLS aliases
    for alias in ("TLS", "SSL"):
        if alias in protos:
            protos["TLS"] = protos.get("TLS", 0) + protos.pop(alias, 0)
    return dict(sorted(protos.items(), key=lambda x: -x[1])[:20])


def get_ip_endpoints(path: str) -> List[Dict]:
    """Top IP endpoints with bytes."""
    out = _run(["tshark", "-r", path, "-q", "-z", "endpoints,ip"])
    endpoints = []
    in_table = False
    for line in out.splitlines():
        if "Endpoint" in line and "IP" in line:
            in_table = True
            continue
        if in_table:
            parts = line.split()
            if len(parts) >= 5 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
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
    return sorted(endpoints, key=lambda x: -x["bytes"])[:20]


def get_tcp_conversations(path: str) -> List[Dict]:
    """TCP conversations from conv,tcp."""
    out = _run(["tshark", "-r", path, "-q", "-z", "conv,tcp"])
    convs = []
    in_table = False
    for line in out.splitlines():
        if "TCP Conversations" in line or ("Address A" in line and "Address B" in line):
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) >= 9:
            # Format: addr:port <-> addr:port frames bytes frames bytes total_frames total_bytes duration
            m = re.match(r"([\d.]+):(\d+)\s+<->\s+([\d.]+):(\d+)", line)
            if m:
                try:
                    num_parts = [p for p in parts if re.match(r"^\d", p)]
                    convs.append({
                        "src_ip": m.group(1), "src_port": int(m.group(2)),
                        "dst_ip": m.group(3), "dst_port": int(m.group(4)),
                        "packets": int(num_parts[4]) if len(num_parts) > 4 else 0,
                        "bytes": int(num_parts[5]) if len(num_parts) > 5 else 0,
                        "duration": float(num_parts[6]) if len(num_parts) > 6 else 0,
                    })
                except (ValueError, IndexError):
                    pass
    return sorted(convs, key=lambda x: -x["bytes"])[:100]


def get_expert_info(path: str) -> List[Dict]:
    """Expert info: retransmissions, resets, etc."""
    out = _run(["tshark", "-r", path, "-q", "-z", "expert"])
    items = []
    for line in out.splitlines():
        m = re.match(r"\s*(Error|Warn|Note|Chat)\s+(\d+)\s+(.*)", line)
        if m:
            items.append({
                "severity": m.group(1).lower(),
                "count": int(m.group(2)),
                "message": m.group(3).strip(),
            })
    return items


# ─── Phase 2: per-packet field extraction ────────────────────────────────────

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ip.dst", "ip.ttl", "ip.flags.mf", "ip.frag_offset",
    "ipv6.src", "ipv6.dst",
    "eth.src", "eth.dst", "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "arp.src.hw_mac",
    "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.stream",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.rst", "tcp.flags.push", "tcp.flags.urg",
    "tcp.window_size", "tcp.len",
    "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack",
    "tcp.analysis.fast_retransmission", "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window", "tcp.analysis.lost_segment",
    "udp.srcport", "udp.dstport", "udp.length",
    "icmp.type", "icmp.code",
    "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type",
    "dns.flags.rcode", "dns.a", "dns.aaaa", "dns.time",
    "http.request.method", "http.request.uri", "http.host",
    "http.response.code", "http.user_agent", "http.content_type", "http.request_number",
    "tls.handshake.type", "tls.handshake.extensions_server_name",
    "tls.handshake.version", "tls.handshake.ciphersuite",
    "tls.record.version",
    "dhcp.option.dhcp", "dhcp.ip.your",
    "ssh.protocol",
    "ftp.request.command", "ftp.response.code",
    "smtp.req.command",
    "smb.cmd", "smb2.cmd",
    "kerberos.msg_type",
    "ldap.requestName",
    "sip.Method", "sip.Status-Code",
    "ntp.stratum", "ntp.mode",
    "snmp.version",
    "rdp.neg_req.selectedProtocol",
    "quic.version",
]


def get_packets(path: str, max_packets: int = MAX_PACKETS) -> List[Dict[str, str]]:
    """
    Extract per-packet fields as list of dicts.
    Uses -T fields -E separator=| for performance.
    """
    cmd = (
        ["tshark", "-r", path, "-T", "fields", "-E", "separator=|",
         "-E", "header=y", "-c", str(max_packets)]
        + [f for field in FIELDS for f in ["-e", field]]
    )
    out = _run(cmd)
    lines = out.splitlines()
    if len(lines) < 2:
        return []

    headers = lines[0].split("|")
    packets = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split("|")
        pkt: Dict[str, str] = {}
        for i, h in enumerate(headers):
            v = values[i] if i < len(values) else ""
            if v:
                pkt[h] = v
        packets.append(pkt)
    return packets
