"""
Regression corpus scenarios.

Each Scenario bundles:
  - pcap_bytes      : valid PCAP binary (for integration tests / manual inspection)
  - tshark_snapshot : pre-recorded tshark output used to mock all tshark calls in
                      unit tests (so no real tshark binary is required)
  - golden          : expected assertions expressed as a plain dict; the regression
                      test file turns these into pytest assertions

The snapshots represent what tshark -T fields would actually return for the
corresponding pcap_bytes.  They are expressed as PacketParseResult so they can
be injected directly into the mocked normalizer.pipeline.get_packets().

tcp.stream is set per-session (0-based int).
Missing flag fields ("0") ARE included because tshark outputs "0" for false flags
on TCP packets (the `if val` filter keeps non-empty strings including "0").
"""
from __future__ import annotations

import sys
import os
import dataclasses
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from tests.corpus.pcap_builder import (
    PcapBuilder, Packet,
    F_SYN, F_ACK, F_FIN, F_RST, F_PSH,
)
from normalizer.tshark import PacketParseResult, PACKET_FIELDS


# ── Helpers ────────────────────────────────────────────────────────────────────

def _pkt(overrides: Dict[str, str]) -> Dict[str, str]:
    """Build a minimal packet field dict with defaults, applying overrides."""
    base: Dict[str, str] = {
        "frame.number":     "1",
        "frame.time_epoch": "1700000000.000000",
        "frame.len":        "54",
        "frame.protocols":  "eth:ethertype:ip:tcp",
        "ip.src":           "192.168.1.1",
        "ip.dst":           "10.0.0.1",
        "ip.ttl":           "64",
        "ip.proto":         "6",
        "tcp.stream":       "0",
        "tcp.srcport":      "50000",
        "tcp.dstport":      "80",
        "tcp.flags.syn":    "0",
        "tcp.flags.ack":    "0",
        "tcp.flags.fin":    "0",
        "tcp.flags.rst":    "0",
        "tcp.flags.psh":    "0",
        "tcp.flags.urg":    "0",
        "tcp.seq":          "0",
        "tcp.ack":          "0",
        "tcp.window_size_value": "65535",
        "tcp.len":          "0",
    }
    base.update(overrides)
    return base


def _parse_result(rows: List[Dict[str, str]], **kwargs) -> PacketParseResult:
    """Wrap a list of row dicts in a PacketParseResult with sane defaults."""
    return PacketParseResult(
        packets=rows,
        raw_line_count=kwargs.get("raw_line_count", len(rows)),
        malformed_line_count=kwargs.get("malformed_line_count", 0),
        fields_used=list(PACKET_FIELDS),
        invalid_fields_removed=kwargs.get("invalid_fields_removed", []),
        attempts=kwargs.get("attempts", 1),
    )


# ── Golden assertion keys ──────────────────────────────────────────────────────
# Each entry in Scenario.golden is interpreted by test_corpus_regression.py.
# Supported keys:
#   expected_error          str | None   — substring that must appear in RuntimeError,
#                                          or None if normalize() should succeed
#   session_count           int          — len(ctx.sessions)
#   dns_tx_count            int          — len(ctx.dns_transactions)
#   tcp_packet_count_min    int          — at least N tcp-flagged packets in ctx.packets
#   session_0_state         str          — ctx.sessions[0].state.value
#   session_0_has_syn       bool
#   session_0_has_synack    bool
#   session_0_has_fin       bool
#   session_0_has_rst       bool
#   session_0_retransmissions_min int
#   dns_tx_0_is_nxdomain    bool
#   all_sessions_half_open  bool         — every session has state=HALF_OPEN
#   protocol_stats_has_udp  bool
#   extraction_profile      str          — profile name used

# ── Scenario dataclass ────────────────────────────────────────────────────────

@dataclasses.dataclass
class Scenario:
    name: str
    description: str
    pcap_bytes: bytes
    file_info: Dict[str, Any]              # mocked get_file_info() result
    protocol_hierarchy: Dict[str, int]     # mocked get_protocol_hierarchy() result
    parse_result: PacketParseResult        # mocked get_packets() result
    tcp_conversations: List[Dict]
    expert_info: List[Dict]
    golden: Dict[str, Any]


# ── 1. empty ──────────────────────────────────────────────────────────────────

def _build_empty() -> Scenario:
    pcap = PcapBuilder().build()      # global header only, zero packets
    return Scenario(
        name="empty",
        description="Valid PCAP global header with zero packet records.",
        pcap_bytes=pcap,
        file_info={"total_packets": 0, "duration_sec": 0.0, "file_size_bytes": 24.0},
        protocol_hierarchy={},
        parse_result=_parse_result([]),
        tcp_conversations=[],
        expert_info=[],
        golden={"expected_error": "could not read any packets"},
    )


# ── 2. corrupted ─────────────────────────────────────────────────────────────

def _build_corrupted() -> Scenario:
    # Truncated PCAP: valid magic, then garbage
    pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\xff" * 8
    return Scenario(
        name="corrupted",
        description="Truncated/corrupted PCAP file.",
        pcap_bytes=pcap,
        file_info={"total_packets": 0, "duration_sec": 0.0, "file_size_bytes": 16.0},
        protocol_hierarchy={},
        parse_result=_parse_result([]),
        tcp_conversations=[],
        expert_info=[],
        golden={"expected_error": "could not read any packets"},
    )


# ── 3. non_tcp (UDP-only DNS traffic) ─────────────────────────────────────────

def _build_non_tcp() -> Scenario:
    b = PcapBuilder()
    b.add(
        Packet.dns_query_pkt("192.168.1.1", "8.8.8.8", 0xAAAA, "example.com", ts=1_700_000_000.0),
        Packet.dns_nxdomain_pkt("8.8.8.8", "192.168.1.1", 0xAAAA, "example.com", ts=1_700_000_000.1),
    )
    rows = [
        {
            "frame.number": "1", "frame.time_epoch": "1700000000.000000",
            "frame.len": "71",   "frame.protocols":  "eth:ethertype:ip:udp:dns",
            "ip.src": "192.168.1.1", "ip.dst": "8.8.8.8",
            "ip.ttl": "64",      "ip.proto": "17",
            "udp.srcport": "53001", "udp.dstport": "53",
            "dns.id": "0xaaaa",  "dns.flags.response": "0",
            "dns.qry.name": "example.com", "dns.qry.type": "1",
            "dns.flags.rcode": "0",
        },
        {
            "frame.number": "2", "frame.time_epoch": "1700000000.100000",
            "frame.len": "71",   "frame.protocols":  "eth:ethertype:ip:udp:dns",
            "ip.src": "8.8.8.8", "ip.dst": "192.168.1.1",
            "ip.ttl": "128",     "ip.proto": "17",
            "udp.srcport": "53", "udp.dstport": "53001",
            "dns.id": "0xaaaa",  "dns.flags.response": "1",
            "dns.qry.name": "example.com", "dns.qry.type": "1",
            "dns.flags.rcode": "0", "dns.a": "93.184.216.34",
            "dns.time": "0.100000",
        },
    ]
    return Scenario(
        name="non_tcp",
        description="UDP-only capture: two DNS packets, no TCP sessions.",
        pcap_bytes=b.build(),
        file_info={"total_packets": 2, "duration_sec": 0.1, "file_size_bytes": 166.0},
        protocol_hierarchy={"eth": 2, "ip": 2, "udp": 2, "dns": 2},
        parse_result=_parse_result(rows),
        tcp_conversations=[],
        expert_info=[],
        golden={
            "expected_error": None,
            "session_count": 0,
            "dns_tx_count": 1,
            "protocol_stats_has_udp": True,
        },
    )


# ── 4. tcp_handshake (clean SYN → FIN close) ──────────────────────────────────

def _build_tcp_handshake() -> Scenario:
    SRC, DST, SP, DP = "192.168.1.10", "10.0.0.5", 50001, 80
    b = PcapBuilder()
    b.add(
        Packet.tcp_syn(SRC, DST, SP, DP, ts=1_700_000_000.000),
        Packet.tcp_synack(DST, SRC, DP, SP, ts=1_700_000_000.010),
        Packet.tcp_ack(SRC, DST, SP, DP, ts=1_700_000_000.020),
        Packet.tcp_data(SRC, DST, SP, DP, payload=b"GET / HTTP/1.0\r\n\r\n",
                        ts=1_700_000_000.030),
        Packet.tcp_data(DST, SRC, DP, SP, payload=b"HTTP/1.0 200 OK\r\n\r\nok",
                        ts=1_700_000_000.050),
        Packet.tcp_fin(SRC, DST, SP, DP, ts=1_700_000_000.100),
        Packet.tcp_fin(DST, SRC, DP, SP, ts=1_700_000_000.110),
    )
    rows = [
        _pkt({"frame.number": "1", "frame.time_epoch": "1700000000.000000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.syn": "1", "tcp.seq": "1000"}),
        _pkt({"frame.number": "2", "frame.time_epoch": "1700000000.010000",
               "ip.src": DST, "ip.dst": SRC, "tcp.srcport": str(DP), "tcp.dstport": str(SP),
               "tcp.flags.syn": "1", "tcp.flags.ack": "1", "tcp.seq": "2000", "tcp.ack": "1001"}),
        _pkt({"frame.number": "3", "frame.time_epoch": "1700000000.020000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.ack": "1", "tcp.seq": "1001", "tcp.ack": "2001"}),
        _pkt({"frame.number": "4", "frame.time_epoch": "1700000000.030000", "frame.len": "72",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.psh": "1", "tcp.flags.ack": "1",
               "tcp.seq": "1001", "tcp.ack": "2001", "tcp.len": "18"}),
        _pkt({"frame.number": "5", "frame.time_epoch": "1700000000.050000", "frame.len": "75",
               "ip.src": DST, "ip.dst": SRC, "tcp.srcport": str(DP), "tcp.dstport": str(SP),
               "tcp.flags.psh": "1", "tcp.flags.ack": "1",
               "tcp.seq": "2001", "tcp.ack": "1019", "tcp.len": "21"}),
        _pkt({"frame.number": "6", "frame.time_epoch": "1700000000.100000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.fin": "1", "tcp.flags.ack": "1",
               "tcp.seq": "1019", "tcp.ack": "2022"}),
        _pkt({"frame.number": "7", "frame.time_epoch": "1700000000.110000",
               "ip.src": DST, "ip.dst": SRC, "tcp.srcport": str(DP), "tcp.dstport": str(SP),
               "tcp.flags.fin": "1", "tcp.flags.ack": "1",
               "tcp.seq": "2022", "tcp.ack": "1020"}),
    ]
    return Scenario(
        name="tcp_handshake",
        description="Complete TCP connection: SYN/SYN-ACK/ACK, data exchange, FIN close.",
        pcap_bytes=b.build(),
        file_info={"total_packets": 7, "duration_sec": 0.11, "file_size_bytes": 560.0},
        protocol_hierarchy={"eth": 7, "ip": 7, "tcp": 7},
        parse_result=_parse_result(rows),
        tcp_conversations=[
            {"src_ip": SRC, "src_port": SP, "dst_ip": DST, "dst_port": DP,
             "packets": 7, "bytes": 560, "duration": 0.11}
        ],
        expert_info=[],
        golden={
            "expected_error": None,
            "session_count": 1,
            "session_0_has_syn": True,
            "session_0_has_synack": True,
            "session_0_has_fin": True,
            "session_0_has_rst": False,
            "session_0_state": "fin_closed",
        },
    )


# ── 5. midstream_tcp ──────────────────────────────────────────────────────────

def _build_midstream() -> Scenario:
    """Mid-stream: data exchange captured without a preceding SYN.
    No FIN or RST so the state machine lands on MID_STREAM."""
    SRC, DST, SP, DP = "10.1.2.3", "10.1.2.4", 60000, 443
    rows = [
        _pkt({"frame.number": "1", "frame.time_epoch": "1700001000.000000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.psh": "1", "tcp.flags.ack": "1",
               "tcp.seq": "5000", "tcp.ack": "6000", "tcp.len": "100"}),
        _pkt({"frame.number": "2", "frame.time_epoch": "1700001000.050000",
               "ip.src": DST, "ip.dst": SRC, "tcp.srcport": str(DP), "tcp.dstport": str(SP),
               "tcp.flags.psh": "1", "tcp.flags.ack": "1",
               "tcp.seq": "6000", "tcp.ack": "5100", "tcp.len": "200"}),
        _pkt({"frame.number": "3", "frame.time_epoch": "1700001000.100000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.psh": "1", "tcp.flags.ack": "1",
               "tcp.seq": "5100", "tcp.ack": "6200", "tcp.len": "80"}),
    ]
    b = PcapBuilder()
    b.add(
        Packet.tcp_data(SRC, DST, SP, DP, seq=5000, ack=6000, ts=1_700_001_000.0),
        Packet.tcp_data(DST, SRC, DP, SP, seq=6000, ack=5100, ts=1_700_001_000.05),
        Packet.tcp_data(SRC, DST, SP, DP, seq=5100, ack=6200, ts=1_700_001_000.1),
    )
    return Scenario(
        name="midstream_tcp",
        description="TCP data exchange captured without a preceding SYN — mid-stream only.",
        pcap_bytes=b.build(),
        file_info={"total_packets": 3, "duration_sec": 0.1, "file_size_bytes": 280.0},
        protocol_hierarchy={"eth": 3, "ip": 3, "tcp": 3},
        parse_result=_parse_result(rows),
        tcp_conversations=[],
        expert_info=[],
        golden={
            "expected_error": None,
            "session_count": 1,
            "session_0_has_syn": False,
            "session_0_has_synack": False,
            "session_0_state": "mid_stream",
        },
    )


# ── 6. retransmissions ────────────────────────────────────────────────────────

def _build_retransmissions() -> Scenario:
    SRC, DST, SP, DP = "192.168.0.1", "192.168.0.2", 54321, 8080
    rows = [
        _pkt({"frame.number": "1", "frame.time_epoch": "1700002000.000000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.syn": "1", "tcp.seq": "100"}),
        _pkt({"frame.number": "2", "frame.time_epoch": "1700002000.100000",
               "ip.src": DST, "ip.dst": SRC, "tcp.srcport": str(DP), "tcp.dstport": str(SP),
               "tcp.flags.syn": "1", "tcp.flags.ack": "1", "tcp.seq": "200", "tcp.ack": "101"}),
        _pkt({"frame.number": "3", "frame.time_epoch": "1700002000.200000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.psh": "1", "tcp.flags.ack": "1",
               "tcp.seq": "101", "tcp.ack": "201", "tcp.len": "50"}),
        # Retransmission of packet 3
        _pkt({"frame.number": "4", "frame.time_epoch": "1700002000.500000",
               "ip.src": SRC, "ip.dst": DST, "tcp.srcport": str(SP), "tcp.dstport": str(DP),
               "tcp.flags.psh": "1", "tcp.flags.ack": "1",
               "tcp.seq": "101", "tcp.ack": "201", "tcp.len": "50",
               "tcp.analysis.retransmission": "1"}),
    ]
    b = PcapBuilder()
    b.add(
        Packet.tcp_syn(SRC, DST, SP, DP, ts=1_700_002_000.0),
        Packet.tcp_synack(DST, SRC, DP, SP, ts=1_700_002_000.1),
        Packet.tcp_data(SRC, DST, SP, DP, ts=1_700_002_000.2),
        Packet.tcp_data(SRC, DST, SP, DP, ts=1_700_002_000.5),
    )
    return Scenario(
        name="retransmissions",
        description="TCP session with a retransmitted data segment.",
        pcap_bytes=b.build(),
        file_info={"total_packets": 4, "duration_sec": 0.5, "file_size_bytes": 320.0},
        protocol_hierarchy={"eth": 4, "ip": 4, "tcp": 4},
        parse_result=_parse_result(rows),
        tcp_conversations=[],
        expert_info=[{"severity": "note", "message": "This frame is a (suspected) retransmission",
                      "count": 1}],
        golden={
            "expected_error": None,
            "session_count": 1,
            "session_0_has_syn": True,
            "session_0_retransmissions_min": 1,
        },
    )


# ── 7. rst_heavy ─────────────────────────────────────────────────────────────

def _build_rst_heavy() -> Scenario:
    CLIENT = "10.10.0.1"
    SERVERS = [("10.10.0.2", 22), ("10.10.0.2", 23), ("10.10.0.2", 25)]
    rows = []
    stream = 0
    for i, (srv, dport) in enumerate(SERVERS):
        sp = 40000 + i
        ts_base = 1_700_003_000.0 + i * 0.1
        rows.append(_pkt({
            "frame.number": str(stream * 2 + 1),
            "frame.time_epoch": f"{ts_base:.6f}",
            "ip.src": CLIENT, "ip.dst": srv,
            "tcp.srcport": str(sp), "tcp.dstport": str(dport),
            "tcp.stream": str(stream),
            "tcp.flags.syn": "1", "tcp.seq": "1000",
        }))
        rows.append(_pkt({
            "frame.number": str(stream * 2 + 2),
            "frame.time_epoch": f"{ts_base + 0.05:.6f}",
            "ip.src": srv, "ip.dst": CLIENT,
            "tcp.srcport": str(dport), "tcp.dstport": str(sp),
            "tcp.stream": str(stream),
            "tcp.flags.rst": "1", "tcp.flags.ack": "1", "tcp.seq": "0",
        }))
        stream += 1
    b = PcapBuilder()
    for i, (srv, dport) in enumerate(SERVERS):
        sp = 40000 + i
        ts = 1_700_003_000.0 + i * 0.1
        b.add(Packet.tcp_syn(CLIENT, srv, sp, dport, ts=ts))
        b.add(Packet.tcp_rst(srv, CLIENT, dport, sp, ts=ts + 0.05))
    return Scenario(
        name="rst_heavy",
        description="Multiple TCP connections refused with RST.",
        pcap_bytes=b.build(),
        file_info={"total_packets": 6, "duration_sec": 0.25, "file_size_bytes": 480.0},
        protocol_hierarchy={"eth": 6, "ip": 6, "tcp": 6},
        parse_result=_parse_result(rows),
        tcp_conversations=[],
        expert_info=[],
        golden={
            "expected_error": None,
            "session_count": 3,
            "all_sessions_have_rst": True,
        },
    )


# ── 8. dns_nxdomain ───────────────────────────────────────────────────────────

def _build_dns_nxdomain() -> Scenario:
    DOMAIN = "nonexistent.example.com"
    b = PcapBuilder()
    b.add(
        Packet.dns_query_pkt("192.168.1.5", "8.8.8.8", 0x1234, DOMAIN, ts=1_700_004_000.0),
        Packet.dns_nxdomain_pkt("8.8.8.8", "192.168.1.5", 0x1234, DOMAIN, ts=1_700_004_000.05),
    )
    rows = [
        {
            "frame.number": "1", "frame.time_epoch": "1700004000.000000",
            "frame.len": "83",   "frame.protocols": "eth:ethertype:ip:udp:dns",
            "ip.src": "192.168.1.5", "ip.dst": "8.8.8.8",
            "ip.ttl": "64",      "ip.proto": "17",
            "udp.srcport": "53001", "udp.dstport": "53",
            "dns.id": "0x1234",  "dns.flags.response": "0",
            "dns.qry.name": DOMAIN, "dns.qry.type": "1",
            "dns.count.queries": "1",
        },
        {
            "frame.number": "2", "frame.time_epoch": "1700004000.050000",
            "frame.len": "83",   "frame.protocols": "eth:ethertype:ip:udp:dns",
            "ip.src": "8.8.8.8", "ip.dst": "192.168.1.5",
            "ip.ttl": "128",     "ip.proto": "17",
            "udp.srcport": "53", "udp.dstport": "53001",
            "dns.id": "0x1234",  "dns.flags.response": "1",
            "dns.qry.name": DOMAIN, "dns.qry.type": "1",
            "dns.flags.rcode": "3",          # NXDOMAIN
            "dns.count.queries": "1",
            "dns.time": "0.050000",
        },
    ]
    return Scenario(
        name="dns_nxdomain",
        description="DNS A query returning NXDOMAIN.",
        pcap_bytes=b.build(),
        file_info={"total_packets": 2, "duration_sec": 0.05, "file_size_bytes": 194.0},
        protocol_hierarchy={"eth": 2, "ip": 2, "udp": 2, "dns": 2},
        parse_result=_parse_result(rows),
        tcp_conversations=[],
        expert_info=[],
        golden={
            "expected_error": None,
            "session_count": 0,
            "dns_tx_count": 1,
            "dns_tx_0_is_nxdomain": True,
            "dns_tx_0_qname": DOMAIN,
        },
    )


# ── 9. port_scan (SYN scan, no responses) ────────────────────────────────────

def _build_port_scan() -> Scenario:
    ATTACKER = "10.0.0.99"
    TARGET = "10.0.0.1"
    PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3389, 8080]
    rows = []
    b = PcapBuilder()
    for stream, dport in enumerate(PORTS):
        sp = 50000 + stream
        ts = 1_700_005_000.0 + stream * 0.01
        rows.append(_pkt({
            "frame.number": str(stream + 1),
            "frame.time_epoch": f"{ts:.6f}",
            "ip.src": ATTACKER, "ip.dst": TARGET,
            "tcp.srcport": str(sp), "tcp.dstport": str(dport),
            "tcp.stream": str(stream),
            "tcp.flags.syn": "1", "tcp.seq": str(1000 + stream),
        }))
        b.add(Packet.tcp_syn(ATTACKER, TARGET, sp, dport, ts=ts))
    return Scenario(
        name="port_scan",
        description="SYN scan: 10 SYN packets to different ports, no responses.",
        pcap_bytes=b.build(),
        file_info={"total_packets": 10, "duration_sec": 0.09, "file_size_bytes": 700.0},
        protocol_hierarchy={"eth": 10, "ip": 10, "tcp": 10},
        parse_result=_parse_result(rows),
        tcp_conversations=[],
        expert_info=[],
        golden={
            "expected_error": None,
            "session_count": 10,
            "all_sessions_half_open": True,
        },
    )


# ── Registry ──────────────────────────────────────────────────────────────────

SCENARIOS: Dict[str, Scenario] = {
    s.name: s for s in [
        _build_empty(),
        _build_corrupted(),
        _build_non_tcp(),
        _build_tcp_handshake(),
        _build_midstream(),
        _build_retransmissions(),
        _build_rst_heavy(),
        _build_dns_nxdomain(),
        _build_port_scan(),
    ]
}
