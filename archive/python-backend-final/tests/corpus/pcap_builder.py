"""
Minimal, dependency-free PCAP binary construction.

Produces RFC-compliant pcap (not pcapng) files using only the standard
library.  Checksums are left as zero — tshark accepts them for analysis.

Usage:
    from tests.corpus.pcap_builder import PcapBuilder, Packet

    builder = PcapBuilder()
    builder.add(Packet.tcp_syn("192.168.1.1", "10.0.0.1", 50000, 80, stream=0, ts=1.0))
    data = builder.build()
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import List

# ── PCAP constants ─────────────────────────────────────────────────────────────

_PCAP_MAGIC = 0xA1B2C3D4
_LINK_TYPE_ETHERNET = 1

# Well-known MAC addresses used in all test frames
_MAC_CLIENT = bytes.fromhex("aabbcc112233")
_MAC_SERVER = bytes.fromhex("aabbcc445566")
_MAC_RESOLVER = bytes.fromhex("aabbcc778899")

# TCP flag bits
F_FIN = 0x01
F_SYN = 0x02
F_RST = 0x04
F_PSH = 0x08
F_ACK = 0x10


# ── Low-level frame builders ───────────────────────────────────────────────────

def _eth(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64,
          pkt_id: int = 1) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                       # version=4, IHL=5
        0,                          # DSCP/ECN
        total_len,
        pkt_id,
        0x4000,                     # DF flag, fragment offset=0
        ttl,
        proto,
        0,                          # checksum (omitted)
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return hdr + payload


def _tcp(src_port: int, dst_port: int, flags: int, seq: int = 0, ack: int = 0,
         window: int = 65535, payload: bytes = b"") -> bytes:
    hdr = struct.pack(
        "!HHIIBHHHH",
        src_port, dst_port,
        seq,
        ack,
        0x50,       # data offset = 5 (20 bytes), reserved = 0
        flags,
        window,
        0,          # checksum (omitted)
        0,          # urgent pointer
    )
    return hdr + payload


def _udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return hdr + payload


def _dns_name(domain: str) -> bytes:
    """Encode a domain name in DNS wire format (length-prefixed labels + null)."""
    out = b""
    for label in domain.encode().split(b"."):
        out += bytes([len(label)]) + label
    return out + b"\x00"


def dns_query(txid: int, domain: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet (header + single question)."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _dns_name(domain) + struct.pack("!HH", qtype, 1)
    return header + question


def dns_nxdomain(txid: int, domain: str, qtype: int = 1) -> bytes:
    """Build a DNS NXDOMAIN response (no answer records)."""
    # flags: QR=1, RD=1, RA=1, RCODE=3 → 0x8183
    header = struct.pack("!HHHHHH", txid, 0x8183, 1, 0, 0, 0)
    question = _dns_name(domain) + struct.pack("!HH", qtype, 1)
    return header + question


def http_request(method: str = "GET", uri: str = "/", host: str = "example.com") -> bytes:
    return (
        f"{method} {uri} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()


def http_response(status: int = 200, body: str = "OK") -> bytes:
    return (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: text/plain\r\n\r\n"
        f"{body}"
    ).encode()


# ── High-level Packet factories ────────────────────────────────────────────────

@dataclass
class Packet:
    """An Ethernet frame ready to be embedded in a PCAP file."""
    data: bytes
    ts_sec: int = 1_700_000_000
    ts_usec: int = 0

    # ── TCP helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
            flags: int, seq: int = 0, ack: int = 0,
            payload: bytes = b"", ts: float = 1_700_000_000.0,
            src_mac: bytes = _MAC_CLIENT, dst_mac: bytes = _MAC_SERVER,
            ttl: int = 64, pkt_id: int = 1) -> "Packet":
        tcp_data = _tcp(src_port, dst_port, flags, seq, ack, payload=payload)
        ip_data = _ipv4(src_ip, dst_ip, 6, tcp_data, ttl=ttl, pkt_id=pkt_id)
        eth_data = _eth(src_mac, dst_mac, 0x0800, ip_data)
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        return Packet(data=eth_data, ts_sec=ts_sec, ts_usec=ts_usec)

    @staticmethod
    def tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                stream: int = 0, seq: int = 1000, ts: float = 1_700_000_000.0) -> "Packet":
        return Packet.tcp(src_ip, dst_ip, src_port, dst_port, F_SYN, seq=seq, ts=ts)

    @staticmethod
    def tcp_synack(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                   seq: int = 2000, ack: int = 1001, ts: float = 1_700_000_000.1) -> "Packet":
        return Packet.tcp(src_ip, dst_ip, src_port, dst_port, F_SYN | F_ACK,
                          seq=seq, ack=ack, ts=ts,
                          src_mac=_MAC_SERVER, dst_mac=_MAC_CLIENT)

    @staticmethod
    def tcp_ack(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                seq: int = 1001, ack: int = 2001, ts: float = 1_700_000_000.2) -> "Packet":
        return Packet.tcp(src_ip, dst_ip, src_port, dst_port, F_ACK,
                          seq=seq, ack=ack, ts=ts)

    @staticmethod
    def tcp_data(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 seq: int = 1001, ack: int = 2001, payload: bytes = b"hello",
                 ts: float = 1_700_000_000.3) -> "Packet":
        return Packet.tcp(src_ip, dst_ip, src_port, dst_port, F_PSH | F_ACK,
                          seq=seq, ack=ack, payload=payload, ts=ts)

    @staticmethod
    def tcp_fin(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                seq: int = 1006, ack: int = 2001, ts: float = 1_700_000_000.4) -> "Packet":
        return Packet.tcp(src_ip, dst_ip, src_port, dst_port, F_FIN | F_ACK,
                          seq=seq, ack=ack, ts=ts)

    @staticmethod
    def tcp_rst(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                seq: int = 0, ts: float = 1_700_000_000.0) -> "Packet":
        return Packet.tcp(src_ip, dst_ip, src_port, dst_port, F_RST | F_ACK,
                          seq=seq, ts=ts)

    # ── UDP / DNS helpers ────────────────────────────────────────────────────

    @staticmethod
    def udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
            payload: bytes, ts: float = 1_700_000_000.0,
            src_mac: bytes = _MAC_CLIENT, dst_mac: bytes = _MAC_RESOLVER) -> "Packet":
        udp_data = _udp(src_port, dst_port, payload)
        ip_data = _ipv4(src_ip, dst_ip, 17, udp_data)
        eth_data = _eth(src_mac, dst_mac, 0x0800, ip_data)
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        return Packet(data=eth_data, ts_sec=ts_sec, ts_usec=ts_usec)

    @staticmethod
    def dns_query_pkt(client: str, resolver: str, txid: int, domain: str,
                      ts: float = 1_700_000_000.0) -> "Packet":
        payload = dns_query(txid, domain)
        return Packet.udp(client, resolver, 53001, 53, payload, ts=ts)

    @staticmethod
    def dns_nxdomain_pkt(resolver: str, client: str, txid: int, domain: str,
                         ts: float = 1_700_000_000.05) -> "Packet":
        payload = dns_nxdomain(txid, domain)
        return Packet.udp(resolver, client, 53, 53001, payload, ts=ts,
                          src_mac=_MAC_RESOLVER, dst_mac=_MAC_CLIENT)


# ── PcapBuilder ───────────────────────────────────────────────────────────────

class PcapBuilder:
    """Accumulates Packet objects and serialises them as a pcap byte string."""

    def __init__(self) -> None:
        self._packets: List[Packet] = []

    def add(self, *packets: Packet) -> "PcapBuilder":
        self._packets.extend(packets)
        return self

    def build(self) -> bytes:
        # Global header
        buf = struct.pack(
            "<IHHiIII",
            _PCAP_MAGIC,
            2,          # version major
            4,          # version minor
            0,          # timezone offset (UTC)
            0,          # timestamp accuracy
            65535,      # snapshot length
            _LINK_TYPE_ETHERNET,
        )
        for pkt in self._packets:
            n = len(pkt.data)
            buf += struct.pack("<IIII", pkt.ts_sec, pkt.ts_usec, n, n)
            buf += pkt.data
        return buf

    def packet_count(self) -> int:
        return len(self._packets)
