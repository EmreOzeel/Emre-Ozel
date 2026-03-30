"""
Normalization pipeline: raw tshark dicts → CaptureContext with typed models.
This is the only layer that interprets raw tshark field strings.
"""
from __future__ import annotations
import math
import hashlib
from collections import defaultdict
from typing import Dict, List, Optional

from models import (
    CaptureContext, FileInfo, PacketRecord, FlowRecord, SessionRecord,
    DnsTransaction, HttpTransaction, TlsHandshake, TCPState,
)
from normalizer.tshark import (
    check_tshark, get_file_info, get_protocol_hierarchy, get_ip_endpoints,
    get_tcp_conversations, get_expert_info, get_packets,
)


def _i(d: dict, key: str, default: int = 0) -> int:
    try:
        return int(d.get(key, default) or default)
    except (ValueError, TypeError):
        return default


def _f(d: dict, key: str, default: float = 0.0) -> float:
    try:
        return float(d.get(key, default) or default)
    except (ValueError, TypeError):
        return default


def _bool(d: dict, key: str) -> bool:
    return d.get(key, "0") == "1"


def _str(d: dict, key: str) -> str:
    return (d.get(key) or "").strip()


# ── Packet normalization ──────────────────────────────────────────────────────

def _normalize_packet(raw: Dict[str, str]) -> Optional[PacketRecord]:
    num = _i(raw, "frame.number")
    ts = _f(raw, "frame.time_epoch")
    if not num or not ts:
        return None

    src_ip = _str(raw, "ip.src") or _str(raw, "ipv6.src")
    dst_ip = _str(raw, "ip.dst") or _str(raw, "ipv6.dst")

    proto_stack = _str(raw, "frame.protocols")
    if "tcp" in proto_stack:
        top_proto = "TCP"
        if "http" in proto_stack:
            top_proto = "HTTP"
        elif "tls" in proto_stack or "ssl" in proto_stack:
            top_proto = "TLS"
        elif "ssh" in proto_stack:
            top_proto = "SSH"
        elif "smtp" in proto_stack:
            top_proto = "SMTP"
        elif "ftp" in proto_stack:
            top_proto = "FTP"
        elif "smb" in proto_stack:
            top_proto = "SMB"
        elif "kerberos" in proto_stack:
            top_proto = "Kerberos"
        elif "rdp" in proto_stack:
            top_proto = "RDP"
    elif "udp" in proto_stack:
        top_proto = "UDP"
        if "dns" in proto_stack:
            top_proto = "DNS"
        elif "dhcp" in proto_stack or "bootp" in proto_stack:
            top_proto = "DHCP"
        elif "ntp" in proto_stack:
            top_proto = "NTP"
        elif "snmp" in proto_stack:
            top_proto = "SNMP"
        elif "sip" in proto_stack:
            top_proto = "SIP"
        elif "quic" in proto_stack:
            top_proto = "QUIC"
    elif "icmp" in proto_stack:
        top_proto = "ICMP"
    elif "arp" in proto_stack:
        top_proto = "ARP"
    else:
        top_proto = proto_stack.split(":")[-1].upper() if proto_stack else "UNKNOWN"

    src_port = _i(raw, "tcp.srcport") or _i(raw, "udp.srcport")
    dst_port = _i(raw, "tcp.dstport") or _i(raw, "udp.dstport")

    pkt = PacketRecord(
        num=num,
        ts=ts,
        frame_len=_i(raw, "frame.len"),
        protocol=top_proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        ip_ttl=_i(raw, "ip.ttl") or _i(raw, "ipv6.hlim"),
        ip_proto=_i(raw, "ip.proto"),
        # TCP
        tcp_stream=_i(raw, "tcp.stream", -1),
        tcp_flags_syn=_bool(raw, "tcp.flags.syn"),
        tcp_flags_ack=_bool(raw, "tcp.flags.ack"),
        tcp_flags_fin=_bool(raw, "tcp.flags.fin"),
        tcp_flags_rst=_bool(raw, "tcp.flags.rst"),
        tcp_flags_psh=_bool(raw, "tcp.flags.psh"),
        tcp_flags_urg=_bool(raw, "tcp.flags.urg"),
        tcp_seq=_i(raw, "tcp.seq"),
        tcp_ack=_i(raw, "tcp.ack"),
        tcp_window=_i(raw, "tcp.window_size_value"),
        tcp_payload_len=_i(raw, "tcp.len"),
        # TCP expert
        retransmission=_bool(raw, "tcp.analysis.retransmission"),
        dup_ack=_bool(raw, "tcp.analysis.duplicate_ack"),
        out_of_order=_bool(raw, "tcp.analysis.out_of_order"),
        fast_retransmit=_bool(raw, "tcp.analysis.fast_retransmission"),
        zero_window=_bool(raw, "tcp.analysis.zero_window"),
        keep_alive=_bool(raw, "tcp.analysis.keep_alive"),
        # Layers present
        has_dns="dns" in proto_stack,
        has_http="http" in proto_stack and "http2" not in proto_stack,
        has_tls="tls" in proto_stack or "ssl" in proto_stack,
        has_arp="arp" in proto_stack,
        has_icmp="icmp" in proto_stack,
        has_dhcp="dhcp" in proto_stack or "bootp" in proto_stack,
        extras=raw,
    )
    return pkt


# ── Flow building ─────────────────────────────────────────────────────────────

def _build_flows(packets: List[PacketRecord]) -> Dict[str, FlowRecord]:
    flows: Dict[str, FlowRecord] = {}
    for pkt in packets:
        if not pkt.src_ip or not pkt.dst_ip:
            continue
        key = pkt.flow_key
        if key not in flows:
            flows[key] = FlowRecord(
                key=key,
                proto=pkt.ip_proto,
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                first_seen=pkt.ts,
                last_seen=pkt.ts,
                tcp_stream=pkt.tcp_stream,
            )
        fl = flows[key]
        fl.last_seen = max(fl.last_seen, pkt.ts)
        fl.packet_nums.append(pkt.num)

        # Direction detection
        if pkt.src_ip == fl.src_ip:
            fl.fwd_packets += 1
            fl.fwd_bytes += pkt.frame_len
        else:
            fl.rev_packets += 1
            fl.rev_bytes += pkt.frame_len

        # Quality counters
        if pkt.retransmission:
            fl.retransmissions += 1
        if pkt.dup_ack:
            fl.dup_acks += 1
        if pkt.out_of_order:
            fl.out_of_order += 1
        if pkt.zero_window:
            fl.zero_windows += 1

        # RTT sample
        rtt_str = pkt.extras.get("tcp.analysis.ack_rtt", "")
        if rtt_str:
            try:
                fl.rtt_samples.append(float(rtt_str))
            except ValueError:
                pass

        # Layer flags
        if pkt.has_dns:
            fl.has_dns = True
        if pkt.has_http:
            fl.has_http = True
        if pkt.has_tls:
            fl.has_tls = True

    return flows


# ── Session building (TCP) ────────────────────────────────────────────────────

def _build_sessions(packets: List[PacketRecord]) -> Dict[int, SessionRecord]:
    sessions: Dict[int, SessionRecord] = {}
    # Fallback: when tcp.stream is absent, group by bidirectional 4-tuple
    _fallback_map: Dict[str, int] = {}
    _next_fallback = -100_000

    for pkt in packets:
        if pkt.tcp_stream < 0:
            # Only create fallback sessions for actual TCP packets
            if pkt.ip_proto != 6:
                continue
            if not (pkt.src_ip and pkt.dst_ip and pkt.src_port and pkt.dst_port):
                continue
            # Assign a stable synthetic stream ID based on the 4-tuple
            a = (pkt.src_ip, pkt.src_port)
            b = (pkt.dst_ip, pkt.dst_port)
            lo, hi = (a, b) if a <= b else (b, a)
            fkey = f"{lo[0]}:{lo[1]}|{hi[0]}:{hi[1]}"
            if fkey not in _fallback_map:
                _fallback_map[fkey] = _next_fallback
                _next_fallback -= 1
            sid = _fallback_map[fkey]
        else:
            sid = pkt.tcp_stream
        if sid not in sessions:
            sessions[sid] = SessionRecord(
                stream_id=sid,
                flow_key=pkt.flow_key,
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                first_data_ts=pkt.ts,
                last_ts=pkt.ts,
            )
        sess = sessions[sid]
        sess.last_ts = max(sess.last_ts, pkt.ts)
        sess.packet_nums.append(pkt.num)

        # Direction
        if pkt.src_ip == sess.src_ip:
            sess.bytes_sent += pkt.frame_len
            sess.packets_sent += 1
        else:
            sess.bytes_recv += pkt.frame_len
            sess.packets_recv += 1

        # State machine
        if pkt.tcp_flags_syn and not pkt.tcp_flags_ack:
            sess.has_syn = True
            sess.syn_ts = pkt.ts
        elif pkt.tcp_flags_syn and pkt.tcp_flags_ack:
            sess.has_synack = True
            sess.synack_ts = pkt.ts
        elif pkt.tcp_flags_fin:
            sess.has_fin = True
            sess.fin_ts = pkt.ts
        elif pkt.tcp_flags_rst:
            sess.has_rst = True

        # Quality
        if pkt.retransmission:
            sess.retransmissions += 1
        if pkt.dup_ack:
            sess.dup_acks += 1
        if pkt.zero_window:
            sess.zero_windows += 1
        if pkt.out_of_order:
            sess.out_of_order += 1
        if pkt.fast_retransmit:
            sess.fast_retransmits += 1

    # Finalize states
    for sess in sessions.values():
        if sess.has_rst:
            sess.state = TCPState.RESET
        elif sess.has_fin:
            sess.state = TCPState.FIN_CLOSED
        elif sess.has_syn and sess.has_synack:
            sess.state = TCPState.ESTABLISHED
        elif sess.has_syn and not sess.has_synack:
            sess.state = TCPState.HALF_OPEN
        else:
            sess.state = TCPState.MID_STREAM

    return sessions


# ── DNS transaction building ──────────────────────────────────────────────────

def _label_entropy(name: str) -> float:
    """Shannon entropy of the longest domain label."""
    labels = name.rstrip(".").split(".")
    longest = max(labels, key=len) if labels else ""
    if not longest:
        return 0.0
    from collections import Counter
    counts = Counter(longest.lower())
    total = len(longest)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def _build_dns_transactions(packets: List[PacketRecord]) -> List[DnsTransaction]:
    # Map txid+resolver → pending query
    pending: Dict[str, DnsTransaction] = {}
    completed: List[DnsTransaction] = []

    for pkt in packets:
        if not pkt.has_dns:
            continue
        raw = pkt.extras
        txid_str = raw.get("dns.id", "")
        is_response = raw.get("dns.flags.response", "0") == "1"
        qname = _str(raw, "dns.qry.name").lower()
        qtype = _str(raw, "dns.qry.type")
        rcode = _str(raw, "dns.flags.rcode")
        src = pkt.src_ip
        dst = pkt.dst_ip

        if not txid_str:
            continue
        try:
            txid = int(txid_str, 16) if txid_str.startswith("0x") else int(txid_str)
        except ValueError:
            continue

        if not is_response:
            # Query
            key = f"{src}-{dst}-{txid}-{qname}"
            tx = DnsTransaction(
                txid=txid,
                query_pkt=pkt.num,
                ts_query=pkt.ts,
                client_ip=src,
                resolver_ip=dst,
                qname=qname,
                qtype=qtype,
            )
            if qname:
                tx.label_entropy = _label_entropy(qname)
                labels = qname.rstrip(".").split(".")
                tx.label_length = max(len(l) for l in labels) if labels else 0
                tx.subdomain_depth = max(0, len(labels) - 2)
            pending[key] = tx
        else:
            # Response — match to query
            matched = None
            for k, tx in list(pending.items()):
                if tx.txid == txid and tx.resolver_ip == src and tx.client_ip == dst:
                    matched = k
                    break
            if matched:
                tx = pending.pop(matched)
                tx.response_pkt = pkt.num
                tx.ts_response = pkt.ts
                tx.rcode = rcode
                tx.is_nxdomain = (rcode == "3")
                tx.is_servfail = (rcode == "2")
                tx.is_truncated = raw.get("dns.flags.truncated", "0") == "1"
                # Answers
                a = _str(raw, "dns.a")
                aaaa = _str(raw, "dns.aaaa")
                cname = _str(raw, "dns.cname")
                if a:
                    tx.answers.extend(a.split("|"))
                if aaaa:
                    tx.answers.extend(aaaa.split("|"))
                if cname:
                    tx.answers.extend(cname.split("|"))
                # TTL
                ttl_str = _str(raw, "dns.resp.ttl")
                if ttl_str:
                    for t in ttl_str.split("|"):
                        try:
                            tx.ttls.append(int(t))
                        except ValueError:
                            pass
                # RTT
                rtt_str = _str(raw, "dns.time")
                if rtt_str:
                    try:
                        tx.rtt_ms = float(rtt_str) * 1000
                    except ValueError:
                        pass
                else:
                    tx.rtt_ms = (tx.ts_response - tx.ts_query) * 1000
                completed.append(tx)

    # Add unanswered queries
    for tx in pending.values():
        completed.append(tx)

    return completed


# ── HTTP transaction building ─────────────────────────────────────────────────

def _build_http_transactions(packets: List[PacketRecord]) -> List[HttpTransaction]:
    # Key: (stream_id, request_number) → pending request
    pending: Dict[str, HttpTransaction] = {}
    completed: List[HttpTransaction] = []

    for pkt in packets:
        if not pkt.has_http:
            continue
        raw = pkt.extras
        stream = pkt.tcp_stream
        req_num = _str(raw, "http.request_number") or "0"
        key = f"{stream}-{req_num}"

        if "http.request.method" in raw:
            tx = HttpTransaction(
                stream_id=stream,
                request_pkt=pkt.num,
                ts_request=pkt.ts,
                client_ip=pkt.src_ip,
                server_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                method=_str(raw, "http.request.method"),
                uri=_str(raw, "http.request.uri"),
                host=_str(raw, "http.host"),
                user_agent=_str(raw, "http.user_agent"),
                referrer=_str(raw, "http.referer"),
                auth_header=_str(raw, "http.authorization"),
                cookie=_str(raw, "http.cookie"),
                content_type_req=_str(raw, "http.content_type"),
            )
            pending[key] = tx

        elif "http.response.code" in raw:
            code_str = _str(raw, "http.response.code")
            try:
                code = int(code_str)
            except ValueError:
                code = 0

            if key in pending:
                tx = pending.pop(key)
                tx.response_pkt = pkt.num
                tx.ts_response = pkt.ts
                tx.status_code = code
                tx.content_type_resp = _str(raw, "http.content_type")
                cl = _str(raw, "http.content_length")
                try:
                    tx.resp_content_length = int(cl)
                except ValueError:
                    pass
                tx.location = _str(raw, "http.location")
                tx.set_cookie = _str(raw, "http.set_cookie")
                tx.latency_ms = (tx.ts_response - tx.ts_request) * 1000
                completed.append(tx)
            else:
                # Response without matched request
                tx = HttpTransaction(
                    stream_id=stream,
                    request_pkt=0,
                    response_pkt=pkt.num,
                    ts_response=pkt.ts,
                    server_ip=pkt.src_ip,
                    client_ip=pkt.dst_ip,
                    status_code=code,
                )
                completed.append(tx)

    # Add unmatched requests
    for tx in pending.values():
        completed.append(tx)

    return completed


# ── TLS handshake building ────────────────────────────────────────────────────

_TLS_VERSIONS = {
    "0x0300": "SSLv3", "0x0301": "TLSv1.0", "0x0302": "TLSv1.1",
    "0x0303": "TLSv1.2", "0x0304": "TLSv1.3",
    "769": "TLSv1.0", "770": "TLSv1.1", "771": "TLSv1.2", "772": "TLSv1.3",
}


def _compute_ja3(raw: dict) -> str:
    """Compute JA3 fingerprint from ClientHello fields."""
    # Version
    ver_str = _str(raw, "tls.handshake.version") or _str(raw, "tls.record.version")
    try:
        ver = int(ver_str, 16) if ver_str.startswith("0x") else int(ver_str)
    except ValueError:
        ver = 0

    # Ciphersuites (all offered, pipe-separated)
    ciphers_raw = _str(raw, "tls.handshake.ciphersuites")
    ciphers = []
    for c in ciphers_raw.split("|"):
        c = c.strip()
        if not c:
            continue
        try:
            v = int(c, 16) if c.startswith("0x") else int(c)
            # Exclude GREASE values
            if not (v & 0x0F0F == 0x0A0A):
                ciphers.append(v)
        except ValueError:
            pass

    # Extensions
    exts_raw = _str(raw, "tls.handshake.extension.type")
    exts = []
    for e in exts_raw.split("|"):
        e = e.strip()
        if not e:
            continue
        try:
            v = int(e, 16) if e.startswith("0x") else int(e)
            if not (v & 0x0F0F == 0x0A0A):
                exts.append(v)
        except ValueError:
            pass

    # Elliptic curves
    curves_raw = _str(raw, "tls.handshake.extensions_supported_group")
    curves = []
    for c in curves_raw.split("|"):
        c = c.strip()
        if not c:
            continue
        try:
            v = int(c, 16) if c.startswith("0x") else int(c)
            if not (v & 0x0F0F == 0x0A0A):
                curves.append(v)
        except ValueError:
            pass

    # EC point formats
    ecfmt_raw = _str(raw, "tls.handshake.extensions_ec_point_format")
    ecfmts = []
    for f in ecfmt_raw.split("|"):
        f = f.strip()
        if not f:
            continue
        try:
            ecfmts.append(int(f, 16) if f.startswith("0x") else int(f))
        except ValueError:
            pass

    ja3_str = (
        f"{ver},"
        f"{'-'.join(str(c) for c in ciphers)},"
        f"{'-'.join(str(e) for e in exts)},"
        f"{'-'.join(str(c) for c in curves)},"
        f"{'-'.join(str(f) for f in ecfmts)}"
    )
    return hashlib.md5(ja3_str.encode()).hexdigest()


def _compute_ja3s(raw: dict) -> str:
    """Compute JA3S fingerprint from ServerHello fields."""
    ver_str = _str(raw, "tls.handshake.version") or _str(raw, "tls.record.version")
    try:
        ver = int(ver_str, 16) if ver_str.startswith("0x") else int(ver_str)
    except ValueError:
        ver = 0

    cipher_str = _str(raw, "tls.handshake.ciphersuite")
    try:
        cipher = int(cipher_str, 16) if cipher_str.startswith("0x") else int(cipher_str)
    except ValueError:
        cipher = 0

    exts_raw = _str(raw, "tls.handshake.extension.type")
    exts = []
    for e in exts_raw.split("|"):
        e = e.strip()
        if not e:
            continue
        try:
            exts.append(int(e, 16) if e.startswith("0x") else int(e))
        except ValueError:
            pass

    ja3s_str = f"{ver},{cipher},{'-'.join(str(e) for e in exts)}"
    return hashlib.md5(ja3s_str.encode()).hexdigest()


def _build_tls_handshakes(packets: List[PacketRecord]) -> List[TlsHandshake]:
    # stream_id → pending handshake
    pending: Dict[int, TlsHandshake] = {}
    completed: List[TlsHandshake] = []

    for pkt in packets:
        if not pkt.has_tls:
            continue
        raw = pkt.extras
        hs_type = _str(raw, "tls.handshake.type")
        stream = pkt.tcp_stream
        if stream < 0:
            continue

        if hs_type == "1":   # ClientHello
            hs = TlsHandshake(
                stream_id=stream,
                client_pkt=pkt.num,
                ts_client=pkt.ts,
                client_ip=pkt.src_ip,
                server_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                sni=_str(raw, "tls.handshake.extensions_server_name"),
            )
            # ClientHello fields for JA3
            ver_str = _str(raw, "tls.handshake.version")
            hs.client_version = _TLS_VERSIONS.get(ver_str, ver_str)
            hs.client_ciphers = [c for c in _str(raw, "tls.handshake.ciphersuites").split("|") if c]
            hs.client_extensions = [e for e in _str(raw, "tls.handshake.extension.type").split("|") if e]
            hs.client_curves = [c for c in _str(raw, "tls.handshake.extensions_supported_group").split("|") if c]
            hs.client_ec_formats = [f for f in _str(raw, "tls.handshake.extensions_ec_point_format").split("|") if f]
            hs.ja3 = _compute_ja3(raw)
            pending[stream] = hs

        elif hs_type == "2":   # ServerHello
            if stream in pending:
                hs = pending[stream]
                hs.server_pkt = pkt.num
                hs.ts_server = pkt.ts
                ver_str = _str(raw, "tls.handshake.version")
                hs.tls_version = _TLS_VERSIONS.get(ver_str, ver_str)
                hs.cipher_suite = _str(raw, "tls.handshake.ciphersuite")
                hs.alpn = _str(raw, "tls.handshake.extensions_alpn_str")
                hs.ja3s = _compute_ja3s(raw)
                completed.append(hs)
                del pending[stream]

        # TLS alert
        alert = _str(raw, "tls.alert_message.desc")
        if alert and stream in pending:
            pending[stream].has_alert = True
            pending[stream].alert_description = alert

    # Remaining incomplete handshakes
    for hs in pending.values():
        completed.append(hs)

    return completed


# ── Main normalization pipeline ───────────────────────────────────────────────

_MAX_PACKETS = 50_000


def normalize(pcap_path: str) -> CaptureContext:
    """
    Full normalization pipeline.
    Phase 1: tshark statistics (no limit)
    Phase 2: per-packet fields (up to 50k)

    Raises RuntimeError if tshark is missing or if the file cannot be parsed.
    """
    # ── 0. Dependency check ───────────────────────────────────────────────────
    check_tshark()

    ctx = CaptureContext()

    # ── Phase 1: statistics ───────────────────────────────────────────────────
    raw_info = get_file_info(pcap_path)
    file_total = int(raw_info.get("total_packets", 0))

    if file_total == 0:
        raise RuntimeError(
            "tshark could not read any packets from the capture file. "
            "The file may be empty, corrupted, or in an unsupported format."
        )

    ctx.file_info = FileInfo(
        file_size_bytes=int(raw_info.get("file_size_bytes", 0)),
        total_packets=file_total,
        duration_sec=float(raw_info.get("duration_sec", 0)),
        first_packet=raw_info.get("first_packet", ""),
        last_packet=raw_info.get("last_packet", ""),
        encapsulation=raw_info.get("encapsulation", ""),
        avg_packet_size=float(raw_info.get("avg_packet_size", 0)),
        avg_packet_rate=float(raw_info.get("avg_packet_rate", 0)),
        avg_bit_rate=float(raw_info.get("avg_bit_rate", 0)),
    )
    ctx.protocol_stats = get_protocol_hierarchy(pcap_path)
    ctx.file_info.filename = pcap_path.rsplit("/", 1)[-1]

    # tshark aggregate stats (always fast, no limit)
    ctx.tcp_conversations = get_tcp_conversations(pcap_path)
    ctx.expert_info = get_expert_info(pcap_path)

    # ── Phase 2: per-packet (capped at 50k) ──────────────────────────────────
    raw_packets = get_packets(pcap_path, max_packets=_MAX_PACKETS)
    ctx.packets_analyzed = len(raw_packets)

    if ctx.packets_analyzed == 0:
        raise RuntimeError(
            f"tshark reported {file_total:,} packets in the file but returned no parseable "
            "packet data. This usually means all field names were rejected by this version "
            "of tshark. Check backend logs for '[tshark] attempt' lines showing which fields "
            "were removed."
        )

    # Packet count sanity check (only when the whole file was read, not truncated at 50k)
    if file_total <= _MAX_PACKETS:
        parse_ratio = ctx.packets_analyzed / file_total
        if parse_ratio < 0.5:
            raise RuntimeError(
                f"Packet parsing produced inconsistent results: "
                f"file contains {file_total:,} packets but only {ctx.packets_analyzed:,} "
                f"({parse_ratio:.0%}) were parsed. "
                "The capture may be truncated or the tshark field extraction failed."
            )

    # Normalize each packet
    for rp in raw_packets:
        pkt = _normalize_packet(rp)
        if pkt:
            ctx.packets.append(pkt)

    # Build flows, sessions, transactions
    ctx.flows = _build_flows(ctx.packets)
    ctx.sessions = _build_sessions(ctx.packets)
    ctx.dns_transactions = _build_dns_transactions(ctx.packets)
    ctx.http_transactions = _build_http_transactions(ctx.packets)
    ctx.tls_handshakes = _build_tls_handshakes(ctx.packets)

    return ctx
