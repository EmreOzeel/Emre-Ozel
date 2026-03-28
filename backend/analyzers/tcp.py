"""TCP session reconstruction and issue detection."""
from collections import defaultdict
from typing import List, Dict, Any


def analyze(packets: List[Dict]) -> Dict[str, Any]:
    streams: Dict[str, Dict] = {}
    issues = []
    retrans_total = 0
    dup_ack_total = 0
    rst_total = 0
    zero_window_total = 0
    out_of_order_total = 0
    failed_handshakes = 0

    # Per-stream state
    stream_state: Dict[str, Dict] = defaultdict(lambda: {
        "syn": False, "synack": False, "fin": False, "rst": False,
        "retrans": 0, "dup_ack": 0, "packets": 0, "bytes": 0,
        "src_ip": "", "dst_ip": "", "src_port": "", "dst_port": "",
        "start_ts": None, "end_ts": None,
    })

    for pkt in packets:
        stream_id = pkt.get("tcp.stream", "")
        if not stream_id:
            continue

        ts_str = pkt.get("frame.time_epoch", "0")
        try:
            ts = float(ts_str)
        except ValueError:
            ts = 0.0

        st = stream_state[stream_id]
        st["packets"] += 1
        try:
            st["bytes"] += int(pkt.get("tcp.len", "0") or 0)
        except ValueError:
            pass

        if st["start_ts"] is None:
            st["start_ts"] = ts
            st["src_ip"] = pkt.get("ip.src", pkt.get("ipv6.src", ""))
            st["dst_ip"] = pkt.get("ip.dst", pkt.get("ipv6.dst", ""))
            st["src_port"] = pkt.get("tcp.srcport", "")
            st["dst_port"] = pkt.get("tcp.dstport", "")
        st["end_ts"] = ts

        syn = pkt.get("tcp.flags.syn") == "1"
        ack = pkt.get("tcp.flags.ack") == "1"
        fin = pkt.get("tcp.flags.fin") == "1"
        rst = pkt.get("tcp.flags.rst") == "1"

        if syn and not ack:
            st["syn"] = True
        if syn and ack:
            st["synack"] = True
        if fin:
            st["fin"] = True
        if rst:
            st["rst"] = True
            rst_total += 1

        if "tcp.analysis.retransmission" in pkt or "tcp.analysis.fast_retransmission" in pkt:
            st["retrans"] += 1
            retrans_total += 1
        if "tcp.analysis.duplicate_ack" in pkt:
            st["dup_ack"] += 1
            dup_ack_total += 1
        if "tcp.analysis.zero_window" in pkt:
            zero_window_total += 1
        if "tcp.analysis.out_of_order" in pkt:
            out_of_order_total += 1

    sessions = []
    for stream_id, st in stream_state.items():
        if st["packets"] == 0:
            continue
        dur = (st["end_ts"] - st["start_ts"]) if st["start_ts"] and st["end_ts"] else 0

        state = "unknown"
        if st["rst"]:
            state = "reset"
        elif st["syn"] and st["synack"] and st["fin"]:
            state = "fin-closed"
        elif st["syn"] and st["synack"]:
            state = "established"
        elif st["syn"] and not st["synack"]:
            state = "half-open"
            failed_handshakes += 1

        sessions.append({
            "stream_id": stream_id,
            "src_ip": st["src_ip"],
            "dst_ip": st["dst_ip"],
            "src_port": st["src_port"],
            "dst_port": st["dst_port"],
            "state": state,
            "packets": st["packets"],
            "bytes": st["bytes"],
            "retrans": st["retrans"],
            "dup_ack": st["dup_ack"],
            "has_rst": st["rst"],
            "has_fin": st["fin"],
            "duration_sec": round(dur, 3),
        })

    sessions.sort(key=lambda x: -x["bytes"])

    # Generate issues
    if retrans_total > 50:
        sev = "critical" if retrans_total > 200 else "warning"
        issues.append({
            "severity": sev, "category": "tcp",
            "title": "High Retransmission Count",
            "description": (
                f"{retrans_total} TCP retransmission detected. "
                "This indicates packet loss, network congestion, or an unstable connection. "
                "Significant retransmissions can cause application slowdowns and timeouts."
            ),
            "count": retrans_total,
        })

    if rst_total > 20:
        sev = "critical" if rst_total > 100 else "warning"
        issues.append({
            "severity": sev, "category": "tcp",
            "title": "Excessive TCP RST Packets",
            "description": (
                f"{rst_total} RST (Reset) packets detected. "
                "RST packets abruptly terminate connections. "
                "High RST counts suggest firewall blocks, application crashes, or deliberate connection teardown."
            ),
            "count": rst_total,
        })

    if failed_handshakes > 10:
        sev = "critical" if failed_handshakes > 50 else "warning"
        issues.append({
            "severity": sev, "category": "tcp",
            "title": "Failed TCP Handshakes",
            "description": (
                f"{failed_handshakes} TCP connection attempts did not receive SYN-ACK. "
                "Possible causes: server unreachable, firewall dropping packets, or port scan activity."
            ),
            "count": failed_handshakes,
        })

    if dup_ack_total > 30:
        issues.append({
            "severity": "warning", "category": "tcp",
            "title": "Duplicate ACKs Detected",
            "description": (
                f"{dup_ack_total} duplicate ACK packets found. "
                "Duplicate ACKs signal missing segments and often precede fast retransmission."
            ),
            "count": dup_ack_total,
        })

    if zero_window_total > 10:
        issues.append({
            "severity": "warning", "category": "tcp",
            "title": "TCP Zero Window",
            "description": (
                f"{zero_window_total} TCP Zero Window advertisements. "
                "The receiver's buffer is full — indicates the application cannot process data fast enough."
            ),
            "count": zero_window_total,
        })

    # Top retransmitting streams
    high_retrans = sorted([s for s in sessions if s["retrans"] >= 5], key=lambda x: -x["retrans"])[:5]
    for s in high_retrans:
        if not any(i.get("stream_id") == s["stream_id"] for i in issues):
            issues.append({
                "severity": "warning", "category": "tcp",
                "title": f"High Retransmissions on Stream",
                "description": (
                    f"Stream {s['src_ip']}:{s['src_port']} → {s['dst_ip']}:{s['dst_port']} "
                    f"has {s['retrans']} retransmissions. This specific flow is experiencing packet loss."
                ),
                "count": s["retrans"],
                "stream_id": s["stream_id"],
            })

    return {
        "sessions": sessions[:200],
        "total_sessions": len(sessions),
        "retransmissions": retrans_total,
        "duplicate_acks": dup_ack_total,
        "resets": rst_total,
        "zero_windows": zero_window_total,
        "out_of_order": out_of_order_total,
        "failed_handshakes": failed_handshakes,
        "issues": issues,
    }
