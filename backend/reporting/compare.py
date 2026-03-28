"""
Capture comparison engine.
Diffs two analysis result dicts and highlights meaningful changes.
"""
from __future__ import annotations
from typing import Dict, Any, List, Set


def _pct_change(old: float, new: float) -> str:
    if old == 0:
        return "+∞" if new > 0 else "0%"
    delta = (new - old) / old * 100
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:.1f}%"


def compare(result_a: Dict[str, Any], result_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two analysis result dicts (capture A = baseline, capture B = new).
    Returns a diff dict highlighting significant changes.
    """
    diff: Dict[str, Any] = {}

    # ── File info ──────────────────────────────────────────────────────────────
    fi_a = result_a.get("file_info", {})
    fi_b = result_b.get("file_info", {})
    diff["file_comparison"] = {
        "a": {
            "filename": fi_a.get("filename", "capture_a"),
            "packets": fi_a.get("total_packets", 0),
            "duration_sec": fi_a.get("duration_sec", 0),
            "size_bytes": fi_a.get("file_size_bytes", 0),
        },
        "b": {
            "filename": fi_b.get("filename", "capture_b"),
            "packets": fi_b.get("total_packets", 0),
            "duration_sec": fi_b.get("duration_sec", 0),
            "size_bytes": fi_b.get("file_size_bytes", 0),
        },
    }

    # ── Issue count diff ───────────────────────────────────────────────────────
    ic_a = result_a.get("issue_counts", {})
    ic_b = result_b.get("issue_counts", {})
    diff["issue_delta"] = {
        "critical": ic_b.get("critical", 0) - ic_a.get("critical", 0),
        "high": ic_b.get("high", 0) - ic_a.get("high", 0),
        "total": ic_b.get("total", 0) - ic_a.get("total", 0),
        "a_total": ic_a.get("total", 0),
        "b_total": ic_b.get("total", 0),
    }

    # ── New findings (in B not in A) ───────────────────────────────────────────
    titles_a: Set[str] = {f["title"] for f in result_a.get("all_issues", [])}
    new_findings = [
        f for f in result_b.get("all_issues", [])
        if f["title"] not in titles_a
    ]
    resolved_findings = [
        f for f in result_a.get("all_issues", [])
        if f["title"] not in {f2["title"] for f2 in result_b.get("all_issues", [])}
    ]
    diff["new_findings"] = new_findings
    diff["resolved_findings"] = resolved_findings

    # ── Protocol distribution change ───────────────────────────────────────────
    ps_a = result_a.get("protocol_stats", {})
    ps_b = result_b.get("protocol_stats", {})
    all_protos = set(ps_a) | set(ps_b)
    proto_delta = {}
    for p in all_protos:
        a_count = ps_a.get(p, 0)
        b_count = ps_b.get(p, 0)
        if abs(b_count - a_count) > 10:
            proto_delta[p] = {
                "a": a_count, "b": b_count,
                "change": _pct_change(a_count, b_count),
            }
    diff["protocol_delta"] = dict(sorted(
        proto_delta.items(),
        key=lambda x: abs(x[1]["b"] - x[1]["a"]),
        reverse=True,
    )[:20])

    # ── TCP quality comparison ─────────────────────────────────────────────────
    tcp_a = result_a.get("tcp", {})
    tcp_b = result_b.get("tcp", {})
    diff["tcp_delta"] = {
        "retransmissions": {
            "a": tcp_a.get("retransmissions", 0),
            "b": tcp_b.get("retransmissions", 0),
            "change": _pct_change(tcp_a.get("retransmissions", 0), tcp_b.get("retransmissions", 0)),
        },
        "zero_windows": {
            "a": tcp_a.get("zero_windows", 0),
            "b": tcp_b.get("zero_windows", 0),
        },
        "failed_handshakes": {
            "a": tcp_a.get("failed_handshakes", 0),
            "b": tcp_b.get("failed_handshakes", 0),
        },
    }

    # ── DNS comparison ─────────────────────────────────────────────────────────
    dns_a = result_a.get("dns", {})
    dns_b = result_b.get("dns", {})
    if dns_a or dns_b:
        diff["dns_delta"] = {
            "nxdomain": {"a": dns_a.get("nxdomain_count", 0), "b": dns_b.get("nxdomain_count", 0)},
            "avg_rtt_ms": {"a": dns_a.get("avg_rtt_ms", 0), "b": dns_b.get("avg_rtt_ms", 0)},
        }

    # ── New hosts in B ─────────────────────────────────────────────────────────
    hosts_a = {h["ip"] for h in result_a.get("hosts", [])}
    hosts_b = {h["ip"] for h in result_b.get("hosts", [])}
    diff["new_hosts"] = sorted(hosts_b - hosts_a)
    diff["removed_hosts"] = sorted(hosts_a - hosts_b)

    # ── Summary sentences ──────────────────────────────────────────────────────
    summary_parts = []
    delta_crit = diff["issue_delta"]["critical"]
    if delta_crit > 0:
        summary_parts.append(f"{delta_crit} new critical finding(s) vs baseline")
    elif delta_crit < 0:
        summary_parts.append(f"{abs(delta_crit)} critical finding(s) resolved since baseline")
    if new_findings:
        summary_parts.append(f"{len(new_findings)} entirely new finding(s)")
    if resolved_findings:
        summary_parts.append(f"{len(resolved_findings)} finding(s) no longer present")
    if diff["new_hosts"]:
        summary_parts.append(f"{len(diff['new_hosts'])} new host(s) observed")
    diff["comparison_summary"] = "; ".join(summary_parts) if summary_parts else "No significant changes detected."

    return diff
