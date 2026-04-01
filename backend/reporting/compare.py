"""
Semantic diff engine for PCAP analysis captures.

Beyond counting finding deltas, this engine detects:
  - Behavioral regression: hosts that changed role between captures
  - New attacker patterns: first-time high-severity findings from a specific source
  - Severity escalation: findings that worsened (medium→critical, low→high)
  - Severity improvement: findings that resolved or de-escalated
  - Host anomaly drift: hosts whose anomaly score increased substantially
  - New external communicants: IPs that appeared in B that were absent in A
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _pct_change(old: float, new: float) -> str:
    if old == 0:
        return "+∞" if new > 0 else "0%"
    delta = (new - old) / old * 100
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:.1f}%"


def _findings_by_rule(findings: List[Dict]) -> Dict[str, Dict]:
    """Index findings by rule_id → highest-severity instance."""
    index: Dict[str, Dict] = {}
    for f in findings:
        rid = f.get("rule_id") or f.get("title", "")
        if not rid:
            continue
        existing = index.get(rid)
        if existing is None:
            index[rid] = f
        else:
            # Keep the worse-severity instance
            if _SEV_ORDER.get(f.get("severity", "info"), 0) > _SEV_ORDER.get(
                existing.get("severity", "info"), 0
            ):
                index[rid] = f
    return index


def _hosts_by_ip(hosts: List[Dict]) -> Dict[str, Dict]:
    return {h["ip"]: h for h in hosts if h.get("ip")}


def compare(result_a: Dict[str, Any], result_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two analysis result dicts (A = baseline, B = incident/current).
    Returns a structured diff with semantic regression signals.
    """
    diff: Dict[str, Any] = {}

    # ── File metadata ──────────────────────────────────────────────────────────
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

    # ── Finding delta ──────────────────────────────────────────────────────────
    ic_a = result_a.get("issue_counts", {})
    ic_b = result_b.get("issue_counts", {})
    diff["issue_delta"] = {
        "critical": ic_b.get("critical", 0) - ic_a.get("critical", 0),
        "high": ic_b.get("high", 0) - ic_a.get("high", 0),
        "total": ic_b.get("total", 0) - ic_a.get("total", 0),
        "a_total": ic_a.get("total", 0),
        "b_total": ic_b.get("total", 0),
    }

    # ── Finding-level diff ─────────────────────────────────────────────────────
    findings_a = result_a.get("all_issues", [])
    findings_b = result_b.get("all_issues", [])
    titles_a: Set[str] = {f["title"] for f in findings_a}
    titles_b: Set[str] = {f["title"] for f in findings_b}

    diff["new_findings"] = [f for f in findings_b if f["title"] not in titles_a]
    diff["resolved_findings"] = [f for f in findings_a if f["title"] not in titles_b]

    # ── Severity escalation / improvement ─────────────────────────────────────
    # Rule IDs present in both; compare worst-severity instances
    rules_a = _findings_by_rule(findings_a)
    rules_b = _findings_by_rule(findings_b)
    common_rules = set(rules_a) & set(rules_b)

    escalated: List[Dict] = []
    improved: List[Dict] = []

    for rid in common_rules:
        f_a = rules_a[rid]
        f_b = rules_b[rid]
        sev_a = _SEV_ORDER.get(f_a.get("severity", "info"), 0)
        sev_b = _SEV_ORDER.get(f_b.get("severity", "info"), 0)
        if sev_b > sev_a:
            escalated.append({
                "rule_id": rid,
                "title": f_b.get("title", rid),
                "severity_a": f_a.get("severity"),
                "severity_b": f_b.get("severity"),
                "affected_hosts": f_b.get("affected_hosts", []),
            })
        elif sev_b < sev_a:
            improved.append({
                "rule_id": rid,
                "title": f_a.get("title", rid),
                "severity_a": f_a.get("severity"),
                "severity_b": f_b.get("severity"),
            })

    diff["severity_escalations"] = escalated
    diff["severity_improvements"] = improved

    # ── Behavioral regression signals ─────────────────────────────────────────
    hosts_a = _hosts_by_ip(result_a.get("hosts", []))
    hosts_b = _hosts_by_ip(result_b.get("hosts", []))
    common_ips = set(hosts_a) & set(hosts_b)

    role_changes: List[Dict] = []
    anomaly_spikes: List[Dict] = []

    for ip in common_ips:
        h_a = hosts_a[ip]
        h_b = hosts_b[ip]
        role_a = h_a.get("role", "unknown")
        role_b = h_b.get("role", "unknown")
        if role_a != role_b and role_b != "unknown":
            role_changes.append({
                "ip": ip,
                "role_a": role_a,
                "role_b": role_b,
                "anomaly_score_b": h_b.get("anomaly_score", 0),
                "suspicious_behaviors": h_b.get("suspicious_behaviors", []),
            })

        score_a = h_a.get("anomaly_score", 0)
        score_b = h_b.get("anomaly_score", 0)
        if score_b >= 3.0 and (score_b - score_a) >= 2.0:
            anomaly_spikes.append({
                "ip": ip,
                "score_a": round(score_a, 2),
                "score_b": round(score_b, 2),
                "delta": round(score_b - score_a, 2),
                "role_b": h_b.get("role", "unknown"),
                "suspicious_behaviors": h_b.get("suspicious_behaviors", []),
            })

    diff["role_changes"] = sorted(role_changes, key=lambda x: -x["anomaly_score_b"])
    diff["anomaly_spikes"] = sorted(anomaly_spikes, key=lambda x: -x["delta"])

    # ── New / removed hosts ────────────────────────────────────────────────────
    ips_a = set(hosts_a)
    ips_b = set(hosts_b)
    diff["new_hosts"] = sorted(ips_b - ips_a)
    diff["removed_hosts"] = sorted(ips_a - ips_b)

    # Enrich new hosts with their profile from B
    diff["new_host_profiles"] = [
        {
            "ip": ip,
            "role": hosts_b[ip].get("role", "unknown"),
            "anomaly_score": hosts_b[ip].get("anomaly_score", 0),
            "suspicious_behaviors": hosts_b[ip].get("suspicious_behaviors", []),
            "unique_dst_ports": hosts_b[ip].get("unique_dst_ports", 0),
        }
        for ip in diff["new_hosts"]
    ]

    # ── Protocol delta ─────────────────────────────────────────────────────────
    ps_a = result_a.get("protocol_stats", {})
    ps_b = result_b.get("protocol_stats", {})
    all_protos = set(ps_a) | set(ps_b)
    proto_delta = {}
    for p in all_protos:
        a_c = ps_a.get(p, 0)
        b_c = ps_b.get(p, 0)
        if abs(b_c - a_c) > 10:
            proto_delta[p] = {
                "a": a_c, "b": b_c,
                "change": _pct_change(a_c, b_c),
            }
    diff["protocol_delta"] = dict(sorted(
        proto_delta.items(),
        key=lambda x: abs(x[1]["b"] - x[1]["a"]),
        reverse=True,
    )[:20])

    # ── TCP quality delta ─────────────────────────────────────────────────────
    tcp_a = result_a.get("tcp", {})
    tcp_b = result_b.get("tcp", {})
    diff["tcp_delta"] = {
        "retransmissions": {
            "a": tcp_a.get("retransmissions", 0),
            "b": tcp_b.get("retransmissions", 0),
            "change": _pct_change(tcp_a.get("retransmissions", 0), tcp_b.get("retransmissions", 0)),
        },
        "failed_handshakes": {
            "a": tcp_a.get("failed_handshakes", 0),
            "b": tcp_b.get("failed_handshakes", 0),
        },
        "zero_windows": {
            "a": tcp_a.get("zero_windows", 0),
            "b": tcp_b.get("zero_windows", 0),
        },
    }

    # ── DNS delta ─────────────────────────────────────────────────────────────
    dns_a = result_a.get("dns", {}) or {}
    dns_b = result_b.get("dns", {}) or {}
    if dns_a or dns_b:
        diff["dns_delta"] = {
            "nxdomain": {
                "a": dns_a.get("nxdomain_count", 0),
                "b": dns_b.get("nxdomain_count", 0),
            },
            "avg_rtt_ms": {
                "a": round(dns_a.get("avg_rtt_ms", 0), 2),
                "b": round(dns_b.get("avg_rtt_ms", 0), 2),
            },
        }

    # ── Semantic verdict ──────────────────────────────────────────────────────
    # Produce a ranked list of regression signals
    signals: List[str] = []

    if escalated:
        names = ", ".join(e["title"] for e in escalated[:3])
        signals.append(
            f"SEVERITY ESCALATION: {len(escalated)} finding(s) worsened — {names}"
        )
    if diff["issue_delta"]["critical"] > 0:
        signals.append(
            f"NEW CRITICAL: {diff['issue_delta']['critical']} more critical finding(s) in B"
        )
    if role_changes:
        for rc in role_changes[:3]:
            signals.append(
                f"ROLE CHANGE: {rc['ip']} changed from {rc['role_a']} → {rc['role_b']}"
                + (f" (anomaly {rc['anomaly_score_b']:.1f})" if rc["anomaly_score_b"] > 0 else "")
            )
    if anomaly_spikes:
        for spike in anomaly_spikes[:3]:
            signals.append(
                f"ANOMALY SPIKE: {spike['ip']} score {spike['score_a']:.1f} → {spike['score_b']:.1f}"
                f" (+{spike['delta']:.1f})"
            )
    if diff["new_findings"]:
        signals.append(f"NEW FINDINGS: {len(diff['new_findings'])} entirely new finding(s) in B")
    if diff["resolved_findings"]:
        signals.append(
            f"RESOLVED: {len(diff['resolved_findings'])} finding(s) no longer present in B"
        )
    if improved:
        signals.append(f"IMPROVED: {len(improved)} finding(s) de-escalated in B")
    if diff["new_hosts"]:
        signals.append(
            f"NEW HOSTS: {len(diff['new_hosts'])} host(s) observed in B not seen in A"
        )
    if not signals:
        signals.append("No significant behavioral changes detected between captures.")

    diff["regression_signals"] = signals
    diff["comparison_summary"] = signals[0] if signals else "No significant changes."

    return diff
