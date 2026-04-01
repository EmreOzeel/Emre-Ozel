"""
Sanity checks for analysis results.

Detects contradictions between what the detection layer reported and what the
raw stats actually show — e.g. a port-scan finding when there were no SYN
packets, or a DNS-exfil finding when NXDOMAIN count is zero.

Returns a list of SanityIssue dicts included in pipeline output as
"sanity_warnings". Each issue has:
  - check_id   : machine-readable identifier
  - severity   : "warning" | "info"
  - message    : analyst-readable description of the contradiction
  - detail     : optional extra context
"""
from __future__ import annotations
from typing import Any, Dict, List


def run_sanity_checks(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run all sanity checks against the completed pipeline result dict.
    Call this after the pipeline produces its output (not inside it).
    """
    issues: List[Dict[str, Any]] = []
    findings = result.get("all_issues", [])          # active (non-suppressed)
    hosts = result.get("hosts", [])
    dns_stats = result.get("dns", {}) or {}
    tcp_stats = result.get("tcp", {}) or {}
    security_stats = result.get("security", {}) or {}

    host_ips = {h.get("ip") for h in hosts}

    for f in findings:
        rid = f.get("rule_id", "")
        affected = f.get("affected_hosts", [])
        src = affected[0] if affected else None

        # ── SCAN-001: port scan finding but no SYN packets ────────────────────
        if rid == "SCAN-001":
            total_syns = tcp_stats.get("total_sessions", 0)
            if total_syns == 0:
                issues.append({
                    "check_id": "SANITY-001",
                    "severity": "warning",
                    "message": f"SCAN-001 fired for {src} but TCP stats show 0 sessions "
                               "(no SYN packets captured). Finding may be based on incomplete capture.",
                    "detail": "Possible mid-stream capture or capture filter excluded SYN packets.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── DNS-001: DNS tunnel finding but no NXDOMAIN / query count is tiny ─
        if rid == "DNS-001":
            nxdomain_count = dns_stats.get("nxdomain_count", 0) or 0
            total_queries = dns_stats.get("total_queries", 0) or 0
            if total_queries < 5:
                issues.append({
                    "check_id": "SANITY-002",
                    "severity": "warning",
                    "message": f"DNS-001 (DNS tunnel) fired but only {total_queries} DNS queries "
                               "were observed. Tunneling requires sustained query volume — "
                               "this may be a false positive on sparse data.",
                    "detail": "Verify entropy calculation had sufficient sample size.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── DNS-002: NXDOMAIN storm finding but NXDOMAIN count is zero ────────
        if rid == "DNS-002":
            nxdomain_count = dns_stats.get("nxdomain_count", 0) or 0
            if nxdomain_count == 0:
                issues.append({
                    "check_id": "SANITY-003",
                    "severity": "warning",
                    "message": "DNS-002 (NXDOMAIN storm) fired but DNS stats show 0 NXDOMAIN "
                               "responses. The finding may reference a stale or incorrect metric.",
                    "detail": "Check whether the PCAP contains DNS response packets.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── ARP-001: ARP spoof finding but only 1 unique host in capture ──────
        if rid == "ARP-001":
            unique_hosts = len(host_ips)
            if unique_hosts <= 1:
                issues.append({
                    "check_id": "SANITY-004",
                    "severity": "warning",
                    "message": "ARP-001 (ARP poisoning) fired but only 1 host was profiled. "
                               "ARP spoofing requires at least 2 hosts. Finding likely triggered "
                               "on incomplete or filtered capture.",
                    "detail": "Capture may be missing ARP replies or was filtered to a single host.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── C2-001: beaconing finding but no periodic intervals recorded ───────
        if rid == "C2-001":
            # Check if the affected host profile shows periodic behavior
            host_profile = next((h for h in hosts if h.get("ip") == src), None)
            if host_profile is not None:
                interval = host_profile.get("periodic_interval_sec")
                if interval is None or interval == 0:
                    issues.append({
                        "check_id": "SANITY-005",
                        "severity": "warning",
                        "message": f"C2-001 (beaconing) fired for {src} but host profile shows "
                                   "no periodic connection interval. The beaconing pattern may "
                                   "not be statistically significant.",
                        "detail": "Consider raising the minimum sample threshold for beaconing detection.",
                        "related_finding": rid,
                        "affected_host": src,
                    })

        # ── Finding references host not in host profiles ───────────────────────
        if src and src not in host_ips and src not in ("unknown", "the flagged host"):
            issues.append({
                "check_id": "SANITY-006",
                "severity": "info",
                "message": f"Finding {rid or f.get('title', '?')} references host {src} "
                           "which does not appear in host profiles. "
                           "Host may have been observed only in one direction.",
                "detail": "Check for asymmetric captures or capture filter dropping return traffic.",
                "related_finding": rid,
                "affected_host": src,
            })

    # ── Cross-finding: critical finding but risk_level is lower ───────────────
    decision = result.get("decision_support", {}) or {}
    reported_risk = decision.get("risk_level", "")
    has_critical_finding = any(f.get("severity") == "critical" for f in findings)
    if has_critical_finding and reported_risk not in ("critical",):
        issues.append({
            "check_id": "SANITY-007",
            "severity": "warning",
            "message": f"Critical-severity findings are present but decision_support reports "
                       f"risk_level='{reported_risk}'. This may indicate a scoring inconsistency.",
            "detail": "Verify that the decision engine is receiving the full active findings list.",
            "related_finding": None,
            "affected_host": None,
        })

    # ── TCP retransmission finding but zero retransmissions in stats ──────────
    tcp_retransmission_findings = [f for f in findings if f.get("rule_id") == "TCP-001"]
    if tcp_retransmission_findings:
        total_retrans = tcp_stats.get("retransmissions", 0) or 0
        if total_retrans == 0:
            issues.append({
                "check_id": "SANITY-008",
                "severity": "warning",
                "message": "TCP-001 (retransmission / congestion) fired but TCP aggregate "
                           "stats show 0 retransmissions. Metric source inconsistency.",
                "detail": "Check whether tshark extraction and session tracking use the same "
                          "retransmission counter.",
                "related_finding": "TCP-001",
                "affected_host": None,
            })

    return issues
