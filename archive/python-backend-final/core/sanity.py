"""
Sanity checks for analysis results.

Detects contradictions between what the detection layer reported and what the
raw stats actually show — e.g. a port-scan finding when there were no SYN
packets, or a DNS-exfil finding when NXDOMAIN count is zero.

Also flags thin-evidence overconfidence: when a critical/high finding has a
low confidence_score it means the severity claim is stronger than the evidence
behind it.

Returns a list of SanityIssue dicts included in pipeline output as
"sanity_warnings". Each issue has:
  - check_id   : machine-readable identifier (SANITY-001 … SANITY-012)
  - severity   : "warning" | "info"
  - message    : analyst-readable description of the contradiction
  - detail     : optional extra context
  - related_finding : rule_id of the contradicted finding, or None
  - affected_host   : primary affected host, or None
"""
from __future__ import annotations

from typing import Any, Dict, List


# Confidence score below this threshold with critical/high severity = overconfident
_LOW_CONF_SCORE_THRESHOLD = 35
# Minimum capture duration (seconds) needed to confirm C2 periodicity
_MIN_C2_CAPTURE_DURATION = 60.0


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
    http_stats = result.get("http", {}) or {}
    file_info = result.get("file_info", {}) or {}

    host_ips = {h.get("ip") for h in hosts}
    capture_duration = file_info.get("duration_sec", 0.0) or 0.0

    for f in findings:
        rid = f.get("rule_id", "")
        affected = f.get("affected_hosts", [])
        src = affected[0] if affected else None
        sev = f.get("severity", "")
        conf_score = f.get("confidence_score", 50)

        # ── SANITY-001: port scan finding but no TCP sessions ─────────────────
        if rid == "SCAN-001":
            total_sessions = tcp_stats.get("total_sessions", 0)
            if total_sessions == 0:
                issues.append({
                    "check_id": "SANITY-001",
                    "severity": "warning",
                    "message": (
                        f"SCAN-001 fired for {src} but TCP stats show 0 sessions "
                        "(no SYN packets captured). Finding may be based on incomplete capture."
                    ),
                    "detail": "Possible mid-stream capture or capture filter excluded SYN packets.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── SANITY-002: DNS tunnel finding but too few queries ────────────────
        # DNS-002 = tunneling (long labels); requires sustained query volume
        if rid == "DNS-002":
            total_queries = dns_stats.get("total_queries", 0) or 0
            if total_queries < 5:
                issues.append({
                    "check_id": "SANITY-002",
                    "severity": "warning",
                    "message": (
                        f"DNS-002 (DNS tunneling) fired but only {total_queries} DNS queries "
                        "were observed. Tunneling requires sustained query volume — "
                        "this may be a false positive on sparse data."
                    ),
                    "detail": "Verify entropy calculation had sufficient sample size.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── SANITY-003: NXDOMAIN storm finding but NXDOMAIN count is zero ─────
        # DNS-001 = NXDOMAIN storm
        if rid == "DNS-001":
            nxdomain_count = dns_stats.get("nxdomain_count", 0) or 0
            if nxdomain_count == 0:
                issues.append({
                    "check_id": "SANITY-003",
                    "severity": "warning",
                    "message": (
                        "DNS-001 (NXDOMAIN storm) fired but DNS stats show 0 NXDOMAIN "
                        "responses. The finding may reference a stale or incorrect metric."
                    ),
                    "detail": "Check whether the PCAP contains DNS response packets.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── SANITY-004: ARP spoof finding but only 1 host profiled ────────────
        if rid == "ARP-001":
            unique_hosts = len(host_ips)
            if unique_hosts <= 1:
                issues.append({
                    "check_id": "SANITY-004",
                    "severity": "warning",
                    "message": (
                        "ARP-001 (ARP poisoning) fired but only 1 host was profiled. "
                        "ARP spoofing requires at least 2 hosts. Finding likely triggered "
                        "on incomplete or filtered capture."
                    ),
                    "detail": "Capture may be missing ARP replies or was filtered to a single host.",
                    "related_finding": rid,
                    "affected_host": src,
                })

        # ── SANITY-005: C2 beaconing but no periodic interval in host profile ──
        if rid == "C2-001":
            host_profile = next((h for h in hosts if h.get("ip") == src), None)
            if host_profile is not None:
                interval = host_profile.get("periodic_interval_sec")
                if not interval:
                    issues.append({
                        "check_id": "SANITY-005",
                        "severity": "warning",
                        "message": (
                            f"C2-001 (beaconing) fired for {src} but host profile shows "
                            "no periodic connection interval. The beaconing pattern may "
                            "not be statistically significant."
                        ),
                        "detail": "Consider raising the minimum sample threshold for beaconing detection.",
                        "related_finding": rid,
                        "affected_host": src,
                    })

        # ── SANITY-006: finding references host not in host profiles ──────────
        if src and src not in host_ips and src not in ("unknown", "the flagged host"):
            issues.append({
                "check_id": "SANITY-006",
                "severity": "info",
                "message": (
                    f"Finding {rid or f.get('title', '?')} references host {src} "
                    "which does not appear in host profiles. "
                    "Host may have been observed only in one direction."
                ),
                "detail": "Check for asymmetric captures or capture filter dropping return traffic.",
                "related_finding": rid,
                "affected_host": src,
            })

        # ── SANITY-009: critical/high finding with very thin evidence ─────────
        # (confidence_score < threshold despite high severity claim)
        if sev in ("critical", "high") and conf_score < _LOW_CONF_SCORE_THRESHOLD:
            issues.append({
                "check_id": "SANITY-009",
                "severity": "warning",
                "message": (
                    f"{rid} is rated {sev.upper()} severity but has a low evidence quality "
                    f"score ({conf_score}/100). The severity claim is stronger than the "
                    "supporting evidence. Verify before escalating."
                ),
                "detail": (
                    f"Only {len(f.get('evidence', {}).get('packet_nums', []))} packet(s) "
                    "in evidence, or evidence lacks concrete metrics. "
                    "Consider this finding provisional until corroborated."
                ),
                "related_finding": rid,
                "affected_host": src,
            })

        # ── SANITY-010: C2 beaconing but capture is too short to confirm ──────
        if rid == "C2-001" and 0 < capture_duration < _MIN_C2_CAPTURE_DURATION:
            issues.append({
                "check_id": "SANITY-010",
                "severity": "warning",
                "message": (
                    f"C2-001 (beaconing) detected but capture duration is only "
                    f"{capture_duration:.1f}s. Statistical periodicity cannot be reliably "
                    f"confirmed in under {_MIN_C2_CAPTURE_DURATION:.0f}s. "
                    "Extend capture before concluding active C2."
                ),
                "detail": (
                    "Beaconing detection computes coefficient of variation over connection "
                    "intervals. With fewer than ~3 intervals, the CoV is not meaningful."
                ),
                "related_finding": rid,
                "affected_host": src,
            })

        # ── SANITY-012: web attack finding but no HTTP transactions ───────────
        if rid in ("HTTP-001", "HTTP-002", "HTTP-003") and http_stats.get("total_requests", 0) == 0:
            issues.append({
                "check_id": "SANITY-012",
                "severity": "warning",
                "message": (
                    f"{rid} (web attack) fired but HTTP stats show 0 requests. "
                    "The finding may reference transactions not captured in HTTP stats, "
                    "or the HTTP extraction layer failed."
                ),
                "detail": "Verify that tshark HTTP dissection is working for this capture.",
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
            "message": (
                f"Critical-severity findings are present but decision_support reports "
                f"risk_level='{reported_risk}'. This may indicate a scoring inconsistency."
            ),
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
                "message": (
                    "TCP-001 (retransmission / congestion) fired but TCP aggregate "
                    "stats show 0 retransmissions. Metric source inconsistency."
                ),
                "detail": (
                    "Check whether tshark extraction and session tracking use the same "
                    "retransmission counter."
                ),
                "related_finding": "TCP-001",
                "affected_host": None,
            })

    # ── SANITY-011: TLS-006 (malicious JA3) with very few packets ────────────
    # A critical JA3 match on a single ClientHello is technically valid, but
    # a single packet in a short capture is worth flagging explicitly.
    tls006_findings = [f for f in findings if f.get("rule_id") == "TLS-006"]
    for tf in tls006_findings:
        n_pkts = len(tf.get("evidence", {}).get("packet_nums", []))
        cap_dur = capture_duration
        if n_pkts <= 2 and (cap_dur < 10 or cap_dur == 0):
            src = tf.get("affected_hosts", [None])[0]
            issues.append({
                "check_id": "SANITY-011",
                "severity": "info",
                "message": (
                    f"TLS-006 (malicious JA3) triggered on only {n_pkts} packet(s) "
                    "in a very short capture. The JA3 hash match is technically valid, "
                    "but a single ClientHello in a brief capture window has limited "
                    "forensic weight. Confirm with a longer capture or EDR telemetry."
                ),
                "detail": (
                    "JA3 hashes are shared across TLS libraries — legitimate tools "
                    "occasionally share fingerprints with known malware. "
                    "Cross-reference the destination IP with threat intelligence."
                ),
                "related_finding": "TLS-006",
                "affected_host": src,
            })

    return issues
