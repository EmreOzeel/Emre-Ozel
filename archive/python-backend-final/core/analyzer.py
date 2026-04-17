"""Main analysis orchestrator — coordinates all analyzers and builds the full result."""
import time
from typing import Any, Dict, List

from analyzers import dns, http, protocols, security, tcp, tls
from core.nlg import (
    generate_executive_summary,
    generate_findings_narrative,
    generate_technical_summary,
)
from core.tshark import (
    get_expert_info,
    get_file_info,
    get_ip_endpoints,
    get_packets,
    get_protocol_hierarchy,
    get_tcp_conversations,
)


def run_analysis(pcap_path: str) -> Dict[str, Any]:
    """
    Full two-phase analysis of a PCAP file.
    Returns a structured result dict ready for JSON serialization.
    """
    start_time = time.time()
    result: Dict[str, Any] = {}

    # ── Phase 1: Fast statistics (no packet limit) ────────────────────────────
    file_info = get_file_info(pcap_path)
    proto_hierarchy = get_protocol_hierarchy(pcap_path)
    ip_endpoints = get_ip_endpoints(pcap_path)
    tcp_conversations = get_tcp_conversations(pcap_path)
    expert_info = get_expert_info(pcap_path)

    result["file_info"] = file_info
    result["protocol_hierarchy"] = proto_hierarchy
    result["ip_endpoints"] = ip_endpoints
    result["tcp_conversations"] = tcp_conversations[:100]
    result["expert_info"] = expert_info

    # ── Phase 2: Per-packet analysis (capped at 50k) ─────────────────────────
    packets: List[Dict] = get_packets(pcap_path)
    result["packets_analyzed"] = len(packets)

    tcp_result = tcp.analyze(packets)
    dns_result = dns.analyze(packets)
    http_result = http.analyze(packets)
    tls_result = tls.analyze(packets)
    security_result = security.analyze(packets)
    protocols_result = protocols.analyze(packets)

    result["tcp"] = tcp_result
    result["dns"] = dns_result
    result["http"] = http_result
    result["tls"] = tls_result
    result["security"] = security_result
    result["protocols"] = protocols_result

    # ── Aggregate all issues ──────────────────────────────────────────────────
    all_issues: List[Dict] = []
    for module_result in [tcp_result, dns_result, http_result, tls_result, security_result, protocols_result]:
        all_issues.extend(module_result.get("issues", []))

    # Sort: critical first, then warning, then info
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    all_issues.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 2))

    # Enrich with recommendations
    all_issues = generate_findings_narrative(all_issues)
    result["all_issues"] = all_issues
    result["issue_counts"] = {
        "critical": sum(1 for i in all_issues if i.get("severity") == "critical"),
        "warning": sum(1 for i in all_issues if i.get("severity") == "warning"),
        "info": sum(1 for i in all_issues if i.get("severity") == "info"),
        "total": len(all_issues),
    }

    # ── Build unified timeline ────────────────────────────────────────────────
    timeline: List[Dict] = []
    for module_result in [dns_result, http_result, tls_result, security_result, protocols_result]:
        timeline.extend(module_result.get("timeline_events", []))

    # Sort by timestamp (0 = unknown, put at end)
    timeline.sort(key=lambda e: e.get("ts", float("inf")) if e.get("ts", 0) > 0 else float("inf"))
    result["timeline"] = timeline[:1000]

    # ── NLG Summaries ─────────────────────────────────────────────────────────
    result["executive_summary"] = generate_executive_summary(result)
    result["technical_summary"] = generate_technical_summary(result)

    # ── Top hosts / conversations ─────────────────────────────────────────────
    result["top_talkers"] = ip_endpoints[:10]

    result["analysis_time_sec"] = round(time.time() - start_time, 2)

    return result
