"""
DNS deep analyzer — operates on normalized DnsTransaction objects.
Detects: NXDOMAIN storm, DNS tunneling, DGA/high-entropy, slow DNS,
unanswered queries, high unique subdomain rate.
"""
from __future__ import annotations
import math
from collections import defaultdict
from typing import Dict, List

from models import (
    CaptureContext, Evidence, Severity, Confidence, TimelineEvent,
)
from detection.engine import build_finding
from detection.rules import load_rules, get_threshold


def _vowel_ratio(s: str) -> float:
    if not s:
        return 0.5
    vowels = sum(1 for c in s.lower() if c in "aeiou")
    return vowels / len(s)


def _is_dga_suspect(qname: str, entropy: float) -> bool:
    """Heuristic DGA detection: high entropy + low vowel ratio + no real TLD pattern."""
    labels = qname.rstrip(".").split(".")
    if not labels:
        return False
    # Check the second-level label (sub.LABEL.tld)
    label = labels[0] if len(labels) <= 2 else labels[-3] if len(labels) >= 3 else labels[0]
    if len(label) < 8:
        return False
    if entropy < 3.5:
        return False
    if _vowel_ratio(label) > 0.35:
        return False   # real words have more vowels
    return True


def analyze(ctx: CaptureContext) -> None:
    config = load_rules()
    txns = ctx.dns_transactions

    if not txns:
        ctx.dns_stats = {
            "total_queries": 0, "unique_domains": 0,
            "nxdomain_count": 0, "servfail_count": 0,
            "avg_rtt_ms": 0.0, "unanswered_count": 0,
            "resolvers": [], "top_queries": [],
            "nxdomains": [], "query_types": {},
        }
        return

    # Aggregation
    domain_counts: Dict[str, int] = defaultdict(int)
    nxdomain_counts: Dict[str, int] = defaultdict(int)
    resolver_counts: Dict[str, int] = defaultdict(int)
    query_type_counts: Dict[str, int] = defaultdict(int)
    rtts: List[float] = []
    unanswered = 0
    servfail_count = 0
    nxdomain_count = 0

    # Tunneling / DGA
    long_label_txns: List = []
    dga_domain_counts: Dict[str, int] = defaultdict(int)

    # Unique subdomains per apex domain
    apex_subs: Dict[str, set] = defaultdict(set)

    for tx in txns:
        qname = tx.qname.lower().rstrip(".")
        if not qname:
            continue

        domain_counts[qname] += 1
        if tx.qtype:
            query_type_counts[tx.qtype] += 1
        if tx.resolver_ip:
            resolver_counts[tx.resolver_ip] += 1

        if tx.is_nxdomain:
            nxdomain_count += 1
            nxdomain_counts[qname] += 1
            ctx.timeline.append(TimelineEvent(
                ts=tx.ts_response, event_type="dns_nxdomain",
                src_ip=tx.resolver_ip, dst_ip=tx.client_ip,
                label=f"NXDOMAIN: {qname}",
                detail=f"NXDOMAIN for {qname} from {tx.client_ip}",
                severity=Severity.INFO, packet_num=tx.response_pkt, protocol="DNS",
            ))

        if tx.is_servfail:
            servfail_count += 1

        if not tx.answered:
            unanswered += 1
        elif tx.rtt_ms > 0:
            rtts.append(tx.rtt_ms)

        # Tunneling: long labels
        if tx.label_length >= 40:
            long_label_txns.append(tx)

        # DGA suspicion
        if _is_dga_suspect(qname, tx.label_entropy):
            # Get apex domain (last 2 labels)
            labels = qname.split(".")
            apex = ".".join(labels[-2:]) if len(labels) >= 2 else qname
            dga_domain_counts[apex] += 1

        # Unique subdomain tracking
        labels = qname.split(".")
        if len(labels) >= 3:
            apex = ".".join(labels[-2:])
            sub = ".".join(labels[:-2])
            apex_subs[apex].add(sub)

    avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
    top_queries = sorted(domain_counts.items(), key=lambda x: -x[1])[:20]
    top_nxdomains = sorted(nxdomain_counts.items(), key=lambda x: -x[1])[:20]
    top_resolvers = sorted(resolver_counts.items(), key=lambda x: -x[1])[:10]

    ctx.dns_stats = {
        "total_queries": len(txns),
        "unique_domains": len(domain_counts),
        "nxdomain_count": nxdomain_count,
        "servfail_count": servfail_count,
        "avg_rtt_ms": round(avg_rtt, 2),
        "unanswered_count": unanswered,
        "query_types": dict(query_type_counts),
        "top_queries": [{"domain": d, "count": c} for d, c in top_queries],
        "nxdomains": [{"domain": d, "count": c} for d, c in top_nxdomains],
        "resolvers": [{"ip": ip, "count": c} for ip, c in top_resolvers],
    }

    # ── NXDOMAIN storm ────────────────────────────────────────────────────────
    min_nx = get_threshold(config, "DNS-001", "min_nxdomain", 20)
    critical_nx = get_threshold(config, "DNS-001", "critical_at", 100)
    if nxdomain_count >= min_nx:
        sev = Severity.CRITICAL if nxdomain_count >= critical_nx else Severity.MEDIUM
        # Top NXDOMAIN clients
        client_nx: Dict[str, int] = defaultdict(int)
        for tx in txns:
            if tx.is_nxdomain and tx.client_ip:
                client_nx[tx.client_ip] += 1
        top_clients = sorted(client_nx.items(), key=lambda x: -x[1])[:5]
        ctx.findings.append(build_finding(
            rule_id="DNS-001",
            severity=sev, confidence=Confidence.HIGH,
            category="dns",
            title=f"NXDOMAIN Storm — {nxdomain_count} Failures",
            description=(
                f"{nxdomain_count} DNS NXDOMAIN responses detected. "
                f"Top domains: {', '.join(d for d, _ in top_nxdomains[:3])}."
            ),
            explanation=(
                "High NXDOMAIN rates can indicate: (1) Domain Generation Algorithm (DGA) malware "
                "cycling through random domain names to find its C2 server, "
                "(2) misconfigured application or DNS suffix search list, "
                "(3) C2 infrastructure that has been sinkholed."
            ),
            possible_causes=[
                "DGA malware (Conficker, Emotet, etc.) generating random C2 domain lookups",
                "Misconfigured DNS search suffix causing failed resolution attempts",
                "Fast-flux C2 infrastructure with domains being taken down",
                "Typosquatting attempts by internal users",
            ],
            recommended_actions=[
                "Correlate NXDOMAIN sources with threat intelligence",
                "Inspect processes on clients with highest NXDOMAIN counts",
                "Enable DNS Security Extensions (DNSSEC) and RPZ filtering",
                "Deploy DNS sinkholing for known DGA patterns",
            ],
            affected_hosts=[c for c, _ in top_clients],
            affected_flows=[],
            evidence=Evidence(
                metrics={
                    "nxdomain_count": nxdomain_count,
                    "unique_nxdomains": len(nxdomain_counts),
                    "top_clients": {c: n for c, n in top_clients},
                },
                samples=[d for d, _ in top_nxdomains[:10]],
                time_first=min((tx.ts_query for tx in txns if tx.is_nxdomain), default=0),
                time_last=max((tx.ts_query for tx in txns if tx.is_nxdomain), default=0),
            ),
            mitre_keys=["nxdomain_storm", "dga_malware"],
        ))

    # ── DNS tunneling (long labels) ───────────────────────────────────────────
    min_label = get_threshold(config, "DNS-002", "min_label_length", 40)
    # Group by client
    tunnel_clients: Dict[str, List] = defaultdict(list)
    for tx in long_label_txns:
        tunnel_clients[tx.client_ip].append(tx)

    if long_label_txns:
        top_tunnelers = sorted(tunnel_clients.items(), key=lambda x: -len(x[1]))
        ctx.findings.append(build_finding(
            rule_id="DNS-002",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            category="dns",
            title=f"DNS Tunneling Suspected — {len(long_label_txns)} Long-Label Queries",
            description=(
                f"{len(long_label_txns)} DNS queries with labels ≥{min_label} characters. "
                f"Top source: {top_tunnelers[0][0]} ({len(top_tunnelers[0][1])} queries)."
            ),
            explanation=(
                "DNS tunneling encodes arbitrary data (files, C2 commands, exfiltrated data) "
                "in DNS query/response labels. Labels are usually short hostnames; very long "
                "labels (>40 chars) are abnormal and a strong indicator of covert DNS channel. "
                "Tools like iodine, dnscat2, and dns2tcp use this technique."
            ),
            possible_causes=[
                "DNS tunneling for data exfiltration (iodine, dnscat2)",
                "C2 communication over DNS to bypass HTTP/HTTPS inspection",
                "Covert channel used by advanced persistent threats",
            ],
            recommended_actions=[
                "Block DNS queries with labels >40 characters at the DNS server or firewall",
                "Deploy DNS-based DLP inspection (e.g., Cisco Umbrella, Infoblox)",
                "Inspect endpoint processes generating these queries",
                "Implement DNS query rate limiting per source IP",
            ],
            affected_hosts=list(tunnel_clients.keys())[:10],
            affected_flows=[],
            evidence=Evidence(
                metrics={
                    "tunneling_queries": len(long_label_txns),
                    "unique_sources": len(tunnel_clients),
                    "max_label_length": max(tx.label_length for tx in long_label_txns),
                },
                packet_nums=[tx.query_pkt for tx in long_label_txns[:10]],
                samples=[tx.qname for tx in long_label_txns[:10]],
                time_first=min(tx.ts_query for tx in long_label_txns),
                time_last=max(tx.ts_query for tx in long_label_txns),
            ),
            mitre_keys=["dns_tunneling", "c2_dns"],
        ))

    # ── High-entropy DGA suspicion ────────────────────────────────────────────
    min_entropy = get_threshold(config, "DNS-003", "min_entropy", 3.8)
    min_occur = get_threshold(config, "DNS-003", "min_occurrences", 5)
    suspicious_dga = {apex: cnt for apex, cnt in dga_domain_counts.items() if cnt >= min_occur}
    if suspicious_dga:
        high_ent_txns = [tx for tx in txns if tx.label_entropy >= min_entropy]
        ctx.findings.append(build_finding(
            rule_id="DNS-003",
            severity=Severity.MEDIUM, confidence=Confidence.LOW,
            category="dns",
            title=f"DGA Suspicious Domains — {len(suspicious_dga)} Apex Domain(s)",
            description=(
                f"{len(high_ent_txns)} DNS queries for high-entropy domain names "
                f"(entropy ≥ {min_entropy} bits/char) consistent with DGA patterns. "
                f"Suspicious apex domains: {', '.join(list(suspicious_dga.keys())[:3])}."
            ),
            explanation=(
                "Domain Generation Algorithms (DGAs) produce pseudo-random domain names "
                "as rendezvous points for C2 communication. DGA domains have high character "
                "entropy and low vowel ratio compared to legitimate domain names. "
                "This detection has low confidence and should be correlated with other indicators."
            ),
            possible_causes=[
                "DGA-based malware (Emotet, TrickBot, Dridex, etc.)",
                "Legitimate services using algorithmic CDN subdomains",
                "UUID or hash-based subdomains in legitimate software",
            ],
            recommended_actions=[
                "Submit suspicious domains to threat intel platforms (VirusTotal, Shodan)",
                "Correlate with endpoint EDR data for processes making these queries",
                "Consider DNS RPZ (Response Policy Zone) blocking for DGA patterns",
            ],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(
                metrics={
                    "high_entropy_queries": len(high_ent_txns),
                    "suspicious_apex_domains": len(suspicious_dga),
                    "avg_entropy": round(sum(tx.label_entropy for tx in high_ent_txns) / max(len(high_ent_txns), 1), 3),
                },
                samples=[tx.qname for tx in sorted(high_ent_txns, key=lambda x: -x.label_entropy)[:10]],
            ),
            mitre_keys=["dga_malware"],
        ))

    # ── High unique subdomain rate ────────────────────────────────────────────
    min_unique_subs = get_threshold(config, "DNS-004", "min_unique_subs", 50)
    for apex, subs in apex_subs.items():
        total_apex = sum(domain_counts.get(f"{s}.{apex}", 0) for s in subs) + domain_counts.get(apex, 0)
        if len(subs) >= min_unique_subs:
            ratio = len(subs) / max(total_apex, 1)
            if ratio >= 0.7:
                ctx.findings.append(build_finding(
                    rule_id="DNS-004",
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    category="dns",
                    title=f"High Unique Subdomain Rate for {apex} ({len(subs)} unique subs)",
                    description=(
                        f"{len(subs)} unique subdomains of {apex} queried ({ratio*100:.0f}% uniqueness ratio). "
                        "This pattern is consistent with DNS tunneling or DGA activity."
                    ),
                    explanation=(
                        "Legitimate CDNs and SaaS platforms use dynamic subdomains, but very high "
                        "unique subdomain rates for a single apex domain — especially with high entropy "
                        "— strongly suggest DNS-based covert channel or DGA C2 communication."
                    ),
                    possible_causes=[
                        "DNS tunneling encoding data in subdomain labels",
                        "DGA-based malware rotating through subdomains",
                        "Content delivery network with dynamic subdomains (lower risk)",
                    ],
                    recommended_actions=[
                        "Inspect traffic to this apex domain for other C2 indicators",
                        "Check if apex domain resolves to known C2 or suspicious IP",
                        "Rate-limit or block DNS queries to this apex domain",
                    ],
                    affected_hosts=[],
                    affected_flows=[],
                    evidence=Evidence(
                        metrics={
                            "apex_domain": apex,
                            "unique_subdomains": len(subs),
                            "uniqueness_ratio": round(ratio, 3),
                        },
                        samples=list(subs)[:10],
                    ),
                    mitre_keys=["dns_tunneling"],
                ))
                break   # report once

    # ── Slow DNS responses ────────────────────────────────────────────────────
    slow_threshold = get_threshold(config, "DNS-005", "slow_rtt_ms", 500)
    min_slow = get_threshold(config, "DNS-005", "min_slow_count", 5)
    slow_txns = [tx for tx in txns if tx.answered and tx.rtt_ms > slow_threshold]
    if len(slow_txns) >= min_slow:
        ctx.findings.append(build_finding(
            rule_id="DNS-005",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            category="dns",
            title=f"Slow DNS Responses — {len(slow_txns)} Queries > {slow_threshold}ms",
            description=(
                f"{len(slow_txns)} DNS queries took >{slow_threshold}ms. "
                f"Slowest: {max(tx.rtt_ms for tx in slow_txns):.0f}ms. "
                f"Average capture RTT: {avg_rtt:.0f}ms."
            ),
            explanation=(
                "DNS resolution latency directly impacts application startup time and "
                "user experience. Slow DNS may indicate overloaded resolvers, "
                "network congestion, or resolver misconfiguration."
            ),
            possible_causes=[
                "DNS resolver under load or misconfigured",
                "DNSSEC validation delays",
                "Network path congestion to upstream DNS servers",
                "Resolver performing recursive lookups to slow authoritative servers",
            ],
            recommended_actions=[
                "Switch to a faster recursive resolver (1.1.1.1, 8.8.8.8) or deploy local caching",
                "Enable DNS caching with appropriate TTL settings",
                "Check resolver CPU and memory utilization",
            ],
            affected_hosts=list({tx.resolver_ip for tx in slow_txns[:5]}),
            affected_flows=[],
            evidence=Evidence(
                metrics={
                    "slow_query_count": len(slow_txns),
                    "max_rtt_ms": round(max(tx.rtt_ms for tx in slow_txns), 1),
                    "avg_rtt_ms": round(avg_rtt, 1),
                    "threshold_ms": slow_threshold,
                },
                samples=[f"{tx.qname} ({tx.rtt_ms:.0f}ms)"
                         for tx in sorted(slow_txns, key=lambda x: -x.rtt_ms)[:5]],
            ),
            mitre_keys=[],
        ))

    # ── Unanswered queries ────────────────────────────────────────────────────
    if unanswered >= 50:
        ctx.findings.append(build_finding(
            rule_id="DNS-006",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            category="dns",
            title=f"Unanswered DNS Queries — {unanswered} Queries",
            description=(
                f"{unanswered} DNS queries received no response within the capture window."
            ),
            explanation=(
                "Unanswered DNS queries may indicate: DNS server overload, "
                "network path issues to resolver, or UDP packet loss. "
                "High rates can cause application timeouts and failures."
            ),
            possible_causes=[
                "DNS resolver overloaded or unreachable",
                "Firewall blocking DNS response traffic",
                "Queries sent near end of capture window (no time for response)",
            ],
            recommended_actions=[
                "Verify DNS resolver availability and performance",
                "Check for firewall rules blocking DNS UDP responses (port 53)",
                "Implement DNS failover to secondary resolver",
            ],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(metrics={"unanswered_count": unanswered}),
            mitre_keys=[],
        ))
