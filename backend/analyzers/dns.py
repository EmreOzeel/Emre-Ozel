"""DNS query/response analysis."""
from collections import defaultdict
from typing import List, Dict, Any

RCODE_MAP = {
    "0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL",
    "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED",
}

QTYPE_MAP = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA",
    "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA",
    "33": "SRV", "255": "ANY",
}


def analyze(packets: List[Dict]) -> Dict[str, Any]:
    queries: Dict[str, Dict] = {}   # dns.id+src → query info
    nxdomains: Dict[str, int] = defaultdict(int)
    servfails: Dict[str, int] = defaultdict(int)
    query_names: Dict[str, int] = defaultdict(int)
    resolvers: Dict[str, int] = defaultdict(int)
    rtts: List[float] = []
    qtype_counts: Dict[str, int] = defaultdict(int)
    issues = []
    timeline_events = []

    for pkt in packets:
        if "dns.qry.name" not in pkt and "dns.flags.response" not in pkt:
            continue

        ts_str = pkt.get("frame.time_epoch", "0")
        try:
            ts = float(ts_str)
        except ValueError:
            ts = 0.0

        src_ip = pkt.get("ip.src", pkt.get("ipv6.src", ""))
        dns_id = pkt.get("dns.id", "")
        is_response = pkt.get("dns.flags.response") == "1"
        name = pkt.get("dns.qry.name", "")
        qtype = QTYPE_MAP.get(pkt.get("dns.qry.type", ""), pkt.get("dns.qry.type", ""))
        rcode = RCODE_MAP.get(pkt.get("dns.flags.rcode", ""), pkt.get("dns.flags.rcode", ""))

        key = f"{dns_id}-{src_ip}"

        if not is_response:
            # DNS Query
            query_names[name] += 1
            qtype_counts[qtype] += 1
            resolvers[pkt.get("ip.dst", "")] += 1
            queries[key] = {
                "name": name, "type": qtype, "src_ip": src_ip,
                "query_ts": ts, "answered": False, "rcode": "",
                "answer": "",
            }
            timeline_events.append({
                "ts": ts, "type": "dns_query",
                "label": f"DNS Query: {name} ({qtype})",
                "detail": f"{src_ip} → DNS: {name}",
                "severity": "info",
            })
        else:
            # DNS Response
            dst_ip = pkt.get("ip.dst", pkt.get("ipv6.dst", ""))
            resp_key = f"{dns_id}-{dst_ip}"
            if resp_key in queries:
                q = queries[resp_key]
                q["answered"] = True
                q["rcode"] = rcode
                q["answer"] = pkt.get("dns.a", pkt.get("dns.aaaa", ""))
                if q.get("query_ts"):
                    rtt = ts - q["query_ts"]
                    q["rtt_ms"] = round(rtt * 1000, 2)
                    rtts.append(rtt)
                queries.pop(resp_key)

                sev = "info"
                if rcode == "NXDOMAIN":
                    nxdomains[name] += 1
                    sev = "warning"
                elif rcode == "SERVFAIL":
                    servfails[name] += 1
                    sev = "warning"

                timeline_events.append({
                    "ts": ts, "type": "dns_response",
                    "label": f"DNS Response: {q['name']} → {q.get('answer','no answer')} [{rcode}]",
                    "detail": f"DNS resolved {q['name']} = {q.get('answer','-')} (rcode={rcode})",
                    "severity": sev,
                })

    # Unanswered queries
    unanswered = [q for q in queries.values() if not q.get("answered")]

    # Build issues
    total_nxdomain = sum(nxdomains.values())
    if total_nxdomain >= 5:
        top = sorted(nxdomains.items(), key=lambda x: -x[1])[:5]
        sev = "critical" if total_nxdomain >= 30 else "warning"
        issues.append({
            "severity": sev, "category": "dns",
            "title": f"NXDOMAIN Storm — {total_nxdomain} Failed DNS Lookups",
            "description": (
                f"{total_nxdomain} DNS queries returned NXDOMAIN (domain does not exist). "
                "This can indicate: malware using DGA (Domain Generation Algorithm), "
                "misconfigured applications, or beaconing to takedown C2 domains. "
                f"Top domains: {', '.join(d for d, _ in top)}."
            ),
            "count": total_nxdomain,
        })

    total_servfail = sum(servfails.values())
    if total_servfail >= 5:
        issues.append({
            "severity": "warning", "category": "dns",
            "title": f"DNS SERVFAIL — {total_servfail} Server Failures",
            "description": (
                f"{total_servfail} DNS queries returned SERVFAIL. "
                "The DNS server failed to process the request. Possible causes: "
                "DNS server overload, DNSSEC validation failure, or zone transfer issues."
            ),
            "count": total_servfail,
        })

    avg_rtt = (sum(rtts) / len(rtts)) if rtts else 0
    max_rtt = max(rtts) if rtts else 0
    slow = [r for r in rtts if r > 1.0]
    if slow:
        issues.append({
            "severity": "warning", "category": "dns",
            "title": f"Slow DNS Responses ({len(slow)} queries > 1s)",
            "description": (
                f"{len(slow)} DNS queries had response times exceeding 1 second. "
                f"Maximum observed RTT: {max_rtt*1000:.0f}ms. "
                "Slow DNS can cause significant application latency as every connection begins with DNS resolution."
            ),
            "count": len(slow),
        })

    # DNS tunneling: very long labels
    tunneling_suspects = [n for n in query_names.keys() if any(len(p) > 40 for p in n.split("."))]
    if len(tunneling_suspects) >= 3:
        issues.append({
            "severity": "critical", "category": "dns",
            "title": "Possible DNS Tunneling",
            "description": (
                f"{len(tunneling_suspects)} DNS queries contain unusually long subdomain labels (>40 chars). "
                "This pattern is typical of DNS tunneling — a technique used to exfiltrate data or "
                "maintain covert C2 channels by encoding data in DNS queries."
            ),
            "count": len(tunneling_suspects),
            "examples": tunneling_suspects[:3],
        })

    top_queries = sorted(query_names.items(), key=lambda x: -x[1])[:20]

    return {
        "total_queries": sum(query_names.values()),
        "unique_domains": len(query_names),
        "nxdomain_count": total_nxdomain,
        "servfail_count": total_servfail,
        "avg_rtt_ms": round(avg_rtt * 1000, 2),
        "max_rtt_ms": round(max_rtt * 1000, 2),
        "unanswered_count": len(unanswered),
        "top_queries": [{"domain": d, "count": c} for d, c in top_queries],
        "nxdomains": [{"domain": d, "count": c} for d, c in sorted(nxdomains.items(), key=lambda x: -x[1])[:20]],
        "query_types": dict(qtype_counts),
        "resolvers": [{"ip": ip, "count": c} for ip, c in sorted(resolvers.items(), key=lambda x: -x[1])[:10]],
        "issues": issues,
        "timeline_events": timeline_events[:500],
    }
