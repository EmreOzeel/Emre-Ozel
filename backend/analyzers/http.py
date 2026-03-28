"""HTTP/HTTPS traffic analysis."""
from collections import defaultdict
from typing import List, Dict, Any
import re


SUSPICIOUS_UA_PATTERNS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"zgrab",
    r"python-requests/", r"go-http-client", r"curl/", r"wget/",
    r"hydra", r"metasploit", r"burpsuite", r"dirbuster", r"gobuster",
]

SENSITIVE_URI_PATTERNS = [
    r"\.php\?.*=.*select", r"union.*select", r"or\s+1=1",
    r"\.\./\.\./", r"etc/passwd", r"cmd=", r"exec\(",
    r"/admin", r"/wp-admin", r"/phpmyadmin", r"/.env",
    r"/shell", r"/webshell",
]


def analyze(packets: List[Dict]) -> Dict[str, Any]:
    requests: Dict[str, Dict] = {}   # http.request_number+stream → req info
    responses: Dict[str, Dict] = {}

    method_counts: Dict[str, int] = defaultdict(int)
    status_counts: Dict[str, int] = defaultdict(int)
    host_counts: Dict[str, int] = defaultdict(int)
    uri_counts: Dict[str, int] = defaultdict(int)
    ua_counts: Dict[str, int] = defaultdict(int)
    content_type_counts: Dict[str, int] = defaultdict(int)

    error_requests = []
    suspicious_uas = []
    sensitive_uris = []
    cleartext_creds = []
    issues = []
    timeline_events = []

    rtts: List[float] = []

    for pkt in packets:
        has_http = (
            "http.request.method" in pkt or
            "http.response.code" in pkt
        )
        if not has_http:
            continue

        ts_str = pkt.get("frame.time_epoch", "0")
        try:
            ts = float(ts_str)
        except ValueError:
            ts = 0.0

        src_ip = pkt.get("ip.src", pkt.get("ipv6.src", ""))
        dst_ip = pkt.get("ip.dst", pkt.get("ipv6.dst", ""))
        stream = pkt.get("tcp.stream", "")
        req_num = pkt.get("http.request_number", "")
        key = f"{stream}-{req_num}"

        if "http.request.method" in pkt:
            method = pkt.get("http.request.method", "")
            uri = pkt.get("http.request.uri", "")
            host = pkt.get("http.host", "")
            ua = pkt.get("http.user_agent", "")

            method_counts[method] += 1
            if host:
                host_counts[host] += 1
            if uri:
                uri_counts[uri] += 1
            if ua:
                ua_counts[ua] += 1

            requests[key] = {
                "method": method, "uri": uri, "host": host,
                "ua": ua, "src_ip": src_ip, "dst_ip": dst_ip,
                "ts": ts, "stream": stream,
            }

            # Check suspicious user agents
            for pattern in SUSPICIOUS_UA_PATTERNS:
                if ua and re.search(pattern, ua, re.I):
                    suspicious_uas.append({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "ua": ua, "uri": uri, "host": host, "ts": ts,
                    })
                    break

            # Check sensitive URIs
            full_uri = f"{host}{uri}" if host else uri
            for pattern in SENSITIVE_URI_PATTERNS:
                if re.search(pattern, full_uri, re.I):
                    sensitive_uris.append({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "method": method, "uri": uri, "host": host, "ts": ts,
                    })
                    break

            # Cleartext credential indicators
            uri_lower = uri.lower()
            if method in ("POST", "PUT") and any(
                kw in uri_lower for kw in ("/login", "/signin", "/auth", "/password", "/credential")
            ):
                cleartext_creds.append({
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "method": method, "uri": uri, "host": host, "ts": ts,
                })

            timeline_events.append({
                "ts": ts, "type": "http_request",
                "label": f"HTTP {method} {host}{uri}",
                "detail": f"{src_ip} → {dst_ip}: {method} {host}{uri}",
                "severity": "info",
            })

        elif "http.response.code" in pkt:
            code_str = pkt.get("http.response.code", "0")
            try:
                code = int(code_str)
            except ValueError:
                code = 0

            status_counts[code_str] += 1
            ct = pkt.get("http.content_type", "")
            if ct:
                content_type_counts[ct.split(";")[0].strip()] += 1

            # Match with request
            if key in requests:
                req = requests[key]
                rtt = ts - req["ts"]
                if rtt > 0:
                    rtts.append(rtt)
                req["response_code"] = code
                req["rtt_ms"] = round(rtt * 1000, 2)
                requests.pop(key)

            if code >= 400:
                error_requests.append({
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "code": code, "ts": ts,
                })

            sev = "info"
            if code >= 500:
                sev = "warning"
            elif code >= 400:
                sev = "info"

            timeline_events.append({
                "ts": ts, "type": "http_response",
                "label": f"HTTP {code}",
                "detail": f"HTTP Response {code} from {src_ip}",
                "severity": sev,
            })

    # Build issues
    error_4xx = sum(v for k, v in status_counts.items() if k.startswith("4"))
    error_5xx = sum(v for k, v in status_counts.items() if k.startswith("5"))

    if error_5xx >= 10:
        sev = "critical" if error_5xx >= 50 else "warning"
        issues.append({
            "severity": sev, "category": "http",
            "title": f"HTTP 5xx Server Errors — {error_5xx} Responses",
            "description": (
                f"{error_5xx} HTTP 5xx server error responses detected. "
                "Server-side errors indicate application bugs, resource exhaustion, or misconfiguration. "
                "High 5xx rates can indicate a service under attack or experiencing failure."
            ),
            "count": error_5xx,
        })

    if error_4xx >= 20:
        issues.append({
            "severity": "warning", "category": "http",
            "title": f"High HTTP 4xx Error Rate — {error_4xx} Responses",
            "description": (
                f"{error_4xx} HTTP 4xx client error responses. "
                "Excessive 4xx errors, especially 404s, may indicate directory brute-forcing or "
                "broken application links. Check for scanning tools probing your web server."
            ),
            "count": error_4xx,
        })

    if suspicious_uas:
        deduped = {s["ua"]: s for s in suspicious_uas}
        issues.append({
            "severity": "warning", "category": "http",
            "title": f"Suspicious HTTP User Agents ({len(deduped)} unique)",
            "description": (
                f"Detected {len(suspicious_uas)} requests from suspicious user agents "
                f"({len(deduped)} unique). These match patterns of security scanners, "
                "vulnerability assessment tools, or automation frameworks: "
                f"{', '.join(list(deduped.keys())[:3])}."
            ),
            "count": len(suspicious_uas),
            "examples": list(deduped.keys())[:5],
        })

    if sensitive_uris:
        issues.append({
            "severity": "critical", "category": "http",
            "title": f"Suspicious URI Patterns — Possible Web Attack",
            "description": (
                f"{len(sensitive_uris)} HTTP requests contain patterns associated with web attacks: "
                "SQL injection, path traversal, command injection, or admin panel probing. "
                f"Example: {sensitive_uris[0]['method']} {sensitive_uris[0]['uri']}"
            ),
            "count": len(sensitive_uris),
            "examples": [f"{s['method']} {s['uri']}" for s in sensitive_uris[:3]],
        })

    if cleartext_creds:
        issues.append({
            "severity": "critical", "category": "http",
            "title": f"Cleartext Credentials Transmitted Over HTTP",
            "description": (
                f"{len(cleartext_creds)} HTTP POST requests to authentication endpoints over "
                "unencrypted HTTP. Passwords and credentials transmitted in plaintext are "
                "trivially interceptable by any network observer."
            ),
            "count": len(cleartext_creds),
            "examples": [f"{c['host']}{c['uri']}" for c in cleartext_creds[:3]],
        })

    avg_rtt = (sum(rtts) / len(rtts)) if rtts else 0
    slow = [r for r in rtts if r > 2.0]
    if slow:
        issues.append({
            "severity": "warning", "category": "http",
            "title": f"Slow HTTP Responses ({len(slow)} > 2s)",
            "description": (
                f"{len(slow)} HTTP requests took more than 2 seconds to receive a response. "
                f"Average response time: {avg_rtt*1000:.0f}ms. "
                "Slow responses indicate server-side bottlenecks or network congestion."
            ),
            "count": len(slow),
        })

    top_hosts = sorted(host_counts.items(), key=lambda x: -x[1])[:20]
    top_uris = sorted(uri_counts.items(), key=lambda x: -x[1])[:20]
    top_uas = sorted(ua_counts.items(), key=lambda x: -x[1])[:10]

    total_requests = sum(method_counts.values())
    total_responses = sum(status_counts.values())

    return {
        "total_requests": total_requests,
        "total_responses": total_responses,
        "method_counts": dict(method_counts),
        "status_counts": dict(status_counts),
        "error_4xx": error_4xx,
        "error_5xx": error_5xx,
        "avg_rtt_ms": round(avg_rtt * 1000, 2),
        "top_hosts": [{"host": h, "count": c} for h, c in top_hosts],
        "top_uris": [{"uri": u, "count": c} for u, c in top_uris],
        "top_user_agents": [{"ua": u, "count": c} for u, c in top_uas],
        "content_types": dict(content_type_counts),
        "suspicious_uas": suspicious_uas[:20],
        "sensitive_uris": sensitive_uris[:20],
        "cleartext_creds": cleartext_creds[:20],
        "issues": issues,
        "timeline_events": timeline_events[:500],
    }
