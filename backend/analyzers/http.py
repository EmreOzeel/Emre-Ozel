"""
HTTP analyzer — inspects ctx.http_transactions for security issues and computes
HTTP traffic statistics stored as ctx.http_stats.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Dict, List, Any

from detection.engine import build_finding, _is_private
from models import (
    CaptureContext, Evidence, Severity, Confidence, TimelineEvent,
)

# ── Suspicious user-agent substrings (case-insensitive) ──────────────────────
_SUSPICIOUS_UA_PATTERNS: List[str] = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "hydra",
    "metasploit", "burpsuite", "dirbuster", "gobuster", "wfuzz",
    "ffuf", "nuclei", "python-requests", "go-http-client",
]

# ── Web-attack URI patterns ───────────────────────────────────────────────────
_WEB_ATTACK_PATTERNS: List[re.Pattern] = [
    # SQL injection
    re.compile(
        r"(?:'|--|;|%27|%22|%3B|%2D%2D|union\s+select|select\s+\*|"
        r"or\s+1\s*=\s*1|and\s+1\s*=\s*1|drop\s+table|insert\s+into|"
        r"benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
        re.IGNORECASE,
    ),
    # Path traversal
    re.compile(
        r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e|"
        r"/etc/passwd|/etc/shadow|/windows/system32|\\\\\.\\\\)",
        re.IGNORECASE,
    ),
    # Command injection
    re.compile(
        r"(?:;|\||`|\$\(|%3B|%7C|%60|%24%28)"
        r"(?:\s*(?:ls|id|whoami|cat|wget|curl|nc|bash|sh|cmd|powershell))",
        re.IGNORECASE,
    ),
    # Admin probing
    re.compile(
        r"(?:/admin|/administrator|/wp-admin|/phpmyadmin|/manager/|"
        r"/console|/shell|/cmd|/webshell|/backdoor|/c99|/r57|"
        r"/adminer|/setup\.php|/config\.php|/\.env|/\.git/|/\.svn/|"
        r"/server-status|/server-info)",
        re.IGNORECASE,
    ),
]

# ── Cleartext-credential endpoint prefixes ────────────────────────────────────
_CRED_PATHS: tuple = ("/login", "/signin", "/auth", "/password")

# ── Latency threshold ─────────────────────────────────────────────────────────
_SLOW_LATENCY_MS = 2_000.0
_SLOW_MIN_COUNT   = 5
_5XX_MIN_COUNT    = 10
_5XX_CRIT_COUNT   = 50
_4XX_MIN_COUNT    = 20


def _top_n(counter: Counter, n: int = 10) -> List[Dict[str, Any]]:
    return [{"host" if len(item) == 2 else "key": k, "count": v}
            for k, v in counter.most_common(n)]


def _top_hosts(counter: Counter, n: int = 10) -> List[Dict[str, Any]]:
    return [{"host": k, "count": v} for k, v in counter.most_common(n)]


def _top_uris(counter: Counter, n: int = 10) -> List[Dict[str, Any]]:
    return [{"uri": k, "count": v} for k, v in counter.most_common(n)]


def _top_uas(counter: Counter, n: int = 10) -> List[Dict[str, Any]]:
    return [{"ua": k, "count": v} for k, v in counter.most_common(n)]


def analyze(ctx: CaptureContext) -> None:
    txns = ctx.http_transactions
    if not txns:
        ctx.http_stats = _empty_stats()
        return

    # ── Per-transaction accumulators ─────────────────────────────────────────
    method_counts:  Counter = Counter()
    status_counts:  Counter = Counter()
    host_counts:    Counter = Counter()
    uri_counts:     Counter = Counter()
    ua_counts:      Counter = Counter()
    content_types:  Counter = Counter()

    total_requests  = 0
    total_responses = 0
    error_4xx       = 0
    error_5xx       = 0
    latency_sum     = 0.0
    latency_n       = 0

    # Detection buckets
    suspicious_ua_list:    List[str] = []
    sensitive_uri_list:    List[str] = []
    cleartext_cred_list:   List[str] = []
    slow_txns:             List[Dict] = []

    # For finding evidence
    sus_ua_pkts:   List[int] = []
    attack_pkts:   List[int] = []
    cred_pkts:     List[int] = []
    slow_pkts:     List[int] = []
    sus_ua_hosts:  List[str] = []
    attack_hosts:  List[str] = []

    for tx in txns:
        # ── Request-level stats ───────────────────────────────────────────────
        if tx.method:
            total_requests += 1
            method_counts[tx.method.upper()] += 1
        if tx.host:
            host_counts[tx.host] += 1
        if tx.uri:
            uri_counts[tx.uri] += 1
        if tx.user_agent:
            ua_counts[tx.user_agent] += 1
        if tx.content_type_req:
            content_types[tx.content_type_req] += 1

        # ── Response-level stats ──────────────────────────────────────────────
        if tx.status_code:
            total_responses += 1
            status_counts[tx.status_code] += 1
            if tx.content_type_resp:
                content_types[tx.content_type_resp] += 1
            if 400 <= tx.status_code < 500:
                error_4xx += 1
            elif 500 <= tx.status_code < 600:
                error_5xx += 1

        # ── Latency tracking ──────────────────────────────────────────────────
        if tx.latency_ms > 0:
            latency_sum += tx.latency_ms
            latency_n   += 1

        # ── HTTP-001: suspicious user agent ───────────────────────────────────
        ua_lower = tx.user_agent.lower()
        matched_tool = next(
            (p for p in _SUSPICIOUS_UA_PATTERNS if p in ua_lower), None
        )
        if matched_tool:
            entry = f"{tx.client_ip} → {tx.host}{tx.uri} [{tx.user_agent}] pkt#{tx.request_pkt}"
            if len(suspicious_ua_list) < 20:
                suspicious_ua_list.append(entry)
            sus_ua_pkts.append(tx.request_pkt)
            sus_ua_hosts.append(tx.client_ip)
            if tx.server_ip:
                sus_ua_hosts.append(tx.server_ip)

            ctx.timeline.append(TimelineEvent(
                ts=tx.ts_request,
                event_type="http_suspicious_ua",
                src_ip=tx.client_ip,
                dst_ip=tx.server_ip,
                label=f"Suspicious UA: {matched_tool}",
                detail=f"UA={tx.user_agent!r} uri={tx.uri}",
                severity=Severity.MEDIUM,
                packet_num=tx.request_pkt,
                protocol="HTTP",
            ))

        # ── HTTP-002: web attack URI patterns ─────────────────────────────────
        uri_str = (tx.uri or "") + ("?" + tx.uri if "?" in (tx.uri or "") else "")
        attack_type = None
        for pat in _WEB_ATTACK_PATTERNS:
            if pat.search(tx.uri or ""):
                attack_type = pat.pattern[:30]
                break
        if attack_type:
            entry = f"{tx.client_ip} {tx.method} {tx.host}{tx.uri} pkt#{tx.request_pkt}"
            if len(sensitive_uri_list) < 20:
                sensitive_uri_list.append(entry)
            attack_pkts.append(tx.request_pkt)
            attack_hosts.append(tx.client_ip)
            if tx.server_ip:
                attack_hosts.append(tx.server_ip)

            ctx.timeline.append(TimelineEvent(
                ts=tx.ts_request,
                event_type="http_web_attack",
                src_ip=tx.client_ip,
                dst_ip=tx.server_ip,
                label="Web attack pattern in URI",
                detail=f"{tx.method} {tx.host}{tx.uri}",
                severity=Severity.HIGH,
                packet_num=tx.request_pkt,
                protocol="HTTP",
            ))

        # ── HTTP-003: cleartext credentials ───────────────────────────────────
        uri_lower = (tx.uri or "").lower()
        if (
            tx.method.upper() == "POST"
            and tx.dst_port == 80
            and any(uri_lower.startswith(p) or f"/{p.lstrip('/')}" in uri_lower
                    for p in _CRED_PATHS)
        ):
            entry = (
                f"{tx.client_ip} POST http://{tx.host}{tx.uri}"
                f" pkt#{tx.request_pkt}"
            )
            if len(cleartext_cred_list) < 20:
                cleartext_cred_list.append(entry)
            cred_pkts.append(tx.request_pkt)

        # ── HTTP-006: slow response ────────────────────────────────────────────
        if tx.latency_ms > _SLOW_LATENCY_MS:
            slow_pkts.append(tx.request_pkt)
            slow_txns.append({
                "uri": tx.uri,
                "latency_ms": tx.latency_ms,
                "pkt": tx.request_pkt,
            })

    avg_latency = latency_sum / latency_n if latency_n else 0.0

    # ── Build ctx.http_stats ──────────────────────────────────────────────────
    ctx.http_stats = {
        "total_requests":       total_requests,
        "total_responses":      total_responses,
        "method_counts":        dict(method_counts),
        "status_counts":        {str(k): v for k, v in status_counts.items()},
        "error_4xx":            error_4xx,
        "error_5xx":            error_5xx,
        "avg_latency_ms":       round(avg_latency, 2),
        "top_hosts":            _top_hosts(host_counts),
        "top_uris":             _top_uris(uri_counts),
        "top_user_agents":      _top_uas(ua_counts),
        "content_types":        dict(content_types),
        "suspicious_ua_list":   suspicious_ua_list,
        "sensitive_uri_list":   sensitive_uri_list,
        "cleartext_cred_list":  cleartext_cred_list,
    }

    # ── Emit findings ─────────────────────────────────────────────────────────

    # HTTP-001: Suspicious user agents
    if sus_ua_pkts:
        ctx.findings.append(build_finding(
            rule_id="HTTP-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="reconnaissance",
            title="Suspicious HTTP User-Agent Detected",
            description=(
                f"{len(sus_ua_pkts)} request(s) used user-agent strings associated "
                "with well-known attack and scanning tools."
            ),
            explanation=(
                "Automated security tools, vulnerability scanners, and exploit frameworks "
                "typically advertise themselves via distinctive user-agent strings. "
                "Detecting these strings indicates active reconnaissance or exploitation "
                "activity against the target web service."
            ),
            possible_causes=[
                "Active vulnerability scanning with tools such as sqlmap, nikto, or nmap",
                "Automated web crawling or enumeration (dirbuster, gobuster, ffuf)",
                "Exploit framework activity (Metasploit, Burp Suite)",
                "Password-spraying or credential stuffing (Hydra)",
                "Legitimate penetration testing activity",
            ],
            recommended_actions=[
                "Block the source IP(s) at the perimeter firewall",
                "Review web server logs for the full scope of requests from these sources",
                "Verify whether a sanctioned pentest is in progress",
                "Enable WAF rules to reject known scanner user-agent strings",
                "Alert SOC for immediate investigation if no pentest is scheduled",
            ],
            affected_hosts=list(dict.fromkeys(sus_ua_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=sus_ua_pkts[:50],
                host_ips=list(dict.fromkeys(sus_ua_hosts))[:20],
                time_first=min(
                    tx.ts_request for tx in txns
                    if tx.request_pkt in set(sus_ua_pkts)
                ) if sus_ua_pkts else 0.0,
                time_last=max(
                    tx.ts_request for tx in txns
                    if tx.request_pkt in set(sus_ua_pkts)
                ) if sus_ua_pkts else 0.0,
                metrics={"total_suspicious_requests": len(sus_ua_pkts)},
                samples=suspicious_ua_list[:20],
            ),
            mitre_keys=["reconnaissance", "active-scanning"],
            tags=["http", "scanner", "user-agent"],
        ))

    # HTTP-002: Web attack URI patterns
    if attack_pkts:
        ctx.findings.append(build_finding(
            rule_id="HTTP-002",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            category="web-attack",
            title="Web Attack Patterns Detected in HTTP URIs",
            description=(
                f"{len(attack_pkts)} request(s) contained URI patterns consistent "
                "with SQL injection, path traversal, command injection, or admin probing."
            ),
            explanation=(
                "Malicious HTTP requests often embed attack payloads directly in the URI, "
                "query string, or request path. Detected patterns include SQL injection "
                "keywords, directory traversal sequences (../), OS command injection "
                "metacharacters, and probing of administrative interfaces."
            ),
            possible_causes=[
                "Automated SQL injection probing (sqlmap, manual payloads)",
                "Directory traversal attempts to access sensitive files",
                "Command injection attempts targeting vulnerable parameters",
                "Administrative panel enumeration and brute-force",
                "Web shell upload or access attempts",
            ],
            recommended_actions=[
                "Immediately review affected URIs in web server and application logs",
                "Block source IP(s) at the firewall and WAF",
                "Verify application input-validation controls are functioning",
                "Check for successful exploitation (2xx responses to attack payloads)",
                "Escalate to incident response if any attack appears successful",
            ],
            affected_hosts=list(dict.fromkeys(attack_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=attack_pkts[:50],
                host_ips=list(dict.fromkeys(attack_hosts))[:20],
                time_first=min(
                    tx.ts_request for tx in txns
                    if tx.request_pkt in set(attack_pkts)
                ) if attack_pkts else 0.0,
                time_last=max(
                    tx.ts_request for tx in txns
                    if tx.request_pkt in set(attack_pkts)
                ) if attack_pkts else 0.0,
                metrics={"total_attack_requests": len(attack_pkts)},
                samples=sensitive_uri_list[:20],
            ),
            mitre_keys=["initial-access", "exploitation"],
            tags=["http", "sqli", "path-traversal", "cmdi", "web-attack"],
        ))

    # HTTP-003: Cleartext credentials
    if cred_pkts:
        cred_hosts = []
        for tx in txns:
            if tx.request_pkt in set(cred_pkts):
                cred_hosts.extend([tx.client_ip, tx.server_ip])
        ctx.findings.append(build_finding(
            rule_id="HTTP-003",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="credential-exposure",
            title="Cleartext Credentials Submitted over Plain HTTP",
            description=(
                f"{len(cred_pkts)} POST request(s) to authentication endpoints were "
                "sent over unencrypted HTTP (port 80), exposing credentials in cleartext."
            ),
            explanation=(
                "Authentication credentials (usernames, passwords, tokens) submitted via "
                "HTTP are transmitted in plaintext and can be trivially captured by any "
                "network observer. This violates basic transport-layer security requirements."
            ),
            possible_causes=[
                "Web application not enforcing HTTPS for authentication",
                "Missing HSTS (HTTP Strict Transport Security) header",
                "Developer or test environment without TLS configured",
                "Misconfigured load balancer or reverse proxy terminating TLS early",
            ],
            recommended_actions=[
                "Enforce HTTPS for all authentication endpoints immediately",
                "Configure HSTS with a long max-age to prevent downgrade attacks",
                "Redirect all HTTP traffic to HTTPS at the web server level",
                "Rotate any credentials that may have been exposed",
                "Audit the application for other endpoints transmitting sensitive data",
            ],
            affected_hosts=list(dict.fromkeys(h for h in cred_hosts if h))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=cred_pkts[:50],
                host_ips=list(dict.fromkeys(h for h in cred_hosts if h))[:20],
                time_first=min(
                    tx.ts_request for tx in txns
                    if tx.request_pkt in set(cred_pkts)
                ) if cred_pkts else 0.0,
                time_last=max(
                    tx.ts_request for tx in txns
                    if tx.request_pkt in set(cred_pkts)
                ) if cred_pkts else 0.0,
                metrics={"cleartext_auth_requests": len(cred_pkts)},
                samples=cleartext_cred_list[:20],
            ),
            mitre_keys=["credential-access", "network-sniffing"],
            tags=["http", "cleartext", "credentials", "authentication"],
        ))

    # HTTP-004: High 5xx error rate
    if error_5xx >= _5XX_MIN_COUNT:
        sev = Severity.CRITICAL if error_5xx >= _5XX_CRIT_COUNT else Severity.HIGH
        err5_pkts = [
            tx.response_pkt for tx in txns
            if tx.status_code and 500 <= tx.status_code < 600 and tx.response_pkt
        ]
        err5_hosts = list(dict.fromkeys(
            h for tx in txns
            if tx.status_code and 500 <= tx.status_code < 600
            for h in (tx.client_ip, tx.server_ip) if h
        ))
        ctx.findings.append(build_finding(
            rule_id="HTTP-004",
            severity=sev,
            confidence=Confidence.HIGH,
            category="availability",
            title=f"High HTTP 5xx Server Error Rate ({error_5xx} errors)",
            description=(
                f"{error_5xx} HTTP 5xx server error responses were observed, "
                f"indicating significant server-side failures or exploitation attempts."
            ),
            explanation=(
                "A high rate of 5xx errors can signal an overloaded or crashing server, "
                "an application under active attack (e.g., DoS, exploit fuzzing), "
                "or a misconfigured back-end. At critical levels (≥50) this may indicate "
                "a denial-of-service condition or successful exploitation disrupting service."
            ),
            possible_causes=[
                "Server under denial-of-service or resource exhaustion attack",
                "Active exploitation fuzzing causing application crashes",
                "Back-end service failures (database, upstream API)",
                "Application bugs triggered by unusual input",
                "Misconfigured or overloaded infrastructure",
            ],
            recommended_actions=[
                "Investigate application and server logs for the root cause of errors",
                "Check server resource utilization (CPU, memory, disk)",
                "Determine whether errors correlate with suspicious source IPs",
                "Enable rate limiting at the load balancer or WAF",
                "Page on-call engineering team if service availability is impacted",
            ],
            affected_hosts=err5_hosts[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=err5_pkts[:50],
                host_ips=err5_hosts[:20],
                metrics={
                    "error_5xx_count": error_5xx,
                    "total_responses": total_responses,
                    "error_rate_pct": round(error_5xx / total_responses * 100, 1)
                    if total_responses else 0.0,
                },
                samples=[
                    f"HTTP {tx.status_code} {tx.host}{tx.uri} pkt#{tx.response_pkt}"
                    for tx in txns
                    if tx.status_code and 500 <= tx.status_code < 600
                ][:20],
            ),
            mitre_keys=["impact", "network-denial-of-service"],
            tags=["http", "5xx", "server-error", "availability"],
        ))

    # HTTP-005: High 4xx error rate (possible brute force / scanner)
    if error_4xx >= _4XX_MIN_COUNT:
        err4_pkts = [
            tx.response_pkt for tx in txns
            if tx.status_code and 400 <= tx.status_code < 500 and tx.response_pkt
        ]
        err4_hosts = list(dict.fromkeys(
            h for tx in txns
            if tx.status_code and 400 <= tx.status_code < 500
            for h in (tx.client_ip, tx.server_ip) if h
        ))
        ctx.findings.append(build_finding(
            rule_id="HTTP-005",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="reconnaissance",
            title=f"High HTTP 4xx Client Error Rate ({error_4xx} errors)",
            description=(
                f"{error_4xx} HTTP 4xx client error responses observed, "
                "suggesting brute-force, credential stuffing, or directory enumeration."
            ),
            explanation=(
                "A high volume of 4xx responses—especially 401/403/404—is a classic "
                "indicator of automated scanning, directory brute-forcing, or credential "
                "stuffing attacks. Attackers iterate through common paths or credentials, "
                "generating many failed requests before finding a valid target."
            ),
            possible_causes=[
                "Directory/path enumeration (gobuster, dirbuster, ffuf)",
                "Credential brute-force generating 401 Unauthorized responses",
                "Scanning for vulnerable endpoints returning 403/404",
                "Web crawler hitting removed or non-existent resources",
                "Misconfigured client making repeated invalid requests",
            ],
            recommended_actions=[
                "Identify and block the top source IPs generating 4xx errors",
                "Implement account lockout or CAPTCHA for authentication endpoints",
                "Enable WAF rate limiting on 4xx thresholds",
                "Review 401 responses to confirm no successful authentications follow",
                "Correlate with HTTP-001/HTTP-002 findings for fuller attack picture",
            ],
            affected_hosts=err4_hosts[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=err4_pkts[:50],
                host_ips=err4_hosts[:20],
                metrics={
                    "error_4xx_count": error_4xx,
                    "total_responses": total_responses,
                    "error_rate_pct": round(error_4xx / total_responses * 100, 1)
                    if total_responses else 0.0,
                },
                samples=[
                    f"HTTP {tx.status_code} {tx.host}{tx.uri} pkt#{tx.response_pkt}"
                    for tx in txns
                    if tx.status_code and 400 <= tx.status_code < 500
                ][:20],
            ),
            mitre_keys=["reconnaissance", "brute-force"],
            tags=["http", "4xx", "brute-force", "scanner"],
        ))

    # HTTP-006: Slow HTTP responses
    if len(slow_pkts) >= _SLOW_MIN_COUNT:
        slow_hosts = list(dict.fromkeys(
            h for tx in txns
            if tx.latency_ms > _SLOW_LATENCY_MS
            for h in (tx.client_ip, tx.server_ip) if h
        ))
        slow_latencies = [tx.latency_ms for tx in txns if tx.latency_ms > _SLOW_LATENCY_MS]
        avg_slow = sum(slow_latencies) / len(slow_latencies)
        ctx.findings.append(build_finding(
            rule_id="HTTP-006",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="availability",
            title=f"Slow HTTP Responses Detected ({len(slow_pkts)} transactions >2000ms)",
            description=(
                f"{len(slow_pkts)} HTTP transactions had response latency exceeding "
                f"2000ms (avg: {avg_slow:.0f}ms), indicating server performance issues."
            ),
            explanation=(
                "Consistently slow HTTP response times may indicate server resource "
                "exhaustion, an application under denial-of-service conditions (e.g., "
                "slowloris), heavy database load, or a slow-HTTP attack where the attacker "
                "holds connections open to exhaust server connection pools."
            ),
            possible_causes=[
                "Slow HTTP attack (slowloris, slow POST) exhausting server threads",
                "Server CPU/memory under high load from concurrent requests",
                "Database query performance degradation",
                "Back-end dependency latency (remote API, cache miss)",
                "Network congestion or bandwidth saturation",
            ],
            recommended_actions=[
                "Configure server-side request timeouts to limit slow connections",
                "Investigate whether slow responses correlate with a single source IP",
                "Enable connection-rate limiting and slow-HTTP mitigation on the WAF",
                "Profile the application for expensive queries or operations",
                "Scale infrastructure or enable CDN caching if load is legitimate",
            ],
            affected_hosts=slow_hosts[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=slow_pkts[:50],
                host_ips=slow_hosts[:20],
                metrics={
                    "slow_transaction_count": len(slow_pkts),
                    "avg_slow_latency_ms": round(avg_slow, 2),
                    "max_latency_ms": round(max(slow_latencies), 2),
                    "threshold_ms": _SLOW_LATENCY_MS,
                },
                samples=[
                    f"latency={t['latency_ms']:.0f}ms uri={t['uri']} pkt#{t['pkt']}"
                    for t in sorted(slow_txns, key=lambda x: -x["latency_ms"])[:20]
                ],
            ),
            mitre_keys=["impact", "network-denial-of-service"],
            tags=["http", "slow-response", "availability", "performance"],
        ))


def _empty_stats() -> Dict[str, Any]:
    return {
        "total_requests": 0,
        "total_responses": 0,
        "method_counts": {},
        "status_counts": {},
        "error_4xx": 0,
        "error_5xx": 0,
        "avg_latency_ms": 0.0,
        "top_hosts": [],
        "top_uris": [],
        "top_user_agents": [],
        "content_types": {},
        "suspicious_ua_list": [],
        "sensitive_uri_list": [],
        "cleartext_cred_list": [],
    }
