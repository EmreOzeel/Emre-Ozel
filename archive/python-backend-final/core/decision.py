"""
Decision support engine.

Takes findings and host profiles from a completed analysis and produces:
  - ranked_causes: most likely root cause explanations, ordered by probability
  - investigation_steps: concrete analyst actions in priority order
  - resolution_guidance: what "done" looks like for each open finding

This is intentionally rule-based (no LLM) — deterministic, testable, auditable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class RootCause:
    rank: int
    cause: str
    probability: str          # "high" | "medium" | "low"
    probability_pct: int      # 0–100
    evidence_summary: str     # one-sentence justification
    next_steps: List[str]     # concrete analyst actions
    resolution: str           # what "resolved" looks like


@dataclass
class DecisionReport:
    ranked_causes: List[RootCause]
    investigation_steps: List[str]   # ordered cross-finding priority list
    resolution_guidance: str          # overall closure criteria
    risk_level: str                   # critical / high / medium / low / clean
    risk_summary: str                 # one paragraph for non-technical audience


# ── Rule tables ───────────────────────────────────────────────────────────────

# Maps rule_id → (human cause label, default probability, next_steps template)
_RULE_CAUSES: Dict[str, Dict] = {
    "SCAN-001": {
        "cause": "Unauthorized network reconnaissance / port scanning",
        "base_prob": 80,
        "steps": [
            "Identify whether {src} is an authorized scanner (Nessus, Qualys, pentest tooling)",
            "Check asset management and change records for {src} at the time of capture",
            "Correlate scan timing with scheduled security assessments or vulnerability scans",
            "If unauthorized: escalate to incident response; isolate {src} from network",
            "Review firewall ACLs — determine if scan reached sensitive segments",
        ],
        "resolution": "Scanner confirmed as authorized and documented, OR host isolated and incident closed.",
    },
    "ARP-001": {
        "cause": "ARP cache poisoning / man-in-the-middle attack",
        "base_prob": 75,
        "steps": [
            "Capture ARP table from affected hosts to confirm the spoofed mapping",
            "Identify the physical switch port hosting the attacker MAC address",
            "Check whether any traffic was intercepted (inspect flows between affected hosts)",
            "Enable Dynamic ARP Inspection (DAI) on the VLAN if not already active",
            "If attack confirmed: rotate credentials for services used on the affected segment",
        ],
        "resolution": "Attacker host identified and removed, ARP tables restored, DAI enabled.",
    },
    "C2-001": {
        "cause": "Command-and-control beaconing (malware callback)",
        "base_prob": 65,
        "steps": [
            "Capture full payload of periodic connections from {src} to confirm C2 content",
            "Submit destination IP/domain {dst} to threat intelligence (VirusTotal, Shodan)",
            "Run memory and disk forensics on {src} to identify the malware process",
            "Block {dst} at perimeter firewall and DNS resolver immediately",
            "Check lateral movement: which other hosts does {src} communicate with?",
            "Review authentication logs on {src} for credential compromise",
        ],
        "resolution": "Malware identified, host re-imaged, IOCs blocked at perimeter, no lateral spread confirmed.",
    },
    "DNS-001": {
        "cause": "NXDOMAIN storm — DGA malware C2 lookups or misconfigured DNS resolver",
        "base_prob": 65,
        "steps": [
            "Review the full list of NXDOMAIN domains from {src} — check for random/DGA patterns",
            "Determine if {src} is a misconfigured application (wrong DNS suffix) or deliberate DGA malware",
            "Check whether NXDOMAIN count correlates with application deployment or config change events",
            "Submit sampled NXDOMAIN domains to threat intelligence feeds for DGA classification",
            "If DGA confirmed: isolate {src}, run malware scan, and add DNS RPZ blocking for the pattern",
        ],
        "resolution": "Root cause (misconfiguration or DGA) confirmed, remediated, NXDOMAIN rate returned to baseline.",
    },
    "DNS-002": {
        "cause": "DNS tunneling — data exfiltration or C2 communication via encoded DNS subdomains",
        "base_prob": 60,
        "steps": [
            "Decode the high-entropy subdomains from {src} — check for base64 or hex encoded data",
            "Submit queried domains to threat intelligence feeds and check for known tunnel providers",
            "Measure label entropy — >3.5 bits/char with labels >40 chars is strong tunneling evidence",
            "Block the tunneled domain at the recursive resolver and DNS firewall immediately",
            "Identify which process on {src} is issuing the long-label queries (EDR process telemetry)",
        ],
        "resolution": "Queries confirmed as legitimate CDN, or DNS tunneling blocked and originating process identified and cleaned.",
    },
    "TCP-001": {
        "cause": "Network congestion, packet loss, or degraded link quality",
        "base_prob": 70,
        "steps": [
            "Identify the network segment with highest retransmission count",
            "Check interface error counters on switches/routers in the affected path",
            "Review QoS policies — are critical flows being deprioritized?",
            "Run continuous ping/traceroute to measure loss and latency on the affected path",
            "Correlate retransmission timestamps with any infrastructure change events",
        ],
        "resolution": "Congested link identified and resolved, or retransmissions confirmed as benign burst traffic.",
    },
    "TLS-001": {
        "cause": "Legacy TLS usage (TLS 1.0/1.1) — compliance or vulnerability risk",
        "base_prob": 85,
        "steps": [
            "Identify all client/server pairs still negotiating TLS 1.0/1.1",
            "Check if clients can be upgraded (OS/library patch) or require legacy support",
            "Set minimum TLS version to 1.2 on all servers if client upgrades are possible",
            "Document exceptions in risk register if legacy clients cannot be upgraded",
        ],
        "resolution": "All connections use TLS 1.2+ or legacy exceptions documented and accepted.",
    },
    "TLS-002": {
        "cause": "TLS certificate validation failure or active MitM interception",
        "base_prob": 65,
        "steps": [
            "Extract the specific alert description (e.g., certificate_expired, bad_certificate)",
            "Verify certificate expiry on {dst} — use: echo | openssl s_client -connect {dst}:443 2>/dev/null | openssl x509 -noout -dates",
            "Confirm the certificate chain is signed by a trusted CA on all affected clients",
            "Check whether {src} is behind a TLS inspection proxy that may be injecting its own cert",
            "Correlate with other indicators — MitM proxies often also produce SNI mismatches",
        ],
        "resolution": "Certificate renewed/corrected, MitM proxy identified and documented, or TLS config updated.",
    },
    "TLS-003": {
        "cause": "Cleartext HTTP traffic on HTTPS port — misconfiguration or C2 evasion",
        "base_prob": 70,
        "steps": [
            "Identify the application or process on {src} sending plaintext to port 443",
            "Inspect the plaintext content — check for encoded commands or exfiltration payloads",
            "Verify whether {dst} is a known internal service or an external IP",
            "If external: correlate with C2 beaconing indicators (periodic intervals, small payload)",
            "Enforce TLS-only policy at network boundary for port 443",
        ],
        "resolution": "Misconfiguration corrected, or C2 cleartext channel blocked and host cleaned.",
    },
    "TLS-004": {
        "cause": "Self-signed TLS certificate — possible malware C2 or internal misconfiguration",
        "base_prob": 60,
        "steps": [
            "Extract certificate details: CN, issuer, validity period for each self-signed connection",
            "Check whether {dst} appears in asset inventory as a known internal service",
            "If external destination: treat as probable C2 indicator — submit IP to threat intelligence",
            "Replace self-signed certs on internal services with CA-signed alternatives",
            "Correlate with C2-001 or beaconing indicators if the destination is external",
        ],
        "resolution": "Internal services migrated to CA-signed certs; external C2 destination blocked and host cleaned.",
    },
    "TLS-005": {
        "cause": "TLS SNI/certificate mismatch — domain fronting, MitM proxy, or server misconfiguration",
        "base_prob": 65,
        "steps": [
            "Compare the SNI hostname in ClientHello with the certificate CN/SANs presented by {dst}",
            "Check HTTP Host header vs TLS SNI — a mismatch is a strong domain-fronting indicator",
            "Identify the certificate issuer — an unexpected CA may indicate a MitM inspection proxy",
            "Review virtual-host bindings on {dst} if it is an internal server",
            "If domain fronting confirmed: block at the CDN/firewall layer and investigate {src}",
        ],
        "resolution": "Domain fronting blocked, MitM proxy identified and documented, or server cert binding corrected.",
    },
    "TLS-006": {
        "cause": "Known malicious TLS fingerprint (JA3) — active malware C2 communication",
        "base_prob": 80,
        "steps": [
            "Immediately isolate {src} from the network to prevent further C2 or lateral spread",
            "Identify the process generating the TLS connection on {src} (netstat, EDR telemetry)",
            "Submit the destination IP {dst} to threat intelligence (VirusTotal, Shodan, AbuseIPDB)",
            "Collect memory and disk forensic image from {src} before remediation",
            "Search for lateral movement — enumerate all hosts {src} connected to after compromise",
        ],
        "resolution": "Malware identified and removed, host re-imaged, C2 IOCs blocked, no lateral spread confirmed.",
    },
    "TCP-002": {
        "cause": "Receive-buffer overflow / slow application consumer causing TCP zero-window stalls",
        "base_prob": 65,
        "steps": [
            "Identify which host sends zero-window advertisements — this is the backpressure source",
            "Check CPU and memory utilization on the affected host during the stall period",
            "Review application logs for slow processing, GC pauses, or lock contention on {dst}",
            "Check OS TCP receive-buffer configuration (net.core.rmem_max, SO_RCVBUF) on {dst}",
            "Correlate stall timestamps with application deployment events or traffic spikes",
        ],
        "resolution": "Root cause (slow consumer, resource exhaustion, or buffer misconfiguration) identified and corrected.",
    },
    "TCP-003": {
        "cause": "Connection filtering (firewall/ACL blocking the port), host unreachable, or service not listening",
        "base_prob": 75,
        "steps": [
            "Verify firewall rules on {dst} allow inbound connections from {src} on the target port",
            "Confirm the service is running and listening: netstat -tlnp | grep <port> on {dst}",
            "Test connectivity from a known-good host to isolate whether the issue is source-specific",
            "Check routing and ACLs between segments — especially if {src} and {dst} are on different VLANs",
            "Review change records — was the service recently stopped, or a firewall rule recently added?",
        ],
        "resolution": "Blocked port confirmed intentional (firewall policy documented), or service restarted/network path restored.",
    },
    "TCP-004": {
        "cause": "SYN flood attack or aggressive scanning leaving half-open connections",
        "base_prob": 70,
        "steps": [
            "Identify all source IPs generating SYN-only traffic and determine if they are legitimate",
            "Check whether SYN cookies are enabled on the target host: sysctl net.ipv4.tcp_syncookies",
            "Implement rate-limiting on SYN packets at the firewall or IPS",
            "If source IPs are spoofed: engage upstream ISP for scrubbing or null-route the source blocks",
            "Monitor {dst} for resource exhaustion (connection table, memory) while mitigation is applied",
        ],
        "resolution": "SYN cookies enabled, rate limiting applied, attack source blocked or scrubbed, and service stable.",
    },
    "TCP-005": {
        "cause": "Asymmetric routing — return traffic does not pass through the capture point",
        "base_prob": 80,
        "steps": [
            "Verify that the capture tap/SPAN port sees both directions of the flows",
            "Check routing tables on the default gateway for asymmetric paths",
            "Add a second capture point on the return path, or use ERSPAN/RSPAN to aggregate both directions",
            "Confirm whether one-sided flows correspond to legitimate asymmetric forwarding (e.g., ECMP, anycast)",
            "If asymmetric routing is unintentional: fix routing policies to ensure symmetric paths",
        ],
        "resolution": "Capture architecture updated to include both directions, or asymmetric routing documented as expected.",
    },
    "TCP-006": {
        "cause": "TCP RST flood — application instability, firewall termination policy, or DoS via RST injection",
        "base_prob": 65,
        "steps": [
            "Identify which host is the primary source of RST packets",
            "Check whether RSTs originate from a firewall or IPS (idle timeout or policy enforcement)",
            "Review application crash logs on {src} — application panics often generate RST storms",
            "Correlate RST timestamps with CPU spikes, memory exhaustion, or recent deployments",
            "If RSTs from an unexpected external source: investigate for RST injection / spoofing",
        ],
        "resolution": "RST source identified, root cause (app crash, firewall policy, or RST injection) remediated.",
    },
    "HTTP-001": {
        "cause": "Automated attack or scanning tool targeting web application",
        "base_prob": 80,
        "steps": [
            "Identify the source IP(s) using the suspicious user-agent and determine if authorized",
            "Review the complete URI list from {src} — check for scanning or exploitation patterns",
            "Check HTTP response codes — 2xx/3xx responses for malicious URIs indicate possible success",
            "Correlate with web server error logs and WAF logs for blocked vs. successful attacks",
            "Block {src} at the WAF or firewall if unauthorized; document if an authorized pentest",
        ],
        "resolution": "Unauthorized scanner blocked, authorized pentest documented, or evidence of successful exploitation escalated.",
    },
    "HTTP-002": {
        "cause": "Active web application attack — SQL injection, path traversal, or command injection",
        "base_prob": 75,
        "steps": [
            "Extract the full set of attack payloads from the flagged URIs and POST bodies",
            "Inspect HTTP response codes — 200/302 responses for attack payloads indicate exploitation",
            "Check database integrity and application logs for unauthorized queries or data access",
            "Review web server access logs for successful execution of traversal or injection payloads",
            "Apply WAF rules for the detected attack patterns and validate patch status of the web app",
        ],
        "resolution": "No successful exploitation confirmed, WAF rules updated, and application patched or mitigated.",
    },
    "HTTP-003": {
        "cause": "Cleartext credential submission over HTTP — authentication data exposed in transit",
        "base_prob": 90,
        "steps": [
            "Identify the login endpoint receiving plaintext credentials (URI and Host header)",
            "Determine the exposure window — when did this start and how many accounts are affected",
            "Immediately force HTTPS redirect (HTTP 301) for all authentication endpoints",
            "Rotate credentials for all accounts that may have been submitted over HTTP",
            "Implement HSTS on the web server to prevent future HTTP submissions",
        ],
        "resolution": "HTTPS enforced with HSTS, all potentially exposed credentials rotated, and HTTP auth endpoints blocked.",
    },
    "HTTP-004": {
        "cause": "Server-side failure, resource exhaustion, or exploitation attempt overwhelming the service",
        "base_prob": 65,
        "steps": [
            "Check web server error logs for the specific 5xx failure reason (uncaught exception, OOM, timeout)",
            "Correlate 5xx timestamps with server CPU/memory metrics — look for resource saturation",
            "Review whether the 5xx errors originate from a single source IP (targeted attack vs. widespread failure)",
            "Inspect request content for attack payloads that may be triggering server errors",
            "Check upstream dependencies (database, cache, external APIs) for availability issues",
        ],
        "resolution": "Root cause identified (application bug, DoS traffic, or resource exhaustion), mitigated, 5xx rate at baseline.",
    },
    "HTTP-005": {
        "cause": "Directory enumeration, brute-force, or application returning errors to unauthorized requests",
        "base_prob": 70,
        "steps": [
            "Identify the source IP(s) generating 4xx responses and determine if automated tool traffic",
            "Review the requested URIs for enumeration patterns (sequential paths, wordlist-based probing)",
            "Check authentication logs for credential-stuffing or brute-force attempts on login endpoints",
            "Implement rate-limiting on the source IP(s) generating excessive 4xx responses",
            "Verify the 4xx responses do not inadvertently confirm existence of resources (use 404 consistently)",
        ],
        "resolution": "Enumeration source blocked or rate-limited, brute-force accounts locked, and server responses normalized.",
    },
    "HTTP-006": {
        "cause": "Server performance degradation, resource saturation, or slow-HTTP DoS attack",
        "base_prob": 55,
        "steps": [
            "Check server CPU, memory, and thread-pool utilization during the slow-response period",
            "Identify whether slow responses cluster around specific URIs or affect all endpoints",
            "Look for slow-HTTP attack patterns (Slowloris, RUDY): many concurrent connections each sending data slowly",
            "Implement minimum request rate enforcement and connection timeout (e.g., nginx: client_body_timeout)",
            "Review upstream dependency latency — slow database queries or external API calls propagate as 5xx/slowness",
        ],
        "resolution": "Performance bottleneck identified and resolved, or slow-HTTP mitigation enabled and attack traffic blocked.",
    },
    "DOS-001": {
        "cause": "TCP SYN flood denial-of-service attack targeting network resources",
        "base_prob": 80,
        "steps": [
            "Confirm whether SYN cookies are enabled on the target: sysctl net.ipv4.tcp_syncookies",
            "Identify the source IP(s) — check if they are spoofed (random) or from a botnet (multiple /24s)",
            "Apply rate-limiting on inbound SYN packets at the border firewall or ISP edge",
            "Contact upstream ISP for null-route or scrubbing center activation if volumetric",
            "Monitor connection table size on {dst} — at saturation, legitimate connections will fail",
        ],
        "resolution": "SYN cookies active, attack traffic mitigated upstream or rate-limited, and legitimate service restored.",
    },
    "DOS-002": {
        "cause": "ICMP echo request flood — bandwidth exhaustion or host resource consumption attack",
        "base_prob": 75,
        "steps": [
            "Confirm whether the ICMP source IP(s) are spoofed or from a legitimate network",
            "Rate-limit or block ICMP echo requests at the firewall ingress (allow only management sources)",
            "Check for ICMP amplification reflectors — ensure no public-facing hosts respond to broadcast pings",
            "Engage upstream ISP if the flood is volumetric and exceeds local mitigation capacity",
            "Monitor bandwidth utilization on the affected interface during the flood",
        ],
        "resolution": "ICMP flood blocked at network perimeter, bandwidth restored, and amplification vectors closed.",
    },
    "LAT-001": {
        "cause": "Lateral movement — internal host accessing sensitive services on other internal systems",
        "base_prob": 70,
        "steps": [
            "Examine authentication logs on all target hosts for unauthorized access from {src}",
            "Run EDR/AV scan on {src} — lateral movement typically follows an initial compromise",
            "Check active sessions on target sensitive services (RDP, SMB, SSH) for anomalous logins",
            "Isolate {src} from internal network segments until compromise is confirmed or ruled out",
            "Enumerate all hosts {src} has connected to in the capture window — map the potential blast radius",
        ],
        "resolution": "Compromised host isolated, unauthorized access blocked, credentials rotated, no further lateral spread confirmed.",
    },
}

_DEFAULT_CAUSE = {
    "cause": "Anomalous network behavior requiring investigation",
    "base_prob": 50,
    "steps": [
        "Review the full evidence packet capture for the flagged activity",
        "Correlate finding with other security logs (SIEM, EDR, firewall)",
        "Determine if the activity matches any known maintenance windows",
    ],
    "resolution": "Activity explained by authorized change or incident response completed.",
}

_RISK_LABELS = {
    "critical": "CRITICAL — Immediate action required. Active threat indicators present.",
    "high": "HIGH — Significant risk. Investigate within 24 hours.",
    "medium": "MEDIUM — Notable concerns. Review within the week.",
    "low": "LOW — Minor issues. Address in next maintenance cycle.",
    "clean": "CLEAN — No significant findings detected.",
}


# ── Core logic ────────────────────────────────────────────────────────────────

def _substitute(template: str, finding: Dict) -> str:
    """Fill {src} / {dst} placeholders from finding's affected_hosts."""
    hosts = finding.get("affected_hosts", [])
    src = hosts[0] if hosts else "the flagged host"
    dst = hosts[1] if len(hosts) > 1 else "the destination"
    return template.replace("{src}", src).replace("{dst}", dst)


def _boost_probability(base: int, finding: Dict) -> int:
    """Adjust base probability up/down based on evidence quality."""
    boost = 0
    confidence = finding.get("confidence", "medium")
    if confidence == "high":
        boost += 15
    elif confidence == "low":
        boost -= 20

    score = finding.get("score", 0)
    if score >= 8:
        boost += 10
    elif score <= 3:
        boost -= 10

    metrics = finding.get("evidence", {}).get("metrics", {})
    if metrics:
        boost += 5   # concrete metrics = stronger signal

    return max(5, min(98, base + boost))


def _prob_label(pct: int) -> str:
    if pct >= 75:
        return "high"
    if pct >= 45:
        return "medium"
    return "low"


def _overall_risk(findings: List[Dict]) -> str:
    active = [f for f in findings if not f.get("suppressed")]
    if any(f.get("severity") == "critical" for f in active):
        return "critical"
    if any(f.get("severity") == "high" for f in active):
        return "high"
    if any(f.get("severity") == "medium" for f in active):
        return "medium"
    if active:
        return "low"
    return "clean"


def _risk_summary(risk: str, findings: List[Dict], hosts: List[Dict]) -> str:
    active = [f for f in findings if not f.get("suppressed")]
    anomalous = [h for h in hosts if h.get("anomaly_score", 0) >= 3.0]

    if risk == "clean":
        return (
            "The network capture shows normal traffic patterns. "
            "No security threats or significant anomalies were detected. "
            "Routine monitoring is recommended."
        )

    parts = []
    crit = [f for f in active if f.get("severity") == "critical"]
    high = [f for f in active if f.get("severity") == "high"]

    if crit:
        parts.append(
            f"{len(crit)} critical issue(s) were identified that require immediate attention. "
            f"The most severe is: {crit[0].get('title', 'unknown')}."
        )
    if high:
        parts.append(f"{len(high)} high-severity issue(s) also require prompt investigation.")
    if anomalous:
        parts.append(
            f"{len(anomalous)} host(s) are behaving abnormally and should be examined "
            f"by a network security analyst."
        )
    parts.append(
        "Review the prioritized investigation steps below and begin with the highest-ranked cause."
    )
    return " ".join(parts)


def build_decision_report(findings: List[Dict], hosts: List[Dict]) -> Dict[str, Any]:
    """
    Build a decision support report from serialized findings and host profiles.
    Returns a JSON-serializable dict.
    """
    active = [f for f in findings if not f.get("suppressed")]

    # Build one RootCause per unique rule_id (worst-severity instance)
    seen_rules: Dict[str, Dict] = {}
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for f in active:
        rid = f.get("rule_id") or f.get("title", "")
        if rid not in seen_rules:
            seen_rules[rid] = f
        else:
            if sev_order.get(f.get("severity", "info"), 0) > sev_order.get(
                seen_rules[rid].get("severity", "info"), 0
            ):
                seen_rules[rid] = f

    # Sort: critical first, then by score
    sorted_findings = sorted(
        seen_rules.values(),
        key=lambda f: (-sev_order.get(f.get("severity", "info"), 0), -f.get("score", 0)),
    )

    ranked_causes = []
    all_steps: List[str] = []

    for rank, finding in enumerate(sorted_findings, start=1):
        rid = finding.get("rule_id", "")
        template = _RULE_CAUSES.get(rid, _DEFAULT_CAUSE)

        prob = _boost_probability(template["base_prob"], finding)
        steps = [_substitute(s, finding) for s in template["steps"]]

        ev_summary = _build_evidence_summary(finding)

        ranked_causes.append({
            "rank": rank,
            "rule_id": rid,
            "cause": template["cause"],
            "probability": _prob_label(prob),
            "probability_pct": prob,
            "evidence_summary": ev_summary,
            "next_steps": steps,
            "resolution": template.get("resolution", _DEFAULT_CAUSE["resolution"]),
            "severity": finding.get("severity"),
            "affected_hosts": finding.get("affected_hosts", [])[:4],
        })

        # Aggregate cross-finding priority steps (top 2 per finding)
        for s in steps[:2]:
            label = f"[{finding.get('severity', '?').upper()} — {rid or finding.get('title', '')}] {s}"
            all_steps.append(label)

    # Add anomalous-host steps if not already covered
    anomalous = sorted(
        [h for h in hosts if h.get("anomaly_score", 0) >= 4.0],
        key=lambda h: -h.get("anomaly_score", 0),
    )[:3]
    for h in anomalous:
        if not any(h.get("ip", "") in s for s in all_steps):
            all_steps.append(
                f"[HOST ANOMALY — {h.get('ip')}] Score {h.get('anomaly_score', 0):.1f}: "
                f"check for {', '.join(h.get('suspicious_behaviors', ['unknown behavior'])[:2])}"
            )

    risk = _overall_risk(findings)
    summary = _risk_summary(risk, findings, hosts)

    return {
        "risk_level": risk,
        "risk_summary": summary,
        "ranked_causes": ranked_causes,
        "investigation_steps": all_steps[:20],   # cap at 20 actionable steps
        "resolution_guidance": (
            "Investigation is complete when: all ranked causes are either confirmed+remediated "
            "or ruled out with documented evidence, affected hosts are verified clean or "
            "re-imaged, and suppression rules are in place for any confirmed false positives."
        ),
    }


def _build_evidence_summary(finding: Dict) -> str:
    """One-sentence justification for why this cause is ranked here."""
    metrics = finding.get("evidence", {}).get("metrics", {}) or {}
    hosts = finding.get("affected_hosts", [])
    src = hosts[0] if hosts else "unknown host"

    if metrics:
        top = list(metrics.items())[:2]
        metric_str = "; ".join(f"{k.replace('_', ' ')}: {v}" for k, v in top)
        return f"Evidence from {src}: {metric_str}."

    samples = finding.get("evidence", {}).get("samples", [])
    if samples:
        return f"Observed from {src}: {samples[0][:80]}."

    return (
        f"Finding triggered on {src} with "
        f"{finding.get('confidence', 'medium')} confidence "
        f"(score {finding.get('score', 0):.1f})."
    )
