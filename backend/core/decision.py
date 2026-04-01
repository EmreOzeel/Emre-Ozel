"""
Decision support engine.

Takes findings and host profiles from a completed analysis and produces:
  - ranked_causes: most likely root cause explanations, ordered by probability
  - investigation_steps: concrete analyst actions in priority order
  - resolution_guidance: what "done" looks like for each open finding

This is intentionally rule-based (no LLM) — deterministic, testable, auditable.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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
        "cause": "DNS-based data exfiltration or malware C2 via DNS tunneling",
        "base_prob": 55,
        "steps": [
            "Decode the high-entropy subdomains to check for encoded data (base64, hex)",
            "Submit queried domains to threat intelligence feeds",
            "Capture DNS traffic and inspect label entropy — >3.5 bits/char indicates encoding",
            "Block the queried domains at the DNS resolver and DNS firewall",
            "Identify which process on {src} is issuing the queries",
        ],
        "resolution": "Queries confirmed as legitimate CDN or DNS tunneling blocked and host cleaned.",
    },
    "DNS-002": {
        "cause": "DNS reconnaissance or misconfigured resolver causing NXDOMAIN storm",
        "base_prob": 60,
        "steps": [
            "Review the full list of queried non-existent domains for patterns (random, sequential)",
            "Determine if {src} is a misconfigured application or deliberate DGA malware",
            "Check whether NXDOMAIN count correlates with application deployment events",
            "If DGA: submit domains to threat intelligence and isolate {src}",
        ],
        "resolution": "Root cause (misconfiguration or DGA) confirmed, remediated, NXDOMAIN rate returned to baseline.",
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
