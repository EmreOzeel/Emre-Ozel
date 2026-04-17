"""
Evidence-first detection engine.
All findings are built via build_finding() which enforces the full evidence model.
Analyzers call emit() to register findings into the CaptureContext.
"""
from __future__ import annotations

import ipaddress
import uuid
from typing import Dict, List, Optional

from detection.mitre import get_mitre
from detection.rules import (
    apply_suppressions,
    load_rules,
    load_suppressions,
)
from models import (
    CaptureContext,
    Confidence,
    Evidence,
    Finding,
    MitreRef,
    Severity,
)

# Score table: severity × confidence → numeric score (0–10)
_SCORE_TABLE: Dict[str, Dict[str, float]] = {
    Severity.CRITICAL: {Confidence.HIGH: 9.5, Confidence.MEDIUM: 8.0, Confidence.LOW: 6.5},
    Severity.HIGH:     {Confidence.HIGH: 8.0, Confidence.MEDIUM: 6.5, Confidence.LOW: 5.0},
    Severity.MEDIUM:   {Confidence.HIGH: 6.0, Confidence.MEDIUM: 4.5, Confidence.LOW: 3.0},
    Severity.LOW:      {Confidence.HIGH: 4.0, Confidence.MEDIUM: 2.5, Confidence.LOW: 1.5},
    Severity.INFO:     {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.5, Confidence.LOW: 0.2},
}

# Per-rule confidence adjustments (positive = more precise, negative = more heuristic)
_RULE_CONF_ADJUST: Dict[str, int] = {
    "ARP-001":  +8,   # directly observed from wire: IP→multiple MAC
    "TLS-006":  +8,   # hash lookup — binary yes/no, not probabilistic
    "DNS-002":  -8,   # entropy heuristic; false positives from CDN/legit long labels
    "C2-001":   -5,   # interval analysis depends heavily on capture duration
    "HTTP-002": -3,   # pattern matching; some SQLi patterns appear in legitimate traffic
}


def _score(severity: Severity, confidence: Confidence) -> float:
    return _SCORE_TABLE.get(severity, {}).get(confidence, 1.0)


def _evidence_confidence(
    confidence: Confidence,
    evidence: Evidence,
    rule_id: str,
) -> int:
    """
    Compute a 0–100 evidence quality score for a finding.

    This is independent of severity — it answers: "how sure are we that
    this detection signal is real, given the evidence collected?"

    High score = many packets, concrete metrics, behavior over time.
    Low score  = single packet, no metrics, short time window.
    """
    cs = 50  # baseline

    # ── Confidence enum ───────────────────────────────────────────────────────
    if confidence == Confidence.HIGH:
        cs += 12
    elif confidence == Confidence.LOW:
        cs -= 18

    # ── Packet count ──────────────────────────────────────────────────────────
    n = len(evidence.packet_nums)
    if n == 0:
        cs -= 20
    elif n < 3:
        cs -= 10
    elif n < 10:
        pass           # neutral
    elif n < 50:
        cs += 6
    elif n < 100:
        cs += 10
    else:
        cs += 14

    # ── Concrete metrics ──────────────────────────────────────────────────────
    if evidence.metrics:
        cs += 8

    # ── Sample strings ────────────────────────────────────────────────────────
    if evidence.samples:
        cs += 5

    # ── Time coverage ─────────────────────────────────────────────────────────
    if evidence.time_first and evidence.time_last:
        duration = evidence.time_last - evidence.time_first
        if duration > 300:
            cs += 10
        elif duration > 60:
            cs += 7
        elif duration > 10:
            cs += 3

    # ── Rule-specific adjustment ──────────────────────────────────────────────
    cs += _RULE_CONF_ADJUST.get(rule_id, 0)

    return max(10, min(95, cs))


def _auto_confidence_note(
    confidence_score: int,
    confidence: Confidence,
    evidence: Evidence,
    rule_id: str,
) -> str:
    """
    Generate an honest confidence explanation when the analyzer did not supply one.
    This ensures every finding explains WHY it has the confidence level it does.
    """
    n_packets = len(evidence.packet_nums)
    has_metrics = bool(evidence.metrics)
    duration = 0.0
    if evidence.time_first and evidence.time_last:
        duration = evidence.time_last - evidence.time_first

    parts = []

    # Signal strength summary
    if confidence_score >= 75:
        parts.append(f"HIGH confidence ({confidence_score}/100).")
    elif confidence_score >= 55:
        parts.append(f"MEDIUM confidence ({confidence_score}/100).")
    else:
        parts.append(f"LOW confidence ({confidence_score}/100) — treat as preliminary.")

    # Evidence basis
    if n_packets == 0:
        parts.append("No packet references in evidence — detection is metric-based only.")
    elif n_packets < 3:
        parts.append(
            f"Thin evidence: only {n_packets} packet(s) referenced. "
            "A single burst or noise event could trigger this."
        )
    elif n_packets < 10:
        parts.append(f"Moderate evidence: {n_packets} packets observed.")
    else:
        parts.append(f"Strong packet evidence: {n_packets} packets referenced.")

    if has_metrics:
        parts.append("Concrete metrics are available to support the finding.")
    else:
        parts.append("No aggregate metrics — detection relies on pattern matching only.")

    if duration > 60:
        parts.append(f"Behavior observed over {duration:.0f}s, suggesting persistence.")
    elif duration > 0:
        parts.append(f"Short time window ({duration:.1f}s) — may be transient.")

    # Rule-specific caveats
    adjust = _RULE_CONF_ADJUST.get(rule_id, 0)
    if adjust < 0:
        parts.append(
            f"Note: {rule_id} uses heuristic detection with known false-positive risk."
        )
    elif adjust > 0:
        parts.append(
            f"Note: {rule_id} uses deterministic detection with low false-positive rate."
        )

    return " ".join(parts)


def build_finding(
    *,
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    category: str,
    title: str,
    description: str,
    explanation: str,
    confidence_note: str = "",
    possible_causes: List[str],
    recommended_actions: List[str],
    affected_hosts: List[str],
    affected_flows: List[str],
    evidence: Evidence,
    mitre_keys: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> Finding:
    mitre: List[MitreRef] = []
    for key in (mitre_keys or []):
        mitre.extend(get_mitre(key))

    conf_score = _evidence_confidence(confidence, evidence, rule_id)
    note = confidence_note or _auto_confidence_note(conf_score, confidence, evidence, rule_id)

    return Finding(
        id=f"{rule_id}-{uuid.uuid4().hex[:8]}",
        severity=severity,
        confidence=confidence,
        score=_score(severity, confidence),
        confidence_score=conf_score,
        category=category,
        title=title,
        description=description,
        explanation=explanation,
        confidence_note=note,
        possible_causes=possible_causes,
        recommended_actions=recommended_actions,
        affected_hosts=list(dict.fromkeys(affected_hosts)),   # dedup preserve order
        affected_flows=list(dict.fromkeys(affected_flows))[:20],
        evidence=evidence,
        mitre=mitre,
        rule_id=rule_id,
        tags=tags or [],
    )


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Merge duplicate findings: same rule_id and same primary affected host.

    When an analyzer fires the same rule multiple times for the same host
    (e.g., every flow triggers retransmission detection independently),
    we keep the highest-scored instance and fold extra samples into it.
    """
    seen: Dict[str, Finding] = {}   # key → best finding
    extras: Dict[str, List[str]] = {}  # key → extra samples to merge

    for f in findings:
        primary = f.affected_hosts[0] if f.affected_hosts else ""
        key = f"{f.rule_id}||{primary}"
        if key not in seen:
            seen[key] = f
            extras[key] = []
        else:
            existing = seen[key]
            # Keep the instance with the higher score
            if f.score > existing.score:
                extras[key].extend(existing.evidence.samples)
                seen[key] = f
            else:
                extras[key].extend(f.evidence.samples)

    # Merge extra samples (cap at 20)
    result = []
    for key, f in seen.items():
        if extras[key]:
            merged = list(dict.fromkeys(f.evidence.samples + extras[key]))[:20]
            f.evidence.samples = merged
        result.append(f)

    return result


def finalize(ctx: CaptureContext, extra_suppressions: Optional[List[Dict]] = None) -> None:
    """Apply suppression rules, deduplicate, and sort findings by score descending.

    extra_suppressions: list of rule dicts (rule_id, src_ip, dst_ip) loaded
    from the database at job time, merged with the static YAML suppressions.
    """
    config = load_rules()
    suppressions = load_suppressions()
    if extra_suppressions:
        suppressions = suppressions + [
            s for s in extra_suppressions
            if isinstance(s, dict)
        ]
    whitelist = config.get("whitelisted_ips", []) or []
    apply_suppressions(ctx.findings, suppressions, whitelist)

    # Deduplicate: same rule + same primary host → keep best, merge samples
    ctx.findings = _deduplicate_findings(ctx.findings)

    ctx.findings.sort(key=lambda f: (-f.score, f.severity))
