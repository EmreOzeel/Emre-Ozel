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


def _score(severity: Severity, confidence: Confidence) -> float:
    return _SCORE_TABLE.get(severity, {}).get(confidence, 1.0)


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

    return Finding(
        id=f"{rule_id}-{uuid.uuid4().hex[:8]}",
        severity=severity,
        confidence=confidence,
        score=_score(severity, confidence),
        category=category,
        title=title,
        description=description,
        explanation=explanation,
        confidence_note=confidence_note,
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


def finalize(ctx: CaptureContext, extra_suppressions: Optional[List[Dict]] = None) -> None:
    """Apply suppression rules and sort findings by score descending.

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
    ctx.findings.sort(key=lambda f: (-f.score, f.severity))
