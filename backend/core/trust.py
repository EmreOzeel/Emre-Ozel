"""
Overall analysis trust score.

Combines three independent signals into a single 0–100 score that answers:
"How much should an analyst trust the conclusions of this analysis?"

Signals
-------
1. Capture completeness (40 % weight)
   — Mid-stream sessions, failed handshakes, one-sided asymmetry.
   A capture full of mid-stream sessions cannot confirm handshakes,
   making all session-level conclusions uncertain.

2. Finding evidence quality (40 % weight)
   — Average confidence_score across all active (non-suppressed) findings.
   A set of well-evidenced findings scores high; thin or heuristic-only
   findings drag the average down.

3. Contradiction penalty (up to −40 pts)
   — Each "warning" sanity issue subtracts from the score.
   Contradictions mean the detection layer and the raw stats disagree,
   which makes findings unreliable regardless of their stated confidence.

Returned dict
-------------
  trust_score         : int 0–100
  trust_label         : short human-readable label with tier
  trust_reasons       : list of strings explaining what drove the score up/down
  low_confidence_findings : list of {rule_id, title, confidence_score, reason}
                           for findings where confidence_score < LOW_CONF_THRESHOLD
"""
from __future__ import annotations

from typing import Any, Dict, List

# Findings below this confidence_score are surfaced explicitly as low-confidence
_LOW_CONF_THRESHOLD = 45

# Sanity warnings of severity "warning" each subtract this many points
_CONTRADICTION_PENALTY_PER = 12
# Maximum total contradiction penalty
_MAX_CONTRADICTION_PENALTY = 40


def compute_trust_score(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute the overall analysis trust score from the completed pipeline output.
    Call after run_sanity_checks() has populated result["sanity_warnings"].
    """
    reasons: List[str] = []

    # ── 1. Capture completeness score (0–100) ─────────────────────────────────
    tcp_stats = result.get("tcp", {}) or {}
    total_sessions = tcp_stats.get("total_sessions", 0) or 0
    midstream = tcp_stats.get("midstream", 0) or 0
    failed_hs = tcp_stats.get("failed_handshakes", 0) or 0

    if total_sessions > 0:
        midstream_pct = midstream / total_sessions * 100
        failed_pct = failed_hs / total_sessions * 100
        capture_score = 100 - (midstream_pct * 0.5) - (failed_pct * 0.3)
        capture_score = max(0.0, min(100.0, capture_score))

        if midstream_pct > 50:
            reasons.append(
                f"Capture quality is poor: {midstream_pct:.0f}% of sessions are mid-stream "
                "(handshake not captured). Session-level conclusions are unreliable."
            )
        elif midstream_pct > 20:
            reasons.append(
                f"{midstream_pct:.0f}% mid-stream sessions reduce confidence in "
                "protocol identification and session state conclusions."
            )
        elif midstream_pct > 0:
            reasons.append(
                f"{midstream:.0f} mid-stream session(s) ({midstream_pct:.0f}%) — "
                "minor capture incompleteness."
            )
        else:
            reasons.append("All TCP sessions have full handshakes captured — capture is complete.")

        if failed_pct > 20:
            reasons.append(
                f"{failed_pct:.0f}% of connection attempts failed (SYN/no SYN-ACK). "
                "High failure rate may indicate firewall filtering or asymmetric routing."
            )
    else:
        # No TCP sessions — may be UDP-only or short capture
        capture_score = 70.0
        reasons.append("No TCP sessions in capture — capture completeness cannot be assessed.")

    # ── 2. Finding evidence quality score (0–100) ─────────────────────────────
    all_issues = result.get("all_issues", []) or []
    if all_issues:
        conf_scores = [f.get("confidence_score", 50) for f in all_issues]
        avg_conf = sum(conf_scores) / len(conf_scores)

        low_conf = [f for f in all_issues if f.get("confidence_score", 50) < _LOW_CONF_THRESHOLD]
        if low_conf:
            reasons.append(
                f"{len(low_conf)} of {len(all_issues)} finding(s) have low evidence quality "
                f"(confidence_score < {_LOW_CONF_THRESHOLD}). "
                "These should be treated as preliminary indicators."
            )
        else:
            reasons.append(
                f"All {len(all_issues)} finding(s) have adequate evidence quality "
                f"(avg confidence_score: {avg_conf:.0f}/100)."
            )
    else:
        avg_conf = 100.0   # no findings = no low-confidence claims
        reasons.append("No active findings — evidence quality component defaults to 100.")

    # ── 3. Contradiction penalty ──────────────────────────────────────────────
    sanity_warnings = result.get("sanity_warnings", []) or []
    warning_count = sum(
        1 for w in sanity_warnings if w.get("severity") == "warning"
    )
    contradiction_penalty = min(warning_count * _CONTRADICTION_PENALTY_PER, _MAX_CONTRADICTION_PENALTY)

    if warning_count > 0:
        reasons.append(
            f"{warning_count} sanity contradiction(s) detected "
            f"(−{contradiction_penalty} pts). "
            "Findings and raw statistics disagree on at least one data point."
        )
    else:
        reasons.append("No sanity contradictions — findings are internally consistent.")

    # ── Combine ───────────────────────────────────────────────────────────────
    raw_score = 0.40 * capture_score + 0.40 * avg_conf - contradiction_penalty
    trust_score = max(5, min(100, int(round(raw_score))))

    # ── Label ─────────────────────────────────────────────────────────────────
    if trust_score >= 85:
        trust_label = "High — analysis results are reliable"
    elif trust_score >= 70:
        trust_label = "Medium — results are mostly reliable; review low-confidence findings"
    elif trust_score >= 50:
        trust_label = "Low — significant uncertainty; treat all findings as preliminary"
    else:
        trust_label = "Poor — multiple contradictions or severely incomplete capture"

    # ── Low-confidence finding inventory ─────────────────────────────────────
    low_confidence_findings = [
        {
            "rule_id": f.get("rule_id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "confidence_score": f.get("confidence_score", 0),
            "reason": f.get("confidence_note", "No confidence note available."),
        }
        for f in all_issues
        if f.get("confidence_score", 50) < _LOW_CONF_THRESHOLD
    ]

    return {
        "trust_score": trust_score,
        "trust_label": trust_label,
        "trust_reasons": reasons,
        "low_confidence_findings": low_confidence_findings,
        # Component breakdown for transparency
        "components": {
            "capture_completeness": round(capture_score, 1),
            "finding_quality": round(avg_conf, 1),
            "contradiction_penalty": contradiction_penalty,
        },
    }
