"""
Investigation package builder and HTML renderer.

build_package()  — assembles a structured dict from path-analysis results,
                   optional compare data, and optional analyst feedback.

render_html()    — renders an investigation-oriented HTML file from the dict.
                   Self-contained (no external deps / CDN calls).

The export is designed to answer four questions:
  1. What happened?
  2. What changed (baseline → incident)?
  3. Why do we think so?
  4. What did the analyst conclude?
"""
from __future__ import annotations

import html
from datetime import datetime
from typing import Any, Dict, List, Optional


# ── Package builder ───────────────────────────────────────────────────────────

def build_package(
    *,
    analysis_id: str,
    source_ip: str,
    destination_ip: str,
    destination_port: Optional[int],
    path_result: dict,
    engine_version: str,
    from_cache: bool = False,
    compare_result: Optional[dict] = None,
    analyst_feedback: Optional[dict] = None,
    saved_query_meta: Optional[dict] = None,
    role_preset_meta: Optional[dict] = None,
) -> dict:
    """Assemble and return a structured investigation package dict."""
    pa = path_result

    path_section = {
        "connection_outcome":    pa.get("connection_outcome", "unknown"),
        "primary_impairment":    pa.get("primary_impairment"),
        "path_impairments":      pa.get("path_impairments", []),
        "path_confidence_score": pa.get("path_confidence_score", 0),
        "confidence_reasons":    pa.get("confidence_reasons", []),
        "path_summary":          pa.get("path_summary", ""),
        "path_steps":            pa.get("path_steps", []),
        "evidence_items":        pa.get("evidence_items", []),
        "alternative_hypotheses":    pa.get("alternative_hypotheses", []),
        "missing_visibility_notes":  pa.get("missing_visibility_notes", []),
    }

    compare_section: Optional[dict] = None
    if compare_result:
        cr = compare_result
        compare_section = {
            "baseline_analysis_id":         cr.get("baseline_analysis_id"),
            "incident_analysis_id":         cr.get("incident_analysis_id"),
            "baseline_summary":             cr.get("baseline_summary"),
            "incident_summary":             cr.get("incident_summary"),
            "outcome_changed":              cr.get("outcome_changed"),
            "outcome_regression":           cr.get("outcome_regression"),
            "key_differences":              cr.get("key_differences", []),
            "impairment_changes":           cr.get("impairment_changes", {}),
            "timing_differences":           cr.get("timing_differences", {}),
            "confidence_changes":           cr.get("confidence_changes", {}),
            "evidence_differences":         cr.get("evidence_differences", {}),
            "most_likely_regression_point": cr.get("most_likely_regression_point"),
        }

    feedback_section: Optional[dict] = None
    if analyst_feedback:
        fb = analyst_feedback
        feedback_section = {
            "verdict":          fb.get("verdict"),
            "analyst_note":     fb.get("analyst_note"),
            "actual_root_cause": fb.get("actual_root_cause"),
            "misleading_step":  fb.get("misleading_step"),
        }

    return {
        "export_metadata": {
            "generated_at":  datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "engine_version": engine_version,
            "from_cache":    from_cache,
        },
        "query": {
            "analysis_id":      analysis_id,
            "source_ip":        source_ip,
            "destination_ip":   destination_ip,
            "destination_port": destination_port,
            "saved_query":      saved_query_meta,
            "role_preset":      role_preset_meta,
        },
        "path_analysis":    path_section,
        "compare_result":   compare_section,
        "analyst_feedback": feedback_section,
    }


# ── HTML renderer ─────────────────────────────────────────────────────────────

def _e(v: Any) -> str:
    return html.escape(str(v) if v is not None else "")


def _outcome_color(outcome: str) -> str:
    return {
        "success":         "#67c23a",
        "partial_success": "#e6a23c",
        "failure":         "#f56c6c",
    }.get(outcome, "#909399")


def _fmt_token(tok: str) -> str:
    return tok.replace("_", " ").title() if tok else "—"


def _kv_row(label: str, value: Any) -> str:
    return (
        f'<tr><td class="kv-label">{_e(label)}</td>'
        f'<td class="kv-value">{_e(value) if value is not None else "—"}</td></tr>'
    )


def _section(title: str, body: str) -> str:
    return f'<section><h2>{_e(title)}</h2>{body}</section>'


def _render_what_happened(pa: dict) -> str:
    outcome = pa.get("connection_outcome", "unknown")
    color   = _outcome_color(outcome)
    imps    = pa.get("path_impairments", [])
    imp_str = ", ".join(_fmt_token(i) for i in imps) if imps else "—"

    rows = (
        f'<tr><td class="kv-label">Outcome</td>'
        f'<td class="kv-value" style="color:{color};font-weight:700">'
        f'{_e(_fmt_token(outcome))}</td></tr>'
        + _kv_row("Primary Impairment", _fmt_token(pa.get("primary_impairment") or ""))
        + _kv_row("All Impairments",    imp_str)
        + _kv_row("Path Confidence",    f'{pa.get("path_confidence_score", 0)}%')
    )
    table = f'<table class="kv-table">{rows}</table>'

    summary = pa.get("path_summary", "")
    summary_html = f'<p class="path-summary">{_e(summary)}</p>' if summary else ""

    return _section("What Happened", table + summary_html)


def _render_path_steps(pa: dict) -> str:
    steps = pa.get("path_steps", [])
    if not steps:
        return ""
    items = "".join(f"<li>{_e(s)}</li>" for s in steps)
    return _section("Path Narrative", f"<ol>{items}</ol>")


def _render_evidence(pa: dict) -> str:
    items = pa.get("evidence_items", [])
    if not items:
        return ""
    _strength_color = {"high": "#f56c6c", "medium": "#e6a23c", "low": "#909399"}
    cards = ""
    for ev in items:
        strength = ev.get("signal_strength", "low")
        color    = _strength_color.get(strength, "#909399")
        typ      = _fmt_token(ev.get("type", ""))
        summary  = ev.get("summary", "")
        cards += (
            f'<div class="ev-card" style="border-left-color:{color}">'
            f'<span class="ev-strength" style="color:{color}">{_e(strength)}</span>'
            f'<span class="ev-type">{_e(typ)}</span>'
            f'<p class="ev-summary">{_e(summary)}</p>'
            f'</div>'
        )
    return _section("Evidence", cards)


def _render_why(pa: dict) -> str:
    reasons = pa.get("confidence_reasons", [])
    alts    = pa.get("alternative_hypotheses", [])
    gaps    = pa.get("missing_visibility_notes", [])

    body = ""
    if reasons:
        items = "".join(f"<li>{_e(r)}</li>" for r in reasons)
        body += f"<h3>Confidence Reasoning</h3><ul>{items}</ul>"
    if alts:
        items = "".join(f"<li>{_e(a)}</li>" for a in alts)
        body += f"<h3>Alternative Hypotheses</h3><ul>{items}</ul>"
    if gaps:
        items = "".join(f"<li>{_e(g)}</li>" for g in gaps)
        body += f"<h3>Visibility Gaps</h3><ul>{items}</ul>"
    if not body:
        return ""
    return _section("Why We Think So", body)


def _render_compare(cr: dict) -> str:
    b_sum = cr.get("baseline_summary", {}) or {}
    i_sum = cr.get("incident_summary", {}) or {}

    b_outcome = b_sum.get("connection_outcome", "unknown")
    i_outcome = i_sum.get("connection_outcome", "unknown")
    regression = cr.get("outcome_regression", False)

    # Regression point
    rp = cr.get("most_likely_regression_point")
    rp_html = ""
    if rp:
        rp_html = f'<p class="regression-point"><strong>Most Likely Cause:</strong> {_e(rp)}</p>'

    # Key differences
    diffs = cr.get("key_differences", [])
    diffs_html = ""
    if diffs:
        items = "".join(f"<li>{_e(d)}</li>" for d in diffs)
        diffs_html = f"<h3>Key Differences</h3><ul>{items}</ul>"

    # Side-by-side outcome summary
    bc, ic = _outcome_color(b_outcome), _outcome_color(i_outcome)
    side = (
        f'<div class="compare-side-row">'
        f'<div class="compare-side baseline-side">'
        f'<div class="side-label">Baseline</div>'
        f'<table class="kv-table">'
        + _kv_row("Outcome",    _fmt_token(b_outcome))
        + _kv_row("Impairment", _fmt_token(b_sum.get("primary_impairment") or ""))
        + _kv_row("Confidence", f'{b_sum.get("path_confidence_score", 0)}%')
        + f'</table></div>'
        f'<div class="compare-arrow">'
        + ("&#9660;" if regression else "&#8594;")
        + f'</div>'
        f'<div class="compare-side incident-side">'
        f'<div class="side-label">Incident</div>'
        f'<table class="kv-table">'
        + _kv_row("Outcome",    _fmt_token(i_outcome))
        + _kv_row("Impairment", _fmt_token(i_sum.get("primary_impairment") or ""))
        + _kv_row("Confidence", f'{i_sum.get("path_confidence_score", 0)}%')
        + f'</table></div>'
        f'</div>'
    )

    # Impairment changes
    imp = cr.get("impairment_changes", {})
    imp_rows = (
        _kv_row("New",        ", ".join(_fmt_token(x) for x in imp.get("new", [])) or "—")
        + _kv_row("Resolved", ", ".join(_fmt_token(x) for x in imp.get("resolved", [])) or "—")
        + _kv_row("Persisting", ", ".join(_fmt_token(x) for x in imp.get("persisting", [])) or "—")
    )
    imp_html = f"<h3>Impairment Changes</h3><table class='kv-table'>{imp_rows}</table>"

    # Timing differences
    td_map = cr.get("timing_differences", {})
    td_html = ""
    if td_map:
        rows_html = "".join(
            f'<tr><td>{_e(k)}</td><td>{_e(v["baseline"])}</td>'
            f'<td>{_e(v["incident"])}</td>'
            f'<td style="color:{("#f56c6c" if v["worsened"] else "#67c23a")}">'
            f'{("+" if v["delta"] > 0 else "")}{_e(v["delta"])}</td></tr>'
            for k, v in td_map.items()
        )
        td_html = (
            "<h3>Timing Differences (ms)</h3>"
            '<table class="timing-table">'
            "<thead><tr><th>Metric</th><th>Baseline</th><th>Incident</th><th>Delta</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
        )

    # Confidence delta
    cc = cr.get("confidence_changes", {})
    cc_html = ""
    if cc:
        delta = cc.get("delta", 0)
        delta_str = f'{("+" if delta > 0 else "")}{delta}'
        cc_rows = (
            _kv_row("Baseline", f'{cc.get("baseline", 0)}%')
            + _kv_row("Incident", f'{cc.get("incident", 0)}%')
            + _kv_row("Delta",    delta_str)
        )
        cc_html = f"<h3>Confidence Changes</h3><table class='kv-table'>{cc_rows}</table>"

    body = rp_html + diffs_html + side + imp_html + td_html + cc_html
    return _section("What Changed (Baseline vs Incident)", body)


def _render_feedback(fb: dict) -> str:
    _verdict_color = {
        "correct":           "#67c23a",
        "partially_correct": "#e6a23c",
        "incorrect":         "#f56c6c",
    }
    verdict = fb.get("verdict", "")
    color   = _verdict_color.get(verdict, "#909399")
    rows = (
        f'<tr><td class="kv-label">Verdict</td>'
        f'<td class="kv-value" style="color:{color};font-weight:700">'
        f'{_e(_fmt_token(verdict))}</td></tr>'
        + _kv_row("Actual Root Cause", fb.get("actual_root_cause") or "")
        + _kv_row("Misleading Step",   fb.get("misleading_step") or "")
        + _kv_row("Analyst Note",      fb.get("analyst_note") or "")
    )
    return _section(
        "Analyst Conclusion",
        f'<table class="kv-table">{rows}</table>',
    )


_CSS = """
*, *::before, *::after { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       font-size: 14px; color: #303133; background: #f4f4f5; margin: 0; padding: 24px 16px; }
.page-wrap { max-width: 900px; margin: 0 auto; }

header { background: #fff; border: 1px solid #dcdfe6; border-radius: 6px;
         padding: 20px 24px; margin-bottom: 20px; }
header h1 { margin: 0 0 6px; font-size: 20px; }
.meta { font-size: 12px; color: #909399; }
.meta .ep { font-family: monospace; font-weight: 700; color: #303133; font-size: 13px; }

section { background: #fff; border: 1px solid #dcdfe6; border-radius: 6px;
          padding: 20px 24px; margin-bottom: 14px; }
section h2 { margin: 0 0 14px; font-size: 15px; font-weight: 700;
             padding-bottom: 8px; border-bottom: 1px solid #ebeef5; color: #303133; }
section h3 { margin: 14px 0 8px; font-size: 13px; font-weight: 600; color: #606266; }

.path-summary { margin: 12px 0 0; font-size: 13px; color: #606266; line-height: 1.6; }

.kv-table { border-collapse: collapse; width: 100%; }
.kv-table tr + tr td { border-top: 1px solid #f4f4f5; }
.kv-label { color: #909399; font-size: 12px; width: 160px; padding: 5px 10px 5px 0;
            white-space: nowrap; vertical-align: top; }
.kv-value { font-size: 13px; padding: 5px 0; }

ol { margin: 0; padding-left: 20px; }
ol li { font-size: 13px; color: #606266; margin-bottom: 6px; line-height: 1.6; }
ul { margin: 0; padding-left: 20px; }
ul li { font-size: 13px; color: #606266; margin-bottom: 4px; line-height: 1.6; }

.ev-card { border-left: 3px solid #909399; padding: 8px 12px;
           margin-bottom: 8px; background: #fafafa; border-radius: 0 4px 4px 0; }
.ev-strength { font-size: 11px; font-weight: 700; text-transform: uppercase;
               margin-right: 8px; }
.ev-type    { font-size: 12px; font-weight: 600; }
.ev-summary { margin: 4px 0 0; font-size: 12px; color: #606266; }

.regression-point { font-size: 13px; font-weight: 600; color: #f56c6c;
                    background: #fff5f5; border-left: 4px solid #f56c6c;
                    padding: 8px 12px; border-radius: 0 4px 4px 0; margin: 0 0 14px; }

.compare-side-row { display: flex; gap: 12px; align-items: flex-start; margin: 14px 0; }
.compare-side { flex: 1; border: 1px solid #ebeef5; border-radius: 4px; padding: 10px 14px; }
.baseline-side { border-top: 3px solid #409eff; }
.incident-side { border-top: 3px solid #e6a23c; }
.side-label { font-size: 11px; font-weight: 700; text-transform: uppercase;
              color: #909399; margin-bottom: 6px; }
.compare-arrow { font-size: 24px; color: #f56c6c; padding-top: 24px;
                 align-self: center; min-width: 28px; text-align: center; }

.timing-table { border-collapse: collapse; width: 100%; font-size: 12px; }
.timing-table th { text-align: left; color: #909399; font-weight: 600;
                   padding: 4px 10px 6px 0; border-bottom: 1px solid #ebeef5; }
.timing-table td { padding: 5px 10px 5px 0; }
.timing-table tr + tr td { border-top: 1px solid #f5f5f5; }
"""


def render_html(package: dict) -> str:
    """Return a complete self-contained HTML investigation package."""
    meta  = package.get("export_metadata", {})
    query = package.get("query", {})
    pa    = package.get("path_analysis", {})
    cr    = package.get("compare_result")
    fb    = package.get("analyst_feedback")

    src  = query.get("source_ip", "")
    dst  = query.get("destination_ip", "")
    port = query.get("destination_port")
    ep   = f"{src} → {dst}" + (f":{port}" if port else "")

    sq   = query.get("saved_query")
    sq_html = ""
    if sq:
        sq_html = f' &nbsp;·&nbsp; Query: <em>{_e(sq.get("name", ""))}</em>'

    body = (
        _render_what_happened(pa)
        + _render_path_steps(pa)
        + _render_evidence(pa)
        + _render_why(pa)
        + (_render_compare(cr) if cr else "")
        + (_render_feedback(fb) if fb else "")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Investigation Package — {_e(ep)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page-wrap">
  <header>
    <h1>Investigation Package</h1>
    <div class="meta">
      <span class="ep">{_e(ep)}</span>{sq_html} &nbsp;·&nbsp;
      Analysis: {_e(query.get("analysis_id", ""))} &nbsp;·&nbsp;
      Generated: {_e(meta.get("generated_at", ""))} &nbsp;·&nbsp;
      Engine: {_e(meta.get("engine_version", ""))}
    </div>
  </header>
  {body}
</div>
</body>
</html>"""
