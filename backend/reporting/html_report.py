"""
HTML report generator for PCAP analysis results.
Produces a single self-contained HTML file with embedded CSS — no external deps.
"""
from __future__ import annotations
import html
from datetime import datetime
from typing import Any, Dict, List


# ── Severity helpers ──────────────────────────────────────────────────────────

_SEV_COLOR = {
    "critical": "#f56c6c",
    "high":     "#e6a23c",
    "medium":   "#f0c040",
    "low":      "#409eff",
    "info":     "#909399",
}

_SEV_BG = {
    "critical": "#fff5f5",
    "high":     "#fdf6ec",
    "medium":   "#fefbe6",
    "low":      "#ecf5ff",
    "info":     "#f4f4f5",
}


def _e(s: Any) -> str:
    """HTML-escape a value."""
    return html.escape(str(s) if s is not None else "")


def _fmt_ts(epoch: float) -> str:
    if not epoch:
        return "—"
    return datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%SZ")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ── Section builders ──────────────────────────────────────────────────────────

def _section(title: str, content: str) -> str:
    return f"""
<section>
  <h2>{_e(title)}</h2>
  {content}
</section>
"""


def _overview(data: Dict) -> str:
    fi = data.get("file_info", {})
    ic = data.get("issue_counts", {})
    rows = [
        ("File", fi.get("filename", "—")),
        ("Size", _fmt_bytes(fi.get("file_size_bytes", 0))),
        ("Packets", f"{fi.get('total_packets', 0):,}"),
        ("Duration", f"{fi.get('duration_sec', 0):.2f} s"),
        ("First packet", fi.get("first_packet", "—")),
        ("Last packet", fi.get("last_packet", "—")),
        ("Encapsulation", fi.get("encapsulation", "—")),
        ("Analysis time", f"{data.get('analysis_time_sec', 0):.2f} s"),
    ]
    table = "<table>" + "".join(
        f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in rows
    ) + "</table>"

    counts = "".join(
        f'<div class="count-chip sev-{sev}">'
        f'<span class="count-num">{ic.get(sev, 0)}</span>'
        f'<span class="count-label">{sev.upper()}</span>'
        f'</div>'
        for sev in ("critical", "high", "medium", "low", "info")
    )

    return _section("Overview", table + f'<div class="count-row">{counts}</div>')


def _executive(data: Dict) -> str:
    summary = _e(data.get("executive_summary", ""))
    bullets = data.get("bullet_summary", {})
    bullet_html = ""
    if isinstance(bullets, dict):
        for section_name, items in bullets.items():
            if not items:
                continue
            items_html = "".join(f"<li>{_e(it)}</li>" for it in items)
            bullet_html += f"<h3>{_e(section_name)}</h3><ul>{items_html}</ul>"
    content = f"<p>{summary}</p>{bullet_html}"
    return _section("Executive Summary", content)


def _findings(data: Dict) -> str:
    findings: List[Dict] = data.get("all_issues", [])
    if not findings:
        return _section("Findings", "<p>No findings.</p>")

    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        color = _SEV_COLOR.get(sev, "#909399")
        bg = _SEV_BG.get(sev, "#f4f4f5")
        hosts = ", ".join(_e(h) for h in (f.get("affected_hosts") or [])[:4])
        mitre = ", ".join(
            f'<a href="{_e(m.get("url",""))}" target="_blank">{_e(m.get("technique_id",""))}</a>'
            for m in (f.get("mitre") or [])[:3]
        )
        confidence_note = f.get("confidence_note", "")
        ev = f.get("evidence", {})
        metrics = ev.get("metrics", {}) or {}
        metric_rows = "".join(
            f"<tr><td>{_e(k.replace('_', ' '))}</td><td><b>{_e(v)}</b></td></tr>"
            for k, v in list(metrics.items())[:8]
        )
        metric_table = f"<table class='metric-table'>{metric_rows}</table>" if metric_rows else ""

        rows.append(f"""
<div class="finding-card" style="border-left-color:{color}; background:{bg}">
  <div class="finding-header">
    <span class="sev-badge" style="background:{color}">{_e(sev.upper())}</span>
    <span class="conf-badge">{_e(f.get('confidence',''))}</span>
    <span class="score-badge">score {f.get('score', 0):.1f}</span>
    <span class="finding-rule">{_e(f.get('rule_id',''))}</span>
  </div>
  <div class="finding-title">{_e(f.get('title',''))}</div>
  <p class="finding-desc">{_e(f.get('description',''))}</p>
  {'<div class="detail-block blue"><b>What is happening:</b> ' + _e(f.get('explanation','')) + '</div>' if f.get('explanation') else ''}
  {'<div class="detail-block slate"><b>Confidence reasoning:</b> ' + _e(confidence_note) + '</div>' if confidence_note else ''}
  {metric_table}
  {'<div class="hosts-row">Affected: ' + hosts + '</div>' if hosts else ''}
  {'<div class="mitre-row">MITRE: ' + mitre + '</div>' if mitre else ''}
</div>""")

    return _section(f"Findings ({len(findings)})", "\n".join(rows))


def _hosts(data: Dict) -> str:
    hosts: List[Dict] = data.get("hosts", [])
    if not hosts:
        return _section("Hosts", "<p>No host data.</p>")

    header = "<tr><th>IP</th><th>Role</th><th>Anomaly</th><th>Sent</th><th>Recv</th><th>Peers</th><th>Dst Ports</th></tr>"
    body = ""
    for h in hosts[:50]:
        score = h.get("anomaly_score", 0)
        score_color = "#f56c6c" if score >= 6 else ("#e6a23c" if score >= 3 else "#67c23a")
        body += (
            f"<tr>"
            f"<td><code>{_e(h.get('ip',''))}</code></td>"
            f"<td>{_e(h.get('role',''))}</td>"
            f"<td style='color:{score_color};font-weight:600'>{score:.1f}</td>"
            f"<td>{_fmt_bytes(h.get('bytes_sent',0))}</td>"
            f"<td>{_fmt_bytes(h.get('bytes_recv',0))}</td>"
            f"<td>{h.get('unique_peers',0)}</td>"
            f"<td>{h.get('unique_dst_ports',0)}</td>"
            f"</tr>"
        )
    return _section("Top Hosts by Anomaly Score", f"<table>{header}{body}</table>")


def _dns_section(data: Dict) -> str:
    dns = data.get("dns", {})
    if not dns:
        return ""
    rows = [
        ("Total queries", dns.get("total_queries", 0)),
        ("NXDOMAIN", dns.get("nxdomain_count", 0)),
        ("SERVFAIL", dns.get("servfail_count", 0)),
        ("Unique domains", dns.get("unique_domains", 0)),
        ("Avg RTT", f"{dns.get('avg_rtt_ms', 0):.1f} ms"),
    ]
    table = "<table>" + "".join(
        f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in rows
    ) + "</table>"
    return _section("DNS", table)


def _tcp_section(data: Dict) -> str:
    tcp = data.get("tcp", {})
    if not tcp:
        return ""
    rows = [
        ("Total sessions", tcp.get("total_sessions", 0)),
        ("Retransmissions", tcp.get("retransmissions", 0)),
        ("Resets", tcp.get("resets", 0)),
        ("Failed handshakes", tcp.get("failed_handshakes", 0)),
        ("Midstream sessions", tcp.get("midstream", 0)),
        ("Duplicate ACKs", tcp.get("duplicate_acks", 0)),
        ("Zero windows", tcp.get("zero_windows", 0)),
    ]
    table = "<table>" + "".join(
        f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in rows
    ) + "</table>"
    return _section("TCP", table)


def _technical(data: Dict) -> str:
    summary = _e(data.get("technical_summary", ""))
    if not summary:
        return ""
    return _section("Technical Summary", f"<p>{summary}</p>")


def _impact_banner(data: Dict) -> str:
    """Non-technical risk banner using decision_support.risk_summary."""
    ds = data.get("decision_support", {}) or {}
    risk = ds.get("risk_level", "")
    summary = ds.get("risk_summary", "")
    if not risk or not summary:
        return ""

    color = {
        "critical": "#f56c6c", "high": "#e6a23c",
        "medium": "#f0c040", "low": "#409eff", "clean": "#67c23a",
    }.get(risk, "#909399")
    bg = {
        "critical": "#fff5f5", "high": "#fdf6ec",
        "medium": "#fefbe6", "low": "#ecf5ff", "clean": "#f0fff4",
    }.get(risk, "#f4f4f5")

    return f"""
<div class="impact-banner" style="border-left-color:{color}; background:{bg}">
  <div class="impact-label" style="color:{color}">RISK LEVEL: {_e(risk.upper())}</div>
  <p class="impact-text">{_e(summary)}</p>
</div>"""


def _decision_support_section(data: Dict) -> str:
    """Ranked root causes with investigation steps — for analysts."""
    ds = data.get("decision_support", {}) or {}
    causes = ds.get("ranked_causes", [])
    steps = ds.get("investigation_steps", [])
    guidance = ds.get("resolution_guidance", "")

    if not causes:
        return ""

    cards = []
    for c in causes:
        prob_pct = c.get("probability_pct", 0)
        prob_label = c.get("probability", "")
        prob_color = "#f56c6c" if prob_pct >= 75 else ("#e6a23c" if prob_pct >= 45 else "#909399")
        steps_html = "".join(f"<li>{_e(s)}</li>" for s in (c.get("next_steps") or []))
        cards.append(f"""
<div class="cause-card">
  <div class="cause-header">
    <span class="cause-rank">#{_e(c.get('rank',''))}</span>
    <span class="cause-title">{_e(c.get('cause',''))}</span>
    <span class="prob-badge" style="color:{prob_color}">
      {_e(prob_label.upper())} ({prob_pct}%)
    </span>
  </div>
  <p class="cause-evidence">{_e(c.get('evidence_summary',''))}</p>
  <div class="cause-steps">
    <b>Investigation steps:</b>
    <ol>{steps_html}</ol>
  </div>
  <div class="cause-resolution">
    <b>Resolved when:</b> {_e(c.get('resolution',''))}
  </div>
</div>""")

    steps_html = "".join(
        f'<li class="inv-step">{_e(s)}</li>' for s in steps
    )
    content = (
        "\n".join(cards) +
        (f"<h3>Prioritized investigation steps</h3><ol>{steps_html}</ol>" if steps else "") +
        (f'<div class="guidance-block">{_e(guidance)}</div>' if guidance else "")
    )
    return _section("Decision Support — Investigation Guidance", content)


def _sanity_warnings_section(data: Dict) -> str:
    """Render sanity check contradictions as analyst notices."""
    warnings = data.get("sanity_warnings", []) or []
    if not warnings:
        return ""

    items = []
    for w in warnings:
        sev = w.get("severity", "info")
        color = "#e6a23c" if sev == "warning" else "#909399"
        items.append(
            f'<div class="sanity-item" style="border-left-color:{color}">'
            f'<span class="sanity-id">{_e(w.get("check_id",""))}</span> '
            f'{_e(w.get("message",""))}'
            + (f'<div class="sanity-detail">{_e(w.get("detail",""))}</div>' if w.get("detail") else "")
            + "</div>"
        )
    return _section(
        f"Analysis Sanity Checks ({len(warnings)} notice(s))",
        "\n".join(items),
    )


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       font-size: 13px; color: #303133; line-height: 1.6; margin: 0; padding: 0;
       background: #f0f2f5; }
.page-wrap { max-width: 1000px; margin: 0 auto; padding: 32px 24px; }
header { background: #1a1a2e; color: #fff; padding: 24px 32px; margin-bottom: 24px; border-radius: 8px; }
header h1 { margin: 0 0 4px; font-size: 22px; }
header .meta { color: #909399; font-size: 12px; }
section { background: #fff; border-radius: 8px; padding: 20px 24px; margin-bottom: 20px;
          border: 1px solid #ebeef5; }
h2 { font-size: 16px; font-weight: 700; margin: 0 0 16px; color: #303133;
     border-bottom: 1px solid #ebeef5; padding-bottom: 8px; }
h3 { font-size: 13px; font-weight: 700; margin: 14px 0 6px; color: #606266; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
table th { text-align: left; color: #909399; font-weight: 600; padding: 5px 10px 5px 0;
           border-bottom: 1px solid #f2f6fc; white-space: nowrap; }
table td { padding: 5px 10px 5px 0; border-bottom: 1px solid #f5f7fa; }
table tr:last-child td { border-bottom: none; }
code { background: #f5f7fa; padding: 1px 5px; border-radius: 3px; font-size: 11px; font-family: monospace; }
a { color: #409eff; text-decoration: none; }
a:hover { text-decoration: underline; }
ul { margin: 0; padding-left: 20px; }
li { margin: 2px 0; }
p { margin: 0 0 8px; }

/* Count chips */
.count-row { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
.count-chip { display: flex; flex-direction: column; align-items: center;
              padding: 8px 16px; border-radius: 6px; min-width: 70px; }
.count-num { font-size: 22px; font-weight: 700; line-height: 1; }
.count-label { font-size: 10px; font-weight: 700; letter-spacing: .08em; margin-top: 2px; }
.sev-critical { background: #fff5f5; color: #f56c6c; }
.sev-high     { background: #fdf6ec; color: #e6a23c; }
.sev-medium   { background: #fefbe6; color: #c09600; }
.sev-low      { background: #ecf5ff; color: #409eff; }
.sev-info     { background: #f4f4f5; color: #909399; }

/* Finding cards */
.finding-card { border: 1px solid #ebeef5; border-left: 4px solid #dcdfe6;
                border-radius: 6px; padding: 12px 16px; margin-bottom: 12px; }
.finding-header { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 6px; }
.sev-badge { color: #fff; padding: 1px 7px; border-radius: 3px; font-size: 11px; font-weight: 700; }
.conf-badge, .score-badge, .finding-rule {
  background: #f4f4f5; color: #606266; padding: 1px 7px;
  border-radius: 3px; font-size: 11px; border: 1px solid #e4e7ed; }
.finding-title { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.finding-desc { color: #606266; margin-bottom: 8px; }
.detail-block { padding: 7px 12px; margin: 6px 0; border-radius: 0 4px 4px 0; font-size: 12px; }
.detail-block.blue  { background: #f0f9ff; border-left: 3px solid #409eff; }
.detail-block.slate { background: #f4f4f5; border-left: 3px solid #909399; }
.metric-table { width: auto; margin: 6px 0; font-size: 12px; }
.metric-table td { padding: 2px 12px 2px 0; border: none; }
.hosts-row, .mitre-row { font-size: 11px; color: #909399; margin-top: 4px; }

/* Impact banner */
.impact-banner { border-left: 5px solid; border-radius: 6px; padding: 14px 18px;
                 margin-bottom: 20px; }
.impact-label { font-size: 13px; font-weight: 800; letter-spacing: .05em; margin-bottom: 6px; }
.impact-text { margin: 0; font-size: 13px; line-height: 1.7; }

/* Decision support */
.cause-card { border: 1px solid #ebeef5; border-radius: 6px; padding: 12px 16px;
              margin-bottom: 10px; }
.cause-header { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; margin-bottom: 6px; }
.cause-rank { font-size: 13px; font-weight: 700; color: #909399; min-width: 20px; }
.cause-title { font-size: 14px; font-weight: 600; flex: 1; }
.prob-badge { font-size: 11px; font-weight: 700; white-space: nowrap; }
.cause-evidence { color: #606266; font-size: 12px; margin: 4px 0 8px; }
.cause-steps { font-size: 12px; margin: 6px 0; }
.cause-steps ol { margin: 4px 0 0 16px; padding: 0; }
.cause-steps li { margin: 3px 0; }
.cause-resolution { font-size: 12px; color: #67c23a; margin-top: 8px; padding: 5px 10px;
                    background: #f0fff4; border-radius: 4px; }
.inv-step { margin: 4px 0; font-size: 12px; }
.guidance-block { margin-top: 14px; padding: 10px 14px; background: #f4f4f5;
                  border-radius: 4px; font-size: 12px; color: #606266; line-height: 1.7; }

/* Sanity warnings */
.sanity-item { border-left: 3px solid; padding: 6px 12px; margin-bottom: 8px;
               border-radius: 0 4px 4px 0; background: #fdf6ec; font-size: 12px; }
.sanity-id { font-weight: 700; margin-right: 6px; color: #e6a23c; }
.sanity-detail { color: #909399; margin-top: 3px; font-size: 11px; }
"""


# ── Main entry ────────────────────────────────────────────────────────────────

def generate_html_report(
    data: Dict[str, Any],
    analysis_id: str,
    filename: str,
    executive_only: bool = False,
) -> str:
    """
    Return a complete self-contained HTML string for the given analysis result dict.

    executive_only=True: produce a simplified view with only the impact banner,
    executive summary, and decision guidance — no raw technical tables.
    """
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    impact = _impact_banner(data)

    if executive_only:
        body = (
            impact +
            _executive(data) +
            _decision_support_section(data)
        )
    else:
        body = (
            impact +
            _overview(data) +
            _executive(data) +
            _decision_support_section(data) +
            _findings(data) +
            _hosts(data) +
            _tcp_section(data) +
            _dns_section(data) +
            _technical(data) +
            _sanity_warnings_section(data)
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PCAP Analysis Report — {_e(filename)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page-wrap">
  <header>
    <h1>PCAP Analysis Report</h1>
    <div class="meta">
      File: {_e(filename)} &nbsp;·&nbsp;
      Analysis ID: {_e(analysis_id)} &nbsp;·&nbsp;
      Generated: {_e(generated_at)}
    </div>
  </header>
  {body}
</div>
</body>
</html>"""
