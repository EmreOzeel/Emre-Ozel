"""
Main analysis pipeline orchestrator.
Coordinates: normalizer → analyzers → profiler → correlator → NLG → serializer.
"""
from __future__ import annotations
import time
import dataclasses
from typing import Any, Dict, List

from normalizer.pipeline import normalize
from analyzers import tcp, dns, http, tls, security, protocols
from profiler.host import build_profiles
from correlator.engine import correlate
from detection.engine import finalize
from core.nlg import generate_executive_summary, generate_technical_summary
from core.interpret import interpret_session, assess_capture_quality, generate_bullet_summary
from models import (
    CaptureContext, Finding, Evidence, HostProfile,
    DnsTransaction, HttpTransaction, TlsHandshake,
    SessionRecord, FlowRecord, TimelineEvent,
)


def _evidence_to_dict(ev: Evidence) -> Dict[str, Any]:
    return {
        "packet_nums": ev.packet_nums[:20],
        "flow_keys": ev.flow_keys[:10],
        "host_ips": ev.host_ips[:10],
        "time_first": ev.time_first,
        "time_last": ev.time_last,
        "metrics": ev.metrics,
        "samples": ev.samples[:10],
    }


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "id": f.id,
        "severity": f.severity if isinstance(f.severity, str) else f.severity.value,
        "confidence": f.confidence if isinstance(f.confidence, str) else f.confidence.value,
        "score": f.score,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "explanation": f.explanation,
        "possible_causes": f.possible_causes,
        "recommended_actions": f.recommended_actions,
        "affected_hosts": f.affected_hosts,
        "affected_flows": f.affected_flows,
        "evidence": _evidence_to_dict(f.evidence),
        "mitre": [
            {
                "tactic": m.tactic,
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "subtechnique_id": m.subtechnique_id,
                "url": m.url,
            }
            for m in f.mitre
        ],
        "rule_id": f.rule_id,
        "suppressed": f.suppressed,
        "tags": f.tags,
    }


def _session_to_dict(s: SessionRecord, interp: Dict[str, Any] = None, flow_story: str = "") -> Dict[str, Any]:
    return {
        "stream_id": s.stream_id,
        "src_ip": s.src_ip, "src_port": s.src_port,
        "dst_ip": s.dst_ip, "dst_port": s.dst_port,
        "state": s.state.value if hasattr(s.state, "value") else s.state,
        "has_syn": s.has_syn, "has_synack": s.has_synack,
        "has_fin": s.has_fin, "has_rst": s.has_rst,
        "bytes_sent": s.bytes_sent, "bytes_recv": s.bytes_recv,
        "packets_sent": s.packets_sent, "packets_recv": s.packets_recv,
        "retransmissions": s.retransmissions, "dup_acks": s.dup_acks,
        "zero_windows": s.zero_windows, "out_of_order": s.out_of_order,
        "handshake_rtt_ms": round(s.handshake_rtt_ms, 3),
        "duration_sec": round(s.last_ts - s.syn_ts, 3) if s.syn_ts else 0,
        "flow_key": s.flow_key,
        # Rich interpretation fields
        "protocol_guess": interp.get("protocol_guess", "") if interp else "",
        "handshake_status": interp.get("handshake_status", "") if interp else "",
        "handshake_label": interp.get("handshake_label", "") if interp else "",
        "close_behavior": interp.get("close_behavior", "") if interp else "",
        "close_label": interp.get("close_label", "") if interp else "",
        "confidence": interp.get("confidence", "") if interp else "",
        "confidence_note": interp.get("confidence_note", "") if interp else "",
        "asymmetry_type": interp.get("asymmetry_type", "") if interp else "",
        "asymmetry_note": interp.get("asymmetry_note", "") if interp else "",
        "quality_notes": interp.get("quality_notes", []) if interp else [],
        "interp_what": interp.get("what", "") if interp else flow_story,
        "interp_why": interp.get("why_matters", "") if interp else "",
        "interp_root_cause": interp.get("root_cause", "") if interp else "",
        "interp_check_next": interp.get("check_next", []) if interp else [],
    }


def _host_to_dict(h: HostProfile) -> Dict[str, Any]:
    return {
        "ip": h.ip, "mac": h.mac,
        "role": h.role.value if hasattr(h.role, "value") else h.role,
        "is_internal": h.is_internal,
        "bytes_sent": h.bytes_sent, "bytes_recv": h.bytes_recv,
        "packets_sent": h.packets_sent, "packets_recv": h.packets_recv,
        "tcp_sessions_initiated": h.tcp_sessions_initiated,
        "tcp_sessions_accepted": h.tcp_sessions_accepted,
        "tcp_sessions_failed": h.tcp_sessions_failed,
        "unique_peers": h.unique_peers,
        "unique_dst_ports": h.unique_dst_ports,
        "unique_src_ports": h.unique_src_ports,
        "protocols": h.protocols,
        "top_peers": [{"ip": p, "bytes": b} for p, b in h.top_peers],
        "open_ports": h.open_ports[:20],
        "anomaly_score": round(h.anomaly_score, 2),
        "suspicious_behaviors": h.suspicious_behaviors,
        "periodic_interval_sec": h.periodic_interval_sec,
        "periodic_jitter": h.periodic_jitter,
    }


def _dns_tx_to_dict(tx: DnsTransaction) -> Dict[str, Any]:
    return {
        "txid": tx.txid,
        "client_ip": tx.client_ip, "resolver_ip": tx.resolver_ip,
        "qname": tx.qname, "qtype": tx.qtype,
        "rcode": tx.rcode,
        "is_nxdomain": tx.is_nxdomain, "is_servfail": tx.is_servfail,
        "answers": tx.answers[:5],
        "rtt_ms": round(tx.rtt_ms, 2),
        "label_entropy": round(tx.label_entropy, 3),
        "label_length": tx.label_length,
        "subdomain_depth": tx.subdomain_depth,
        "answered": tx.answered,
        "ts": tx.ts_query,
    }


def _http_tx_to_dict(tx: HttpTransaction) -> Dict[str, Any]:
    return {
        "client_ip": tx.client_ip, "server_ip": tx.server_ip,
        "method": tx.method, "uri": tx.uri[:200],
        "host": tx.host, "user_agent": tx.user_agent[:200],
        "status_code": tx.status_code,
        "latency_ms": round(tx.latency_ms, 2),
        "content_type": tx.content_type_resp,
        "ts": tx.ts_request,
    }


def _tls_hs_to_dict(hs: TlsHandshake) -> Dict[str, Any]:
    return {
        "stream_id": hs.stream_id,
        "client_ip": hs.client_ip, "server_ip": hs.server_ip,
        "dst_port": hs.dst_port,
        "sni": hs.sni,
        "tls_version": hs.tls_version,
        "cipher_suite": hs.cipher_suite,
        "alpn": hs.alpn,
        "ja3": hs.ja3, "ja3s": hs.ja3s,
        "has_alert": hs.has_alert,
        "alert_description": hs.alert_description,
        "cert_self_signed": hs.cert_self_signed,
        "cert_expired": hs.cert_expired,
        "cert_mismatch": hs.cert_mismatch,
        "ts": hs.ts_client,
    }


def _timeline_to_dict(e: TimelineEvent) -> Dict[str, Any]:
    return {
        "ts": e.ts,
        "type": e.event_type,
        "src_ip": e.src_ip, "dst_ip": e.dst_ip,
        "label": e.label, "detail": e.detail,
        "severity": e.severity.value if hasattr(e.severity, "value") else e.severity,
        "protocol": e.protocol,
        "packet_num": e.packet_num,
    }


def run_pipeline(pcap_path: str) -> Dict[str, Any]:
    """
    Full analysis pipeline: normalize → analyze → profile → correlate → serialize.
    Returns a JSON-serializable dict.
    """
    t0 = time.time()

    # ── 1. Normalize ──────────────────────────────────────────────────────────
    ctx = normalize(pcap_path)

    # ── 2. Run all analyzers ──────────────────────────────────────────────────
    tcp.analyze(ctx)
    dns.analyze(ctx)
    http.analyze(ctx)
    tls.analyze(ctx)
    security.analyze(ctx)
    protocols.analyze(ctx)

    # ── 3. Host profiling ─────────────────────────────────────────────────────
    build_profiles(ctx)

    # ── 4. Correlation + storylines ───────────────────────────────────────────
    correlate(ctx)

    # ── 5. Finalize findings (suppression + sort) ─────────────────────────────
    finalize(ctx)

    # ── 6. NLG summaries ─────────────────────────────────────────────────────
    ctx.executive_summary = generate_executive_summary(ctx)
    ctx.technical_summary = generate_technical_summary(ctx)

    # ── 7. Interpretation layer ───────────────────────────────────────────────
    # Per-session rich interpretations
    session_interpretations: Dict[int, Dict] = {}
    for sess in ctx.sessions.values():
        session_interpretations[sess.stream_id] = interpret_session(sess, ctx)

    # Capture quality assessment
    capture_assessment = assess_capture_quality(ctx)

    # Bullet summary
    bullet_summary = generate_bullet_summary(ctx)

    ctx.analysis_time_sec = round(time.time() - t0, 2)

    # ── 8. Serialize to JSON-safe dict ────────────────────────────────────────
    sev_val = lambda f: f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    issue_counts = {
        "critical": sum(1 for f in ctx.findings if sev_val(f) == "critical" and not f.suppressed),
        "high":     sum(1 for f in ctx.findings if sev_val(f) == "high" and not f.suppressed),
        "medium":   sum(1 for f in ctx.findings if sev_val(f) == "medium" and not f.suppressed),
        "warning":  sum(1 for f in ctx.findings if sev_val(f) in ("high", "medium") and not f.suppressed),
        "total":    sum(1 for f in ctx.findings if not f.suppressed),
    }

    # Sessions sorted by bytes; attach rich interpretations
    sessions_sorted = sorted(
        ctx.sessions.values(),
        key=lambda s: -((s.bytes_sent or 0) + (s.bytes_recv or 0)),
    )[:200]

    # Top hosts by anomaly score
    hosts_sorted = sorted(ctx.hosts.values(), key=lambda h: -h.anomaly_score)[:100]

    return {
        # File metadata
        "file_info": dataclasses.asdict(ctx.file_info),
        "packets_analyzed": ctx.packets_analyzed,
        "analysis_time_sec": ctx.analysis_time_sec,

        # Structured extraction diagnostics — always present so downstream tools
        # and the expert-info UI can display them without guessing.
        "extraction_diagnostics": ctx.extraction_diagnostics,

        # Interpretation layer (new)
        "bullet_summary": bullet_summary,
        "capture_assessment": capture_assessment,

        # Protocol stats
        "protocol_stats": ctx.protocol_stats,
        "ip_endpoints": ctx.tcp_conversations[:50],
        "tcp_conversations": ctx.tcp_conversations[:50],
        "expert_info": ctx.expert_info[:50],

        # TCP aggregate
        "tcp": {
            "total_sessions": len(ctx.sessions),
            "retransmissions": sum(s.retransmissions for s in ctx.sessions.values()),
            "resets": sum(1 for s in ctx.sessions.values() if s.has_rst),
            "failed_handshakes": sum(
                1 for s in ctx.sessions.values()
                if s.has_syn and not s.has_synack
            ),
            "midstream": sum(1 for s in ctx.sessions.values() if not s.has_syn),
            "duplicate_acks": sum(s.dup_acks for s in ctx.sessions.values()),
            "zero_windows": sum(s.zero_windows for s in ctx.sessions.values()),
            "out_of_order": sum(s.out_of_order for s in ctx.sessions.values()),
            "sessions": [
                _session_to_dict(
                    s,
                    interp=session_interpretations.get(s.stream_id),
                    flow_story=ctx.flow_stories.get(s.flow_key, ""),
                )
                for s in sessions_sorted
            ],
        },

        # DNS
        "dns": getattr(ctx, "dns_stats", {}),

        # HTTP
        "http": getattr(ctx, "http_stats", {}),

        # TLS
        "tls": getattr(ctx, "tls_stats", {}),

        # Protocol breakdown
        "protocols": getattr(ctx, "protocol_details", {}),

        # Security detections
        "security": getattr(ctx, "security_stats", {}),

        # Hosts
        "hosts": [_host_to_dict(h) for h in hosts_sorted],
        "host_stories": ctx.host_stories,

        # Transactions (capped)
        "dns_transactions": [_dns_tx_to_dict(tx) for tx in ctx.dns_transactions[:500]],
        "http_transactions": [_http_tx_to_dict(tx) for tx in ctx.http_transactions[:200]],
        "tls_handshakes": [_tls_hs_to_dict(hs) for hs in ctx.tls_handshakes[:200]],

        # Timeline
        "timeline": [_timeline_to_dict(e) for e in ctx.timeline[:1000]],

        # Flow stories
        "flow_stories": ctx.flow_stories,

        # Findings (all, including suppressed)
        "all_findings": [_finding_to_dict(f) for f in ctx.findings],
        "all_issues": [_finding_to_dict(f) for f in ctx.findings if not f.suppressed],
        "suppressed_findings": [_finding_to_dict(f) for f in ctx.findings if f.suppressed],
        "issue_counts": issue_counts,

        # Narratives
        "executive_summary": ctx.executive_summary,
        "technical_summary": ctx.technical_summary,
        "capture_story": ctx.capture_story,
    }
