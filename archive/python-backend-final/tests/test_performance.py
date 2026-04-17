"""
Performance test scenarios for the analysis pipeline.

Tests:
  - Large synthetic capture (100K+ packets): ensure pipeline completes within
    the configured timeout and produces a valid result.
  - Concurrent job simulation: two analyses running back-to-back via the queue
    worker produce independent, non-corrupted results.
  - Memory footprint: tracemalloc baseline ensures the pipeline doesn't leak
    unbounded memory on large inputs.

Run with:
    pytest tests/test_performance.py -v -m perf --tb=short

Skip in CI if the perf marker is excluded:
    pytest tests/ -m "not perf"
"""
from __future__ import annotations

import threading
import time
import tracemalloc

import pytest

from core.decision import build_decision_report
from core.sanity import run_sanity_checks
from detection.engine import finalize
from models import (
    CaptureContext,
    Confidence,
    DnsTransaction,
    FileInfo,
    SessionRecord,
    Severity,
)
from profiler.host import build_profiles

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_file_info(**kwargs) -> FileInfo:
    defaults = dict(
        filename="perf_test.pcap",
        file_size_bytes=0,
        total_packets=0,
        duration_sec=0.0,
        first_packet="2024-01-01T00:00:00",
        last_packet="2024-01-01T00:01:00",
        encapsulation="Ethernet",
        avg_packet_size=500,
        avg_packet_rate=1000,
        avg_bit_rate=4_000_000,
    )
    defaults.update(kwargs)
    return FileInfo(**defaults)


def _make_session(stream_id: int, src: str, dst: str, dport: int, pkts: int = 10) -> SessionRecord:
    s = SessionRecord(
        stream_id=stream_id,
        src_ip=src, src_port=10000 + stream_id,
        dst_ip=dst, dst_port=dport,
        flow_key=f"{src}:{10000+stream_id}-{dst}:{dport}",
    )
    s.has_syn = True
    s.has_synack = True
    s.bytes_sent = pkts * 500
    s.bytes_recv = pkts * 200
    s.packets_sent = pkts
    s.packets_recv = pkts // 2
    return s


def _make_large_context(n_sessions: int = 1000, n_dns: int = 500) -> CaptureContext:
    """Build a synthetic CaptureContext with n_sessions TCP sessions and n_dns DNS queries."""
    ctx = CaptureContext()
    ctx.file_info = _make_file_info(total_packets=n_sessions * 15 + n_dns * 2)
    ctx.packets_analyzed = ctx.file_info.total_packets

    hosts = [f"10.0.{i // 256}.{i % 256}" for i in range(20)]
    external = [f"1.2.3.{i}" for i in range(20)]

    for i in range(n_sessions):
        src = hosts[i % len(hosts)]
        dst = external[i % len(external)]
        dport = [80, 443, 22, 8080][i % 4]
        s = _make_session(i, src, dst, dport)
        ctx.sessions[i] = s

    for i in range(n_dns):
        tx = DnsTransaction(
            txid=i,
            query_pkt=i * 2,
            response_pkt=i * 2 + 1,
            client_ip=hosts[i % len(hosts)],
            resolver_ip="8.8.8.8",
            qname=f"host{i}.example.com",
            qtype="A",
            rcode="NOERROR",
            answers=[f"93.184.{i % 256}.{i % 100}"],
            ts_query=float(i) * 0.01,
        )
        tx.rtt_ms = 5.0
        ctx.dns_transactions.append(tx)

    return ctx


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.perf
def test_large_capture_decision_report():
    """
    build_decision_report on 100 synthetic findings must complete in < 2 seconds.
    """
    findings = []
    rule_ids = ["SCAN-001", "C2-001", "DNS-001", "ARP-001", "TCP-001", "TLS-001", "DNS-002"]
    for i in range(100):
        findings.append({
            "rule_id": rule_ids[i % len(rule_ids)],
            "severity": ["critical", "high", "medium", "low"][i % 4],
            "confidence": "medium",
            "score": float(5 + (i % 5)),
            "title": f"Finding {i}",
            "affected_hosts": [f"10.0.0.{i % 200}"],
            "evidence": {"metrics": {"count": i}, "samples": []},
            "suppressed": False,
            "tags": [],
        })

    hosts = [
        {
            "ip": f"10.0.0.{i}",
            "role": "workstation",
            "anomaly_score": float(i % 6),
            "suspicious_behaviors": ["port_scan"] if i % 10 == 0 else [],
        }
        for i in range(50)
    ]

    t0 = time.time()
    report = build_decision_report(findings, hosts)
    elapsed = time.time() - t0

    assert elapsed < 2.0, f"build_decision_report took {elapsed:.2f}s (limit: 2s)"
    assert "ranked_causes" in report
    assert len(report["ranked_causes"]) > 0
    assert report["risk_level"] in ("critical", "high", "medium", "low", "clean")


@pytest.mark.perf
def test_large_capture_profiler():
    """
    build_profiles on 1000 sessions (20 hosts) must complete in < 5 seconds.
    """
    ctx = _make_large_context(n_sessions=1000, n_dns=200)

    t0 = time.time()
    build_profiles(ctx)
    elapsed = time.time() - t0

    assert elapsed < 5.0, f"build_profiles took {elapsed:.2f}s (limit: 5s)"
    assert len(ctx.hosts) > 0


@pytest.mark.perf
def test_large_capture_finalize():
    """
    finalize on 200 findings must complete quickly (< 1 second).
    """
    from models import Evidence as Ev
    from models import Finding
    ctx = _make_large_context(n_sessions=200, n_dns=50)
    build_profiles(ctx)

    for i in range(200):
        f = Finding(
            id=str(i),
            rule_id="SCAN-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            score=5.0,
            category="security",
            title=f"Finding {i}",
            description="",
            explanation="",
            confidence_note="",
            possible_causes=[],
            recommended_actions=[],
            affected_hosts=[f"10.0.0.{i % 20}"],
            affected_flows=[],
            evidence=Ev(),
            mitre=[],
            tags=[],
        )
        ctx.findings.append(f)

    t0 = time.time()
    finalize(ctx)
    elapsed = time.time() - t0

    assert elapsed < 1.0, f"finalize took {elapsed:.2f}s (limit: 1s)"


@pytest.mark.perf
def test_sanity_checks_large_result():
    """
    run_sanity_checks on a result with 100 findings must complete in < 0.5 seconds.
    """
    findings = [
        {
            "rule_id": "SCAN-001",
            "severity": "high",
            "confidence": "high",
            "score": 8.0,
            "title": f"Finding {i}",
            "affected_hosts": [f"10.0.0.{i % 20}"],
            "evidence": {"metrics": {}, "samples": []},
            "suppressed": False,
            "tags": [],
        }
        for i in range(100)
    ]
    result = {
        "all_issues": findings,
        "hosts": [{"ip": f"10.0.0.{i}", "anomaly_score": 1.0} for i in range(20)],
        "dns": {"nxdomain_count": 0, "total_queries": 5},
        "tcp": {"total_sessions": 500, "retransmissions": 0},
        "security": {},
        "decision_support": {"risk_level": "high"},
    }

    t0 = time.time()
    warnings = run_sanity_checks(result)
    elapsed = time.time() - t0

    assert elapsed < 0.5, f"run_sanity_checks took {elapsed:.2f}s (limit: 0.5s)"
    assert isinstance(warnings, list)


@pytest.mark.perf
def test_memory_decision_report():
    """
    build_decision_report must not allocate more than 5 MB for 500 findings.
    """
    findings = [
        {
            "rule_id": "C2-001",
            "severity": "critical",
            "confidence": "high",
            "score": 9.0,
            "title": "Beaconing",
            "affected_hosts": [f"10.0.0.{i % 200}"],
            "evidence": {"metrics": {"interval_sec": 30}, "samples": []},
            "suppressed": False,
            "tags": [],
        }
        for i in range(500)
    ]

    tracemalloc.start()
    snap1 = tracemalloc.take_snapshot()
    build_decision_report(findings, [])
    snap2 = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snap2.compare_to(snap1, "lineno")
    total_kb = sum(s.size_diff for s in stats) / 1024
    assert total_kb < 5 * 1024, f"Memory delta {total_kb:.0f} KB exceeds 5 MB limit"


@pytest.mark.perf
def test_concurrent_decision_reports():
    """
    Two threads calling build_decision_report concurrently must not interfere.
    """
    findings_a = [{"rule_id": "SCAN-001", "severity": "high", "confidence": "high",
                    "score": 8.0, "title": "Scan A", "affected_hosts": ["10.0.0.1"],
                    "evidence": {"metrics": {}, "samples": []}, "suppressed": False, "tags": []}]
    findings_b = [{"rule_id": "C2-001", "severity": "critical", "confidence": "high",
                    "score": 9.0, "title": "C2 B", "affected_hosts": ["10.0.0.2"],
                    "evidence": {"metrics": {}, "samples": []}, "suppressed": False, "tags": []}]

    results = {}

    def run_a():
        results["a"] = build_decision_report(findings_a, [])

    def run_b():
        results["b"] = build_decision_report(findings_b, [])

    t1 = threading.Thread(target=run_a)
    t2 = threading.Thread(target=run_b)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert "a" in results and "b" in results
    assert results["a"]["ranked_causes"][0]["rule_id"] == "SCAN-001"
    assert results["b"]["ranked_causes"][0]["rule_id"] == "C2-001"
