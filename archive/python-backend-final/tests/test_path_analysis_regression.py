"""
Path Analysis regression suite — correctness validation.

For each of the 7 known scenarios this suite asserts, in one place, that
CausalPathEngine.analyze() produces exactly the right:

    connection_outcome       — success / partial_success / failure / unknown
    primary_impairment       — dominant impairment token or None
    path_confidence_score    — within a declared [min, max] range
    path_steps               — must contain every declared keyword
    evidence_items           — declared types must be present with stated signal_strength

A ValidationReport helper formats per-check pass/fail details so that any
pytest failure message is immediately actionable without digging into repr().

Run standalone to print a human-readable report across all scenarios:
    python tests/test_path_analysis_regression.py
"""
from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest
from core.causal_path import CausalPathEngine, ConnectionState
from models import FlowRecord, PacketRecord, TCPState


# ── Shared endpoint constants ─────────────────────────────────────────────────

CLIENT  = "10.0.0.5"
SERVER  = "10.0.0.1"
FW_IP   = "10.0.0.1"     # same as SERVER for firewall scenarios
LB_VIP  = "10.0.1.10"
BACKEND = "10.0.2.20"


# ── Packet / flow builders ────────────────────────────────────────────────────

def _pkt(num, ts, src, dst, sport=54321, dport=80,
         syn=False, ack=False, rst=False, fin=False, payload=0):
    return PacketRecord(
        num=num, ts=ts, frame_len=60 + payload, protocol="TCP",
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        ip_proto=6,
        tcp_flags_syn=syn, tcp_flags_ack=ack,
        tcp_flags_rst=rst, tcp_flags_fin=fin,
        tcp_payload_len=payload,
    )


def _flow(src, dst, sport=54321, dport=80, first_seen=1.0, last_seen=1.1,
          fwd_packets=1, rev_packets=0):
    key = f"{src}:{sport}-{dst}:{dport}-6"
    return FlowRecord(
        key=key, proto=6,
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        first_seen=first_seen, last_seen=last_seen,
        fwd_packets=fwd_packets, rev_packets=rev_packets,
        state=TCPState.ESTABLISHED,
    )


def _engine(packets, flows=None):
    flows_dict = {f.key: f for f in (flows or [])}
    return CausalPathEngine(packets, flows_dict, [], None)


# ══════════════════════════════════════════════════════════════════════════════
# Validation framework
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScenarioExpectation:
    """
    Declares the expected output of CausalPathEngine.analyze() for one scenario.

    Attributes:
        scenario:              Human-readable scenario name.
        connection_outcome:    Expected outcome token (exact match).
        primary_impairment:    Expected primary impairment token, or None.
        confidence_min:        Inclusive lower bound for path_confidence_score.
        confidence_max:        Inclusive upper bound for path_confidence_score.
        path_steps_keywords:   Every string here must appear (case-insensitive)
                               somewhere in the concatenated path_steps.
        evidence_types:        Every type string here must appear in evidence_items.
        evidence_strength:     Dict mapping evidence type → minimum signal strength.
                               "high" >= "medium" >= "low".
    """
    scenario: str
    connection_outcome: str
    primary_impairment: Optional[str]
    confidence_min: int
    confidence_max: int
    path_steps_keywords: List[str]
    evidence_types: List[str]
    evidence_strength: Dict[str, str] = field(default_factory=dict)


_STRENGTH_ORDER = {"high": 2, "medium": 1, "low": 0}


@dataclass
class CheckResult:
    name: str
    passed: bool
    expected: Any
    actual: Any

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        if self.passed:
            return f"  [{status}] {self.name}"
        short_actual = str(self.actual)[:160]
        return (
            f"  [{status}] {self.name}\n"
            f"           expected : {self.expected!r}\n"
            f"           actual   : {short_actual}"
        )


@dataclass
class ValidationReport:
    scenario: str
    checks: List[CheckResult]

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failed_checks(self) -> List[CheckResult]:
        return [c for c in self.checks if not c.passed]

    def summary(self) -> str:
        total  = len(self.checks)
        n_pass = sum(1 for c in self.checks if c.passed)
        status = "PASS" if self.passed else "FAIL"
        lines  = [
            "",
            "=" * 62,
            f"[{status}] {self.scenario}  ({n_pass}/{total} checks)",
        ]
        lines.extend(str(c) for c in self.checks)
        if not self.passed:
            lines.append(f"\n  ↳ {len(self.failed_checks)} check(s) failed.")
        return "\n".join(lines)

    def __repr__(self) -> str:  # shows in pytest diff output
        return self.summary()


def validate(expectation: ScenarioExpectation, result) -> ValidationReport:
    """
    Compare a PathAnalysisResult against a ScenarioExpectation.

    Returns a ValidationReport whose .passed property is suitable for
    `assert report.passed, report.summary()`.
    """
    checks: List[CheckResult] = []

    # 1 — connection_outcome (exact)
    checks.append(CheckResult(
        name="connection_outcome",
        passed=result.connection_outcome == expectation.connection_outcome,
        expected=expectation.connection_outcome,
        actual=result.connection_outcome,
    ))

    # 2 — primary_impairment (exact, including None)
    checks.append(CheckResult(
        name="primary_impairment",
        passed=result.primary_impairment == expectation.primary_impairment,
        expected=expectation.primary_impairment,
        actual=result.primary_impairment,
    ))

    # 3 — path_confidence_score within [min, max]
    score    = result.path_confidence_score
    in_range = expectation.confidence_min <= score <= expectation.confidence_max
    checks.append(CheckResult(
        name="path_confidence_score",
        passed=in_range,
        expected=f"[{expectation.confidence_min}, {expectation.confidence_max}]",
        actual=score,
    ))

    # 4 — path_steps keywords (all must appear)
    combined = " ".join(result.path_steps).lower()
    for kw in expectation.path_steps_keywords:
        checks.append(CheckResult(
            name=f"path_steps ∋ '{kw}'",
            passed=kw.lower() in combined,
            expected=f"'{kw}' somewhere in path_steps",
            actual=(combined[:180] + "…") if len(combined) > 180 else combined,
        ))

    # 5 — evidence_item types (all declared types must be present)
    actual_types = {e.type for e in result.evidence_items}
    for ev_type in expectation.evidence_types:
        checks.append(CheckResult(
            name=f"evidence type '{ev_type}' present",
            passed=ev_type in actual_types,
            expected=ev_type,
            actual=sorted(actual_types),
        ))

    # 6 — evidence signal_strength (minimum bound per declared type)
    for ev_type, min_strength in expectation.evidence_strength.items():
        ev_items = [e for e in result.evidence_items if e.type == ev_type]
        if not ev_items:
            checks.append(CheckResult(
                name=f"evidence '{ev_type}' signal_strength >= {min_strength}",
                passed=False,
                expected=f"evidence item of type '{ev_type}'",
                actual="not found",
            ))
        else:
            actual_str = ev_items[0].signal_strength
            ok = (_STRENGTH_ORDER.get(actual_str, -1)
                  >= _STRENGTH_ORDER.get(min_strength, 99))
            checks.append(CheckResult(
                name=f"evidence '{ev_type}' signal_strength >= {min_strength}",
                passed=ok,
                expected=f">= {min_strength}",
                actual=actual_str,
            ))

    return ValidationReport(scenario=expectation.scenario, checks=checks)


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 1 — Firewall drop (silent drop, no SYN-ACK ever arrives)
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTATION_FIREWALL_DROP = ScenarioExpectation(
    scenario="Firewall Drop — silent SYN drop, no SYN-ACK",
    connection_outcome="failure",
    primary_impairment="connection_establishment_failure",
    confidence_min=0,
    confidence_max=80,
    path_steps_keywords=["not observed"],
    evidence_types=["connection_establishment_failure"],
    evidence_strength={"connection_establishment_failure": "high"},
)


class TestFirewallDropRegression:
    """Client sends SYN to a port that a firewall silently drops."""

    def _packets(self):
        return [_pkt(1, 1.000, CLIENT, SERVER, dport=443, syn=True)]

    def _result(self):
        return _engine(self._packets()).analyze(CLIENT, SERVER, 443)

    def test_connection_outcome(self):
        assert self._result().connection_outcome == "failure"

    def test_primary_impairment(self):
        assert self._result().primary_impairment == "connection_establishment_failure"

    def test_path_confidence_score_range(self):
        score = self._result().path_confidence_score
        assert 0 <= score <= 80, f"score {score} outside [0, 80]"

    def test_path_steps_mention_not_observed(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "not observed" in combined

    def test_evidence_type_connection_establishment_failure(self):
        types = {e.type for e in self._result().evidence_items}
        assert "connection_establishment_failure" in types

    def test_evidence_strength_is_high(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "connection_establishment_failure"]
        assert ev and ev[0].signal_strength == "high"

    def test_full_validation_report(self):
        report = validate(_EXPECTATION_FIREWALL_DROP, self._result())
        assert report.passed, report.summary()


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 2 — Firewall reset (RST from known firewall address)
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTATION_FIREWALL_RESET = ScenarioExpectation(
    scenario="Firewall Reset — RST from known firewall IP",
    connection_outcome="failure",
    primary_impairment="connection_establishment_failure",
    confidence_min=0,
    confidence_max=80,
    path_steps_keywords=["reset"],
    evidence_types=["connection_establishment_failure", "firewall_interference"],
    evidence_strength={
        "connection_establishment_failure": "high",
        "firewall_interference": "high",
    },
)


class TestFirewallResetRegression:
    """Client sends SYN; known firewall IP sends RST+ACK immediately."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, FW_IP, dport=80, syn=True),
            _pkt(2, 1.002, FW_IP,  CLIENT, sport=80, rst=True, ack=True),
        ]

    def _roles(self):
        return {"firewall_ips": [FW_IP]}

    def _result(self):
        return _engine(self._packets()).analyze(CLIENT, FW_IP, 80,
                                                roles=self._roles())

    def test_connection_outcome(self):
        assert self._result().connection_outcome == "failure"

    def test_primary_impairment(self):
        # connection_establishment_failure ranks above firewall_interference
        assert self._result().primary_impairment == "connection_establishment_failure"

    def test_path_confidence_score_range(self):
        score = self._result().path_confidence_score
        assert 0 <= score <= 80, f"score {score} outside [0, 80]"

    def test_path_steps_mention_reset(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "reset" in combined

    def test_evidence_type_connection_establishment_failure(self):
        types = {e.type for e in self._result().evidence_items}
        assert "connection_establishment_failure" in types

    def test_evidence_type_firewall_interference(self):
        types = {e.type for e in self._result().evidence_items}
        assert "firewall_interference" in types

    def test_firewall_evidence_strength_is_high(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "firewall_interference"]
        assert ev and ev[0].signal_strength == "high"

    def test_full_validation_report(self):
        report = validate(_EXPECTATION_FIREWALL_RESET, self._result())
        assert report.passed, report.summary()


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — LB backend pool failure (frontend reachable, backend not forwarded)
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTATION_LB_BACKEND_FAILURE = ScenarioExpectation(
    scenario="LB Backend Pool Failure — LB frontend ok, no backend forwarding",
    # ESTABLISHED_NO_DATA → "no_server_response" impairment → outcome = failure
    # "no_server_response" ranks above "lb_backend_issue" in priority list
    connection_outcome="failure",
    primary_impairment="no_server_response",
    confidence_min=50,
    confidence_max=90,
    path_steps_keywords=["load balancer", "backend"],
    evidence_types=["no_server_response", "lb_backend_issue"],
    evidence_strength={
        "no_server_response": "high",
        "lb_backend_issue": "medium",
    },
)


class TestLBBackendFailureRegression:
    """Client completes handshake with LB; LB never forwards to any backend."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, LB_VIP, dport=80, syn=True),
            _pkt(2, 1.010, LB_VIP, CLIENT, sport=80, syn=True, ack=True),
            _pkt(3, 1.011, CLIENT, LB_VIP, dport=80, ack=True),
        ]

    def _flows(self):
        return [
            _flow(CLIENT, LB_VIP, dport=80, first_seen=1.000, last_seen=1.050,
                  fwd_packets=2, rev_packets=1),
        ]

    def _roles(self):
        return {"load_balancer_vips": [LB_VIP], "backend_ips": [BACKEND]}

    def _result(self):
        return _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )

    def test_connection_outcome(self):
        assert self._result().connection_outcome == "failure"

    def test_primary_impairment(self):
        # "no_server_response" beats "lb_backend_issue" on priority
        assert self._result().primary_impairment == "no_server_response"

    def test_lb_backend_issue_in_path_impairments(self):
        assert "lb_backend_issue" in self._result().path_impairments

    def test_path_confidence_score_range(self):
        score = self._result().path_confidence_score
        assert 50 <= score <= 90, f"score {score} outside [50, 90]"

    def test_path_steps_mention_load_balancer(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "load balancer" in combined

    def test_path_steps_mention_backend(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "backend" in combined

    def test_evidence_type_no_server_response(self):
        types = {e.type for e in self._result().evidence_items}
        assert "no_server_response" in types

    def test_evidence_type_lb_backend_issue(self):
        types = {e.type for e in self._result().evidence_items}
        assert "lb_backend_issue" in types

    def test_no_server_response_evidence_strength_high(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "no_server_response"]
        assert ev and ev[0].signal_strength == "high"

    def test_lb_backend_issue_evidence_strength_medium(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "lb_backend_issue"]
        assert ev and ev[0].signal_strength == "medium"

    def test_full_validation_report(self):
        report = validate(_EXPECTATION_LB_BACKEND_FAILURE, self._result())
        assert report.passed, report.summary()


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 4 — Backend slow response (DATA_OBSERVED, first_response > 200 ms)
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTATION_BACKEND_SLOW = ScenarioExpectation(
    scenario="Backend Slow Response — DATA_OBSERVED, first_response ~350 ms",
    # DATA_OBSERVED + no return_path_problem → success; slow response is an impairment
    connection_outcome="success",
    primary_impairment="backend_response_delay",
    confidence_min=70,
    confidence_max=100,
    path_steps_keywords=["delay"],
    evidence_types=["backend_response_delay"],
    evidence_strength={"backend_response_delay": "medium"},
)


class TestBackendSlowResponseRegression:
    """Fast handshake; pure ACK; server data arrives ~350 ms later."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, SERVER, dport=80, syn=True),
            _pkt(2, 1.020, SERVER, CLIENT, sport=80, syn=True, ack=True),
            _pkt(3, 1.021, CLIENT, SERVER, dport=80, ack=True),         # pure ACK
            _pkt(4, 1.371, SERVER, CLIENT, sport=80, ack=True, payload=512),
        ]

    def _result(self):
        return _engine(self._packets()).analyze(CLIENT, SERVER, 80)

    def test_connection_outcome(self):
        # Data was exchanged — connection succeeded even though response was slow
        assert self._result().connection_outcome == "success"

    def test_primary_impairment(self):
        assert self._result().primary_impairment == "backend_response_delay"

    def test_path_confidence_score_range(self):
        score = self._result().path_confidence_score
        assert 70 <= score <= 100, f"score {score} outside [70, 100]"

    def test_first_response_time_captured_correctly(self):
        frt = self._result().timing_breakdown.get("first_response_time_ms")
        assert frt is not None and frt > 200, f"first_response_time_ms={frt}"

    def test_path_steps_mention_delay(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "delay" in combined

    def test_evidence_type_backend_response_delay(self):
        types = {e.type for e in self._result().evidence_items}
        assert "backend_response_delay" in types

    def test_delay_evidence_has_packet_refs(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "backend_response_delay"]
        assert ev and len(ev[0].packet_refs) >= 2

    def test_delay_evidence_summary_contains_ms(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "backend_response_delay"]
        assert ev and "ms" in ev[0].summary

    def test_delay_evidence_signal_strength_medium(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "backend_response_delay"]
        # 350 ms < 500 ms threshold for "high" → expected "medium"
        assert ev and ev[0].signal_strength == "medium"

    def test_full_validation_report(self):
        report = validate(_EXPECTATION_BACKEND_SLOW, self._result())
        assert report.passed, report.summary()


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 5 — Backend no response (connection established, zero app data)
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTATION_BACKEND_NO_RESPONSE = ScenarioExpectation(
    scenario="Backend No Response — handshake complete, no application data",
    connection_outcome="failure",
    primary_impairment="no_server_response",
    confidence_min=0,
    confidence_max=85,
    path_steps_keywords=["no server response"],
    evidence_types=["no_server_response"],
    evidence_strength={"no_server_response": "high"},
)


class TestBackendNoResponseRegression:
    """TCP handshake completes; server never sends any application data."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, SERVER, dport=8080, syn=True),
            _pkt(2, 1.015, SERVER, CLIENT, sport=8080, syn=True, ack=True),
            _pkt(3, 1.016, CLIENT, SERVER, dport=8080, ack=True),
        ]

    def _result(self):
        return _engine(self._packets()).analyze(CLIENT, SERVER, 8080)

    def test_connection_outcome(self):
        assert self._result().connection_outcome == "failure"

    def test_primary_impairment(self):
        assert self._result().primary_impairment == "no_server_response"

    def test_path_confidence_score_range(self):
        score = self._result().path_confidence_score
        assert 0 <= score <= 85, f"score {score} outside [0, 85]"

    def test_path_steps_mention_no_server_response(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "no server response" in combined

    def test_evidence_type_no_server_response(self):
        types = {e.type for e in self._result().evidence_items}
        assert "no_server_response" in types

    def test_no_server_response_evidence_strength_high(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "no_server_response"]
        assert ev and ev[0].signal_strength == "high"

    def test_no_server_response_evidence_has_packet_refs(self):
        ev = [e for e in self._result().evidence_items
              if e.type == "no_server_response"]
        assert ev and len(ev[0].packet_refs) >= 2  # SYN + SYN-ACK at minimum

    def test_full_validation_report(self):
        report = validate(_EXPECTATION_BACKEND_NO_RESPONSE, self._result())
        assert report.passed, report.summary()


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 6 — Return path interruption (backend replied to LB, no LB→client)
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTATION_RETURN_PATH = ScenarioExpectation(
    scenario="Return Path Interruption — backend responded, LB→client flow absent",
    # ESTABLISHED_NO_DATA (no data in client↔LB packets) → failure
    # "no_server_response" ranks above "return_path_problem" in priority list
    connection_outcome="failure",
    primary_impairment="no_server_response",
    confidence_min=50,
    confidence_max=90,
    path_steps_keywords=["load balancer", "no return"],
    evidence_types=["no_server_response", "return_path_problem"],
    evidence_strength={
        "no_server_response": "high",
        "return_path_problem": "medium",
    },
)


class TestReturnPathInterruptionRegression:
    """Backend responds to LB but the LB→client return flow is absent from capture."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT,  LB_VIP, dport=80, syn=True),
            _pkt(2, 1.010, LB_VIP,  CLIENT, sport=80, syn=True, ack=True),
            _pkt(3, 1.011, CLIENT,  LB_VIP, dport=80, ack=True),
        ]

    def _flows(self):
        return [
            # client → LB
            _flow(CLIENT,  LB_VIP,  dport=80,   first_seen=1.000, last_seen=1.050),
            # LB → backend (forwarding observed)
            _flow(LB_VIP,  BACKEND, sport=40001, dport=8080,
                  first_seen=1.015, last_seen=1.100),
            # backend → LB (response observed)
            _flow(BACKEND, LB_VIP,  sport=8080,  dport=40001,
                  first_seen=1.080, last_seen=1.100),
            # intentionally no LB → CLIENT return flow
        ]

    def _roles(self):
        return {"load_balancer_vips": [LB_VIP], "backend_ips": [BACKEND]}

    def _result(self):
        return _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )

    def test_connection_outcome(self):
        # ESTABLISHED_NO_DATA → failure (even though backend responded internally)
        assert self._result().connection_outcome == "failure"

    def test_primary_impairment(self):
        # "no_server_response" is higher priority than "return_path_problem"
        assert self._result().primary_impairment == "no_server_response"

    def test_return_path_problem_in_path_impairments(self):
        assert "return_path_problem" in self._result().path_impairments

    def test_path_confidence_score_range(self):
        score = self._result().path_confidence_score
        assert 50 <= score <= 90, f"score {score} outside [50, 90]"

    def test_path_steps_mention_load_balancer(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "load balancer" in combined

    def test_path_steps_mention_no_return(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "no return" in combined

    def test_evidence_type_no_server_response(self):
        types = {e.type for e in self._result().evidence_items}
        assert "no_server_response" in types

    def test_evidence_type_return_path_problem(self):
        types = {e.type for e in self._result().evidence_items}
        assert "return_path_problem" in types

    def test_return_path_evidence_strength_medium(self):
        # Return path absence could be a capture gap → not high confidence
        ev = [e for e in self._result().evidence_items
              if e.type == "return_path_problem"]
        assert ev and ev[0].signal_strength == "medium"

    def test_full_validation_report(self):
        report = validate(_EXPECTATION_RETURN_PATH, self._result())
        assert report.passed, report.summary()


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 7 — Clean successful flow (no failure expected anywhere)
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTATION_CLEAN_FLOW = ScenarioExpectation(
    scenario="Clean Successful Flow — full handshake + data, no failure",
    connection_outcome="success",
    primary_impairment=None,
    confidence_min=70,
    confidence_max=100,
    path_steps_keywords=["initiated"],
    evidence_types=[],       # no impairments → no evidence expected
    evidence_strength={},
)


class TestCleanFlowRegression:
    """Full three-way handshake (with pure ACK) followed by server data."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, SERVER, dport=80, syn=True),
            _pkt(2, 1.018, SERVER, CLIENT, sport=80, syn=True, ack=True),
            _pkt(3, 1.019, CLIENT, SERVER, dport=80, ack=True),       # pure ACK
            _pkt(4, 1.050, SERVER, CLIENT, sport=80, ack=True, payload=1024),
        ]

    def _result(self):
        return _engine(self._packets()).analyze(CLIENT, SERVER, 80)

    def test_connection_outcome(self):
        assert self._result().connection_outcome == "success"

    def test_primary_impairment_is_none(self):
        assert self._result().primary_impairment is None

    def test_no_path_impairments(self):
        assert self._result().path_impairments == []

    def test_path_confidence_score_range(self):
        score = self._result().path_confidence_score
        assert 70 <= score <= 100, f"score {score} outside [70, 100]"

    def test_path_steps_mention_initiated(self):
        combined = " ".join(self._result().path_steps).lower()
        assert "initiated" in combined

    def test_no_evidence_items(self):
        assert self._result().evidence_items == []

    def test_evidence_items_serialise_empty(self):
        d = self._result().to_dict()
        assert d["evidence_items"] == []

    def test_full_validation_report(self):
        report = validate(_EXPECTATION_CLEAN_FLOW, self._result())
        assert report.passed, report.summary()


# ══════════════════════════════════════════════════════════════════════════════
# Standalone report — run all scenarios and print results
# ══════════════════════════════════════════════════════════════════════════════

ALL_SCENARIO_SPECS = [
    (
        _EXPECTATION_FIREWALL_DROP,
        lambda: _engine([_pkt(1, 1.000, CLIENT, SERVER, dport=443, syn=True)])
                .analyze(CLIENT, SERVER, 443),
    ),
    (
        _EXPECTATION_FIREWALL_RESET,
        lambda: _engine(
            [
                _pkt(1, 1.000, CLIENT, FW_IP, dport=80, syn=True),
                _pkt(2, 1.002, FW_IP,  CLIENT, sport=80, rst=True, ack=True),
            ]
        ).analyze(CLIENT, FW_IP, 80, roles={"firewall_ips": [FW_IP]}),
    ),
    (
        _EXPECTATION_LB_BACKEND_FAILURE,
        lambda: _engine(
            [
                _pkt(1, 1.000, CLIENT, LB_VIP, dport=80, syn=True),
                _pkt(2, 1.010, LB_VIP, CLIENT, sport=80, syn=True, ack=True),
                _pkt(3, 1.011, CLIENT, LB_VIP, dport=80, ack=True),
            ],
            [_flow(CLIENT, LB_VIP, dport=80, first_seen=1.000, last_seen=1.050,
                   fwd_packets=2, rev_packets=1)],
        ).analyze(CLIENT, LB_VIP, 80,
                  roles={"load_balancer_vips": [LB_VIP], "backend_ips": [BACKEND]}),
    ),
    (
        _EXPECTATION_BACKEND_SLOW,
        lambda: _engine(
            [
                _pkt(1, 1.000, CLIENT, SERVER, dport=80, syn=True),
                _pkt(2, 1.020, SERVER, CLIENT, sport=80, syn=True, ack=True),
                _pkt(3, 1.021, CLIENT, SERVER, dport=80, ack=True),
                _pkt(4, 1.371, SERVER, CLIENT, sport=80, ack=True, payload=512),
            ]
        ).analyze(CLIENT, SERVER, 80),
    ),
    (
        _EXPECTATION_BACKEND_NO_RESPONSE,
        lambda: _engine(
            [
                _pkt(1, 1.000, CLIENT, SERVER, dport=8080, syn=True),
                _pkt(2, 1.015, SERVER, CLIENT, sport=8080, syn=True, ack=True),
                _pkt(3, 1.016, CLIENT, SERVER, dport=8080, ack=True),
            ]
        ).analyze(CLIENT, SERVER, 8080),
    ),
    (
        _EXPECTATION_RETURN_PATH,
        lambda: _engine(
            [
                _pkt(1, 1.000, CLIENT,  LB_VIP, dport=80, syn=True),
                _pkt(2, 1.010, LB_VIP,  CLIENT, sport=80, syn=True, ack=True),
                _pkt(3, 1.011, CLIENT,  LB_VIP, dport=80, ack=True),
            ],
            [
                _flow(CLIENT,  LB_VIP,  dport=80,   first_seen=1.000, last_seen=1.050),
                _flow(LB_VIP,  BACKEND, sport=40001, dport=8080,
                      first_seen=1.015, last_seen=1.100),
                _flow(BACKEND, LB_VIP,  sport=8080,  dport=40001,
                      first_seen=1.080, last_seen=1.100),
            ],
        ).analyze(CLIENT, LB_VIP, 80,
                  roles={"load_balancer_vips": [LB_VIP], "backend_ips": [BACKEND]}),
    ),
    (
        _EXPECTATION_CLEAN_FLOW,
        lambda: _engine(
            [
                _pkt(1, 1.000, CLIENT, SERVER, dport=80, syn=True),
                _pkt(2, 1.018, SERVER, CLIENT, sport=80, syn=True, ack=True),
                _pkt(3, 1.019, CLIENT, SERVER, dport=80, ack=True),
                _pkt(4, 1.050, SERVER, CLIENT, sport=80, ack=True, payload=1024),
            ]
        ).analyze(CLIENT, SERVER, 80),
    ),
]


def generate_full_report() -> str:
    """Run all scenarios through the validator and return a formatted report."""
    reports = []
    for expectation, result_fn in ALL_SCENARIO_SPECS:
        result = result_fn()
        reports.append(validate(expectation, result))

    total  = sum(len(r.checks) for r in reports)
    passed = sum(len([c for c in r.checks if c.passed]) for r in reports)
    n_scenarios_ok = sum(1 for r in reports if r.passed)

    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════╗",
        "║          PATH ANALYSIS REGRESSION REPORT                     ║",
        "╚══════════════════════════════════════════════════════════════╝",
    ]
    for r in reports:
        lines.append(r.summary())

    overall = "ALL PASS" if n_scenarios_ok == len(reports) else "FAILURES DETECTED"
    lines += [
        "",
        "─" * 62,
        f"Scenarios : {n_scenarios_ok}/{len(reports)} passed",
        f"Checks    : {passed}/{total} passed",
        f"Result    : {overall}",
        "─" * 62,
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(generate_full_report())
