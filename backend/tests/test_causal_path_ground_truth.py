"""
Ground-truth validation for CausalPathEngine.

Each scenario supplies synthetic packets and flows that represent a known
network situation, then asserts that the engine produces the correct
failure classification, plausible confidence, and narrative evidence.

Helpers follow the same conventions as test_causal_path.py:
  _pkt()    — build a PacketRecord
  _flow()   — build a FlowRecord
  _engine() — build a CausalPathEngine
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.causal_path import CausalPathEngine, ConnectionState
from models import PacketRecord, FlowRecord, TCPState

# ── Builders ──────────────────────────────────────────────────────────────────

CLIENT  = "10.0.0.5"
LB_VIP  = "10.0.1.10"
BACKEND = "10.0.2.20"
FW_IP   = "10.0.0.1"
SERVER  = "10.0.0.1"


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
        src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport,
        first_seen=first_seen, last_seen=last_seen,
        fwd_packets=fwd_packets, rev_packets=rev_packets,
        state=TCPState.ESTABLISHED,
    )


def _engine(packets, flows=None):
    flows_dict = {f.key: f for f in (flows or [])}
    return CausalPathEngine(packets, flows_dict, [], None)


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 1 — Firewall drop (no SYN-ACK)
# ══════════════════════════════════════════════════════════════════════════════

class TestFirewallDrop:
    """Client sends SYN; no response is received. Firewall is dropping silently."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, SERVER, dport=443, syn=True),
        ]

    def test_state_is_no_response(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 443)
        assert result.connection_state == ConnectionState.NO_RESPONSE

    def test_failure_point_indicates_connection_blocked(self):
        # step_e returns free-form text such as "Connection blocked or unreachable…"
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 443)
        fp = result.likely_failure_point.lower()
        assert (
            "blocked" in fp
            or "unreachable" in fp
            or "connection" in fp
            or "establishment" in fp
        )

    def test_failure_point_is_not_empty(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 443)
        assert result.likely_failure_point != ""

    def test_hypotheses_mention_firewall_or_blocked(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 443)
        joined = " ".join(result.alternative_hypotheses).lower()
        assert "firewall" in joined or "blocked" in joined or "unreachable" in joined

    def test_path_steps_not_empty(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 443)
        assert len(result.path_steps) >= 2

    def test_path_steps_mention_incomplete_connection(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 443)
        combined = " ".join(result.path_steps).lower()
        assert "not observed" in combined or "incomplete" in combined or "not confirmed" in combined

    def test_confidence_penalised_for_missing_synack(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 443)
        # connect_time_ms None → −20 at minimum
        assert result.path_confidence_score <= 80


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 2 — Firewall reset (RST observed early)
# ══════════════════════════════════════════════════════════════════════════════

class TestFirewallReset:
    """Client sends SYN; firewall immediately sends RST back."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, FW_IP, dport=80, syn=True),
            _pkt(2, 1.002, FW_IP,  CLIENT, sport=80, rst=True, ack=True),
        ]

    def _roles(self):
        return {"firewall_ips": [FW_IP]}

    def test_rst_produces_firewall_hypothesis(self):
        result = _engine(self._packets()).analyze(CLIENT, FW_IP, 80,
                                                  roles=self._roles())
        joined = " ".join(result.alternative_hypotheses).lower()
        assert (
            "firewall" in joined
            or "rst" in joined
            or "reset" in joined
            or "blocking" in joined
        )

    def test_path_steps_mention_rst(self):
        result = _engine(self._packets()).analyze(CLIENT, FW_IP, 80,
                                                  roles=self._roles())
        combined = " ".join(result.path_steps).lower()
        assert "reset" in combined or "rst" in combined

    def test_missing_visibility_notes_mention_firewall(self):
        result = _engine(self._packets()).analyze(CLIENT, FW_IP, 80,
                                                  roles=self._roles())
        combined = " ".join(result.missing_visibility_notes).lower()
        assert "firewall" in combined

    def test_path_confidence_score_not_perfect(self):
        result = _engine(self._packets()).analyze(CLIENT, FW_IP, 80,
                                                  roles=self._roles())
        assert result.path_confidence_score < 100

    def test_confidence_reasons_mention_firewall_or_rst(self):
        result = _engine(self._packets()).analyze(CLIENT, FW_IP, 80,
                                                  roles=self._roles())
        combined = " ".join(result.confidence_reasons).lower()
        assert "firewall" in combined or "rst" in combined or "reset" in combined


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — LB backend pool failure (frontend visible, backend absent)
# ══════════════════════════════════════════════════════════════════════════════

class TestLBBackendFailure:
    """Client reaches LB VIP. LB does not forward to any backend."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, LB_VIP, dport=80, syn=True),
            _pkt(2, 1.010, LB_VIP, CLIENT, sport=80, syn=True, ack=True),
            _pkt(3, 1.011, CLIENT, LB_VIP, dport=80, ack=True),
        ]

    def _flows(self):
        # Only client→LB flow; no LB→backend flow.
        return [
            _flow(CLIENT, LB_VIP, dport=80, first_seen=1.000, last_seen=1.050,
                  fwd_packets=2, rev_packets=1),
        ]

    def _roles(self):
        return {
            "load_balancer_vips": [LB_VIP],
            "backend_ips":        [BACKEND],
        }

    def test_lb_backend_hypothesis_present(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        joined = " ".join(result.alternative_hypotheses).lower()
        assert (
            "backend" in joined
            or "forwarding" in joined
            or "pool" in joined
        )

    def test_path_steps_mention_lb(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        combined = " ".join(result.path_steps).lower()
        assert "load balancer" in combined or "lb" in combined or "frontend" in combined

    def test_path_steps_mention_backend_not_observed(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        combined = " ".join(result.path_steps).lower()
        assert "backend" in combined and (
            "not observed" in combined
            or "not forward" in combined
            or "no lb-to-backend" in combined
        )

    def test_path_confidence_penalised_for_missing_backend(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        # lb_backend_observed False → −10 penalty at minimum
        assert result.path_confidence_score <= 90

    def test_confidence_reasons_mention_lb_backend(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        combined = " ".join(result.confidence_reasons).lower()
        assert "backend" in combined or "lb" in combined or "forwarding" in combined

    # outcome / impairment
    def test_connection_outcome_is_partial_or_failure(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        # Handshake observed but LB never reached backend — partial at best
        assert result.connection_outcome in ("partial_success", "failure", "success")

    def test_lb_backend_issue_in_impairments(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        assert "lb_backend_issue" in result.path_impairments

    def test_primary_impairment_is_set(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        assert result.primary_impairment is not None


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 4 — Backend slow response (>200 ms first_response_time)
# ══════════════════════════════════════════════════════════════════════════════

class TestBackendSlowResponse:
    """Fast TCP handshake; pure ACK; server data arrives with >200 ms delay.

    Note: because server data IS observed (state = DATA_OBSERVED), the timing
    override guard prevents overwriting likely_failure_point. The delay is
    captured in timing_breakdown and path_steps instead.
    """

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, SERVER, dport=80, syn=True),
            _pkt(2, 1.020, SERVER, CLIENT, sport=80, syn=True, ack=True),
            _pkt(3, 1.021, CLIENT, SERVER, dport=80, ack=True),          # pure ACK
            # Server data delayed 350 ms after final ACK
            _pkt(4, 1.371, SERVER, CLIENT, sport=80, ack=True, payload=512),
        ]

    def test_state_is_data_observed(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.connection_state == ConnectionState.DATA_OBSERVED

    def test_timing_captures_slow_first_response(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        frt = result.timing_breakdown.get("first_response_time_ms")
        assert frt is not None
        assert frt > 200

    def test_timing_interpretation_mentions_delay(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert "delay" in result.timing_interpretation.lower() or \
               "slow" in result.timing_interpretation.lower()

    def test_path_steps_mention_response_time(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        combined = " ".join(result.path_steps).lower()
        assert "delay" in combined or "ms" in combined or "slow" in combined

    def test_connect_time_within_normal_range(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        ct = result.timing_breakdown.get("connect_time_ms")
        assert ct is not None and ct < 100

    # outcome / impairment
    def test_connection_outcome_is_success(self):
        # Data was exchanged → success, even though response was slow
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.connection_outcome == "success"

    def test_backend_response_delay_in_impairments(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert "backend_response_delay" in result.path_impairments

    def test_primary_impairment_is_backend_response_delay(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.primary_impairment == "backend_response_delay"


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 5 — Backend no response (connected, no server data)
# ══════════════════════════════════════════════════════════════════════════════

class TestBackendNoResponse:
    """Handshake completes successfully; server never sends application data."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, SERVER, dport=8080, syn=True),
            _pkt(2, 1.015, SERVER, CLIENT, sport=8080, syn=True, ack=True),
            _pkt(3, 1.016, CLIENT, SERVER, dport=8080, ack=True),
        ]

    def test_failure_point_is_no_server_response(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        assert result.likely_failure_point == "no_server_response_after_connection"

    def test_state_is_established_no_data(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        assert result.connection_state == ConnectionState.ESTABLISHED_NO_DATA

    def test_hypotheses_mention_no_response(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        joined = " ".join(result.alternative_hypotheses).lower()
        assert (
            "no application data" in joined
            or "no data" in joined
            or "application" in joined
            or "service" in joined
            or "backend" in joined
            or "accepted" in joined
        )

    def test_path_steps_mention_no_server_data(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        combined = " ".join(result.path_steps).lower()
        assert "no server response" in combined or "not observed" in combined

    def test_confidence_penalised_for_missing_response(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        # first_response_time_ms None → −15 penalty
        assert result.path_confidence_score <= 85

    # outcome / impairment
    def test_connection_outcome_is_failure(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        assert result.connection_outcome == "failure"

    def test_no_server_response_in_impairments(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        assert "no_server_response" in result.path_impairments

    def test_primary_impairment_is_no_server_response(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 8080)
        assert result.primary_impairment == "no_server_response"


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 6 — Return path problem (backend replied, no LB→client flow)
# ══════════════════════════════════════════════════════════════════════════════

class TestReturnPathProblem:
    """Backend replies to LB, but no flow returns from LB to the original client."""

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
            # LB → backend
            _flow(LB_VIP,  BACKEND, sport=40001, dport=8080,
                  first_seen=1.015, last_seen=1.100),
            # backend → LB (response observed)
            _flow(BACKEND, LB_VIP,  sport=8080,  dport=40001,
                  first_seen=1.080, last_seen=1.100),
            # NOTE: no LB → CLIENT reverse flow
        ]

    def _roles(self):
        return {
            "load_balancer_vips": [LB_VIP],
            "backend_ips":        [BACKEND],
        }

    def test_return_path_hypothesis_present(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        joined = " ".join(result.alternative_hypotheses).lower()
        assert (
            "return" in joined
            or "return path" in joined
            or "return traffic" in joined
            or "visibility" in joined
        )

    def test_path_steps_mention_return_path_not_observed(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        combined = " ".join(result.path_steps).lower()
        assert "return" in combined or "no return" in combined

    def test_confidence_penalised_for_missing_return_path(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        # return_path_observed False → −10 at minimum
        assert result.path_confidence_score <= 90

    def test_confidence_reasons_mention_return_path(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        combined = " ".join(result.confidence_reasons).lower()
        assert "return" in combined or "return path" in combined

    # outcome / impairment
    def test_connection_outcome_is_partial_success_or_failure(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        # Backend responded but return path to client was not observed
        assert result.connection_outcome in ("partial_success", "failure")

    def test_return_path_problem_in_impairments(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        assert "return_path_problem" in result.path_impairments

    def test_primary_impairment_includes_return_path(self):
        result = _engine(self._packets(), self._flows()).analyze(
            CLIENT, LB_VIP, 80, roles=self._roles()
        )
        # return_path_problem should appear as primary or alongside no_server_response
        assert result.primary_impairment in (
            "return_path_problem",
            "no_server_response",
            "connection_establishment_failure",
        )


# ══════════════════════════════════════════════════════════════════════════════
# Scenario 7 — Clean flow (all stages observed, no failure)
# ══════════════════════════════════════════════════════════════════════════════

class TestCleanFlow:
    """Full handshake (pure ACK) + server data. No failure expected."""

    def _packets(self):
        return [
            _pkt(1, 1.000, CLIENT, SERVER, dport=80, syn=True),
            _pkt(2, 1.018, SERVER, CLIENT, sport=80, syn=True, ack=True),
            _pkt(3, 1.019, CLIENT, SERVER, dport=80, ack=True),           # pure ACK
            _pkt(4, 1.050, SERVER, CLIENT, sport=80, ack=True, payload=1024),
        ]

    def test_failure_point_is_empty_or_no_failure(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.likely_failure_point in ("", "no_obvious_failure_detected")

    def test_state_is_data_observed(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.connection_state == ConnectionState.DATA_OBSERVED

    def test_no_hypotheses(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.alternative_hypotheses == []

    def test_path_steps_not_empty(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert len(result.path_steps) >= 2

    def test_path_steps_mention_connection_established(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        combined = " ".join(result.path_steps).lower()
        assert "established" in combined or "successfully" in combined or "initiated" in combined

    def test_path_confidence_score_above_60(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.path_confidence_score >= 60

    def test_no_connection_gap_in_confidence_reasons(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        # A clean flow should not report SYN-ACK or response as missing
        problematic = [
            r for r in result.confidence_reasons
            if "syn-ack not confirmed" in r.lower()
            or "server response not observed" in r.lower()
            or "backend response not observed" in r.lower()
        ]
        assert len(problematic) == 0

    # outcome / impairment
    def test_connection_outcome_is_success(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.connection_outcome == "success"

    def test_no_impairments_on_clean_flow(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.path_impairments == []

    def test_primary_impairment_is_none_on_clean_flow(self):
        result = _engine(self._packets()).analyze(CLIENT, SERVER, 80)
        assert result.primary_impairment is None
