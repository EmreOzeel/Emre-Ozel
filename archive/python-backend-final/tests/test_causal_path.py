"""
Foundation tests for CausalPathEngine.
Verifies the 5-step pipeline classification and result model.
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.causal_path import CausalPathEngine, ConnectionState, PathAnalysisResult
from models import PacketRecord, FlowRecord, CaptureContext, TCPState


def _pkt(num, ts, src, dst, sport=54321, dport=80, proto=6,
         syn=False, ack=False, fin=False, rst=False, payload=0):
    return PacketRecord(
        num=num, ts=ts, frame_len=60 + payload, protocol="TCP",
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        ip_proto=proto,
        tcp_flags_syn=syn, tcp_flags_ack=ack,
        tcp_flags_fin=fin, tcp_flags_rst=rst,
        tcp_payload_len=payload,
    )


def _engine(packets, flows=None):
    return CausalPathEngine(packets, flows or {}, [], None)


# ── ConnectionState.NO_ATTEMPT ────────────────────────────────────────────────

class TestNoAttempt:
    def test_empty_capture(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert result.connection_state == ConnectionState.NO_ATTEMPT

    def test_unrelated_traffic_only(self):
        pkts = [_pkt(1, 1.0, "192.168.1.5", "192.168.1.6", syn=True)]
        result = _engine(pkts).analyze("10.0.0.1", "10.0.0.2", 80)
        assert result.connection_state == ConnectionState.NO_ATTEMPT

    def test_summary_mentions_no_connection(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert "no connection" in result.path_summary.lower() or \
               "not observed" in result.path_summary.lower() or \
               "observed" in result.path_summary.lower()

    def test_no_failure_point_when_no_attempt(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert result.likely_failure_point == ""

    def test_hypotheses_present(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert len(result.alternative_hypotheses) >= 2


# ── ConnectionState.NO_RESPONSE ───────────────────────────────────────────────

class TestNoResponse:
    def _packets(self):
        return [_pkt(1, 1.0, "10.0.0.5", "10.0.0.1", dport=443, syn=True)]

    def test_syn_no_synack(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 443)
        assert result.connection_state == ConnectionState.NO_RESPONSE

    def test_failure_point_set(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 443)
        assert result.likely_failure_point != ""

    def test_summary_mentions_no_synack(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 443)
        assert "syn" in result.path_summary.lower() or "no response" in result.path_summary.lower() or \
               "did not respond" in result.path_summary.lower()

    def test_hypotheses_include_firewall(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 443)
        joined = " ".join(result.alternative_hypotheses).lower()
        assert "firewall" in joined or "blocked" in joined or "down" in joined

    def test_timing_has_total_latency(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 443)
        assert "total_observed_latency_ms" in result.timing_breakdown


# ── ConnectionState.ESTABLISHED_NO_DATA ──────────────────────────────────────

class TestEstablishedNoData:
    def _packets(self):
        return [
            _pkt(1, 1.000, "10.0.0.5", "10.0.0.1", dport=80, syn=True),
            _pkt(2, 1.015, "10.0.0.1", "10.0.0.5", sport=80, syn=True, ack=True),
            _pkt(3, 1.016, "10.0.0.5", "10.0.0.1", dport=80, ack=True),
        ]

    def test_state(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert result.connection_state == ConnectionState.ESTABLISHED_NO_DATA

    def test_connect_time_ms_computed(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert "connect_time_ms" in result.timing_breakdown
        assert result.timing_breakdown["connect_time_ms"] == pytest.approx(15.0, abs=0.5)

    def test_failure_point_set(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert result.likely_failure_point != ""

    def test_summary_mentions_no_data(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        summary = result.path_summary.lower()
        assert "no application data" in summary or "no data" in summary or \
               "no useful payload" in summary or "without useful" in summary


# ── ConnectionState.DATA_OBSERVED ─────────────────────────────────────────────

class TestDataObserved:
    def _packets(self):
        return [
            _pkt(1, 1.000, "10.0.0.5", "10.0.0.1", dport=80, syn=True),
            _pkt(2, 1.020, "10.0.0.1", "10.0.0.5", sport=80, syn=True, ack=True),
            _pkt(3, 1.021, "10.0.0.5", "10.0.0.1", dport=80, ack=True, payload=512),
            _pkt(4, 1.055, "10.0.0.1", "10.0.0.5", sport=80, ack=True, payload=1024),
        ]

    def test_state(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert result.connection_state == ConnectionState.DATA_OBSERVED

    def test_no_failure_point(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert result.likely_failure_point == ""

    def test_no_hypotheses_when_success(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert result.alternative_hypotheses == []

    def test_summary_mentions_server_responded(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert "responded" in result.path_summary.lower() or \
               "interaction" in result.path_summary.lower()

    def test_evidence_packets_populated(self):
        result = _engine(self._packets()).analyze("10.0.0.5", "10.0.0.1", 80)
        assert len(result.evidence_packets) == 4


# ── Result model ──────────────────────────────────────────────────────────────

class TestResultModel:
    def test_to_dict_has_all_required_keys(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        d = result.to_dict()
        required = [
            "source_ip", "destination_ip", "destination_port", "protocol",
            "connection_state", "path_summary", "hop_sequence",
            "firewall_observation", "load_balancer_observation", "backend_observation",
            "timing_breakdown", "return_path_observation",
            "likely_failure_point", "alternative_hypotheses",
            "confidence_score", "confidence_reasoning",
            "evidence_packets", "evidence_flows", "missing_visibility_notes",
        ]
        for key in required:
            assert key in d, f"Missing key in to_dict(): {key}"

    def test_confidence_score_in_range(self):
        pkts = [_pkt(1, 1.0, "10.0.0.5", "10.0.0.1", dport=80, syn=True)]
        result = _engine(pkts).analyze("10.0.0.5", "10.0.0.1", 80)
        assert 10 <= result.confidence_score <= 95

    def test_hop_sequence_contains_src_and_dst(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert "10.0.0.1" in result.hop_sequence
        assert "10.0.0.2" in result.hop_sequence

    def test_visibility_note_when_no_packets(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert result.missing_visibility_notes

    def test_visibility_note_when_no_port_specified(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2")
        notes = " ".join(result.missing_visibility_notes).lower()
        assert "port" in notes

    def test_protocol_inferred_as_tcp(self):
        pkts = [_pkt(1, 1.0, "10.0.0.5", "10.0.0.1", dport=80, syn=True)]
        result = _engine(pkts).analyze("10.0.0.5", "10.0.0.1", 80)
        assert result.protocol == "TCP"

    def test_protocol_unknown_when_no_packets(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert result.protocol == "unknown"

    def test_connection_state_serializes_as_string(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        d = result.to_dict()
        assert isinstance(d["connection_state"], str)


# ── Return path analysis ──────────────────────────────────────────────────────

class TestReturnPath:
    def test_asymmetric_forward_only(self):
        pkts = [_pkt(1, 1.0, "10.0.0.5", "10.0.0.1", dport=80, syn=True)]
        result = _engine(pkts).analyze("10.0.0.5", "10.0.0.1", 80)
        assert "only forward" in result.return_path_observation.lower() or \
               "asymmetric" in result.return_path_observation.lower()

    def test_symmetric_traffic(self):
        pkts = [
            _pkt(1, 1.0, "10.0.0.5", "10.0.0.1", dport=80, syn=True),
            _pkt(2, 1.02, "10.0.0.1", "10.0.0.5", sport=80, syn=True, ack=True),
        ]
        result = _engine(pkts).analyze("10.0.0.5", "10.0.0.1", 80)
        note = result.return_path_observation.lower()
        assert "symmetric" in note or "1x" in note or "1.00" in note

    def test_no_packets_return_path_note(self):
        result = _engine([]).analyze("10.0.0.1", "10.0.0.2", 80)
        assert "no packets" in result.return_path_observation.lower() or \
               "either direction" in result.return_path_observation.lower()
