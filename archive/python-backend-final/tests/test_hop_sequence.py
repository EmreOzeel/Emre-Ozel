"""
Unit tests for build_hop_sequence() — Phase 2 hop sequence builder.
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.causal_path import TopologyRoles, build_hop_sequence
from models import PacketRecord


SRC = "10.0.0.5"
DST = "10.0.0.1"
FW  = "10.0.0.254"

_EMPTY_ROLES = TopologyRoles()
_ROLES = TopologyRoles(
    firewall_ips=["10.0.0.254"],
    load_balancer_vips=["10.0.1.10"],
    backend_ips=["10.0.2.20"],
)


def _pkt(num, ts, src, dst, sport=54321, dport=80,
         syn=False, ack=False, rst=False):
    return PacketRecord(
        num=num, ts=ts, frame_len=60, protocol="TCP",
        src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport,
        ip_proto=6,
        tcp_flags_syn=syn, tcp_flags_ack=ack, tcp_flags_rst=rst,
    )


# ── Normal TCP handshake ──────────────────────────────────────────────────────

class TestNormalHandshake:
    def _packets(self):
        return [
            _pkt(1, 1.000, SRC, DST, dport=80, syn=True),
            _pkt(2, 1.020, DST, SRC, sport=80, syn=True, ack=True),
            _pkt(3, 1.021, SRC, DST, dport=80, ack=True),
        ]

    def test_two_steps_produced(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert len(steps) == 2

    def test_first_step_is_client_initiated(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[0]["step"] == "client_initiated"

    def test_second_step_is_connection_established(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[1]["step"] == "connection_established"

    def test_src_dst_correct_in_first_step(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[0]["src"] == SRC
        assert steps[0]["dst"] == DST

    def test_src_dst_reversed_in_second_step(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[1]["src"] == DST
        assert steps[1]["dst"] == SRC

    def test_timestamps_populated(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[0]["ts"] == 1.0
        assert steps[1]["ts"] == 1.02

    def test_roles_unknown_when_no_topology(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[0]["source_role"] == "unknown"
        assert steps[0]["dest_role"]   == "unknown"

    def test_roles_annotated_when_topology_given(self):
        roles = TopologyRoles(backend_ips=[DST])
        steps = build_hop_sequence(self._packets(), SRC, DST, roles, 80)
        assert steps[0]["dest_role"] == "backend"

    def test_port_filter_excludes_other_ports(self):
        pkts = self._packets() + [
            _pkt(10, 2.0, SRC, DST, dport=443, syn=True),
        ]
        steps = build_hop_sequence(pkts, SRC, DST, _EMPTY_ROLES, 80)
        assert len(steps) == 2   # port 443 SYN excluded


# ── SYN without SYN-ACK (no RST) ─────────────────────────────────────────────

class TestSynNoSynAck:
    def _packets(self):
        return [_pkt(1, 1.0, SRC, DST, dport=80, syn=True)]

    def test_two_steps_produced(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert len(steps) == 2

    def test_first_step_client_initiated(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[0]["step"] == "client_initiated"

    def test_second_step_connection_failed(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[1]["step"] == "connection_failed"

    def test_failed_step_dst_is_src_of_failure(self):
        # When timed out, we attribute failure to the destination side
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[1]["src"] == DST

    def test_no_connection_established_step(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        labels = [s["step"] for s in steps]
        assert "connection_established" not in labels


# ── RST case ─────────────────────────────────────────────────────────────────

class TestRstCase:
    def _packets(self):
        return [
            _pkt(1, 1.000, SRC, DST, dport=80, syn=True),
            _pkt(2, 1.005, DST, SRC, sport=80, rst=True),
        ]

    def test_two_steps_produced(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert len(steps) == 2

    def test_connection_failed_step_present(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[1]["step"] == "connection_failed"

    def test_rst_source_ip_correct(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[1]["src"] == DST   # RST came from destination

    def test_rst_timestamp_used(self):
        steps = build_hop_sequence(self._packets(), SRC, DST, _EMPTY_ROLES, 80)
        assert steps[1]["ts"] == 1.005

    def test_rst_from_firewall_annotated(self):
        pkts = [
            _pkt(1, 1.0, SRC, FW,  dport=80, syn=True),
            _pkt(2, 1.005, FW, SRC, sport=80, rst=True),
        ]
        steps = build_hop_sequence(pkts, SRC, FW, _ROLES, 80)
        assert steps[1]["source_role"] == "firewall"


# ── Empty / edge cases ────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_no_packets_returns_empty(self):
        steps = build_hop_sequence([], SRC, DST, _EMPTY_ROLES, 80)
        assert steps == []

    def test_unrelated_packets_returns_empty(self):
        pkts = [_pkt(1, 1.0, "192.168.1.5", "192.168.1.6", dport=80, syn=True)]
        steps = build_hop_sequence(pkts, SRC, DST, _EMPTY_ROLES, 80)
        assert steps == []

    def test_no_port_filter_matches_any_port(self):
        pkts = [
            _pkt(1, 1.0, SRC, DST, dport=443, syn=True),
            _pkt(2, 1.02, DST, SRC, sport=443, syn=True, ack=True),
        ]
        steps = build_hop_sequence(pkts, SRC, DST, _EMPTY_ROLES)   # no port
        assert steps[0]["step"] == "client_initiated"
        assert steps[1]["step"] == "connection_established"

    def test_all_steps_have_required_keys(self):
        pkts = [_pkt(1, 1.0, SRC, DST, dport=80, syn=True)]
        for step in build_hop_sequence(pkts, SRC, DST, _EMPTY_ROLES, 80):
            for key in ("step", "src", "dst", "source_role", "dest_role", "ts"):
                assert key in step, f"Missing key '{key}' in step {step}"
