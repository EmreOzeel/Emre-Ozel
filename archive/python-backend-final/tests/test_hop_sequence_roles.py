"""
Role-aware hop sequence tests — Phase 2 enhancement.
Covers: firewall drop, firewall reset, LB frontend OK / backend missing,
        backend slow response, and generic fallback.
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.causal_path import TopologyRoles, build_hop_sequence
from models import PacketRecord

CLIENT  = "10.0.0.5"
FW      = "10.0.0.254"
LB_VIP  = "10.0.1.10"
BACKEND = "10.0.2.20"


def _roles(**kw) -> TopologyRoles:
    return TopologyRoles(
        firewall_ips       = kw.get("fw",  []),
        load_balancer_vips = kw.get("lb",  []),
        backend_ips        = kw.get("be",  []),
        backend_subnets    = kw.get("sub", []),
    )


def _pkt(num, ts, src, dst, sport=54321, dport=80,
         syn=False, ack=False, rst=False, payload=0):
    return PacketRecord(
        num=num, ts=ts, frame_len=60 + payload, protocol="TCP",
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        ip_proto=6,
        tcp_flags_syn=syn, tcp_flags_ack=ack, tcp_flags_rst=rst,
        tcp_payload_len=payload,
    )


def _steps(pkts, src, dst, roles, port=80):
    return build_hop_sequence(pkts, src, dst, roles, destination_port=port)


def _labels(steps):
    return [s["step"] for s in steps]


# ═══════════════════════════════════════════════════════════════════════════════
# Firewall scenarios
# ═══════════════════════════════════════════════════════════════════════════════

class TestFirewallDrop:
    """SYN sent to firewall IP — no reply at all."""

    def _pkts(self):
        return [_pkt(1, 1.0, CLIENT, FW, dport=443, syn=True)]

    def test_firewall_drop_suspected_step(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert "firewall_drop_suspected" in _labels(steps)

    def test_no_connection_established(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert "connection_established" not in _labels(steps)

    def test_client_initiated_present(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert steps[0]["step"] == "client_initiated"

    def test_drop_step_src_is_firewall(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        drop = next(s for s in steps if s["step"] == "firewall_drop_suspected")
        assert drop["source_role"] == "firewall"

    def test_two_steps_total(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert len(steps) == 2


class TestFirewallReset:
    """Firewall sends RST immediately after SYN."""

    def _pkts(self):
        return [
            _pkt(1, 1.000, CLIENT, FW, dport=443, syn=True),
            _pkt(2, 1.002, FW, CLIENT, sport=443, rst=True),
        ]

    def test_firewall_reset_observed_step(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert "firewall_reset_observed" in _labels(steps)

    def test_no_drop_when_rst_present(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert "firewall_drop_suspected" not in _labels(steps)

    def test_reset_step_source_role_is_firewall(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        rst_step = next(s for s in steps if s["step"] == "firewall_reset_observed")
        assert rst_step["source_role"] == "firewall"

    def test_reset_timestamp_matches_rst_packet(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        rst_step = next(s for s in steps if s["step"] == "firewall_reset_observed")
        assert rst_step["ts"] == pytest.approx(1.002)

    def test_firewall_pass_not_present(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert "firewall_pass_observed" not in _labels(steps)


class TestFirewallPass:
    """Firewall passes traffic — SYN-ACK received from firewall IP."""

    def _pkts(self):
        return [
            _pkt(1, 1.000, CLIENT, FW, dport=443, syn=True),
            _pkt(2, 1.010, FW, CLIENT, sport=443, syn=True, ack=True),
        ]

    def test_firewall_pass_observed(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert "firewall_pass_observed" in _labels(steps)

    def test_no_drop_or_reset(self):
        r = _roles(fw=[FW])
        steps = _steps(self._pkts(), CLIENT, FW, r, port=443)
        assert "firewall_drop_suspected"  not in _labels(steps)
        assert "firewall_reset_observed"  not in _labels(steps)


# ═══════════════════════════════════════════════════════════════════════════════
# Load balancer scenarios
# ═══════════════════════════════════════════════════════════════════════════════

class TestLBFrontendOKBackendMissing:
    """
    Client→LB handshake succeeds.
    No SYN from LB toward any backend IP found in capture.
    """

    def _pkts(self):
        return [
            _pkt(1, 1.000, CLIENT,  LB_VIP, dport=80,  syn=True),
            _pkt(2, 1.005, LB_VIP, CLIENT,  sport=80,  syn=True, ack=True),
            _pkt(3, 1.006, CLIENT,  LB_VIP, dport=80,  ack=True),
        ]

    def test_frontend_connection_observed(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert "lb_frontend_connection_observed" in _labels(steps)

    def test_lb_backend_connection_missing(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert "lb_backend_connection_missing" in _labels(steps)

    def test_no_generic_connection_established(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert "connection_established" not in _labels(steps)

    def test_missing_step_has_note(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        missing = next(s for s in steps if s["step"] == "lb_backend_connection_missing")
        assert "note" in missing and missing["note"]

    def test_three_steps_total(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert len(steps) == 3   # client_initiated + frontend + missing


class TestLBFrontendAndBackendFound:
    """Backend SYN visible in capture — backend connection step produced."""

    def _pkts(self):
        return [
            _pkt(1, 1.000, CLIENT,  LB_VIP,  dport=80,   syn=True),
            _pkt(2, 1.005, LB_VIP,  CLIENT,  sport=80,   syn=True, ack=True),
            _pkt(3, 1.010, LB_VIP,  BACKEND, dport=8080, syn=True),   # LB→backend
        ]

    def test_frontend_observed(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert "lb_frontend_connection_observed" in _labels(steps)

    def test_no_backend_missing_step(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert "lb_backend_connection_missing" not in _labels(steps)

    def test_connection_established_step_present(self):
        r = _roles(lb=[LB_VIP], be=[BACKEND])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert "connection_established" in _labels(steps)

    def test_backend_syn_subnet_also_works(self):
        r = _roles(lb=[LB_VIP], sub=["10.0.2.0/24"])
        steps = _steps(self._pkts(), CLIENT, LB_VIP, r)
        assert "lb_backend_connection_missing" not in _labels(steps)


# ═══════════════════════════════════════════════════════════════════════════════
# Backend slow response
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackendSlowResponse:
    """Backend responds, but with a noticeable delay."""

    def _pkts(self, response_delay=0.8):
        return [
            _pkt(1, 1.000,              CLIENT,  BACKEND, dport=8080, syn=True),
            _pkt(2, 1.010,              BACKEND, CLIENT,  sport=8080, syn=True, ack=True),
            _pkt(3, 1.011,              CLIENT,  BACKEND, dport=8080, ack=True, payload=200),
            _pkt(4, 1.010+response_delay, BACKEND, CLIENT, sport=8080, payload=512),
        ]

    def test_slow_response_step_when_over_threshold(self):
        r = _roles(be=[BACKEND])
        steps = build_hop_sequence(
            self._pkts(0.8), CLIENT, BACKEND, r, 8080, slow_threshold_ms=500.0
        )
        assert "backend_response_slow" in _labels(steps)

    def test_no_slow_step_when_under_threshold(self):
        r = _roles(be=[BACKEND])
        steps = build_hop_sequence(
            self._pkts(0.1), CLIENT, BACKEND, r, 8080, slow_threshold_ms=500.0
        )
        assert "backend_response_slow" not in _labels(steps)

    def test_slow_step_carries_delay_ms(self):
        r = _roles(be=[BACKEND])
        steps = build_hop_sequence(
            self._pkts(0.8), CLIENT, BACKEND, r, 8080, slow_threshold_ms=500.0
        )
        slow = next(s for s in steps if s["step"] == "backend_response_slow")
        assert slow["delay_ms"] == pytest.approx(800.0, abs=5.0)

    def test_slow_step_carries_threshold(self):
        r = _roles(be=[BACKEND])
        steps = build_hop_sequence(
            self._pkts(0.8), CLIENT, BACKEND, r, 8080, slow_threshold_ms=500.0
        )
        slow = next(s for s in steps if s["step"] == "backend_response_slow")
        assert slow["threshold_ms"] == 500.0

    def test_connection_established_still_present_before_slow(self):
        r = _roles(be=[BACKEND])
        steps = build_hop_sequence(
            self._pkts(0.8), CLIENT, BACKEND, r, 8080, slow_threshold_ms=500.0
        )
        labels = _labels(steps)
        assert "connection_established" in labels
        assert labels.index("connection_established") < labels.index("backend_response_slow")


# ═══════════════════════════════════════════════════════════════════════════════
# Backward compatibility — unknown destination still works
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenericFallback:
    def test_normal_handshake_unknown_role(self):
        pkts = [
            _pkt(1, 1.0,  CLIENT, "10.9.9.9", dport=80, syn=True),
            _pkt(2, 1.02, "10.9.9.9", CLIENT, sport=80, syn=True, ack=True),
        ]
        steps = build_hop_sequence(pkts, CLIENT, "10.9.9.9", TopologyRoles(), 80)
        assert _labels(steps) == ["client_initiated", "connection_established"]

    def test_syn_only_unknown_role(self):
        pkts = [_pkt(1, 1.0, CLIENT, "10.9.9.9", dport=80, syn=True)]
        steps = build_hop_sequence(pkts, CLIENT, "10.9.9.9", TopologyRoles(), 80)
        assert _labels(steps) == ["client_initiated", "connection_failed"]
