"""
Unit tests for classify_ip_role() — Phase 2 role-aware classification.
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.causal_path import TopologyRoles, classify_ip_role


def _roles(
    fw=None, lb=None, be=None, subnets=None
) -> TopologyRoles:
    return TopologyRoles(
        firewall_ips       = fw      or [],
        load_balancer_vips = lb      or [],
        backend_ips        = be      or [],
        backend_subnets    = subnets or [],
    )


# ── Exact-match tests ─────────────────────────────────────────────────────────

class TestFirewallMatch:
    def test_exact_match(self):
        r = _roles(fw=["10.0.0.254"])
        assert classify_ip_role("10.0.0.254", r) == "firewall"

    def test_non_member_not_firewall(self):
        r = _roles(fw=["10.0.0.254"])
        assert classify_ip_role("10.0.0.1", r) != "firewall"

    def test_multiple_firewall_ips(self):
        r = _roles(fw=["10.0.0.253", "10.0.0.254"])
        assert classify_ip_role("10.0.0.253", r) == "firewall"
        assert classify_ip_role("10.0.0.254", r) == "firewall"


class TestLoadBalancerMatch:
    def test_exact_match(self):
        r = _roles(lb=["10.0.1.10"])
        assert classify_ip_role("10.0.1.10", r) == "load_balancer"

    def test_non_member_not_lb(self):
        r = _roles(lb=["10.0.1.10"])
        assert classify_ip_role("10.0.1.11", r) != "load_balancer"

    def test_multiple_vips(self):
        r = _roles(lb=["10.0.1.10", "10.0.1.11"])
        assert classify_ip_role("10.0.1.11", r) == "load_balancer"


class TestBackendIpMatch:
    def test_exact_match(self):
        r = _roles(be=["10.0.2.20"])
        assert classify_ip_role("10.0.2.20", r) == "backend"

    def test_non_member_not_backend(self):
        r = _roles(be=["10.0.2.20"])
        assert classify_ip_role("10.0.2.21", r) != "backend"


# ── Subnet-match tests ────────────────────────────────────────────────────────

class TestBackendSubnetMatch:
    def test_ip_inside_subnet(self):
        r = _roles(subnets=["10.0.2.0/24"])
        assert classify_ip_role("10.0.2.50", r) == "backend"

    def test_ip_outside_subnet(self):
        r = _roles(subnets=["10.0.2.0/24"])
        assert classify_ip_role("10.0.3.50", r) == "unknown"

    def test_subnet_boundary_first(self):
        r = _roles(subnets=["10.0.2.0/24"])
        assert classify_ip_role("10.0.2.1", r) == "backend"

    def test_subnet_boundary_last(self):
        r = _roles(subnets=["10.0.2.0/24"])
        assert classify_ip_role("10.0.2.254", r) == "backend"

    def test_multiple_subnets(self):
        r = _roles(subnets=["10.0.2.0/24", "10.0.3.0/24"])
        assert classify_ip_role("10.0.3.100", r) == "backend"

    def test_slash32_exact_subnet(self):
        r = _roles(subnets=["192.168.1.5/32"])
        assert classify_ip_role("192.168.1.5", r) == "backend"
        assert classify_ip_role("192.168.1.6", r) == "unknown"

    def test_invalid_subnet_skipped(self):
        # Bad subnet string must not crash — IP falls through to unknown
        r = _roles(subnets=["not-a-subnet"])
        assert classify_ip_role("10.0.0.1", r) == "unknown"


# ── Unknown / empty config ────────────────────────────────────────────────────

class TestUnknown:
    def test_empty_roles_always_unknown(self):
        r = _roles()
        assert classify_ip_role("10.0.0.1",   r) == "unknown"
        assert classify_ip_role("192.168.1.1", r) == "unknown"
        assert classify_ip_role("8.8.8.8",     r) == "unknown"

    def test_ip_not_in_any_list(self):
        r = _roles(fw=["10.0.0.254"], lb=["10.0.1.10"], be=["10.0.2.20"])
        assert classify_ip_role("172.16.0.1", r) == "unknown"


# ── Priority tests ────────────────────────────────────────────────────────────

class TestPriority:
    def test_firewall_beats_lb(self):
        """Same IP in both firewall and LB lists → firewall wins."""
        r = _roles(fw=["10.0.0.1"], lb=["10.0.0.1"])
        assert classify_ip_role("10.0.0.1", r) == "firewall"

    def test_firewall_beats_backend(self):
        r = _roles(fw=["10.0.0.1"], be=["10.0.0.1"])
        assert classify_ip_role("10.0.0.1", r) == "firewall"

    def test_lb_beats_backend_exact(self):
        r = _roles(lb=["10.0.0.1"], be=["10.0.0.1"])
        assert classify_ip_role("10.0.0.1", r) == "load_balancer"

    def test_backend_exact_beats_subnet(self):
        """Exact backend_ips match takes priority over subnet (same result but tested order)."""
        r = _roles(be=["10.0.2.20"], subnets=["10.0.2.0/24"])
        assert classify_ip_role("10.0.2.20", r) == "backend"

    def test_lb_beats_backend_subnet(self):
        r = _roles(lb=["10.0.2.20"], subnets=["10.0.2.0/24"])
        assert classify_ip_role("10.0.2.20", r) == "load_balancer"

    def test_firewall_beats_backend_subnet(self):
        r = _roles(fw=["10.0.2.20"], subnets=["10.0.2.0/24"])
        assert classify_ip_role("10.0.2.20", r) == "firewall"


# ── TopologyRoles.has_topology helper ────────────────────────────────────────

class TestHasTopology:
    def test_empty_is_false(self):
        assert not _roles().has_topology

    def test_fw_only_is_true(self):
        assert _roles(fw=["10.0.0.254"]).has_topology

    def test_lb_only_is_true(self):
        assert _roles(lb=["10.0.1.10"]).has_topology

    def test_subnet_only_is_true(self):
        assert _roles(subnets=["10.0.2.0/24"]).has_topology
