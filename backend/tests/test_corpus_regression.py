"""
Corpus-based correctness regression tests.

Each test runs the full normalize() pipeline against a scenario from the
regression corpus by mocking all tshark calls with pre-recorded snapshots.
This means no tshark binary is required for the default test suite.

Optional integration tests (require a real tshark binary) are marked with
@pytest.mark.integration and are skipped by default.  Run them explicitly:

    pytest backend/tests/test_corpus_regression.py -m integration -v

Design contract
---------------
The corpus (tests/corpus/scenarios.py) defines:
  - pcap_bytes       : valid PCAP binary (for human inspection / real-tshark runs)
  - tshark_snapshot  : pre-recorded tshark responses (mocked in unit tests)
  - golden           : key/value assertions evaluated here

The golden dict uses the following keys (see scenarios.py for full docs):
  expected_error, session_count, dns_tx_count, protocol_stats_has_udp,
  session_0_state, session_0_has_syn, session_0_has_synack, session_0_has_fin,
  session_0_has_rst, session_0_retransmissions_min,
  all_sessions_half_open, all_sessions_have_rst,
  dns_tx_0_is_nxdomain, dns_tx_0_qname
"""
from __future__ import annotations

import sys
import os
import tempfile
import pytest
from contextlib import ExitStack
from unittest.mock import patch
from typing import Any, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.corpus.scenarios import SCENARIOS, Scenario
from models import TCPState

_BASE = "normalizer.pipeline"


# ── Mock helper ────────────────────────────────────────────────────────────────

def _run_with_mocks(scenario: Scenario, profile_name: str = "balanced"):
    """
    Run normalize() with all tshark sub-calls mocked using scenario data.
    Returns CaptureContext on success, or raises the exception on failure.
    """
    from normalizer.pipeline import normalize

    with ExitStack() as stack:
        stack.enter_context(patch(f"{_BASE}.check_tshark",
                                  return_value=("/usr/bin/tshark", "TShark 4.2.0 (test)")))
        stack.enter_context(patch(f"{_BASE}.get_file_info",
                                  return_value=scenario.file_info))
        stack.enter_context(patch(f"{_BASE}.get_protocol_hierarchy",
                                  return_value=scenario.protocol_hierarchy))
        stack.enter_context(patch(f"{_BASE}.get_tcp_conversations",
                                  return_value=scenario.tcp_conversations))
        stack.enter_context(patch(f"{_BASE}.get_expert_info",
                                  return_value=scenario.expert_info))
        stack.enter_context(patch(f"{_BASE}.get_packets",
                                  return_value=scenario.parse_result))
        return normalize("/fake/corpus.pcap", profile_name=profile_name)


def _assert_golden(ctx, golden: Dict[str, Any], scenario_name: str) -> None:
    """Evaluate golden assertions against a CaptureContext."""

    if "session_count" in golden:
        assert len(ctx.sessions) == golden["session_count"], (
            f"[{scenario_name}] expected {golden['session_count']} sessions, "
            f"got {len(ctx.sessions)}"
        )

    if "dns_tx_count" in golden:
        assert len(ctx.dns_transactions) == golden["dns_tx_count"], (
            f"[{scenario_name}] expected {golden['dns_tx_count']} DNS transactions, "
            f"got {len(ctx.dns_transactions)}"
        )

    if golden.get("protocol_stats_has_udp"):
        assert ctx.protocol_stats.get("udp", 0) > 0, (
            f"[{scenario_name}] expected protocol_stats to contain 'udp'"
        )

    # Session-level assertions (first session by stream_id sort)
    first = sorted(ctx.sessions.values(), key=lambda s: s.stream_id)[0] if ctx.sessions else None

    for attr in ("has_syn", "has_synack", "has_fin", "has_rst"):
        key = f"session_0_{attr}"
        if key in golden:
            assert first is not None, f"[{scenario_name}] no sessions for {key}"
            actual = getattr(first, attr)
            assert actual == golden[key], (
                f"[{scenario_name}] session.{attr}: expected {golden[key]}, got {actual}"
            )

    if "session_0_state" in golden:
        assert first is not None
        assert first.state.value == golden["session_0_state"], (
            f"[{scenario_name}] session.state: expected {golden['session_0_state']}, "
            f"got {first.state.value}"
        )

    if "session_0_retransmissions_min" in golden:
        assert first is not None
        assert first.retransmissions >= golden["session_0_retransmissions_min"], (
            f"[{scenario_name}] session.retransmissions: "
            f"expected ≥{golden['session_0_retransmissions_min']}, got {first.retransmissions}"
        )

    if golden.get("all_sessions_half_open"):
        for s in ctx.sessions.values():
            assert s.state == TCPState.HALF_OPEN, (
                f"[{scenario_name}] session {s.stream_id} not HALF_OPEN: {s.state}"
            )

    if golden.get("all_sessions_have_rst"):
        for s in ctx.sessions.values():
            assert s.has_rst, (
                f"[{scenario_name}] session {s.stream_id} missing RST flag"
            )

    # DNS transaction assertions
    if "dns_tx_0_is_nxdomain" in golden:
        assert ctx.dns_transactions, f"[{scenario_name}] no DNS transactions"
        tx = ctx.dns_transactions[0]
        assert tx.is_nxdomain == golden["dns_tx_0_is_nxdomain"], (
            f"[{scenario_name}] dns_tx.is_nxdomain: "
            f"expected {golden['dns_tx_0_is_nxdomain']}, got {tx.is_nxdomain}"
        )

    if "dns_tx_0_qname" in golden:
        assert ctx.dns_transactions
        assert ctx.dns_transactions[0].qname == golden["dns_tx_0_qname"], (
            f"[{scenario_name}] dns_tx.qname mismatch"
        )


# ── Per-scenario tests ─────────────────────────────────────────────────────────

class TestEmptyCapture:
    def test_raises_error(self):
        s = SCENARIOS["empty"]
        with pytest.raises(RuntimeError) as exc:
            _run_with_mocks(s)
        assert s.golden["expected_error"].lower() in str(exc.value).lower()


class TestCorruptedCapture:
    def test_raises_error(self):
        s = SCENARIOS["corrupted"]
        with pytest.raises(RuntimeError) as exc:
            _run_with_mocks(s)
        assert s.golden["expected_error"].lower() in str(exc.value).lower()


class TestNonTcpCapture:
    def test_no_tcp_sessions(self):
        s = SCENARIOS["non_tcp"]
        ctx = _run_with_mocks(s)
        _assert_golden(ctx, s.golden, s.name)

    def test_dns_transaction_matched(self):
        """The single DNS query-response pair must be matched into one transaction."""
        ctx = _run_with_mocks(SCENARIOS["non_tcp"])
        assert len(ctx.dns_transactions) == 1
        tx = ctx.dns_transactions[0]
        assert tx.qname == "example.com"
        assert not tx.is_nxdomain
        assert tx.answered

    def test_extraction_diagnostics_populated(self):
        ctx = _run_with_mocks(SCENARIOS["non_tcp"])
        d = ctx.extraction_diagnostics
        assert d["tshark_path"] == "/usr/bin/tshark"
        assert "TShark" in d["tshark_version"]
        assert d["validation_profile"] == "balanced"
        assert d["raw_line_count"] == 2
        assert d["malformed_line_count"] == 0
        assert d["essential_rate"] == 1.0


class TestTcpHandshake:
    def test_session_state(self):
        s = SCENARIOS["tcp_handshake"]
        ctx = _run_with_mocks(s)
        _assert_golden(ctx, s.golden, s.name)

    def test_session_details(self):
        ctx = _run_with_mocks(SCENARIOS["tcp_handshake"])
        assert len(ctx.sessions) == 1
        sess = next(iter(ctx.sessions.values()))
        assert sess.has_syn
        assert sess.has_synack
        assert sess.has_fin
        assert not sess.has_rst
        assert sess.state == TCPState.FIN_CLOSED
        # Both sides sent data
        assert sess.bytes_sent > 0
        assert sess.bytes_recv > 0

    def test_strict_profile_passes(self):
        """All essential fields present → strict profile must not raise."""
        ctx = _run_with_mocks(SCENARIOS["tcp_handshake"], profile_name="strict")
        assert len(ctx.sessions) == 1

    def test_profile_name_stored_in_diagnostics(self):
        ctx = _run_with_mocks(SCENARIOS["tcp_handshake"], profile_name="strict")
        assert ctx.extraction_diagnostics["validation_profile"] == "strict"


class TestMidstreamTcp:
    def test_session_mid_stream(self):
        s = SCENARIOS["midstream_tcp"]
        ctx = _run_with_mocks(s)
        _assert_golden(ctx, s.golden, s.name)

    def test_no_syn_flag(self):
        ctx = _run_with_mocks(SCENARIOS["midstream_tcp"])
        sess = next(iter(ctx.sessions.values()))
        assert not sess.has_syn
        assert sess.state == TCPState.MID_STREAM


class TestRetransmissions:
    def test_retransmission_counted(self):
        s = SCENARIOS["retransmissions"]
        ctx = _run_with_mocks(s)
        _assert_golden(ctx, s.golden, s.name)
        sess = next(iter(ctx.sessions.values()))
        assert sess.retransmissions >= 1


class TestRstHeavy:
    def test_all_sessions_have_rst(self):
        s = SCENARIOS["rst_heavy"]
        ctx = _run_with_mocks(s)
        _assert_golden(ctx, s.golden, s.name)

    def test_session_count(self):
        ctx = _run_with_mocks(SCENARIOS["rst_heavy"])
        assert len(ctx.sessions) == 3


class TestDnsNxdomain:
    def test_nxdomain_detected(self):
        s = SCENARIOS["dns_nxdomain"]
        ctx = _run_with_mocks(s)
        _assert_golden(ctx, s.golden, s.name)

    def test_rtt_computed(self):
        """50 ms RTT must be derived from the dns.time field in the snapshot."""
        ctx = _run_with_mocks(SCENARIOS["dns_nxdomain"])
        tx = ctx.dns_transactions[0]
        assert tx.rtt_ms == pytest.approx(50.0, abs=1.0)

    def test_rcode_3(self):
        ctx = _run_with_mocks(SCENARIOS["dns_nxdomain"])
        assert ctx.dns_transactions[0].rcode == "3"


class TestPortScan:
    def test_all_sessions_half_open(self):
        s = SCENARIOS["port_scan"]
        ctx = _run_with_mocks(s)
        _assert_golden(ctx, s.golden, s.name)

    def test_session_count(self):
        ctx = _run_with_mocks(SCENARIOS["port_scan"])
        assert len(ctx.sessions) == 10

    def test_all_sessions_from_same_src(self):
        ctx = _run_with_mocks(SCENARIOS["port_scan"])
        src_ips = {s.src_ip for s in ctx.sessions.values()}
        assert src_ips == {"10.0.0.99"}


# ── Validation profile threshold tests ────────────────────────────────────────

class TestValidationProfiles:
    """Ensure profile thresholds are respected independently of scenario content."""

    def _scenario_with_malformed(self, total: int, malformed: int):
        """Return a tcp_handshake-based scenario override with custom parse stats."""
        from tests.corpus.scenarios import _parse_result
        from normalizer.tshark import PacketParseResult, PACKET_FIELDS
        s = SCENARIOS["tcp_handshake"]
        good_rows = s.parse_result.packets
        bad_pr = PacketParseResult(
            packets=good_rows,
            raw_line_count=total,
            malformed_line_count=malformed,
            fields_used=list(PACKET_FIELDS),
            invalid_fields_removed=[],
            attempts=1,
        )
        import dataclasses
        return dataclasses.replace(s, parse_result=bad_pr)

    def test_balanced_allows_20pct_malformed(self):
        """20% malformed < balanced threshold (30%) → should pass."""
        s = self._scenario_with_malformed(total=100, malformed=20)
        ctx = _run_with_mocks(s, profile_name="balanced")
        assert ctx is not None

    def test_balanced_rejects_35pct_malformed(self):
        """35% malformed > balanced threshold (30%) → must raise."""
        s = self._scenario_with_malformed(total=100, malformed=35)
        with pytest.raises(RuntimeError, match="unreliable"):
            _run_with_mocks(s, profile_name="balanced")

    def test_strict_rejects_10pct_malformed(self):
        """10% malformed > strict threshold (5%) → must raise."""
        s = self._scenario_with_malformed(total=100, malformed=10)
        with pytest.raises(RuntimeError, match="unreliable"):
            _run_with_mocks(s, profile_name="strict")

    def test_permissive_allows_60pct_malformed(self):
        """60% malformed < permissive threshold (70%) → should pass."""
        s = self._scenario_with_malformed(total=100, malformed=60)
        ctx = _run_with_mocks(s, profile_name="permissive")
        assert ctx is not None

    def test_unknown_profile_raises_value_error(self):
        from config.validation import get_profile
        with pytest.raises(ValueError, match="Unknown validation profile"):
            get_profile("nonexistent")


# ── Integration tests (require real tshark) ────────────────────────────────────

@pytest.mark.integration
class TestIntegration:
    """
    End-to-end tests that write PCAP bytes to disk and run real tshark.
    Skipped unless -m integration is passed.
    Requires tshark to be installed on the test machine.
    """

    def _normalize_real(self, pcap_bytes: bytes, profile: str = "balanced"):
        import shutil
        if not shutil.which("tshark"):
            pytest.skip("tshark not installed")
        from normalizer.pipeline import normalize
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_bytes)
            path = f.name
        try:
            return normalize(path, profile_name=profile)
        finally:
            os.unlink(path)

    def test_empty_pcap_raises(self):
        with pytest.raises(RuntimeError):
            self._normalize_real(SCENARIOS["empty"].pcap_bytes)

    def test_tcp_handshake_real_tshark(self):
        ctx = self._normalize_real(SCENARIOS["tcp_handshake"].pcap_bytes)
        assert len(ctx.sessions) >= 1
        sess = next(iter(ctx.sessions.values()))
        assert sess.has_syn

    def test_dns_nxdomain_real_tshark(self):
        ctx = self._normalize_real(SCENARIOS["dns_nxdomain"].pcap_bytes)
        # May or may not parse DNS depending on tshark version field support
        assert ctx.packets_analyzed >= 1
