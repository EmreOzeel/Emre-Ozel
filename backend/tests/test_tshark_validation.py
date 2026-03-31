"""
Tests for tshark dependency check and packet-extraction validation.

All subprocess/filesystem calls are mocked so no tshark binary is required.
Run with:  pytest backend/tests/test_tshark_validation.py -v
"""
import sys
import os
import pytest
from unittest.mock import MagicMock, patch

# Make sure the backend package root is on sys.path when running from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from normalizer.tshark import check_tshark, get_packets, PacketParseResult, PACKET_FIELDS


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_run_result(stdout="", stderr="", returncode=0):
    r = MagicMock()
    r.stdout = stdout
    r.stderr = stderr
    r.returncode = returncode
    return r


def _minimal_packet_line(fields):
    """Build one tshark output line with frame.number=1, ts=1.0, len=60, protocols=eth:ip."""
    row = [""] * len(fields)
    idx = {f: i for i, f in enumerate(fields)}
    if "frame.number" in idx:
        row[idx["frame.number"]] = "1"
    if "frame.time_epoch" in idx:
        row[idx["frame.time_epoch"]] = "1700000000.000000"
    if "frame.len" in idx:
        row[idx["frame.len"]] = "60"
    if "frame.protocols" in idx:
        row[idx["frame.protocols"]] = "eth:ethertype:ip:tcp"
    return "\t".join(row)


# ── check_tshark tests ─────────────────────────────────────────────────────────

class TestCheckTshark:

    def test_tshark_missing_raises(self):
        """RuntimeError with install instructions when tshark binary is absent."""
        with patch("shutil.which", return_value=None):
            with pytest.raises(RuntimeError) as exc:
                check_tshark()
        assert "tshark is required" in str(exc.value)
        assert "apt-get" in str(exc.value)

    def test_tshark_nonzero_exit_raises(self):
        """RuntimeError when tshark binary exists but --version exits non-zero."""
        with patch("shutil.which", return_value="/usr/bin/tshark"), \
             patch("subprocess.run", return_value=_make_run_result(returncode=1)):
            with pytest.raises(RuntimeError) as exc:
                check_tshark()
        assert "failed to execute" in str(exc.value)

    def test_tshark_present_logs_path_and_version(self, capsys):
        """Successful check prints binary path and version line."""
        version_out = "TShark (Wireshark) 4.2.0\n"
        with patch("shutil.which", return_value="/usr/bin/tshark"), \
             patch("subprocess.run", return_value=_make_run_result(stdout=version_out)):
            check_tshark()   # must not raise
        captured = capsys.readouterr()
        assert "/usr/bin/tshark" in captured.out
        assert "TShark (Wireshark) 4.2.0" in captured.out


# ── get_packets tests ──────────────────────────────────────────────────────────

class TestGetPackets:

    def test_zero_parsed_rows_when_tshark_returns_empty(self):
        """Zero raw lines → raw_line_count=0, packets=[]."""
        with patch("subprocess.run", return_value=_make_run_result(stdout="")):
            result = get_packets("/fake.pcap")
        assert isinstance(result, PacketParseResult)
        assert result.raw_line_count == 0
        assert result.packets == []

    def test_malformed_lines_counted_correctly(self):
        """Lines with fewer than 4 tab-separated fields increment malformed_line_count."""
        # Two malformed lines (1-field each) + one valid line
        fields = list(PACKET_FIELDS)
        valid_line = _minimal_packet_line(fields)
        stdout = "only_one_field\nonly_one_field\n" + valid_line + "\n"
        with patch("subprocess.run", return_value=_make_run_result(stdout=stdout)):
            result = get_packets("/fake.pcap")
        assert result.raw_line_count == 3
        assert result.malformed_line_count == 2
        assert len(result.packets) == 1

    def test_invalid_fields_removed_and_retried(self):
        """When tshark reports invalid fields, they are removed and extraction is retried."""
        fields = list(PACKET_FIELDS)
        valid_line = _minimal_packet_line(fields)

        # First call: tshark rejects some fields
        bad_stderr = "The following fields aren't valid:\nntp.mode\nrdp.neg_req.selectedProtocol\n"
        first = _make_run_result(stdout="", stderr=bad_stderr, returncode=1)
        # Second call: succeeds
        second = _make_run_result(stdout=valid_line)

        with patch("subprocess.run", side_effect=[first, second]):
            result = get_packets("/fake.pcap")

        assert "ntp.mode" in result.invalid_fields_removed
        assert "rdp.neg_req.selectedProtocol" in result.invalid_fields_removed
        assert result.attempts == 2
        assert len(result.packets) == 1

    def test_small_valid_capture_does_not_fail(self):
        """10 valid packet lines → parse succeeds with no malformed lines."""
        fields = list(PACKET_FIELDS)
        lines = [_minimal_packet_line(fields) for _ in range(10)]
        stdout = "\n".join(lines) + "\n"
        with patch("subprocess.run", return_value=_make_run_result(stdout=stdout)):
            result = get_packets("/fake.pcap")
        assert result.raw_line_count == 10
        assert result.malformed_line_count == 0
        assert len(result.packets) == 10
        assert all("frame.number" in p for p in result.packets)


# ── normalize() integration tests ─────────────────────────────────────────────

class TestNormalizeValidation:
    """
    Integration tests for the validation logic in normalizer.pipeline.normalize().
    We mock get_file_info, get_protocol_hierarchy, get_tcp_conversations,
    get_expert_info, and get_packets to isolate the validation checks.
    """

    _PATCH_BASE = "normalizer.pipeline"

    def _patch_all(self, file_total, parse_result):
        """Return a context-manager stack that patches all tshark calls."""
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch(f"{self._PATCH_BASE}.check_tshark"))
        stack.enter_context(patch(
            f"{self._PATCH_BASE}.get_file_info",
            return_value={"total_packets": file_total, "duration_sec": 1.0,
                          "file_size_bytes": 1024},
        ))
        stack.enter_context(patch(f"{self._PATCH_BASE}.get_protocol_hierarchy", return_value={}))
        stack.enter_context(patch(f"{self._PATCH_BASE}.get_tcp_conversations", return_value=[]))
        stack.enter_context(patch(f"{self._PATCH_BASE}.get_expert_info", return_value=[]))
        stack.enter_context(patch(f"{self._PATCH_BASE}.get_packets", return_value=parse_result))
        return stack

    def test_zero_packet_file_raises(self):
        """capinfos reports 0 packets → RuntimeError about empty/corrupt file."""
        from normalizer.pipeline import normalize
        with patch(f"{self._PATCH_BASE}.check_tshark"), \
             patch(f"{self._PATCH_BASE}.get_file_info", return_value={"total_packets": 0}):
            with pytest.raises(RuntimeError) as exc:
                normalize("/fake.pcap")
        assert "could not read any packets" in str(exc.value).lower() or \
               "empty" in str(exc.value).lower()

    def test_zero_raw_lines_raises(self):
        """tshark outputs nothing despite non-empty file → RuntimeError."""
        from normalizer.pipeline import normalize
        parse = PacketParseResult(
            packets=[], raw_line_count=0, malformed_line_count=0,
            fields_used=[], invalid_fields_removed=[], attempts=1,
        )
        with self._patch_all(file_total=100, parse_result=parse):
            with pytest.raises(RuntimeError) as exc:
                normalize("/fake.pcap")
        assert "produced no output" in str(exc.value)

    def test_high_malformed_rate_raises(self):
        """More than 70% malformed lines → RuntimeError about unreliable extraction."""
        from normalizer.pipeline import normalize
        parse = PacketParseResult(
            packets=[], raw_line_count=100, malformed_line_count=80,
            fields_used=[], invalid_fields_removed=[], attempts=1,
        )
        with self._patch_all(file_total=100, parse_result=parse):
            with pytest.raises(RuntimeError) as exc:
                normalize("/fake.pcap")
        assert "unreliable" in str(exc.value).lower()

    def test_low_essential_field_rate_raises(self):
        """frame.number absent in >50% of packets → RuntimeError about field mapping."""
        from normalizer.pipeline import normalize
        # 10 packets, none have frame.number
        broken_packets = [{"ip.src": "1.2.3.4"} for _ in range(10)]
        parse = PacketParseResult(
            packets=broken_packets, raw_line_count=10, malformed_line_count=0,
            fields_used=list(PACKET_FIELDS), invalid_fields_removed=[], attempts=1,
        )
        with self._patch_all(file_total=10, parse_result=parse):
            with pytest.raises(RuntimeError) as exc:
                normalize("/fake.pcap")
        assert "frame.number" in str(exc.value)

    def test_small_valid_capture_succeeds(self):
        """10 well-formed packets with frame.number present → normalize completes."""
        from normalizer.pipeline import normalize
        fields = list(PACKET_FIELDS)
        good_packets = [
            {
                "frame.number": str(i + 1),
                "frame.time_epoch": "1700000000.0",
                "frame.len": "60",
                "frame.protocols": "eth:ethertype:ip:tcp",
            }
            for i in range(10)
        ]
        parse = PacketParseResult(
            packets=good_packets, raw_line_count=10, malformed_line_count=0,
            fields_used=fields, invalid_fields_removed=[], attempts=1,
        )
        with self._patch_all(file_total=10, parse_result=parse):
            ctx = normalize("/fake.pcap")
        assert ctx.packets_analyzed == 10
