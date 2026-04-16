#!/usr/bin/env python3
"""
Standalone syslog validation tool for PCAP Analyzer.

Starts a temporary UDP syslog listener, prints received lines in real-time,
parses each line with the PaloAlto/FortiGate/GenericKV parsers, and reports
statistics at the end.

Usage:
    python3 scripts/validate_syslog.py [--port 5514] [--timeout 60]

No Django/FastAPI dependencies required — only the parser modules.
"""
from __future__ import annotations

import argparse
import json
import signal
import socket
import sys
import os
from collections import Counter
from datetime import datetime

# ── Path setup — allow running from repo root or scripts/ ────────────────────
_script_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.join(os.path.dirname(_script_dir), "backend")
if os.path.isdir(_backend_dir):
    sys.path.insert(0, _backend_dir)
else:
    # Running from backend/ directly
    sys.path.insert(0, os.path.join(_script_dir, ".."))

from collector.parsers.base import register_parser, clear_registry, detect_format
from collector.parsers.paloalto import PaloAltoParser
from collector.parsers.fortigate import FortiGateParser
from collector.parsers.generic_kv import GenericKVParser


def main():
    parser = argparse.ArgumentParser(
        description="Validate syslog input by parsing lines with PCAP Analyzer parsers."
    )
    parser.add_argument("--port", type=int, default=5514, help="UDP port to listen on (default: 5514)")
    parser.add_argument("--timeout", type=int, default=60, help="Seconds to listen (default: 60)")
    args = parser.parse_args()

    # Register parsers in priority order
    clear_registry()
    register_parser(PaloAltoParser())
    register_parser(FortiGateParser())
    register_parser(GenericKVParser())

    # Statistics
    total_received = 0
    parsed_ok = 0
    parse_failures = 0
    log_types = Counter()       # TRAFFIC, THREAT, fortigate, generic_kv, unknown
    parser_hits = Counter()     # paloalto, fortigate, generic_kv
    failed_lines = []           # first 10 failed lines (truncated)
    sample_events = []          # first 3 successfully parsed events

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", args.port))
    except PermissionError:
        print(f"ERROR: Cannot bind to port {args.port}. Try running with sudo or use a port > 1024.")
        sys.exit(1)
    except OSError as e:
        print(f"ERROR: Cannot bind to port {args.port}: {e}")
        sys.exit(1)

    sock.settimeout(1.0)  # 1-second timeout for non-blocking checks

    # Handle Ctrl+C gracefully
    stop = False

    def on_signal(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print(f"Listening on UDP :{args.port} for {args.timeout} seconds...")
    print(f"Point your firewall syslog output here. Press Ctrl+C to stop early.")
    print()

    start_time = datetime.now()

    while not stop:
        elapsed = (datetime.now() - start_time).total_seconds()
        if elapsed >= args.timeout:
            break

        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break

        raw_line = data.decode("utf-8", errors="replace").strip()
        if not raw_line:
            continue

        total_received += 1
        now_str = datetime.now().strftime("%H:%M:%S")

        # Strip syslog header (RFC3164 priority)
        line = raw_line
        if line.startswith("<"):
            close = line.find(">")
            if close > 0 and close < 6:
                line = line[close + 1:].strip()

        # Try to detect and parse
        matched_parser = detect_format(line)
        if matched_parser is None:
            parse_failures += 1
            log_types["unknown"] += 1
            truncated = raw_line[:100] + ("..." if len(raw_line) > 100 else "")
            if len(failed_lines) < 10:
                failed_lines.append(truncated)
            print(f"  [{now_str}] \u2717 UNKNOWN  {truncated}")
            continue

        event = matched_parser.parse(line)
        if event is None:
            parse_failures += 1
            log_types["unparseable"] += 1
            truncated = raw_line[:100] + ("..." if len(raw_line) > 100 else "")
            if len(failed_lines) < 10:
                failed_lines.append(truncated)
            print(f"  [{now_str}] \u2717 FAILED   {truncated}")
            continue

        # Successfully parsed
        parsed_ok += 1
        parser_hits[matched_parser.PARSER_ID] += 1

        # Determine log type
        if matched_parser.PARSER_ID == "paloalto":
            fields = line.split(",", 5)
            lt = fields[3].strip() if len(fields) > 3 else "?"
        elif matched_parser.PARSER_ID == "fortigate":
            lt = "FORTIGATE"
        else:
            lt = "GENERIC"
        log_types[lt] += 1

        # Pretty-print parsed event
        src = event.get("source_ip", "?")
        dst = event.get("destination_ip", "?")
        dport = event.get("destination_port", "")
        proto = event.get("protocol", "")
        action = event.get("action", "?")
        b_in = event.get("bytes_in", 0) or 0
        b_out = event.get("bytes_out", 0) or 0
        total_bytes = b_in + b_out

        dst_str = f"{dst}:{dport}" if dport else dst
        print(f"  [{now_str}] \u2713 {lt:<8} {src} \u2192 {dst_str} ({proto}, {action}, {total_bytes} bytes)")

        # Collect samples
        if len(sample_events) < 3:
            sample_events.append(event)

    sock.close()

    # ── Summary ──────────────────────────────────────────────────────────────
    duration = (datetime.now() - start_time).total_seconds()
    pct = f"{parsed_ok / total_received * 100:.1f}%" if total_received > 0 else "N/A"

    print()
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Duration:          {duration:.0f}s")
    print(f"  Total received:    {total_received}")
    print(f"  Parsed OK:         {parsed_ok}  ({pct})")
    print(f"  Parse failures:    {parse_failures}")
    print()

    if log_types:
        print("  Log types:")
        for lt, count in log_types.most_common():
            print(f"    {lt:<16} {count}")
        print()

    if parser_hits:
        print("  Parser matches:")
        for pid, count in parser_hits.most_common():
            print(f"    {pid:<16} {count}")
        print()

    if failed_lines:
        print("  Failed lines (first 10):")
        for fl in failed_lines:
            print(f"    {fl}")
        print()

    if sample_events:
        print("  Sample parsed event:")
        sample = sample_events[0]
        # Convert datetime to string for JSON output
        display = {}
        for k, v in sample.items():
            if isinstance(v, datetime):
                display[k] = v.isoformat()
            elif v is not None:
                display[k] = v
        print(json.dumps(display, indent=4))
        print()

    if total_received == 0:
        print("  No syslog messages received.")
        print(f"  Verify your device is sending to this host on UDP port {args.port}.")
        print()


if __name__ == "__main__":
    main()
