#!/usr/bin/env python3
"""
Offline parser test tool for PCAP Analyzer.

Reads a sample log file and runs all registered parsers against each line.
Reports parse rate per parser, failure details, and sample parsed events.

Usage:
    python3 scripts/test_parser.py --file sample_logs.txt
    python3 scripts/test_parser.py --file /var/log/syslog_capture.txt --verbose

Options:
    --file FILE     Path to a text file with one syslog line per line
    --verbose       Print every line's parse result
    --limit N       Only process first N lines (default: all)
    --strip-header  Strip RFC3164 syslog priority header before parsing
"""
from __future__ import annotations

import argparse
import json
import sys
import os
import time
from collections import Counter
from datetime import datetime

# ── Path setup ───────────────────────────────────────────────────────────────
_script_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.join(os.path.dirname(_script_dir), "backend")
if os.path.isdir(_backend_dir):
    sys.path.insert(0, _backend_dir)
else:
    sys.path.insert(0, os.path.join(_script_dir, ".."))

from collector.parsers.base import register_parser, clear_registry, detect_format, get_registry
from collector.parsers.paloalto import PaloAltoParser
from collector.parsers.fortigate import FortiGateParser
from collector.parsers.generic_kv import GenericKVParser


def strip_syslog_header(line: str) -> str:
    """Remove RFC3164 priority prefix like <134> from syslog lines."""
    if line.startswith("<"):
        close = line.find(">")
        if 0 < close < 6:
            return line[close + 1:].strip()
    return line


def main():
    ap = argparse.ArgumentParser(
        description="Test PCAP Analyzer parsers against a sample log file."
    )
    ap.add_argument("--file", required=True, help="Path to log file (one syslog line per line)")
    ap.add_argument("--verbose", action="store_true", help="Print each line's parse result")
    ap.add_argument("--limit", type=int, default=0, help="Process only first N lines (0 = all)")
    ap.add_argument("--strip-header", action="store_true", help="Strip RFC3164 syslog priority header")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f"ERROR: File not found: {args.file}")
        sys.exit(1)

    # Register parsers
    clear_registry()
    register_parser(PaloAltoParser())
    register_parser(FortiGateParser())
    register_parser(GenericKVParser())

    parsers = get_registry()
    print(f"Registered parsers: {', '.join(p.PARSER_ID for p in parsers)}")
    print(f"Input file: {args.file}")
    print()

    # Statistics
    total_lines = 0
    empty_lines = 0
    parser_counts = Counter()   # parser_id -> count of successful parses
    detect_counts = Counter()   # parser_id -> count of can_parse matches
    no_match = 0                # lines where no parser matched
    parse_fail = 0              # lines where parser matched but parse() returned None
    failed_lines = []           # first 20 failed lines
    sample_events = {}          # parser_id -> first parsed event

    # Timing
    start = time.time()

    with open(args.file, "r", errors="replace") as f:
        for line_num, raw_line in enumerate(f, 1):
            if args.limit and line_num > args.limit:
                break

            line = raw_line.strip()
            if not line:
                empty_lines += 1
                continue

            total_lines += 1

            if args.strip_header:
                line = strip_syslog_header(line)

            # Detect parser
            matched = detect_format(line)

            if matched is None:
                no_match += 1
                if len(failed_lines) < 20:
                    failed_lines.append((line_num, "NO_MATCH", line[:120]))
                if args.verbose:
                    print(f"  [{line_num:>6}] NO MATCH  {line[:80]}")
                continue

            detect_counts[matched.PARSER_ID] += 1

            # Try parsing
            event = matched.parse(line)
            if event is None:
                parse_fail += 1
                if len(failed_lines) < 20:
                    failed_lines.append((line_num, f"{matched.PARSER_ID}:FAIL", line[:120]))
                if args.verbose:
                    print(f"  [{line_num:>6}] {matched.PARSER_ID} FAIL  {line[:80]}")
                continue

            parser_counts[matched.PARSER_ID] += 1

            # Collect sample
            if matched.PARSER_ID not in sample_events:
                sample_events[matched.PARSER_ID] = event

            if args.verbose:
                src = event.get("source_ip", "?")
                dst = event.get("destination_ip", "?")
                action = event.get("action", "?")
                print(f"  [{line_num:>6}] {matched.PARSER_ID:<12} {src} -> {dst} ({action})")

    elapsed = time.time() - start
    total_processed = total_lines
    total_parsed = sum(parser_counts.values())
    pct = f"{total_parsed / total_processed * 100:.1f}%" if total_processed > 0 else "N/A"
    rate = f"{total_processed / elapsed:.0f}" if elapsed > 0 else "N/A"

    # ── Report ───────────────────────────────────────────────────────────────
    print()
    print("=" * 64)
    print("  Parser Test Results")
    print("=" * 64)
    print(f"  File:              {args.file}")
    print(f"  Total lines:       {total_lines + empty_lines} ({empty_lines} empty, skipped)")
    print(f"  Processed:         {total_processed}")
    print(f"  Successfully parsed: {total_parsed}  ({pct})")
    print(f"  No parser matched: {no_match}")
    print(f"  Parser matched but failed: {parse_fail}")
    print(f"  Time:              {elapsed:.2f}s ({rate} lines/sec)")
    print()

    # Per-parser breakdown
    print("  Parser breakdown:")
    print(f"    {'Parser':<16} {'Detected':>10} {'Parsed OK':>12} {'Failed':>10}")
    print(f"    {'-'*16} {'-'*10} {'-'*12} {'-'*10}")
    all_parser_ids = sorted(set(list(detect_counts.keys()) + list(parser_counts.keys())))
    for pid in all_parser_ids:
        detected = detect_counts.get(pid, 0)
        parsed = parser_counts.get(pid, 0)
        failed = detected - parsed
        print(f"    {pid:<16} {detected:>10} {parsed:>12} {failed:>10}")
    if no_match:
        print(f"    {'(no match)':<16} {no_match:>10} {'—':>12} {'—':>10}")
    print()

    # Failed lines
    if failed_lines:
        print(f"  Failed lines (first {len(failed_lines)}):")
        for ln, reason, text in failed_lines:
            print(f"    line {ln:<6} [{reason}]  {text}")
        print()

    # Sample events
    if sample_events:
        for pid, event in sample_events.items():
            print(f"  Sample event ({pid}):")
            display = {}
            for k, v in event.items():
                if isinstance(v, datetime):
                    display[k] = v.isoformat()
                elif v is not None:
                    display[k] = v
            print(json.dumps(display, indent=4))
            print()

    if total_processed == 0:
        print("  No non-empty lines found in file.")
        sys.exit(1)

    # Exit code: 0 if any lines parsed, 1 if none parsed
    sys.exit(0 if total_parsed > 0 else 1)


if __name__ == "__main__":
    main()
