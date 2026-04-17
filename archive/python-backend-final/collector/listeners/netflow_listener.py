"""
NetFlow v9 / IPFIX (v10) UDP listener for the live ingestion layer.

Receives NetFlow/IPFIX datagrams, parses headers + template/data
FlowSets, decodes flow records, and feeds them into the Pipeline via
``process_flow()``.

Architecture
------------

  ┌──────────────────────────┐
  │  UDP socket on :2055     │
  └────────────┬─────────────┘
               │  raw datagram
               ▼
  ┌──────────────────────────┐
  │  parse_packet()          │  header → version dispatch
  │    ├─ _parse_v9()        │  template + data FlowSets
  │    └─ _parse_ipfix()     │
  └────────────┬─────────────┘
               │  list of flow dicts
               ▼
  ┌──────────────────────────┐
  │  Pipeline.process_flow() │  normalise → buffer
  └──────────────────────────┘

Template caching
~~~~~~~~~~~~~~~~

NetFlow v9 and IPFIX use a template-based encoding.  Each exporter
periodically sends template FlowSets that describe the field layout
of subsequent data FlowSets.  Templates are cached in-process per
``(source_id, template_id)`` so data FlowSets received before their
template has arrived are silently dropped.

Thread safety
~~~~~~~~~~~~~

The listener runs a single UDP recv loop in one daemon thread.  The
template cache is protected by a ``threading.Lock``.
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from collector.pipeline import Pipeline

logger = logging.getLogger("collector.netflow")

# Defaults
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 2055
DEFAULT_RECV_SIZE = 65535

# ── NetFlow / IPFIX field type IDs we care about ─────────────────────────────

FIELD_IPV4_SRC_ADDR   = 8
FIELD_IPV4_DST_ADDR   = 12
FIELD_L4_SRC_PORT     = 7
FIELD_L4_DST_PORT     = 11
FIELD_PROTOCOL        = 4
FIELD_IN_BYTES        = 1
FIELD_IN_PKTS         = 2
FIELD_OUT_BYTES       = 23
FIELD_OUT_PKTS        = 24
FIELD_FIRST_SWITCHED  = 22
FIELD_LAST_SWITCHED   = 21
FIELD_FLOW_START_MS   = 152
FIELD_FLOW_END_MS     = 153

_PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6"}

# Field type → (normalised key, decoder)
# Decoder is a callable(bytes) → python value.
_FIELD_DECODERS: Dict[int, Tuple[str, Callable]] = {
    FIELD_IPV4_SRC_ADDR:  ("source_ip",        lambda b: socket.inet_ntoa(b)),
    FIELD_IPV4_DST_ADDR:  ("destination_ip",    lambda b: socket.inet_ntoa(b)),
    FIELD_L4_SRC_PORT:    ("source_port",       lambda b: int.from_bytes(b, "big")),
    FIELD_L4_DST_PORT:    ("destination_port",  lambda b: int.from_bytes(b, "big")),
    FIELD_PROTOCOL:       ("_protocol_num",     lambda b: int.from_bytes(b, "big")),
    FIELD_IN_BYTES:       ("bytes_in",          lambda b: int.from_bytes(b, "big")),
    FIELD_IN_PKTS:        ("packets_in",        lambda b: int.from_bytes(b, "big")),
    FIELD_OUT_BYTES:      ("bytes_out",         lambda b: int.from_bytes(b, "big")),
    FIELD_OUT_PKTS:       ("packets_out",       lambda b: int.from_bytes(b, "big")),
    FIELD_FIRST_SWITCHED: ("_first_switched",   lambda b: int.from_bytes(b, "big")),
    FIELD_LAST_SWITCHED:  ("_last_switched",    lambda b: int.from_bytes(b, "big")),
    FIELD_FLOW_START_MS:  ("_flow_start_ms",    lambda b: int.from_bytes(b, "big")),
    FIELD_FLOW_END_MS:    ("_flow_end_ms",      lambda b: int.from_bytes(b, "big")),
}


# ── Template cache ───────────────────────────────────────────────────────────

class TemplateCache:
    """Thread-safe cache of NetFlow v9 / IPFIX templates.

    Key: ``(source_id, template_id)``
    Value: list of ``(field_type, field_length)`` tuples.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._store: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}

    def put(self, source_id: int, template_id: int, fields: List[Tuple[int, int]]):
        with self._lock:
            self._store[(source_id, template_id)] = fields

    def get(self, source_id: int, template_id: int) -> Optional[List[Tuple[int, int]]]:
        with self._lock:
            return self._store.get((source_id, template_id))

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._store)


# ── Packet parsing ───────────────────────────────────────────────────────────

class ParsedHeader:
    __slots__ = ("version", "count", "uptime", "unix_secs",
                 "sequence", "source_id", "length", "export_time",
                 "observation_domain")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def parse_header(data: bytes) -> Optional[ParsedHeader]:
    """Parse the first 2 bytes to determine version, then the full header."""
    if len(data) < 4:
        return None
    version = struct.unpack("!H", data[0:2])[0]
    if version == 9:
        return _parse_v9_header(data)
    if version == 10:
        return _parse_ipfix_header(data)
    return None


def _parse_v9_header(data: bytes) -> Optional[ParsedHeader]:
    if len(data) < 20:
        return None
    (version, count, uptime, unix_secs,
     sequence, source_id) = struct.unpack("!HHIIII", data[0:20])
    return ParsedHeader(
        version=version, count=count, uptime=uptime,
        unix_secs=unix_secs, sequence=sequence, source_id=source_id,
        length=len(data), export_time=unix_secs, observation_domain=source_id,
    )


def _parse_ipfix_header(data: bytes) -> Optional[ParsedHeader]:
    if len(data) < 16:
        return None
    (version, length, export_time,
     sequence, observation_domain) = struct.unpack("!HHIII", data[0:16])
    return ParsedHeader(
        version=version, count=0, uptime=0,
        unix_secs=export_time, sequence=sequence,
        source_id=observation_domain, length=length,
        export_time=export_time, observation_domain=observation_domain,
    )


def parse_flowsets(
    data: bytes,
    header: ParsedHeader,
    cache: TemplateCache,
) -> List[Dict[str, Any]]:
    """Parse all FlowSets in a NetFlow v9 / IPFIX packet.

    Returns a list of decoded flow record dicts.
    """
    offset = 20 if header.version == 9 else 16
    flows: List[Dict[str, Any]] = []

    while offset + 4 <= len(data):
        fs_id, fs_len = struct.unpack("!HH", data[offset:offset + 4])
        if fs_len < 4:
            break  # malformed
        fs_data = data[offset + 4: offset + fs_len]

        if fs_id == 0:
            # Template FlowSet (v9)
            _parse_template_flowset(fs_data, header.source_id, cache)
        elif fs_id == 2:
            # IPFIX Template FlowSet
            _parse_template_flowset(fs_data, header.observation_domain, cache)
        elif fs_id > 255:
            # Data FlowSet
            decoded = _decode_data_flowset(
                fs_data, fs_id, header, cache,
            )
            flows.extend(decoded)
        # fs_id 1 = Options Template — skip for now

        offset += fs_len
        # Pad to 4-byte boundary
        pad = (4 - (fs_len % 4)) % 4
        offset += pad

    return flows


def _parse_template_flowset(
    data: bytes,
    source_id: int,
    cache: TemplateCache,
) -> None:
    """Parse one or more template records inside a Template FlowSet."""
    pos = 0
    while pos + 4 <= len(data):
        template_id, field_count = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        fields: List[Tuple[int, int]] = []
        for _ in range(field_count):
            if pos + 4 > len(data):
                return
            ftype, flen = struct.unpack("!HH", data[pos:pos + 4])
            # IPFIX enterprise bit — strip it (we ignore enterprise fields)
            ftype = ftype & 0x7FFF
            fields.append((ftype, flen))
            pos += 4
        cache.put(source_id, template_id, fields)


def _decode_data_flowset(
    data: bytes,
    template_id: int,
    header: ParsedHeader,
    cache: TemplateCache,
) -> List[Dict[str, Any]]:
    """Decode data records using a cached template."""
    src_id = header.source_id if header.version == 9 else header.observation_domain
    template = cache.get(src_id, template_id)
    if template is None:
        return []  # template not yet received — silently skip

    record_len = sum(flen for _, flen in template)
    if record_len == 0:
        return []

    flows: List[Dict[str, Any]] = []
    pos = 0
    while pos + record_len <= len(data):
        raw: Dict[str, Any] = {}
        fpos = pos
        for ftype, flen in template:
            field_bytes = data[fpos:fpos + flen]
            decoder = _FIELD_DECODERS.get(ftype)
            if decoder is not None:
                key, fn = decoder
                try:
                    raw[key] = fn(field_bytes)
                except Exception:
                    pass
            fpos += flen

        flow = _build_flow_dict(raw, header)
        if flow:
            flows.append(flow)
        pos += record_len

    return flows


def _build_flow_dict(
    raw: Dict[str, Any],
    header: ParsedHeader,
) -> Optional[Dict[str, Any]]:
    """Convert decoded fields into a normalised flow dict."""
    src = raw.get("source_ip")
    dst = raw.get("destination_ip")
    if not src or not dst:
        return None

    # Protocol number → name
    proto_num = raw.get("_protocol_num")
    protocol = _PROTO_MAP.get(proto_num, str(proto_num) if proto_num is not None else None)

    # Event time: prefer IPFIX millisecond timestamps, fall back to header
    flow_start_ms = raw.get("_flow_start_ms")
    if flow_start_ms and flow_start_ms > 0:
        event_time = datetime.fromtimestamp(flow_start_ms / 1000.0, tz=timezone.utc).replace(tzinfo=None)
    else:
        event_time = datetime.utcfromtimestamp(header.unix_secs) if header.unix_secs else None

    # Duration from switched times or IPFIX ms timestamps
    duration_ms = None
    first_sw = raw.get("_first_switched")
    last_sw = raw.get("_last_switched")
    flow_end_ms = raw.get("_flow_end_ms")
    if flow_start_ms and flow_end_ms and flow_end_ms >= flow_start_ms:
        duration_ms = flow_end_ms - flow_start_ms
    elif first_sw is not None and last_sw is not None and last_sw >= first_sw:
        duration_ms = last_sw - first_sw  # uptime-based ms delta

    parser_id = "ipfix" if header.version == 10 else "netflow_v9"

    return {
        "event_time":       event_time,
        "source_ip":        src,
        "destination_ip":   dst,
        "source_port":      raw.get("source_port"),
        "destination_port": raw.get("destination_port"),
        "protocol":         protocol,
        "action":           "allow",  # NetFlow only exports forwarded flows
        "bytes_in":         raw.get("bytes_in"),
        "bytes_out":        raw.get("bytes_out"),
        "packets_in":       raw.get("packets_in"),
        "packets_out":      raw.get("packets_out"),
        "duration_ms":      duration_ms,
        "_parser_id":       parser_id,
    }


# ── NetFlow listener ─────────────────────────────────────────────────────────

class NetflowListener:
    """UDP listener for NetFlow v9 / IPFIX packets.

    Parameters
    ----------
    pipeline : Pipeline
        Shared pipeline (``process_flow`` is called for each decoded record).
    listener_ref : optional
        The parent SyslogListener for shared flush/buffer (or None if
        standalone).  When set, decoded flows are buffered on the
        syslog listener's pipeline and flushed by its timer.
    host / port : bind address (default 0.0.0.0:2055).
    """

    def __init__(
        self,
        pipeline: Pipeline,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
    ):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.cache = TemplateCache()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._running = False

        # Stats
        self._lock = threading.Lock()
        self._packets_received = 0
        self._flows_decoded = 0

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self.host, self.port))
        self._thread = threading.Thread(
            target=self._recv_loop,
            name="netflow-udp",
            daemon=True,
        )
        self._thread.start()
        logger.info("NetFlow listener started on %s:%d", self.host, self.port)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        logger.info("NetFlow listener stopped")

    @property
    def running(self) -> bool:
        return self._running

    @property
    def packets_received(self) -> int:
        return self._packets_received

    @property
    def flows_decoded(self) -> int:
        return self._flows_decoded

    @property
    def templates_known(self) -> int:
        return self.cache.count

    def _recv_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(DEFAULT_RECV_SIZE)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.exception("NetFlow recv error")
                break

            with self._lock:
                self._packets_received += 1

            header = parse_header(data)
            if header is None:
                continue

            flows = parse_flowsets(data, header, self.cache)
            for flow in flows:
                parser_id = flow.pop("_parser_id", "netflow_v9")
                event = self.pipeline.process_flow(flow, parser_id=parser_id)
                if event is not None:
                    self.pipeline.buffer(event)

            with self._lock:
                self._flows_decoded += len(flows)
