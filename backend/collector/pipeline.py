"""
Live event ingestion pipeline.

Receives raw syslog lines, auto-detects the format, parses them through
the matching vendor parser, normalises the output into a ``LiveEvent``
dict, and provides a batch writer that bulk-inserts into the database.

The pipeline is intentionally stateless between lines — each line is
processed independently.  The batch writer accumulates events in memory
and flushes when the buffer reaches ``BATCH_SIZE`` or ``FLUSH_INTERVAL``
seconds have elapsed, whichever comes first.

Usage from the syslog listener::

    from collector.pipeline import Pipeline

    pipe = Pipeline(source_id="fw01", device_role="perimeter")
    event = pipe.process_line(raw_line)   # returns dict or None
    if event:
        pipe.buffer(event)
    pipe.flush(db)   # bulk insert buffered events

Or from tests::

    event = pipe.process_line(line)
    assert event["action"] == "allow"
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from collector.parsers.base import detect_format


# Maximum raw_line length stored on the model (truncated for storage).
_RAW_LINE_MAX = 2000

# ── Normalised field whitelist ───────────────────────────────────────────────
# Only these keys are carried from the parser output to the final event dict.
# Anything else the parser emits is silently dropped so we don't accidentally
# store unbounded vendor-specific fields.
_NORMALISED_FIELDS = frozenset({
    "event_time",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "action",
    "reason",
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "duration_ms",
    "nat_source_ip",
    "nat_destination_ip",
    "nat_source_port",
    "nat_destination_port",
    "application",
    "service",
    "backend_ip",
    "backend_port",
    "response_time_ms",
    "health_status",
})


class Pipeline:
    """Stateless line processor + buffered batch writer.

    Parameters
    ----------
    source_id : str
        Device hostname or IP that sent the log (set once per listener
        connection, not per line).
    device_role : str
        Operational role of the source device (perimeter / internal / dmz).
        Defaults to "unknown".
    """

    def __init__(
        self,
        source_id: str = "unknown",
        device_role: str = "unknown",
    ):
        self.source_id = source_id
        self.device_role = device_role
        self._buffer: List[Dict[str, Any]] = []
        self._stats = {
            "received": 0,
            "parsed": 0,
            "dropped": 0,
        }

    # ── Public API ───────────────────────────────────────────────────────────

    def process_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse and normalise a single raw log line.

        Returns a normalised event dict ready for ``buffer()`` / DB
        insertion, or ``None`` if the line is unparseable.
        """
        self._stats["received"] += 1

        if not line or not line.strip():
            self._stats["dropped"] += 1
            return None

        # Strip syslog priority prefix if present: "<134>..." → "..."
        clean = _strip_syslog_priority(line)

        parser = detect_format(clean)
        if parser is None:
            self._stats["dropped"] += 1
            return None

        parsed = parser.parse(clean)
        if parsed is None:
            self._stats["dropped"] += 1
            return None

        event = self._normalise(parsed, parser, line)
        self._stats["parsed"] += 1
        return event

    def buffer(self, event: Dict[str, Any]) -> None:
        """Add a normalised event to the in-memory buffer."""
        self._buffer.append(event)

    def flush(self, db) -> int:
        """Bulk-insert all buffered events into the database.

        ``db`` is a SQLAlchemy ``Session``.  Returns the number of rows
        inserted.  Clears the buffer regardless of success so a transient
        DB error doesn't cause unbounded memory growth.
        """
        if not self._buffer:
            return 0

        from database import LiveEventModel

        events = self._buffer
        self._buffer = []

        rows = [LiveEventModel(**evt) for evt in events]
        db.bulk_save_objects(rows)
        db.commit()
        return len(rows)

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def reset_stats(self) -> None:
        self._stats = {"received": 0, "parsed": 0, "dropped": 0}

    # ── Internal ─────────────────────────────────────────────────────────────

    def _normalise(
        self,
        parsed: Dict[str, Any],
        parser,
        raw_line: str,
    ) -> Dict[str, Any]:
        """Build the final event dict from the parser output."""
        now = datetime.utcnow()

        event: Dict[str, Any] = {
            "source_id":   self.source_id,
            "device_type": parser.DEVICE_TYPE,
            "device_role": self.device_role,
            "parser_id":   parser.PARSER_ID,
            "received_at": now,
            "raw_line":    raw_line[:_RAW_LINE_MAX] if raw_line else None,
        }

        # Copy whitelisted fields from parser output
        for key in _NORMALISED_FIELDS:
            val = parsed.get(key)
            if val is not None:
                event[key] = val

        # Ensure event_time falls back to now if the parser couldn't extract it
        if not event.get("event_time"):
            event["event_time"] = now

        # Ensure required fields have a value
        event.setdefault("source_ip", "0.0.0.0")
        event.setdefault("destination_ip", "0.0.0.0")
        event.setdefault("action", "unknown")

        return event


def _strip_syslog_priority(line: str) -> str:
    """Remove the RFC 3164/5424 priority prefix ``<NNN>`` if present.

    Only strips when the content between ``<`` and ``>`` is numeric
    (1–3 digits) so that lines starting with XML-like tags are not
    accidentally mangled.
    """
    if line.startswith("<"):
        idx = line.find(">", 1, 6)
        if idx != -1 and line[1:idx].isdigit():
            return line[idx + 1:].lstrip()
    return line
