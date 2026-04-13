"""
Base parser interface and format auto-detection for the live ingestion layer.

Every vendor parser subclasses ``BaseParser`` and implements:

  - ``can_parse(line)``  — fast check (first ~200 chars) returning True if
    this parser can handle the line.
  - ``parse(line)``      — extract vendor-specific fields into a flat dict.
  - ``PARSER_ID``        — stable string identifier (stored on LiveEventModel).
  - ``DEVICE_TYPE``      — default device_type for events from this parser.

``detect_format(line, parsers)`` iterates the registered parsers and returns
the first one whose ``can_parse`` returns True, or falls back to the
``GenericKVParser`` if no specific parser matches.

The normalised dict returned by ``parse()`` is NOT a LiveEventModel yet —
the pipeline layer converts it.  The parse output should include at minimum:

    {
        "event_time":      datetime | str (ISO) | None,
        "source_ip":       str,
        "destination_ip":  str,
        "action":          str,
    }

All other fields are optional and will be carried through to the model when
present.
"""
from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional


class BaseParser(abc.ABC):
    """Abstract base for all live-event parsers."""

    # Subclasses MUST set these class attributes.
    PARSER_ID: str = ""          # e.g. "paloalto", "fortigate"
    DEVICE_TYPE: str = ""        # e.g. "firewall", "load_balancer"

    @abc.abstractmethod
    def can_parse(self, line: str) -> bool:
        """Return True if this parser can handle *line*.

        Implementations should be fast — inspect the first ~200 characters,
        check for a vendor-specific prefix or field pattern, and return.
        """
        ...

    @abc.abstractmethod
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """Extract fields from *line* into a flat dict.

        Return ``None`` if the line turns out to be unparseable after a
        deeper look (malformed, incomplete, irrelevant log type like a
        system/config log that doesn't describe a network event).

        The returned dict should use the normalised field names defined by
        the ``LiveEventModel`` schema.  Unknown vendor-specific fields can
        be silently dropped.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} parser_id={self.PARSER_ID!r}>"


# ── Registry + auto-detection ────────────────────────────────────────────────

# Parsers are registered in priority order: vendor-specific first, generic
# fallbacks last.  ``detect_format`` returns the first match.
_REGISTRY: List[BaseParser] = []


def register_parser(parser: BaseParser) -> None:
    """Add a parser instance to the global registry."""
    _REGISTRY.append(parser)


def get_registry() -> List[BaseParser]:
    """Return the current parser registry (for testing / introspection)."""
    return list(_REGISTRY)


def clear_registry() -> None:
    """Remove all parsers (used by tests)."""
    _REGISTRY.clear()


def detect_format(line: str) -> Optional[BaseParser]:
    """Return the first registered parser that can handle *line*, or None.

    The caller should treat None as "unparseable" and either drop the line
    or log it for review.  The generic KV parser (when registered) is
    intentionally permissive so None only happens when the line is truly
    empty or gibberish.
    """
    if not line or not line.strip():
        return None
    for parser in _REGISTRY:
        try:
            if parser.can_parse(line):
                return parser
        except Exception:
            # A parser bug must not crash the pipeline
            continue
    return None
