"""
Tshark extraction validation profiles.

Three built-in profiles control how strictly the normalizer validates packet
extraction quality before running analysis:

  strict     – Production deployments with a known-good tshark version.
               Fails fast on any hint of extraction problems.
  balanced   – Default.  Tolerates minor non-IP-traffic variation while
               still catching clear extraction failures.
  permissive – Legacy tshark builds or unusual link-layer captures with
               many non-IP packets that naturally have sparse fields.

Active profile is set via the TSHARK_VALIDATION_PROFILE environment variable
(default: "balanced") or passed directly to normalize().
"""
from __future__ import annotations

import dataclasses
import os
from typing import Dict


@dataclasses.dataclass(frozen=True)
class ValidationProfile:
    """
    Thresholds for deciding whether tshark field extraction is reliable enough
    to proceed with analysis.

    Attributes:
        name:
            Profile identifier used in log messages and diagnostics.
        max_malformed_rate:
            Maximum fraction (0–1) of non-empty output lines allowed to have
            fewer than 4 tab-separated fields.  Lines below this threshold are
            counted as "malformed" — caused by a broken field separator or
            tshark error text bleeding into stdout.  Exceeding this rate means
            the extraction is unreliable and analysis is aborted.
        min_essential_rate:
            Minimum fraction (0–1) of parsed packet rows that must contain
            'frame.number'.  This field is present in every packet tshark
            reads; its absence indicates a broken field-to-column mapping.
    """
    name: str
    max_malformed_rate: float
    min_essential_rate: float


PROFILES: Dict[str, ValidationProfile] = {
    # Strict: reject if >5% of lines are malformed or <95% have frame.number.
    "strict": ValidationProfile(
        name="strict",
        max_malformed_rate=0.05,
        min_essential_rate=0.95,
    ),
    # Balanced: tolerate up to 30% malformed lines (large non-IP captures have
    # many 2–3 field rows for ARP/STP frames) while still catching total failures.
    "balanced": ValidationProfile(
        name="balanced",
        max_malformed_rate=0.30,
        min_essential_rate=0.70,
    ),
    # Permissive: only abort on total extraction failure.
    "permissive": ValidationProfile(
        name="permissive",
        max_malformed_rate=0.70,
        min_essential_rate=0.50,
    ),
}

_DEFAULT = "balanced"


def get_profile(name: str | None = None) -> ValidationProfile:
    """
    Return a ValidationProfile by name.

    Resolution order:
      1. ``name`` argument (if provided)
      2. ``TSHARK_VALIDATION_PROFILE`` environment variable
      3. Built-in default ("balanced")

    Raises ValueError for unknown profile names.
    """
    key = (
        name
        or os.environ.get("TSHARK_VALIDATION_PROFILE")
        or _DEFAULT
    ).lower().strip()
    if key not in PROFILES:
        raise ValueError(
            f"Unknown validation profile {key!r}. "
            f"Valid options: {', '.join(sorted(PROFILES))}"
        )
    return PROFILES[key]
