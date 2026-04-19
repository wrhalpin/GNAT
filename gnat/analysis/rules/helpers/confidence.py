# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Confidence, reliability, and credibility helpers."""

from __future__ import annotations

from typing import Any

_RELIABILITY_ORDER = ["F", "E", "D", "C", "B", "A"]


def has_confidence(h: Any) -> bool:
    """True if the hypothesis has a ConfidenceScore assigned."""
    return getattr(h, "confidence", None) is not None


def stix_confidence(h: Any) -> int:
    """STIX confidence (0-100), or 0 if no confidence set."""
    conf = getattr(h, "confidence", None)
    if conf is None:
        return 0
    return getattr(conf, "stix_confidence", 0)


def confidence_band(h: Any) -> str | None:
    """Return the confidence level band (HIGH/MEDIUM/LOW) or None."""
    conf = getattr(h, "confidence", None)
    if conf is None:
        return None
    band = getattr(conf, "band", None)
    if band is None:
        return None
    return band.value if hasattr(band, "value") else str(band)


def reliability_of(h: Any) -> str | None:
    """Source reliability letter (A-F) or None."""
    conf = getattr(h, "confidence", None)
    if conf is None:
        return None
    sr = getattr(conf, "source_reliability", None)
    if sr is None:
        return None
    return sr.value if hasattr(sr, "value") else str(sr)


def credibility_of(h: Any) -> int | None:
    """Information credibility (1-6) or None."""
    conf = getattr(h, "confidence", None)
    if conf is None:
        return None
    ic = getattr(conf, "information_credibility", None)
    if ic is None:
        return None
    return ic.value if hasattr(ic, "value") else int(ic)


def reliability_at_least(h: Any, level: str) -> bool:
    """True if reliability meets or exceeds the given level."""
    actual = reliability_of(h)
    if actual is None:
        return False
    try:
        return _RELIABILITY_ORDER.index(actual) >= _RELIABILITY_ORDER.index(level)
    except ValueError:
        return False


def credibility_at_least(h: Any, level: int) -> bool:
    """True if credibility meets or exceeds the given level (lower is better)."""
    actual = credibility_of(h)
    if actual is None:
        return False
    return actual <= level
