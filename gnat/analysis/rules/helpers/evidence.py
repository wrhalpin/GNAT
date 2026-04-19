# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Evidence count and ratio helpers."""

from __future__ import annotations

from typing import Any


def supporting_count(h: Any) -> int:
    """Number of supporting evidence items."""
    return len(getattr(h, "supporting_evidence", []) or [])


def refuting_count(h: Any) -> int:
    """Number of refuting evidence items."""
    return len(getattr(h, "refuting_evidence", []) or [])


def evidence_count(h: Any) -> int:
    """Total evidence items (supporting + refuting)."""
    return supporting_count(h) + refuting_count(h)


def has_refutation(h: Any) -> bool:
    """True if any refuting evidence exists."""
    return refuting_count(h) > 0


def support_ratio(h: Any) -> float:
    """Supporting / (total + 1). Smoothed to avoid division by zero."""
    total = evidence_count(h)
    return supporting_count(h) / (total + 1)
