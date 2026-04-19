# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Hypothesis status helpers."""

from __future__ import annotations

from typing import Any

from gnat.analysis.investigations.models import HypothesisStatus


def status_of(h: Any) -> HypothesisStatus:
    """Return the current HypothesisStatus."""
    return getattr(h, "status", HypothesisStatus.OPEN)


def is_open(h: Any) -> bool:
    """True if hypothesis status is OPEN."""
    return status_of(h) == HypothesisStatus.OPEN


def is_supported(h: Any) -> bool:
    """True if hypothesis status is SUPPORTED."""
    return status_of(h) == HypothesisStatus.SUPPORTED


def is_refuted(h: Any) -> bool:
    """True if hypothesis status is REFUTED."""
    return status_of(h) == HypothesisStatus.REFUTED


def is_inconclusive(h: Any) -> bool:
    """True if hypothesis status is INCONCLUSIVE."""
    return status_of(h) == HypothesisStatus.INCONCLUSIVE
