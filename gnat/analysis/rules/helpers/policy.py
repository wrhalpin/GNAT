# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""AI confidence ceiling policy helper."""

from __future__ import annotations

from typing import Any

from gnat.analysis.rules.helpers.confidence import stix_confidence
from gnat.analysis.rules.helpers.source import ai_only


def within_ai_ceiling(h: Any, ctx: Any) -> bool:
    """True if NOT ai-only, OR ai-only AND confidence <= ceiling."""
    if not ai_only(h, ctx):
        return True
    ceiling = getattr(ctx.policy, "ai_confidence_ceiling", 60)
    return stix_confidence(h) <= ceiling
