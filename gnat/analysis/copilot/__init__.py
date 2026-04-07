"""
gnat.analysis.copilot
======================

Analyst assistance tools — gap detection and LLM-backed report drafting.

Modules
-------
gap_detector
    :class:`~.gap_detector.GapDetector` — rule-based hypothesis gap detection.
    Surfaces missing evidence types for common analytical claims (lateral
    movement, exfiltration, attribution, etc.).  No LLM required.
drafting
    :class:`~.drafting.ReportDraftingAssistant` — LLM-backed executive summary
    and key-findings narrative drafting.  Integrates with
    :class:`~gnat.agents.llm.LLMClient`.

Quick start::

    from gnat.analysis.copilot import GapDetector, ReportDraftingAssistant

    detector = GapDetector()
    gaps     = detector.detect(hypothesis, investigation)
    for gap in gaps:
        print(f"[{gap.severity}] {gap.description}")
"""

from gnat.analysis.copilot.drafting import DraftResult, ReportDraftingAssistant
from gnat.analysis.copilot.gap_detector import (
    GapDetector,
    GapRecommendation,
    GapSeverity,
)

__all__ = [
    "GapDetector",
    "GapRecommendation",
    "GapSeverity",
    "ReportDraftingAssistant",
    "DraftResult",
]
