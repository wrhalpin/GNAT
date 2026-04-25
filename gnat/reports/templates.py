# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reports.templates
=======================

Template-driven report section definitions.

Replaces hard-coded ``if report_type == "daily"`` chains in
:class:`~gnat.reports.generator.ReportGenerator` with a registry-based
approach where each report type declares its sections, their data sources,
and optional visibility conditions.

Usage::

    from gnat.reports.templates import TemplateRegistry, ReportTemplate, SectionSpec

    # Register a custom template
    TemplateRegistry.register("weekly-summary", ReportTemplate(
        name="weekly-summary",
        sections=[
            SectionSpec("exec_summary",  title="Executive Summary",  aggregator_field="top_threats"),
            SectionSpec("ioc_table",     title="IOC Volume",         aggregator_field="ioc_counts",
                        condition_expr="agg.total_objects > 0"),
            SectionSpec("malware",       title="Malware Families",   aggregator_field="malware_families",
                        condition_expr="agg.malware_count > 0"),
        ],
    ))

    tpl = TemplateRegistry.get("weekly-summary")
    visible = [s for s in tpl.sections if tpl.evaluate_condition(s, aggregates)]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SectionSpec:
    """
    Specification for a single report section.

    Parameters
    ----------
    id : str
        Unique section identifier within the template.
    title : str
        Human-readable section heading.
    aggregator_field : str
        Name of the :class:`~gnat.reports.aggregator.ReportAggregates` field
        that provides data for this section.  Empty string means no data binding.
    renderer_fn : str
        Name of the renderer function in ``_RENDERERS`` dict of
        :class:`~gnat.reports.generator.ReportGenerator`.  Defaults to
        ``aggregator_field`` when empty.
    condition_expr : str
        Simple Python expression string evaluated against ``agg``
        (a :class:`~gnat.reports.aggregator.ReportAggregates` instance).
        The section is skipped when the expression evaluates to ``False``.
        Empty string means always include.
    order : int
        Sort order within the report (lower = earlier).
    """

    id: str
    title: str = ""
    aggregator_field: str = ""
    renderer_fn: str = ""
    condition_expr: str = ""
    order: int = 0

    def __post_init__(self) -> None:
        if not self.renderer_fn:
            self.renderer_fn = self.aggregator_field


@dataclass
class ReportTemplate:
    """
    A named report template consisting of ordered :class:`SectionSpec` objects.

    Parameters
    ----------
    name : str
        Template name; matches ``ReportConfig.report_type``.
    sections : list[SectionSpec]
        Ordered list of sections.  Sorted by ``SectionSpec.order`` when iterating.
    metadata : dict
        Arbitrary metadata (author, version, description).
    """

    name: str
    sections: list[SectionSpec] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def sorted_sections(self) -> list[SectionSpec]:
        """Return sections ordered by ``SectionSpec.order``."""
        return sorted(self.sections, key=lambda s: s.order)

    def evaluate_condition(
        self,
        section: SectionSpec,
        aggregates: Any,
    ) -> bool:
        """
        Evaluate the section's ``condition_expr`` against *aggregates*.

        Parameters
        ----------
        section : SectionSpec
        aggregates : ReportAggregates

        Returns
        -------
        bool
            ``True`` when the section should be included.
        """
        if not section.condition_expr:
            return True
        try:
            return bool(eval(section.condition_expr, {"agg": aggregates}))  # nosec B307
        except Exception as exc:
            logger.warning(
                "ReportTemplate %r: condition_expr %r raised %s — including section",
                self.name,
                section.condition_expr,
                exc,
            )
            return True


class TemplateRegistry:
    """
    Registry of named :class:`ReportTemplate` objects.

    Provides a class-level mapping from template name → template.
    The ``daily``, ``weekly``, ``incident``, and ``executive`` templates
    are pre-registered with sensible defaults.

    Examples
    --------
    ::

        tpl = TemplateRegistry.get("daily")
        for section in tpl.sorted_sections():
            print(section.id, section.title)
    """

    _registry: dict[str, ReportTemplate] = {}

    @classmethod
    def register(cls, name: str, template: ReportTemplate) -> None:
        """Register a :class:`ReportTemplate` by name."""
        cls._registry[name] = template
        logger.debug("TemplateRegistry.register: %r", name)

    @classmethod
    def get(cls, name: str) -> ReportTemplate | None:
        """
        Retrieve a template by name.

        Returns ``None`` when the name is not found.
        """
        return cls._registry.get(name)

    @classmethod
    def get_or_default(cls, name: str) -> ReportTemplate:
        """
        Retrieve a template by name, falling back to ``"daily"`` when absent.
        """
        tpl = cls._registry.get(name)
        if tpl is None:
            tpl = cls._registry.get("daily")
        if tpl is None:
            # Emergency fallback: empty template
            tpl = ReportTemplate(name=name, sections=[])
        return tpl

    @classmethod
    def list_names(cls) -> list[str]:
        """Return all registered template names."""
        return list(cls._registry.keys())


# ── Built-in template definitions ────────────────────────────────────────────

_DAILY_SECTIONS = [
    SectionSpec("exec_summary", "Executive Summary", "top_threats", order=1),
    SectionSpec("ioc_volume", "IOC Volume Trends", "ioc_counts", order=2),
    SectionSpec(
        "indicators",
        "New Indicators",
        "indicators",
        condition_expr="len(getattr(agg, 'indicators', [])) > 0",
        order=3,
    ),
    SectionSpec(
        "malware",
        "Malware Families",
        "malware_families",
        condition_expr="getattr(agg, 'malware_count', 0) > 0",
        order=4,
    ),
    SectionSpec(
        "threat_actors",
        "Threat Actor Activity",
        "threat_actors",
        condition_expr="getattr(agg, 'actor_count', 0) > 0",
        order=5,
    ),
    SectionSpec(
        "gaps",
        "Analytical Gaps",
        "gaps",
        condition_expr="len(getattr(agg, 'gaps', [])) > 0",
        order=6,
    ),
    SectionSpec("recommendations", "Recommendations", "recommendations", order=7),
]

_WEEKLY_SECTIONS = [
    SectionSpec("exec_summary", "Weekly Executive Summary", "top_threats", order=1),
    SectionSpec("ioc_volume", "IOC Volume (7-day)", "ioc_counts", order=2),
    SectionSpec("sector_threats", "Sector-Specific Threats", "sector_breakdown", order=3),
    SectionSpec(
        "malware",
        "Malware Families",
        "malware_families",
        condition_expr="getattr(agg, 'malware_count', 0) > 0",
        order=4,
    ),
    SectionSpec(
        "campaigns",
        "Active Campaigns",
        "campaigns",
        condition_expr="getattr(agg, 'campaign_count', 0) > 0",
        order=5,
    ),
    SectionSpec(
        "vulnerabilities",
        "Key Vulnerabilities",
        "vulnerabilities",
        condition_expr="getattr(agg, 'vuln_count', 0) > 0",
        order=6,
    ),
    SectionSpec(
        "gaps",
        "Analytical Gaps",
        "gaps",
        condition_expr="len(getattr(agg, 'gaps', [])) > 0",
        order=7,
    ),
    SectionSpec("recommendations", "Recommendations", "recommendations", order=8),
]

_INCIDENT_SECTIONS = [
    SectionSpec("incident_summary", "Incident Summary", "top_threats", order=1),
    SectionSpec("iocs", "Indicators of Compromise", "indicators", order=2),
    SectionSpec(
        "attack_patterns",
        "Attack Patterns",
        "attack_patterns",
        condition_expr="getattr(agg, 'attack_pattern_count', 0) > 0",
        order=3,
    ),
    SectionSpec(
        "malware",
        "Malware Involved",
        "malware_families",
        condition_expr="getattr(agg, 'malware_count', 0) > 0",
        order=4,
    ),
    SectionSpec("timeline", "Event Timeline", "timeline_events", order=5),
    SectionSpec("containment", "Containment Actions", "recommendations", order=6),
]

_EXECUTIVE_SECTIONS = [
    SectionSpec("exec_summary", "Executive Summary", "top_threats", order=1),
    SectionSpec("risk_posture", "Current Risk Posture", "sector_breakdown", order=2),
    SectionSpec(
        "top_threats",
        "Top Threat Actors",
        "threat_actors",
        condition_expr="getattr(agg, 'actor_count', 0) > 0",
        order=3,
    ),
    SectionSpec("metrics", "Key Metrics", "ioc_counts", order=4),
    SectionSpec("recommendations", "Strategic Recommendations", "recommendations", order=5),
]

# Register built-in templates
TemplateRegistry.register(
    "daily",
    ReportTemplate("daily", _DAILY_SECTIONS, {"description": "Daily threat intelligence brief"}),
)
TemplateRegistry.register(
    "weekly",
    ReportTemplate(
        "weekly", _WEEKLY_SECTIONS, {"description": "Weekly threat intelligence summary"}
    ),
)
TemplateRegistry.register(
    "incident",
    ReportTemplate(
        "incident", _INCIDENT_SECTIONS, {"description": "Incident-specific investigation report"}
    ),
)
TemplateRegistry.register(
    "executive",
    ReportTemplate(
        "executive", _EXECUTIVE_SECTIONS, {"description": "Executive-level threat brief"}
    ),
)

_CROSS_TOOL_SECTIONS = [
    SectionSpec("investigation_header", "Investigation Overview", "investigation_header", order=1),
    SectionSpec("timeline", "Timeline", "timeline_events", order=2),
    SectionSpec("gnat_findings", "GNAT / Core Findings", "gnat_findings", order=3),
    SectionSpec(
        "sandgnat_findings",
        "SandGNAT Findings",
        "sandgnat_findings",
        condition_expr="getattr(agg, 'sandgnat_count', 0) > 0",
        order=4,
    ),
    SectionSpec(
        "sensegnat_findings",
        "SenseGNAT Findings",
        "sensegnat_findings",
        condition_expr="getattr(agg, 'sensegnat_count', 0) > 0",
        order=5,
    ),
    SectionSpec(
        "redgnat_findings",
        "RedGNAT Findings",
        "redgnat_findings",
        condition_expr="getattr(agg, 'redgnat_count', 0) > 0",
        order=6,
    ),
    SectionSpec("confidence_summary", "Confidence and Attribution", "confidence_summary", order=7),
    SectionSpec("recommendations", "Recommendations", "recommendations", order=8),
    SectionSpec("stix_appendix", "Appendix: STIX References", "stix_refs", order=9),
]
TemplateRegistry.register(
    "cross_tool_investigation",
    ReportTemplate(
        "cross_tool_investigation",
        _CROSS_TOOL_SECTIONS,
        {"description": "Cross-tool investigation report grouped by addon origin"},
    ),
)
