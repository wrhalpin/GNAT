# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reports.templates.cross_tool_investigation
==================================================

Report template for cross-tool investigations.

Pulls evidence from an investigation and groups findings by origin tool
(SandGNAT, SenseGNAT, RedGNAT, GNAT, external) so analysts get a unified
view of all addon contributions.

Usage::

    from gnat.reports.templates.cross_tool_investigation import (
        CrossToolInvestigationTemplate,
    )

    template = CrossToolInvestigationTemplate()
    sections = template.render(
        investigation_id="IC-2026-0001",
        service=investigation_service,
        graph=evidence_graph,
    )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

ORIGIN_LABELS = {
    "sandgnat": "SandGNAT Findings",
    "sensegnat": "SenseGNAT Findings",
    "redgnat": "RedGNAT Findings",
    "gnat": "GNAT / Core Findings",
    "external": "External Sources",
}

ORIGIN_ORDER = ["gnat", "sandgnat", "sensegnat", "redgnat", "external"]


@dataclass
class ReportSection:
    """A rendered section of the cross-tool investigation report."""

    title: str
    order: int
    content: dict[str, Any] = field(default_factory=dict)


class CrossToolInvestigationTemplate:
    """
    Template that renders an investigation report grouped by origin tool.

    Sections
    --------
    1. Investigation header (title, status, hypotheses, analyst notes)
    2. Timeline (filtered by investigation_id)
    3. Per-origin evidence sections
    4. Confidence and attribution summary
    5. Recommendations
    6. Appendix: raw STIX references
    """

    name = "cross_tool_investigation"

    def render(
        self,
        investigation_id: str,
        service: Any,
        graph: Any | None = None,
        timeline_builder: Any | None = None,
        drafting_assistant: Any | None = None,
    ) -> list[ReportSection]:
        """
        Render all report sections for the given investigation.

        Parameters
        ----------
        investigation_id : str
            Target investigation.
        service : InvestigationService
            Service to fetch investigation data.
        graph : EvidenceGraph, optional
            Evidence graph for the investigation.
        timeline_builder : TimelineBuilder, optional
            Timeline builder instance.
        drafting_assistant : ReportDraftingAssistant, optional
            AI drafting assistant (respects confidence ceiling).

        Returns
        -------
        list of ReportSection
        """
        sections: list[ReportSection] = []

        inv = service.get(investigation_id)

        sections.append(self._header_section(inv))
        sections.append(self._timeline_section(inv, timeline_builder))

        origin_sections = self._origin_sections(inv, graph)
        sections.extend(origin_sections)

        sections.append(self._confidence_section(inv))
        sections.append(self._recommendations_section(inv, drafting_assistant))
        sections.append(self._appendix_section(inv, graph))

        return sections

    def _header_section(self, inv: Any) -> ReportSection:
        hypotheses = []
        for hyp in getattr(inv, "hypothesis", []):
            hypotheses.append({
                "id": hyp.id,
                "statement": hyp.statement,
                "status": hyp.status.value if hasattr(hyp.status, "value") else str(hyp.status),
            })

        notes = []
        for note in getattr(inv, "notes", []):
            notes.append({
                "id": note.id,
                "content": note.content,
                "author": note.author,
                "created_at": note.created_at.isoformat() if hasattr(note.created_at, "isoformat") else str(note.created_at),
            })

        return ReportSection(
            title="Investigation Overview",
            order=10,
            content={
                "investigation_id": inv.id,
                "title": inv.title,
                "status": inv.status.value if hasattr(inv.status, "value") else str(inv.status),
                "description": inv.description,
                "created_by": inv.created_by,
                "hypotheses": hypotheses,
                "notes": notes,
            },
        )

    def _timeline_section(
        self, inv: Any, timeline_builder: Any | None
    ) -> ReportSection:
        timeline_events: list[dict[str, Any]] = []
        if timeline_builder is not None:
            try:
                events = timeline_builder.build(investigation_id=inv.id)
                for evt in events:
                    timeline_events.append(
                        evt.to_dict() if hasattr(evt, "to_dict") else {"event": str(evt)}
                    )
            except Exception:
                logger.warning("Timeline build failed for %s", inv.id)

        return ReportSection(
            title="Timeline",
            order=20,
            content={"events": timeline_events},
        )

    def _origin_sections(
        self, inv: Any, graph: Any | None
    ) -> list[ReportSection]:
        grouped: dict[str, list[dict[str, Any]]] = {o: [] for o in ORIGIN_ORDER}

        if graph is not None:
            for node in graph.nodes.values():
                origin = getattr(node, "origin", "gnat")
                if origin not in grouped:
                    grouped[origin] = []
                node_summary = {
                    "node_id": node.node_id,
                    "node_type": node.node_type.value
                    if hasattr(node.node_type, "value")
                    else str(node.node_type),
                    "platform": node.platform,
                    "ioc_values": node.ioc_values,
                    "investigation_link_type": getattr(node, "investigation_link_type", None),
                }
                if node.stix:
                    node_summary["stix_type"] = node.stix.get("type", "")
                    node_summary["stix_id"] = node.stix.get("id", "")
                grouped[origin].append(node_summary)

        sections: list[ReportSection] = []
        order = 30
        for origin in ORIGIN_ORDER:
            nodes = grouped.get(origin, [])
            if not nodes and origin not in ("gnat",):
                continue
            sections.append(
                ReportSection(
                    title=ORIGIN_LABELS.get(origin, origin),
                    order=order,
                    content={
                        "origin": origin,
                        "node_count": len(nodes),
                        "nodes": nodes,
                    },
                )
            )
            order += 10
        return sections

    def _confidence_section(self, inv: Any) -> ReportSection:
        return ReportSection(
            title="Confidence and Attribution Summary",
            order=80,
            content={
                "hypothesis_count": len(getattr(inv, "hypothesis", [])),
                "indicator_count": len(getattr(inv, "indicators", [])),
                "observable_count": len(getattr(inv, "observables", [])),
                "source_connectors": getattr(inv, "source_connectors", []),
            },
        )

    def _recommendations_section(
        self, inv: Any, drafting_assistant: Any | None
    ) -> ReportSection:
        recommendations: str = ""
        if drafting_assistant is not None:
            try:
                recommendations = drafting_assistant.draft_recommendations(
                    investigation_id=inv.id
                )
            except Exception:
                logger.warning("Drafting assistant failed for %s", inv.id)

        return ReportSection(
            title="Recommendations",
            order=90,
            content={"text": recommendations},
        )

    def _appendix_section(
        self, inv: Any, graph: Any | None
    ) -> ReportSection:
        stix_refs: list[str] = list(getattr(inv, "indicators", []))
        stix_refs.extend(getattr(inv, "observables", []))

        if graph is not None:
            for node in graph.nodes.values():
                stix_id = (node.stix or {}).get("id", "")
                if stix_id and stix_id not in stix_refs:
                    stix_refs.append(stix_id)

        return ReportSection(
            title="Appendix: STIX References",
            order=100,
            content={"stix_object_ids": stix_refs},
        )
