# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Unit tests for the cross-tool investigation report template.

Verifies that :class:`CrossToolInvestigationTemplate` correctly renders
sections grouped by origin, handles multiple origins, and degrades
gracefully when some origins have no data.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

from gnat.investigations.model import EvidenceGraph, EvidenceNode, NodeType, Seed, SeedType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ALL_ORIGINS = ("gnat", "sandgnat", "sensegnat", "redgnat")


def _make_node(
    platform: str = "xsoar",
    origin: str = "gnat",
    node_type: NodeType = NodeType.INCIDENT,
    investigation_id: str | None = None,
) -> EvidenceNode:
    """Build a minimal EvidenceNode for test fixtures."""
    src_id = str(uuid.uuid4())[:8]
    node_id = f"{platform}::{node_type.value}::{src_id}"
    return EvidenceNode(
        node_id=node_id,
        node_type=node_type,
        platform=platform,
        source_id=src_id,
        stix={
            "type": "observed-data",
            "id": f"observed-data--{src_id}",
            "name": f"Test node from {origin}",
            "created": "2026-04-20T12:00:00Z",
            "modified": "2026-04-20T14:00:00Z",
        },
        raw={"id": src_id, "name": f"Raw from {origin}"},
        origin=origin,
        investigation_id=investigation_id or f"investigation--{uuid.uuid4()}",
        investigation_origin=origin,
        investigation_link_type="confirmed",
    )


def _make_evidence_graph(
    origins: tuple[str, ...] = ALL_ORIGINS,
    nodes_per_origin: int = 2,
    investigation_id: str | None = None,
) -> EvidenceGraph:
    """Build an EvidenceGraph with nodes distributed across origins."""
    inv_id = investigation_id or f"investigation--{uuid.uuid4()}"
    graph = EvidenceGraph(
        title="Cross-tool investigation test",
        seeds=[Seed("10.0.0.1", SeedType.IP)],
    )
    for origin in origins:
        for i in range(nodes_per_origin):
            node = _make_node(
                platform="xsoar" if i % 2 == 0 else "greymatter",
                origin=origin,
                node_type=NodeType.INCIDENT if i % 2 == 0 else NodeType.OBSERVABLE,
                investigation_id=inv_id,
            )
            graph.nodes[node.node_id] = node
    return graph


def _mock_service(investigation_id: str | None = None) -> MagicMock:
    """Mock InvestigationService that returns a basic investigation."""
    svc = MagicMock()
    inv = MagicMock()
    inv.id = investigation_id or f"investigation--{uuid.uuid4()}"
    inv.title = "Cross-tool investigation"
    inv.status = MagicMock(value="in_progress")
    inv.tags = ["apt28", "ransomware"]
    inv.created_by = "analyst@example.com"
    inv.created_at = MagicMock(isoformat=lambda: "2026-04-20T12:00:00+00:00")
    inv.source_connectors = ["xsoar", "greymatter"]
    inv.hypothesis = []
    inv.indicators = []
    inv.observables = []
    svc.get.return_value = inv
    svc.summary.return_value = {
        "id": inv.id,
        "title": inv.title,
        "status": "in_progress",
        "hypothesis_count": 0,
        "indicator_count": 0,
    }
    return svc


def _as_graph_arg(graph: EvidenceGraph) -> EvidenceGraph:
    """The template's render() method accesses graph.nodes directly,
    so we pass the EvidenceGraph as-is (no mock wrapping needed)."""
    return graph


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCrossToolInvestigationTemplate:
    """Tests for CrossToolInvestigationTemplate.render()."""

    def test_renders_with_all_four_origins(self):
        """Template produces a non-empty result when all four origins are present."""
        from gnat.reports.templates.cross_tool_investigation import (
            CrossToolInvestigationTemplate,
        )

        inv_id = f"investigation--{uuid.uuid4()}"
        graph = _make_evidence_graph(origins=ALL_ORIGINS, investigation_id=inv_id)
        service = _mock_service(investigation_id=inv_id)
        gq = _as_graph_arg(graph)

        template = CrossToolInvestigationTemplate()
        sections = template.render(
            investigation_id=inv_id,
            service=service,
            graph=gq,
        )

        assert sections is not None
        assert len(sections) > 0

    def test_sections_grouped_by_origin(self):
        """Template produces sections whose content reflects grouping by origin."""
        from gnat.reports.templates.cross_tool_investigation import (
            CrossToolInvestigationTemplate,
        )

        inv_id = f"investigation--{uuid.uuid4()}"
        graph = _make_evidence_graph(
            origins=("gnat", "sandgnat", "redgnat"),
            nodes_per_origin=3,
            investigation_id=inv_id,
        )
        service = _mock_service(investigation_id=inv_id)
        gq = _as_graph_arg(graph)

        template = CrossToolInvestigationTemplate()
        sections = template.render(
            investigation_id=inv_id,
            service=service,
            graph=gq,
        )

        # Verify that sections reference the different origins
        # The template should produce at least one section per origin
        section_text = " ".join(
            str(getattr(s, "title", "") or "") + " " + str(getattr(s, "content", "") or "")
            for s in sections
        ).lower()

        for origin in ("gnat", "sandgnat", "redgnat"):
            assert origin in section_text, (
                f"Expected origin {origin!r} to appear in rendered sections"
            )

    def test_handles_empty_origins_gracefully(self):
        """Template renders without error when some origins have no data."""
        from gnat.reports.templates.cross_tool_investigation import (
            CrossToolInvestigationTemplate,
        )

        inv_id = f"investigation--{uuid.uuid4()}"
        # Only one origin has data
        graph = _make_evidence_graph(
            origins=("gnat",),
            nodes_per_origin=2,
            investigation_id=inv_id,
        )
        service = _mock_service(investigation_id=inv_id)
        gq = _as_graph_arg(graph)

        template = CrossToolInvestigationTemplate()
        sections = template.render(
            investigation_id=inv_id,
            service=service,
            graph=gq,
        )

        # Should still render without errors
        assert sections is not None
        assert len(sections) > 0

    def test_empty_graph_produces_sections(self):
        """Template does not crash on a completely empty graph."""
        from gnat.reports.templates.cross_tool_investigation import (
            CrossToolInvestigationTemplate,
        )

        inv_id = f"investigation--{uuid.uuid4()}"
        graph = EvidenceGraph(
            title="Empty investigation",
            seeds=[Seed("10.0.0.1", SeedType.IP)],
        )
        service = _mock_service(investigation_id=inv_id)
        gq = _as_graph_arg(graph)

        template = CrossToolInvestigationTemplate()
        sections = template.render(
            investigation_id=inv_id,
            service=service,
            graph=gq,
        )

        # Should produce at least a header/summary section, even if empty
        assert sections is not None

    def test_single_origin_sections(self):
        """When only one origin is present, template still groups correctly."""
        from gnat.reports.templates.cross_tool_investigation import (
            CrossToolInvestigationTemplate,
        )

        inv_id = f"investigation--{uuid.uuid4()}"
        graph = _make_evidence_graph(
            origins=("sensegnat",),
            nodes_per_origin=4,
            investigation_id=inv_id,
        )
        service = _mock_service(investigation_id=inv_id)
        gq = _as_graph_arg(graph)

        template = CrossToolInvestigationTemplate()
        sections = template.render(
            investigation_id=inv_id,
            service=service,
            graph=gq,
        )

        assert sections is not None
        assert len(sections) > 0
        # sensegnat should appear somewhere in the output
        section_text = " ".join(
            str(getattr(s, "title", "") or "") + " " + str(getattr(s, "content", "") or "")
            for s in sections
        ).lower()
        assert "sensegnat" in section_text
