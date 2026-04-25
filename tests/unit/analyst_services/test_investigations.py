# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for :mod:`gnat.analyst_services.investigations`."""

from __future__ import annotations

from unittest.mock import MagicMock

from gnat.analyst_services.context import AnalystContext
from gnat.analyst_services.investigations import InvestigationsService
from gnat.investigations.model import (
    EvidenceGraph,
    Seed,
    SeedType,
)
from gnat.schemas.investigations import EvidenceGraphSchema

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_ctx(actor: str = "analyst@test.com") -> AnalystContext:
    return AnalystContext(actor=actor, tenant="t1", request_id="req-1")


def _make_graph() -> EvidenceGraph:
    return EvidenceGraph(
        title="Test Investigation",
        seeds=[Seed(value="1.2.3.4", seed_type=SeedType.IP)],
    )


# ── Tests: build ─────────────────────────────────────────────────────────────


class TestBuild:
    def test_returns_evidence_graph_schema(self):
        graph = _make_graph()
        mock_builder = MagicMock()
        mock_builder.build.return_value = graph

        svc = InvestigationsService(builder=mock_builder)
        result = svc.build(
            _make_ctx(),
            seeds=[{"value": "1.2.3.4", "seed_type": "ip"}],
            title="Test",
        )
        assert isinstance(result, EvidenceGraphSchema)
        assert result.title == "Test Investigation"
        mock_builder.build.assert_called_once()

    def test_passes_expand_depth(self):
        graph = _make_graph()
        mock_builder = MagicMock()
        mock_builder.build.return_value = graph

        svc = InvestigationsService(builder=mock_builder)
        svc.build(
            _make_ctx(),
            seeds=[{"value": "evil.com", "seed_type": "domain"}],
            title="Deep expand",
            expand_depth=3,
        )
        call_kwargs = mock_builder.build.call_args
        assert call_kwargs.kwargs["expand_depth"] == 3

    def test_converts_seed_dicts_to_domain_objects(self):
        graph = _make_graph()
        mock_builder = MagicMock()
        mock_builder.build.return_value = graph

        svc = InvestigationsService(builder=mock_builder)
        svc.build(
            _make_ctx(),
            seeds=[
                {"value": "1.2.3.4", "seed_type": "ip"},
                {
                    "value": "INC-123",
                    "seed_type": "case_id",
                    "hint_platform": "xsoar",
                },
            ],
            title="Multi-seed",
        )
        call_args = mock_builder.build.call_args
        seed_list = call_args.kwargs["seeds"]
        assert len(seed_list) == 2
        assert isinstance(seed_list[0], Seed)
        assert seed_list[0].seed_type == SeedType.IP
        assert seed_list[1].hint_platform == "xsoar"


# ── Tests: get_graph_summary ─────────────────────────────────────────────────


class TestGetGraphSummary:
    def test_returns_summary_dict(self):
        graph = _make_graph()
        mock_builder = MagicMock()
        svc = InvestigationsService(builder=mock_builder)
        result = svc.get_graph_summary(_make_ctx(), graph)
        assert isinstance(result, dict)
        assert "title" in result
        assert result["title"] == "Test Investigation"

    def test_delegates_to_graph_summary(self):
        mock_graph = MagicMock()
        mock_graph.summary.return_value = {"nodes": 5, "edges": 3}

        mock_builder = MagicMock()
        svc = InvestigationsService(builder=mock_builder)
        result = svc.get_graph_summary(_make_ctx(), mock_graph)
        mock_graph.summary.assert_called_once()
        assert result == {"nodes": 5, "edges": 3}
