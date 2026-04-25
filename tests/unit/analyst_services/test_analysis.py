# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for :mod:`gnat.analyst_services.analysis`."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from gnat.analysis.investigations.models import (
    Hypothesis,
    Investigation,
    InvestigationStatus,
)
from gnat.analyst_services.analysis import AnalysisService
from gnat.analyst_services.context import AnalystContext
from gnat.analyst_services.exceptions import (
    InvestigationNotFound,
    TransitionError,
)
from gnat.schemas.analysis.investigation import (
    AnalystNoteSchema,
    HypothesisSchema,
    InvestigationSchema,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_ctx(actor: str = "analyst@test.com") -> AnalystContext:
    return AnalystContext(actor=actor, tenant="t1", request_id="req-1")


def _make_investigation(**overrides) -> Investigation:
    defaults = {
        "title": "Test Investigation",
        "created_by": "analyst@test.com",
        "id": "inv-001",
        "description": "Test description",
        "tags": ["test"],
    }
    defaults.update(overrides)
    return Investigation(**defaults)


def _mock_store(investigations: list[Investigation] | None = None) -> MagicMock:
    store = MagicMock()
    inv_list = investigations or [_make_investigation()]
    by_id = {inv.id: inv for inv in inv_list}

    def get_side_effect(inv_id):
        return by_id.get(inv_id)

    store.get.side_effect = get_side_effect
    store.list.return_value = inv_list
    store.save.side_effect = lambda inv: inv
    return store


# ── Tests: get_investigation ─────────────────────────────────────────────────


class TestGetInvestigation:
    def test_returns_schema(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        result = svc.get_investigation(_make_ctx(), "inv-001")
        assert isinstance(result, InvestigationSchema)
        assert result.id == "inv-001"
        assert result.title == "Test Investigation"

    def test_not_found_raises(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        with pytest.raises(InvestigationNotFound):
            svc.get_investigation(_make_ctx(), "nonexistent")


# ── Tests: list_investigations ───────────────────────────────────────────────


class TestListInvestigations:
    def test_returns_list_of_schemas(self):
        inv1 = _make_investigation(id="inv-1", title="One")
        inv2 = _make_investigation(id="inv-2", title="Two")
        store = _mock_store([inv1, inv2])
        svc = AnalysisService(store=store)
        results = svc.list_investigations(_make_ctx())
        assert len(results) == 2
        assert all(isinstance(r, InvestigationSchema) for r in results)

    def test_passes_filters_to_store(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        svc.list_investigations(_make_ctx(), status="open", tag="apt", limit=10, offset=5)
        store.list.assert_called_once_with(
            status=InvestigationStatus.OPEN,
            tag="apt",
            limit=10,
            offset=5,
        )


# ── Tests: create_investigation ──────────────────────────────────────────────


class TestCreateInvestigation:
    def test_returns_schema_with_defaults(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        result = svc.create_investigation(_make_ctx(), title="New Investigation")
        assert isinstance(result, InvestigationSchema)
        assert result.title == "New Investigation"
        assert result.status == "open"
        store.save.assert_called_once()

    def test_uses_ctx_actor_as_created_by(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        result = svc.create_investigation(_make_ctx(actor="bob@acme.com"), title="Bob's inv")
        assert result.created_by == "bob@acme.com"


# ── Tests: transition ────────────────────────────────────────────────────────


class TestTransition:
    def test_valid_transition(self):
        inv = _make_investigation(status=InvestigationStatus.OPEN)
        store = _mock_store([inv])
        svc = AnalysisService(store=store)
        result = svc.transition(_make_ctx(), "inv-001", "in_progress")
        assert isinstance(result, InvestigationSchema)
        assert result.status == "in_progress"
        store.save.assert_called_once()

    def test_invalid_transition_raises(self):
        inv = _make_investigation(status=InvestigationStatus.OPEN)
        store = _mock_store([inv])
        svc = AnalysisService(store=store)
        with pytest.raises(TransitionError):
            svc.transition(_make_ctx(), "inv-001", "closed")

    def test_not_found_raises(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        with pytest.raises(InvestigationNotFound):
            svc.transition(_make_ctx(), "nonexistent", "in_progress")


# ── Tests: add_hypothesis ────────────────────────────────────────────────────


class TestAddHypothesis:
    def test_returns_hypothesis_schema(self):
        inv = _make_investigation()
        store = _mock_store([inv])
        svc = AnalysisService(store=store)
        result = svc.add_hypothesis(_make_ctx(), "inv-001", "Threat actor reused C2")
        assert isinstance(result, HypothesisSchema)
        assert result.statement == "Threat actor reused C2"
        assert len(inv.hypothesis) == 1

    def test_not_found_raises(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        with pytest.raises(InvestigationNotFound):
            svc.add_hypothesis(_make_ctx(), "nonexistent", "test")


# ── Tests: add_note ──────────────────────────────────────────────────────────


class TestAddNote:
    def test_returns_note_schema(self):
        inv = _make_investigation()
        store = _mock_store([inv])
        svc = AnalysisService(store=store)
        result = svc.add_note(_make_ctx(), "inv-001", "Initial triage.", "analyst@test.com")
        assert isinstance(result, AnalystNoteSchema)
        assert result.content == "Initial triage."
        assert result.author == "analyst@test.com"
        assert len(inv.notes) == 1


# ── Tests: get_timeline ─────────────────────────────────────────────────────


class TestGetTimeline:
    def test_returns_timeline_schemas(self):
        inv = _make_investigation()
        store = _mock_store([inv])
        mock_builder = MagicMock()
        from gnat.analysis.timeline import TimelineEvent, TimelineEventType

        mock_builder.from_investigation.return_value = [
            TimelineEvent(
                timestamp=datetime(2026, 4, 1, tzinfo=timezone.utc),
                title="Investigation opened",
                event_type=TimelineEventType.INVESTIGATION_OPENED,
            )
        ]
        svc = AnalysisService(store=store, timeline_builder=mock_builder)
        result = svc.get_timeline(_make_ctx(), "inv-001")
        assert len(result) == 1
        assert result[0].title == "Investigation opened"
        mock_builder.from_investigation.assert_called_once_with(inv)

    def test_creates_default_builder_if_none(self):
        inv = _make_investigation()
        store = _mock_store([inv])
        svc = AnalysisService(store=store, timeline_builder=None)
        result = svc.get_timeline(_make_ctx(), "inv-001")
        # Should return at least the "investigation opened" event
        assert len(result) >= 1


# ── Tests: query_graph ───────────────────────────────────────────────────────


class TestQueryGraph:
    def test_delegates_to_factory(self):
        from gnat.analysis.graph import GraphContext

        mock_ctx = GraphContext(
            nodes={"n1": MagicMock()},
            edges=[],
            seed_ids=["n1"],
        )
        mock_gq = MagicMock()
        mock_gq.pivot.return_value = mock_ctx
        factory = MagicMock(return_value=mock_gq)

        store = _mock_store()
        svc = AnalysisService(store=store, graph_query_factory=factory)
        graph = MagicMock()
        result = svc.query_graph(_make_ctx(), graph, "n1", hops=2)
        factory.assert_called_once_with(graph)
        mock_gq.pivot.assert_called_once_with("n1", hops=2)


# ── Tests: detect_gaps ───────────────────────────────────────────────────────


class TestDetectGaps:
    def test_returns_gap_schemas(self):
        from gnat.analysis.copilot.gap_detector import (
            GapRecommendation,
            GapSeverity,
        )

        inv = _make_investigation()
        hyp = Hypothesis(statement="Lateral movement via RDP")
        inv.hypothesis.append(hyp)

        mock_detector = MagicMock()
        mock_detector.detect.return_value = [
            GapRecommendation(
                description="No host observable.",
                severity=GapSeverity.HIGH,
                suggested_action="Link a hostname.",
                rule_id="lateral-movement-no-host",
            )
        ]

        store = _mock_store([inv])
        svc = AnalysisService(store=store, gap_detector=mock_detector)
        result = svc.detect_gaps(_make_ctx(), "inv-001")
        assert len(result) == 1
        assert result[0].rule_id == "lateral-movement-no-host"
        mock_detector.detect.assert_called_once_with(hyp, inv)

    def test_not_found_raises(self):
        store = _mock_store()
        svc = AnalysisService(store=store)
        with pytest.raises(InvestigationNotFound):
            svc.detect_gaps(_make_ctx(), "nonexistent")
