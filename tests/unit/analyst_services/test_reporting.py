# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for :mod:`gnat.analyst_services.reporting`."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from gnat.analysis.tlp import TLPLevel
from gnat.analyst_services.context import AnalystContext
from gnat.analyst_services.exceptions import ReportNotFound, TransitionError
from gnat.analyst_services.reporting import ReportingService
from gnat.reporting.models import Report, ReportStatus, ReportType
from gnat.schemas.analysis.copilot import DraftResultSchema
from gnat.schemas.reporting import ReportSchema

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_ctx(actor: str = "analyst@test.com") -> AnalystContext:
    return AnalystContext(actor=actor, tenant="t1", request_id="req-1")


def _make_report(**overrides) -> Report:
    defaults = {
        "title": "Test Report",
        "report_type": ReportType.INCIDENT_REPORT,
        "id": "rpt-001",
        "authors": ["analyst@test.com"],
        "status": ReportStatus.DRAFT,
        "classification": TLPLevel.AMBER,
    }
    defaults.update(overrides)
    return Report(**defaults)


def _mock_report_service(reports: list[Report] | None = None) -> MagicMock:
    svc = MagicMock()
    rpt_list = reports or [_make_report()]
    by_id = {r.id: r for r in rpt_list}

    def get_side_effect(rpt_id):
        rpt = by_id.get(rpt_id)
        if rpt is None:
            from gnat.reporting.service import ReportError

            raise ReportError(f"Report not found: {rpt_id}")
        return rpt

    svc.get.side_effect = get_side_effect
    svc.list.return_value = rpt_list
    svc.create.side_effect = lambda **kwargs: _make_report(**kwargs)
    return svc


# ── Tests: create ────────────────────────────────────────────────────────────


class TestCreate:
    def test_returns_report_schema(self):
        mock_svc = _mock_report_service()
        reporting = ReportingService(report_service=mock_svc)
        result = reporting.create(_make_ctx(), title="New Report", report_type="incident_report")
        assert isinstance(result, ReportSchema)
        mock_svc.create.assert_called_once()

    def test_uses_ctx_actor_as_default_author(self):
        mock_svc = _mock_report_service()
        reporting = ReportingService(report_service=mock_svc)
        reporting.create(
            _make_ctx(actor="bob@acme.com"),
            title="Report",
            report_type="incident_report",
        )
        call_kwargs = mock_svc.create.call_args.kwargs
        assert call_kwargs["authors"] == ["bob@acme.com"]


# ── Tests: get ───────────────────────────────────────────────────────────────


class TestGet:
    def test_returns_report_schema(self):
        mock_svc = _mock_report_service()
        reporting = ReportingService(report_service=mock_svc)
        result = reporting.get(_make_ctx(), "rpt-001")
        assert isinstance(result, ReportSchema)
        assert result.id == "rpt-001"

    def test_not_found_raises(self):
        mock_svc = _mock_report_service()
        reporting = ReportingService(report_service=mock_svc)
        with pytest.raises(ReportNotFound):
            reporting.get(_make_ctx(), "nonexistent")


# ── Tests: transition ────────────────────────────────────────────────────────


class TestTransition:
    def test_valid_transition_review(self):
        rpt = _make_report(status=ReportStatus.DRAFT)
        mock_svc = _mock_report_service([rpt])
        # submit_for_review returns the updated report
        updated = _make_report(status=ReportStatus.REVIEW)
        mock_svc.submit_for_review.return_value = updated

        reporting = ReportingService(report_service=mock_svc)
        result = reporting.transition(_make_ctx(), "rpt-001", "review")
        assert isinstance(result, ReportSchema)
        mock_svc.submit_for_review.assert_called_once()

    def test_invalid_transition_raises(self):
        rpt = _make_report(status=ReportStatus.DRAFT)
        mock_svc = _mock_report_service([rpt])
        reporting = ReportingService(report_service=mock_svc)
        with pytest.raises(TransitionError):
            reporting.transition(_make_ctx(), "rpt-001", "published")

    def test_not_found_raises(self):
        mock_svc = _mock_report_service()
        reporting = ReportingService(report_service=mock_svc)
        with pytest.raises(ReportNotFound):
            reporting.transition(_make_ctx(), "nonexistent", "review")


# ── Tests: draft_summary ─────────────────────────────────────────────────────


class TestDraftSummary:
    def test_no_linked_report_returns_warning(self):
        mock_svc = MagicMock()
        mock_svc.list.return_value = []
        reporting = ReportingService(report_service=mock_svc)
        result = reporting.draft_summary(_make_ctx(), "inv-001")
        assert isinstance(result, DraftResultSchema)
        assert len(result.warnings) > 0
        assert "No report linked" in result.warnings[0]

    def test_no_drafting_assistant_returns_placeholder(self):
        rpt = _make_report(linked_investigation="inv-001")
        mock_svc = MagicMock()
        mock_svc.list.return_value = [rpt]
        reporting = ReportingService(report_service=mock_svc, drafting_assistant=None)
        result = reporting.draft_summary(_make_ctx(), "inv-001")
        assert isinstance(result, DraftResultSchema)
        assert "DRAFT REQUIRED" in result.executive_summary

    def test_delegates_to_drafting_assistant(self):
        from gnat.analysis.copilot.drafting import DraftResult

        rpt = _make_report(linked_investigation="inv-001")
        mock_svc = MagicMock()
        mock_svc.list.return_value = [rpt]

        mock_drafter = MagicMock()
        mock_drafter.draft_executive_summary.return_value = DraftResult(
            executive_summary="Summary text",
            key_findings_narrative="Findings text",
            model="claude-sonnet-4-6",
        )

        reporting = ReportingService(report_service=mock_svc, drafting_assistant=mock_drafter)
        result = reporting.draft_summary(_make_ctx(), "inv-001")
        assert isinstance(result, DraftResultSchema)
        assert result.executive_summary == "Summary text"
        mock_drafter.draft_executive_summary.assert_called_once_with(rpt)


# ── Tests: export_stix ───────────────────────────────────────────────────────


class TestExportStix:
    def test_returns_cached_bundle(self):
        import json

        bundle = {"type": "bundle", "objects": []}
        rpt = _make_report(stix_bundle_json=json.dumps(bundle))
        mock_svc = _mock_report_service([rpt])
        reporting = ReportingService(report_service=mock_svc)
        result = reporting.export_stix(_make_ctx(), "rpt-001")
        assert isinstance(result, dict)
        assert result["type"] == "bundle"

    def test_not_found_raises(self):
        mock_svc = _mock_report_service()
        reporting = ReportingService(report_service=mock_svc)
        with pytest.raises(ReportNotFound):
            reporting.export_stix(_make_ctx(), "nonexistent")
