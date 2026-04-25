# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analyst_services.reporting
==================================

:class:`ReportingService` — thin orchestration wrapper over the
:class:`~gnat.reporting.service.ReportService` and the optional
:class:`~gnat.analysis.copilot.drafting.ReportDraftingAssistant`.

Every method accepts an :class:`AnalystContext` as its first argument,
delegates to the underlying domain service, and returns Pydantic schemas.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.analyst_services.context import AnalystContext
from gnat.analyst_services.exceptions import ReportNotFound, TransitionError
from gnat.schemas.analysis.copilot import DraftResultSchema
from gnat.schemas.reporting import ReportSchema

logger = logging.getLogger(__name__)


class ReportingService:
    """
    Orchestration layer for report lifecycle management.

    Parameters
    ----------
    report_service : ReportService
        The domain report service that handles persistence and state
        transitions.
    drafting_assistant : ReportDraftingAssistant or None
        Optional LLM-backed drafting assistant.
    """

    def __init__(
        self,
        report_service: Any,
        drafting_assistant: Any | None = None,
    ) -> None:
        self._report_service = report_service
        self._drafting_assistant = drafting_assistant

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def create(
        self,
        ctx: AnalystContext,
        title: str,
        report_type: str,
        classification: str = "amber",
        created_by: str | None = None,
    ) -> ReportSchema:
        """
        Create a new report in DRAFT status.

        Parameters
        ----------
        ctx : AnalystContext
        title : str
        report_type : str
        classification : str
        created_by : str, optional
            Defaults to ``ctx.actor``.

        Returns
        -------
        ReportSchema
        """
        logger.info(
            "ReportingService.create: actor=%s title=%r type=%s",
            ctx.actor,
            title,
            report_type,
        )
        from gnat.analysis.tlp import TLPLevel
        from gnat.reporting.models import ReportType

        report = self._report_service.create(
            title=title,
            report_type=ReportType(report_type),
            authors=[created_by or ctx.actor],
            classification=TLPLevel(classification),
        )
        return ReportSchema.from_domain(report)

    def get(
        self,
        ctx: AnalystContext,
        report_id: str,
    ) -> ReportSchema:
        """
        Retrieve a single report by ID.

        Parameters
        ----------
        ctx : AnalystContext
        report_id : str

        Returns
        -------
        ReportSchema

        Raises
        ------
        ReportNotFound
            If the report does not exist.
        """
        logger.info(
            "ReportingService.get: actor=%s id=%s",
            ctx.actor,
            report_id,
        )
        from gnat.reporting.service import ReportError

        try:
            report = self._report_service.get(report_id)
        except ReportError as exc:
            raise ReportNotFound(str(exc)) from exc
        return ReportSchema.from_domain(report)

    # ── State machine ────────────────────────────────────────────────────────

    def transition(
        self,
        ctx: AnalystContext,
        report_id: str,
        new_status: str,
    ) -> ReportSchema:
        """
        Transition a report to a new lifecycle state.

        Parameters
        ----------
        ctx : AnalystContext
        report_id : str
        new_status : str

        Returns
        -------
        ReportSchema

        Raises
        ------
        ReportNotFound
            If the report does not exist.
        TransitionError
            If the transition is invalid.
        """
        logger.info(
            "ReportingService.transition: actor=%s id=%s new_status=%s",
            ctx.actor,
            report_id,
            new_status,
        )
        from gnat.reporting.models import ReportStatus
        from gnat.reporting.service import ReportError

        try:
            report = self._report_service.get(report_id)
        except ReportError as exc:
            raise ReportNotFound(str(exc)) from exc

        target = ReportStatus(new_status)
        if not report.can_transition_to(target):
            raise TransitionError(
                f"Cannot transition report from {report.status.value!r} to {new_status!r}."
            )

        # Delegate to the appropriate domain method based on target status
        try:
            if target == ReportStatus.REVIEW:
                report = self._report_service.submit_for_review(report_id, submitter=ctx.actor)
            elif target == ReportStatus.PUBLISHED:
                report = self._report_service.publish(report_id, changed_by=ctx.actor)
            elif target == ReportStatus.ARCHIVED:
                report = self._report_service.archive(report_id, changed_by=ctx.actor)
            else:
                report = self._report_service._transition(
                    report_id, target, ctx.actor, f"Transitioned to {new_status}."
                )
        except ReportError as exc:
            raise TransitionError(str(exc)) from exc

        return ReportSchema.from_domain(report)

    # ── Drafting ─────────────────────────────────────────────────────────────

    def draft_summary(
        self,
        ctx: AnalystContext,
        investigation_id: str,
    ) -> DraftResultSchema:
        """
        Draft an executive summary for the report linked to an investigation.

        Parameters
        ----------
        ctx : AnalystContext
        investigation_id : str

        Returns
        -------
        DraftResultSchema
        """
        logger.info(
            "ReportingService.draft_summary: actor=%s investigation_id=%s",
            ctx.actor,
            investigation_id,
        )
        # Find a report linked to this investigation
        reports = self._report_service.list(linked_investigation=investigation_id)
        if not reports:
            from gnat.analysis.copilot.drafting import DraftResult

            return DraftResultSchema.from_domain(
                DraftResult(
                    executive_summary="",
                    key_findings_narrative="",
                    warnings=[f"No report linked to investigation {investigation_id}."],
                )
            )
        report = reports[0]
        if self._drafting_assistant is None:
            from gnat.analysis.copilot.drafting import DraftResult

            return DraftResultSchema.from_domain(
                DraftResult(
                    executive_summary=f"[DRAFT REQUIRED] {report.title}",
                    key_findings_narrative="",
                    warnings=["No drafting assistant configured."],
                )
            )
        result = self._drafting_assistant.draft_executive_summary(report)
        return DraftResultSchema.from_domain(result)

    # ── STIX export ──────────────────────────────────────────────────────────

    def export_stix(
        self,
        ctx: AnalystContext,
        report_id: str,
    ) -> dict[str, Any]:
        """
        Export a report as a STIX 2.1 bundle.

        Parameters
        ----------
        ctx : AnalystContext
        report_id : str

        Returns
        -------
        dict
            STIX 2.1 bundle dict.

        Raises
        ------
        ReportNotFound
            If the report does not exist.
        """
        logger.info(
            "ReportingService.export_stix: actor=%s id=%s",
            ctx.actor,
            report_id,
        )
        from gnat.reporting.service import ReportError

        try:
            report = self._report_service.get(report_id)
        except ReportError as exc:
            raise ReportNotFound(str(exc)) from exc

        if report.stix_bundle_json:
            import json

            return json.loads(report.stix_bundle_json)

        from gnat.reporting.export.stix import report_to_stix_bundle

        return report_to_stix_bundle(report)
