"""
gnat.agents.workflows.incident_response
=========================================

Pre-built incident response workflow.

Steps:

1. **enrich** — enrich all known IOCs
2. **correlate** — build and score the entity relationship graph
3. **gap_detect** — identify evidence gaps
4. **draft_report** — produce a draft incident report
5. **transition_review** — move investigation to REVIEW status

Usage::

    from gnat.agents.workflows.incident_response import build_incident_response_workflow
    from gnat.agents.workflow import WorkflowContext

    wf = build_incident_response_workflow(
        dispatcher = enrichment_dispatcher,
        resolver   = entity_resolver,
        scorer     = relationship_scorer,
        detector   = gap_detector,
        assistant  = report_drafting_assistant,
        service    = investigation_service,
        iocs       = ["ransomware.c2.example.com"],
    )

    ctx    = WorkflowContext(investigation_id="inv-456", shared={}, results={})
    result = wf.run(ctx)
"""

from __future__ import annotations

from typing import Any

from gnat.agents.steps import (
    correlate_step,
    draft_report_step,
    enrich_step,
    gap_detect_step,
    transition_step,
)
from gnat.agents.workflow import Workflow


def build_incident_response_workflow(
    dispatcher: Any = None,
    resolver: Any = None,
    scorer: Any = None,
    detector: Any = None,
    assistant: Any = None,
    service: Any = None,
    iocs: list[str] | None = None,
    review_status: Any = None,
    author: str = "incident-response-workflow",
) -> Workflow:
    """
    Build an incident response :class:`~gnat.agents.workflow.Workflow`.

    Parameters
    ----------
    dispatcher : EnrichmentDispatcher, optional
    resolver : EntityResolver, optional
    scorer : RelationshipScorer, optional
    detector : GapDetector, optional
    assistant : ReportDraftingAssistant, optional
    service : InvestigationService, optional
    iocs : list[str], optional
        IOC values to enrich.
    review_status : InvestigationStatus, optional
        Target status after the workflow.  Defaults to
        ``InvestigationStatus.REVIEW``.
    author : str
        Author name recorded in transition notes.

    Returns
    -------
    Workflow
    """
    if review_status is None:
        try:
            from gnat.analysis.investigations.models import InvestigationStatus

            review_status = InvestigationStatus.REVIEW
        except (ImportError, AttributeError):
            try:
                from gnat.analysis.investigations.models import InvestigationStatus

                review_status = InvestigationStatus.IN_PROGRESS
            except ImportError:
                review_status = "review"

    wf = Workflow("incident-response")
    wf.add_step(enrich_step(dispatcher, iocs or [], name="enrich"))
    wf.add_step(correlate_step(resolver, scorer, name="correlate"))
    wf.add_step(gap_detect_step(detector, name="gap_detect"))
    wf.add_step(draft_report_step(assistant, name="draft_report"))
    wf.add_step(
        transition_step(
            service,
            review_status,
            note="Incident response workflow complete — escalating for review.",
            author=author,
            name="transition_review",
        )
    )
    return wf
