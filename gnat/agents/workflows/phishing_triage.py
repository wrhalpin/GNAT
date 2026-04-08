"""
gnat.agents.workflows.phishing_triage
======================================

Pre-built phishing triage workflow.

The workflow runs the following steps in order:

1. **enrich** — enrich IOCs extracted from the phishing sample
2. **correlate** — resolve and score entity relationships
3. **gap_detect** — identify analytical gaps
4. **draft_report** — draft a preliminary report
5. **transition** — move the investigation to IN_PROGRESS

Usage::

    from gnat.agents.workflows.phishing_triage import build_phishing_triage_workflow
    from gnat.agents.workflow import WorkflowContext

    wf = build_phishing_triage_workflow(
        dispatcher = enrichment_dispatcher,
        resolver   = entity_resolver,
        scorer     = relationship_scorer,
        detector   = gap_detector,
        assistant  = report_drafting_assistant,
        service    = investigation_service,
        iocs       = ["evil.example.com", "1.2.3.4"],
    )

    ctx    = WorkflowContext(investigation_id="inv-123", shared={}, results={})
    result = wf.run(ctx)
    print(result.success, result.steps_completed)
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


def build_phishing_triage_workflow(
    dispatcher: Any = None,
    resolver:   Any = None,
    scorer:     Any = None,
    detector:   Any = None,
    assistant:  Any = None,
    service:    Any = None,
    iocs:       list[str] | None = None,
    new_status: Any = None,
    author:     str = "phishing-triage-workflow",
) -> Workflow:
    """
    Build a phishing triage :class:`~gnat.agents.workflow.Workflow`.

    All component parameters are optional — pass ``None`` to skip that step
    (it will be a no-op and the workflow will still succeed).

    Parameters
    ----------
    dispatcher : EnrichmentDispatcher, optional
    resolver : EntityResolver, optional
    scorer : RelationshipScorer, optional
    detector : GapDetector, optional
    assistant : ReportDraftingAssistant, optional
    service : InvestigationService, optional
    iocs : list[str], optional
        IOC values to enrich in the enrich step.
    new_status : InvestigationStatus, optional
        Target status for the transition step.  Defaults to
        ``InvestigationStatus.IN_PROGRESS``.
    author : str
        Author name recorded in the transition note.

    Returns
    -------
    Workflow
    """
    if new_status is None:
        try:
            from gnat.analysis.investigations.models import InvestigationStatus
            new_status = InvestigationStatus.IN_PROGRESS
        except ImportError:
            new_status = "in_progress"

    wf = Workflow("phishing-triage")
    wf.add_step(enrich_step(dispatcher, iocs or [], name="enrich"))
    wf.add_step(correlate_step(resolver, scorer, name="correlate"))
    wf.add_step(gap_detect_step(detector, name="gap_detect"))
    wf.add_step(draft_report_step(assistant, name="draft_report"))
    wf.add_step(transition_step(
        service, new_status,
        note   = "Automated phishing triage workflow complete.",
        author = author,
        name   = "transition",
    ))
    return wf
