"""
gnat.agents.steps
==================

Built-in :class:`~gnat.agents.workflow.WorkflowStep` factories for common
GNAT investigation automation tasks.

Each factory returns a :class:`~gnat.agents.workflow.WorkflowStep` that wraps
an existing GNAT component.  Components can be ``None`` — the step then
performs a no-op and records ``None`` in the context (useful for testing or
when the component is optional).

Usage::

    from gnat.agents.workflow import Workflow, WorkflowContext
    from gnat.agents.steps import enrich_step, gap_detect_step, transition_step
    from gnat.analysis.investigations.models import InvestigationStatus

    wf = (
        Workflow("triage")
        .add_step(enrich_step(dispatcher, ["8.8.8.8"]))
        .add_step(gap_detect_step(detector))
        .add_step(transition_step(inv_service, InvestigationStatus.IN_PROGRESS))
    )
    result = wf.run(WorkflowContext(investigation_id="inv-1"))
"""

from __future__ import annotations

from typing import Any

from gnat.agents.workflow import WorkflowContext, WorkflowStep

# ── Enrichment step ───────────────────────────────────────────────────────────


def enrich_step(
    dispatcher: Any,
    values: list[str],
    name: str = "enrich",
    **step_kwargs: Any,
) -> WorkflowStep:
    """
    Return a step that calls ``dispatcher.enrich_batch(values)``.

    The enrichment results are stored in ``ctx.shared["enrichment_results"]``.

    Parameters
    ----------
    dispatcher : EnrichmentDispatcher | None
        The enrichment dispatcher to use.  If ``None``, the step is a no-op.
    values : list[str]
        Values to enrich (IPs, domains, hashes, etc.).
    name : str
        Step name (default ``"enrich"``).
    **step_kwargs
        Forwarded to :class:`~gnat.agents.workflow.WorkflowStep`.
    """

    def _action(ctx: WorkflowContext) -> Any:
        if dispatcher is None:
            ctx.shared["enrichment_results"] = {}
            return {}
        result = dispatcher.enrich_batch(values)
        ctx.shared["enrichment_results"] = result
        return result

    return WorkflowStep(name=name, action=_action, **step_kwargs)


# ── Correlation step ──────────────────────────────────────────────────────────


def correlate_step(
    resolver: Any,
    scorer: Any,
    name: str = "correlate",
    **step_kwargs: Any,
) -> WorkflowStep:
    """
    Return a step that resolves entities and scores relationships.

    Calls ``resolver.resolve_all()`` if available, then
    ``scorer.score_all()`` if available.  Results stored in
    ``ctx.shared["correlation_results"]``.

    Parameters
    ----------
    resolver : EntityResolver | None
    scorer : RelationshipScorer | None
    name : str
    """

    def _action(ctx: WorkflowContext) -> Any:
        result: dict[str, Any] = {}
        if resolver is not None and hasattr(resolver, "resolve_all"):
            result["entities"] = resolver.resolve_all()
        if scorer is not None and hasattr(scorer, "score_all"):
            result["relationships"] = scorer.score_all()
        ctx.shared["correlation_results"] = result
        return result

    return WorkflowStep(name=name, action=_action, **step_kwargs)


# ── Gap detection step ────────────────────────────────────────────────────────


def gap_detect_step(
    detector: Any,
    name: str = "gap_detect",
    **step_kwargs: Any,
) -> WorkflowStep:
    """
    Return a step that calls ``detector.detect_all(investigation_id)``.

    Results stored in ``ctx.shared["gaps"]``.  Requires
    ``ctx.investigation_id`` to be set.

    Parameters
    ----------
    detector : GapDetector | None
    name : str
    """

    def _action(ctx: WorkflowContext) -> Any:
        if detector is None:
            ctx.shared["gaps"] = []
            return []
        inv_id = ctx.investigation_id
        if inv_id and hasattr(detector, "detect_all"):
            gaps = detector.detect_all(inv_id)
        elif hasattr(detector, "detect_all"):
            gaps = detector.detect_all()
        else:
            gaps = []
        ctx.shared["gaps"] = gaps
        return gaps

    return WorkflowStep(name=name, action=_action, **step_kwargs)


# ── Report drafting step ──────────────────────────────────────────────────────


def draft_report_step(
    assistant: Any,
    name: str = "draft_report",
    **step_kwargs: Any,
) -> WorkflowStep:
    """
    Return a step that calls ``assistant.draft_full(investigation_id)``.

    The draft text is stored in ``ctx.shared["report_draft"]``.

    Parameters
    ----------
    assistant : ReportDraftingAssistant | None
    name : str
    """

    def _action(ctx: WorkflowContext) -> Any:
        if assistant is None:
            ctx.shared["report_draft"] = ""
            return ""
        inv_id = ctx.investigation_id
        if inv_id and hasattr(assistant, "draft_full"):
            draft = assistant.draft_full(inv_id)
        else:
            draft = ""
        ctx.shared["report_draft"] = draft
        return draft

    return WorkflowStep(name=name, action=_action, **step_kwargs)


# ── State transition step ─────────────────────────────────────────────────────


def transition_step(
    service: Any,
    new_status: Any,
    note: str | None = None,
    author: str | None = None,
    name: str = "transition",
    **step_kwargs: Any,
) -> WorkflowStep:
    """
    Return a step that calls ``service.transition(investigation_id, new_status)``.

    Requires ``ctx.investigation_id`` to be set.

    Parameters
    ----------
    service : InvestigationService | None
    new_status : InvestigationStatus
    note : str, optional
    author : str, optional
    name : str
    """

    def _action(ctx: WorkflowContext) -> Any:
        if service is None or ctx.investigation_id is None:
            return None
        return service.transition(
            ctx.investigation_id,
            new_status,
            note=note,
            author=author,
        )

    return WorkflowStep(name=name, action=_action, **step_kwargs)


# ── Arbitrary callable step ───────────────────────────────────────────────────


def fn_step(
    fn: Any,
    name: str,
    **step_kwargs: Any,
) -> WorkflowStep:
    """
    Wrap any callable as a :class:`~gnat.agents.workflow.WorkflowStep`.

    The callable receives ``(ctx: WorkflowContext)`` and its return value
    is stored in ``ctx.results[name]`` automatically.

    Parameters
    ----------
    fn : Callable[[WorkflowContext], Any]
    name : str
    """
    return WorkflowStep(name=name, action=fn, **step_kwargs)
