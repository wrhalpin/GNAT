# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.workflows.auto_investigation
=========================================

Autonomous investigation workflow.

Triggered by an incoming alert, this workflow automatically:

1. **enrich** — enrich IOCs from the alert payload
2. **correlate** — resolve entity relationships and score them
3. **gap_detect** — identify analytical gaps in the data
4. **hypothesis** — draft an initial hypothesis via the AI agent
5. **score** — compute a confidence score; store in ``ctx.shared["score"]``
6. **route** — branch on score: high-confidence → open investigation,
   low-confidence → request analyst review
7. **open_investigation** *(high path)* — create investigation record
8. **analyst_review** *(low path)* — submit to HITL review queue
9. **transition** — move investigation to IN_PROGRESS (high path only)

Usage::

    from gnat.agents.workflows.auto_investigation import build_auto_investigation_workflow
    from gnat.agents.workflow import WorkflowContext

    wf = build_auto_investigation_workflow(
        dispatcher  = enrichment_dispatcher,
        resolver    = entity_resolver,
        scorer      = relationship_scorer,
        detector    = gap_detector,
        llm_client  = llm,
        inv_service = investigation_service,
        hitl        = hitl_gateway,
        confidence_threshold = 0.7,
    )

    ctx    = WorkflowContext(shared={"alert": alert_payload, "iocs": ["evil.com"]})
    result = wf.run(ctx)
    print(result.success, result.steps_completed)
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.agents.steps import (
    correlate_step,
    fn_step,
    gap_detect_step,
    transition_step,
)
from gnat.agents.workflow import RetryPolicy, Workflow, WorkflowContext, WorkflowStep

logger = logging.getLogger(__name__)

_DEFAULT_CONFIDENCE_THRESHOLD = 0.7


def _hypothesis_action(llm_client: Any) -> Any:
    """Return a step action that drafts an initial hypothesis using the LLM."""

    def action(ctx: WorkflowContext) -> str:
        if llm_client is None:
            ctx.shared["hypothesis"] = "No LLM client configured — manual analysis required."
            return ctx.shared["hypothesis"]

        alert = ctx.shared.get("alert", {})
        enrich = ctx.shared.get("enrichment_results", {})
        gaps = ctx.shared.get("gaps", [])

        prompt = (
            "You are a threat intelligence analyst. Given the following alert and enrichment data, "
            "draft a concise initial hypothesis about the threat activity.\n\n"
            f"Alert: {alert}\n\n"
            f"Enrichment results: {enrich}\n\n"
            f"Analytical gaps: {gaps}\n\n"
            "Respond with a 2–3 sentence hypothesis."
        )
        try:
            response = llm_client.chat([{"role": "user", "content": prompt}], temperature=0.3)
            # Handle Claude and OpenAI response formats
            hypothesis = ""
            if "content" in response:
                for block in response.get("content", []):
                    if block.get("type") == "text":
                        hypothesis = block.get("text", "")
                        break
            elif "choices" in response:
                hypothesis = response["choices"][0].get("message", {}).get("content", "")
            ctx.shared["hypothesis"] = hypothesis
            return hypothesis
        except Exception as exc:
            logger.warning("auto_investigation hypothesis step failed: %s", exc)
            ctx.shared["hypothesis"] = f"Hypothesis generation failed: {exc}"
            return ctx.shared["hypothesis"]

    return action


def _score_action(ctx: WorkflowContext) -> float:
    """
    Compute a confidence score from enrichment data and store it in ctx.shared["score"].

    Scoring heuristics:
    - Base score from alert's ``score`` / ``severity`` field if present
    - Adjust upward for rich enrichment results (many hits)
    - Adjust downward for critical analytical gaps
    """
    # Start from alert score
    alert = ctx.shared.get("alert", {})
    base = float(alert.get("score", alert.get("severity", 0.5)))
    if base > 1.0:
        base /= 100.0  # normalise 0-100 → 0-1

    score = max(0.0, min(1.0, base))

    # Bonus for corroborated enrichment data
    enrichment = ctx.shared.get("enrichment_results", {})
    if isinstance(enrichment, dict) and len(enrichment) > 3:
        score = min(1.0, score + 0.1)

    # Penalty for critical gaps
    gaps = ctx.shared.get("gaps", [])
    critical_gaps = [g for g in gaps if getattr(g, "severity", "") in ("critical", "high")]
    if critical_gaps:
        score = max(0.0, score - 0.15 * min(len(critical_gaps), 3))

    ctx.shared["score"] = round(score, 3)
    logger.debug("auto_investigation score_action: score=%.3f", score)
    return score


def _open_investigation_action(inv_service: Any) -> Any:
    """Return a step action that opens a new investigation."""

    def action(ctx: WorkflowContext) -> Any:
        if inv_service is None:
            logger.debug("auto_investigation: no inv_service — skipping open_investigation")
            ctx.shared["investigation_opened"] = False
            return None

        alert = ctx.shared.get("alert", {})
        hypothesis = ctx.shared.get("hypothesis", "")
        try:
            inv = inv_service.create(
                title=alert.get("title", "Auto-generated investigation"),
                description=hypothesis,
                severity=alert.get("severity", "medium"),
                source=alert.get("source", "auto-investigation"),
            )
            ctx.investigation_id = getattr(inv, "id", None) or str(inv)
            ctx.shared["investigation"] = inv
            ctx.shared["investigation_opened"] = True
            logger.info("auto_investigation: opened investigation %s", ctx.investigation_id)
            return inv
        except Exception as exc:
            logger.error("auto_investigation: open_investigation failed: %s", exc)
            ctx.shared["investigation_opened"] = False
            raise

    return action


def _analyst_review_action(hitl: Any) -> Any:
    """Return a step action that submits to the HITL analyst review queue."""

    def action(ctx: WorkflowContext) -> Any:
        if hitl is None:
            logger.debug("auto_investigation: no HITL gateway — skipping analyst_review")
            ctx.shared["review_submitted"] = False
            return None

        alert = ctx.shared.get("alert", {})
        hypothesis = ctx.shared.get("hypothesis", "")
        score = ctx.shared.get("score", 0.0)
        try:
            from gnat.agents.hitl import AgentAction

            action_obj = AgentAction(
                agent_id="auto-investigation-workflow",
                action_type="open_investigation",
                target_ref=alert.get("id", ""),
                impact_level="high",
                metadata={
                    "hypothesis": hypothesis,
                    "score": score,
                    "alert": alert,
                },
            )
            review = hitl.submit_for_approval(action_obj)
            ctx.shared["review_item"] = review
            ctx.shared["review_submitted"] = True
            logger.info("auto_investigation: submitted for analyst review (score=%.3f)", score)
            return review
        except Exception as exc:
            logger.warning("auto_investigation: analyst_review submission failed: %s", exc)
            ctx.shared["review_submitted"] = False
            return None

    return action


def build_auto_investigation_workflow(
    dispatcher: Any = None,
    resolver: Any = None,
    scorer: Any = None,
    detector: Any = None,
    llm_client: Any = None,
    inv_service: Any = None,
    hitl: Any = None,
    confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD,
) -> Workflow:
    """
    Build the autonomous investigation :class:`~gnat.agents.workflow.Workflow`.

    All component parameters are optional — missing components cause those
    steps to become no-ops so the workflow still completes.

    Parameters
    ----------
    dispatcher : EnrichmentDispatcher, optional
    resolver : EntityResolver, optional
    scorer : RelationshipScorer, optional
    detector : GapDetector, optional
    llm_client : LLMClient, optional
        Used for hypothesis generation.
    inv_service : InvestigationService, optional
        Used to create investigation records.
    hitl : HITLGateway, optional
        Used to submit low-confidence cases for analyst review.
    confidence_threshold : float
        Score above which the workflow opens an investigation automatically.
        Default ``0.7``.

    Returns
    -------
    Workflow
    """
    wf = Workflow("auto-investigation")

    # ── 1. Enrich IOCs from the alert ─────────────────────────────────────────
    def _get_iocs(ctx: WorkflowContext) -> list[str]:
        return ctx.shared.get("iocs", [])

    def _enrich_action(ctx: WorkflowContext) -> Any:
        iocs = _get_iocs(ctx)
        if dispatcher is None or not iocs:
            return None
        try:
            results = dispatcher.enrich_batch(iocs)
            ctx.shared["enrichment_results"] = results
            return results
        except Exception as exc:
            logger.warning("auto_investigation: enrich failed: %s", exc)
            ctx.shared["enrichment_results"] = {}
            raise

    wf.add_step(
        WorkflowStep(
            name="enrich",
            action=_enrich_action,
            retry=RetryPolicy(max_attempts=2, backoff_seconds=1.0),
        )
    )

    # ── 2. Correlate relationships ────────────────────────────────────────────
    wf.add_step(correlate_step(resolver, scorer, name="correlate"))

    # ── 3. Gap detection ──────────────────────────────────────────────────────
    wf.add_step(gap_detect_step(detector, name="gap_detect"))

    # ── 4. Hypothesis generation ──────────────────────────────────────────────
    wf.add_step(
        WorkflowStep(
            name="hypothesis",
            action=_hypothesis_action(llm_client),
            retry=RetryPolicy(max_attempts=2, backoff_seconds=2.0),
        )
    )

    # ── 5. Confidence scoring ─────────────────────────────────────────────────
    wf.add_step(fn_step(_score_action, name="score"))

    # ── 6. Branch: high-confidence → open investigation, low → analyst review ─
    def _router(ctx: WorkflowContext) -> str:
        score = float(ctx.shared.get("score", 0.0))
        return "open_investigation" if score >= confidence_threshold else "analyst_review"

    wf.add_step(
        WorkflowStep(
            name="route",
            action=lambda ctx: None,
            branch_on=_router,
        )
    )

    # ── 7a. High path: open investigation ────────────────────────────────────
    wf.add_step(
        WorkflowStep(
            name="open_investigation",
            action=_open_investigation_action(inv_service),
            on_success="transition",
            on_failure="analyst_review",
        )
    )

    # ── 7b. Low path: analyst review ─────────────────────────────────────────
    wf.add_step(
        WorkflowStep(
            name="analyst_review",
            action=_analyst_review_action(hitl),
        )
    )

    # ── 8. Transition to IN_PROGRESS (only reached via high path) ────────────
    try:
        from gnat.analysis.investigations.models import InvestigationStatus

        new_status = InvestigationStatus.IN_PROGRESS
    except ImportError:
        new_status = "in_progress"

    wf.add_step(
        transition_step(
            inv_service,
            new_status,
            note="Investigation automatically opened by autonomous pipeline.",
            author="auto-investigation-workflow",
            name="transition",
        )
    )

    return wf
