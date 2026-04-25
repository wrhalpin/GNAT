# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analyst_services.analysis
=================================

:class:`AnalysisService` — thin orchestration wrapper over the
investigation store, timeline builder, graph query, and gap detector
domain services.

Every method accepts an :class:`AnalystContext` as its first argument,
delegates to the underlying domain service, and returns Pydantic schemas.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from gnat.analyst_services.context import AnalystContext
from gnat.analyst_services.exceptions import (
    InvestigationNotFound,
    TransitionError,
)
from gnat.schemas.analysis.copilot import GapRecommendationSchema
from gnat.schemas.analysis.graph import GraphContextSchema
from gnat.schemas.analysis.investigation import (
    AnalystNoteSchema,
    HypothesisSchema,
    InvestigationSchema,
)
from gnat.schemas.analysis.timeline import TimelineEventSchema

logger = logging.getLogger(__name__)


class AnalysisService:
    """
    Orchestration layer for investigation analysis operations.

    Parameters
    ----------
    store : InvestigationStore
        Persistence backend for investigations.
    timeline_builder : TimelineBuilder or None
        Optional timeline construction helper.
    graph_query_factory : callable or None
        Factory ``(EvidenceGraph) -> GraphQuery``; used by
        :meth:`query_graph`.
    gap_detector : GapDetector or None
        Optional gap detection engine.
    """

    def __init__(
        self,
        store: Any,
        timeline_builder: Any | None = None,
        graph_query_factory: Callable[..., Any] | None = None,
        gap_detector: Any | None = None,
    ) -> None:
        self._store = store
        self._timeline_builder = timeline_builder
        self._graph_query_factory = graph_query_factory
        self._gap_detector = gap_detector

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_investigation(self, investigation_id: str) -> Any:
        """Fetch an investigation or raise :class:`InvestigationNotFound`."""
        inv = self._store.get(investigation_id)
        if inv is None:
            raise InvestigationNotFound(f"Investigation not found: {investigation_id}")
        return inv

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def get_investigation(
        self,
        ctx: AnalystContext,
        investigation_id: str,
    ) -> InvestigationSchema:
        """
        Retrieve a single investigation by ID.

        Parameters
        ----------
        ctx : AnalystContext
        investigation_id : str

        Returns
        -------
        InvestigationSchema
        """
        logger.info(
            "AnalysisService.get_investigation: actor=%s id=%s",
            ctx.actor,
            investigation_id,
        )
        inv = self._get_investigation(investigation_id)
        return InvestigationSchema.from_domain(inv)

    def list_investigations(
        self,
        ctx: AnalystContext,
        status: str | None = None,
        tag: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[InvestigationSchema]:
        """
        List investigations with optional filters.

        Parameters
        ----------
        ctx : AnalystContext
        status : str, optional
        tag : str, optional
        limit : int
        offset : int

        Returns
        -------
        list of InvestigationSchema
        """
        logger.info(
            "AnalysisService.list_investigations: actor=%s status=%s tag=%s",
            ctx.actor,
            status,
            tag,
        )
        from gnat.analysis.investigations.models import InvestigationStatus

        status_enum = InvestigationStatus(status) if status else None
        results = self._store.list(
            status=status_enum,
            tag=tag,
            limit=limit,
            offset=offset,
        )
        return [InvestigationSchema.from_domain(inv) for inv in results]

    def create_investigation(
        self,
        ctx: AnalystContext,
        title: str,
        created_by: str | None = None,
        description: str = "",
        classification: str | None = None,
        tags: list[str] | None = None,
    ) -> InvestigationSchema:
        """
        Create a new investigation in OPEN status.

        Parameters
        ----------
        ctx : AnalystContext
        title : str
        created_by : str, optional
            Defaults to ``ctx.actor``.
        description : str
        classification : str, optional
        tags : list of str, optional

        Returns
        -------
        InvestigationSchema
        """
        logger.info(
            "AnalysisService.create_investigation: actor=%s title=%r",
            ctx.actor,
            title,
        )
        from gnat.analysis.investigations.models import Investigation
        from gnat.analysis.tlp import TLPLevel

        tlp = TLPLevel(classification) if classification else TLPLevel.AMBER
        inv = Investigation(
            title=title,
            created_by=created_by or ctx.actor,
            description=description,
            classification=tlp,
            tags=list(tags or []),
        )
        self._store.save(inv)
        return InvestigationSchema.from_domain(inv)

    # ── State machine ────────────────────────────────────────────────────────

    def transition(
        self,
        ctx: AnalystContext,
        investigation_id: str,
        new_status: str,
        note: str | None = None,
        author: str | None = None,
    ) -> InvestigationSchema:
        """
        Transition an investigation to a new lifecycle state.

        Parameters
        ----------
        ctx : AnalystContext
        investigation_id : str
        new_status : str
        note : str, optional
        author : str, optional

        Returns
        -------
        InvestigationSchema

        Raises
        ------
        TransitionError
            If the transition is invalid.
        """
        logger.info(
            "AnalysisService.transition: actor=%s id=%s new_status=%s",
            ctx.actor,
            investigation_id,
            new_status,
        )
        from gnat.analysis.investigations.models import InvestigationStatus

        inv = self._get_investigation(investigation_id)
        target = InvestigationStatus(new_status)
        if not inv.can_transition_to(target):
            raise TransitionError(
                f"Cannot transition investigation from {inv.status.value!r} to {new_status!r}."
            )
        from datetime import datetime, timezone

        inv.status = target
        inv.updated_at = datetime.now(tz=timezone.utc)
        if note and author:
            from gnat.analysis.investigations.models import AnalystNote

            inv.notes.append(AnalystNote(content=note, author=author))
        self._store.save(inv)
        return InvestigationSchema.from_domain(inv)

    # ── Hypotheses ───────────────────────────────────────────────────────────

    def add_hypothesis(
        self,
        ctx: AnalystContext,
        investigation_id: str,
        statement: str,
        confidence: float | None = None,
    ) -> HypothesisSchema:
        """
        Add an analytical hypothesis to an investigation.

        Parameters
        ----------
        ctx : AnalystContext
        investigation_id : str
        statement : str
        confidence : float, optional

        Returns
        -------
        HypothesisSchema
        """
        logger.info(
            "AnalysisService.add_hypothesis: actor=%s id=%s",
            ctx.actor,
            investigation_id,
        )
        from gnat.analysis.investigations.models import Hypothesis

        inv = self._get_investigation(investigation_id)
        hyp = Hypothesis(statement=statement)
        if confidence is not None:
            from gnat.analysis.confidence import ConfidenceScore

            hyp.confidence = ConfidenceScore(value=confidence)
        inv.hypothesis.append(hyp)
        from datetime import datetime, timezone

        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return HypothesisSchema.from_domain(hyp)

    # ── Notes ────────────────────────────────────────────────────────────────

    def add_note(
        self,
        ctx: AnalystContext,
        investigation_id: str,
        content: str,
        author: str,
    ) -> AnalystNoteSchema:
        """
        Add a markdown note to an investigation.

        Parameters
        ----------
        ctx : AnalystContext
        investigation_id : str
        content : str
        author : str

        Returns
        -------
        AnalystNoteSchema
        """
        logger.info(
            "AnalysisService.add_note: actor=%s id=%s author=%s",
            ctx.actor,
            investigation_id,
            author,
        )
        from gnat.analysis.investigations.models import AnalystNote

        inv = self._get_investigation(investigation_id)
        note = AnalystNote(content=content, author=author)
        inv.notes.append(note)
        from datetime import datetime, timezone

        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return AnalystNoteSchema.from_domain(note)

    # ── Timeline ─────────────────────────────────────────────────────────────

    def get_timeline(
        self,
        ctx: AnalystContext,
        investigation_id: str,
    ) -> list[TimelineEventSchema]:
        """
        Build a chronological timeline for an investigation.

        Parameters
        ----------
        ctx : AnalystContext
        investigation_id : str

        Returns
        -------
        list of TimelineEventSchema
        """
        logger.info(
            "AnalysisService.get_timeline: actor=%s id=%s",
            ctx.actor,
            investigation_id,
        )
        inv = self._get_investigation(investigation_id)
        if self._timeline_builder is None:
            from gnat.analysis.timeline import TimelineBuilder

            builder = TimelineBuilder()
        else:
            builder = self._timeline_builder
        events = builder.from_investigation(inv)
        return [TimelineEventSchema.from_domain(e) for e in events]

    # ── Graph query ──────────────────────────────────────────────────────────

    def query_graph(
        self,
        ctx: AnalystContext,
        graph: Any,
        node_id: str,
        hops: int = 1,
    ) -> GraphContextSchema:
        """
        Pivot from *node_id* in an evidence graph, returning the
        neighbourhood within *hops* edges.

        Parameters
        ----------
        ctx : AnalystContext
        graph : EvidenceGraph
            The evidence graph to query.
        node_id : str
        hops : int

        Returns
        -------
        GraphContextSchema
        """
        logger.info(
            "AnalysisService.query_graph: actor=%s node=%s hops=%d",
            ctx.actor,
            node_id,
            hops,
        )
        if self._graph_query_factory is not None:
            gq = self._graph_query_factory(graph)
        else:
            from gnat.analysis.graph import GraphQuery

            gq = GraphQuery(graph)
        context = gq.pivot(node_id, hops=hops)
        return GraphContextSchema.from_domain(context)

    # ── Gap detection ────────────────────────────────────────────────────────

    def detect_gaps(
        self,
        ctx: AnalystContext,
        investigation_id: str,
    ) -> list[GapRecommendationSchema]:
        """
        Run gap detection for all hypotheses in an investigation.

        Parameters
        ----------
        ctx : AnalystContext
        investigation_id : str

        Returns
        -------
        list of GapRecommendationSchema
        """
        logger.info(
            "AnalysisService.detect_gaps: actor=%s id=%s",
            ctx.actor,
            investigation_id,
        )
        inv = self._get_investigation(investigation_id)
        if self._gap_detector is None:
            from gnat.analysis.copilot.gap_detector import GapDetector

            detector = GapDetector()
        else:
            detector = self._gap_detector
        all_gaps: list[GapRecommendationSchema] = []
        for hyp in inv.hypothesis:
            gaps = detector.detect(hyp, inv)
            all_gaps.extend(GapRecommendationSchema.from_domain(g) for g in gaps)
        return all_gaps
