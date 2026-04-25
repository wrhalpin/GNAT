# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analyst_services.investigations
========================================

:class:`InvestigationsService` — thin orchestration wrapper over the
:class:`~gnat.investigations.builder.InvestigationBuilder` evidence graph
pipeline.

Every method accepts an :class:`AnalystContext` as its first argument,
delegates to the underlying domain service, and returns Pydantic schemas.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.analyst_services.context import AnalystContext
from gnat.schemas.investigations import EvidenceGraphSchema

logger = logging.getLogger(__name__)


class InvestigationsService:
    """
    Orchestration layer for evidence graph construction.

    Parameters
    ----------
    builder : InvestigationBuilder
        The domain builder that runs the five-step evidence graph
        pipeline.
    """

    def __init__(self, builder: Any) -> None:
        self._builder = builder

    def build(
        self,
        ctx: AnalystContext,
        seeds: list[dict[str, Any]],
        title: str = "Investigation",
        expand_depth: int = 1,
    ) -> EvidenceGraphSchema:
        """
        Run the evidence graph pipeline from a set of seeds.

        Parameters
        ----------
        ctx : AnalystContext
        seeds : list of dict
            Each dict should have ``value``, ``seed_type``, and optionally
            ``hint_platform``.
        title : str
        expand_depth : int

        Returns
        -------
        EvidenceGraphSchema
        """
        logger.info(
            "InvestigationsService.build: actor=%s title=%r seeds=%d",
            ctx.actor,
            title,
            len(seeds),
        )
        from gnat.investigations.model import Seed, SeedType

        seed_objects = [
            Seed(
                value=s["value"],
                seed_type=SeedType(s["seed_type"]),
                hint_platform=s.get("hint_platform"),
            )
            for s in seeds
        ]
        graph = self._builder.build(
            seeds=seed_objects,
            title=title,
            expand_depth=expand_depth,
        )
        return EvidenceGraphSchema.from_domain(graph)

    def get_graph_summary(
        self,
        ctx: AnalystContext,
        graph: Any,
    ) -> dict[str, Any]:
        """
        Return a compact summary dict for an evidence graph.

        Parameters
        ----------
        ctx : AnalystContext
        graph : EvidenceGraph
            The evidence graph to summarise.

        Returns
        -------
        dict
        """
        logger.info(
            "InvestigationsService.get_graph_summary: actor=%s",
            ctx.actor,
        )
        return graph.summary()
