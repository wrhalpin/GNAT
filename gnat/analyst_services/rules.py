# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analyst_services.rules
===============================

:class:`RulesService` — thin orchestration wrapper over the analysis
rule engine, rule loader, and audit writer.

Every method accepts an :class:`AnalystContext` as its first argument,
delegates to the underlying domain service, and returns Pydantic-compatible
data structures.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.analyst_services.context import AnalystContext

logger = logging.getLogger(__name__)


class RulesService:
    """
    Orchestration layer for analysis rule evaluation and audit.

    Parameters
    ----------
    engine : AnalysisRuleEngine
        The rule evaluation engine.
    loader : RuleLoader
        Discovers and loads rule files.
    audit_writer : AuditWriter
        Records rule firing audit trails.
    """

    def __init__(
        self,
        engine: Any,
        loader: Any,
        audit_writer: Any,
    ) -> None:
        self._engine = engine
        self._loader = loader
        self._audit_writer = audit_writer

    def list_rules(
        self,
        ctx: AnalystContext,
    ) -> list[dict[str, Any]]:
        """
        List all currently loaded rules.

        Parameters
        ----------
        ctx : AnalystContext

        Returns
        -------
        list of dict
            Each dict contains ``name``, ``description``, ``phase``,
            ``priority``, ``tags``, and ``source_file``.
        """
        logger.info(
            "RulesService.list_rules: actor=%s",
            ctx.actor,
        )
        self._loader.reload_if_changed()
        rules = self._loader.rules or self._loader.load()
        return [
            {
                "name": r.name,
                "description": r.description,
                "phase": r.phase,
                "priority": r.priority,
                "tags": r.tags,
                "source_file": str(r.source_file),
            }
            for r in rules
        ]

    def evaluate(
        self,
        ctx: AnalystContext,
        hypothesis: Any,
        context: Any,
        workspace_id: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Evaluate all rules against a hypothesis and record audit entries.

        Parameters
        ----------
        ctx : AnalystContext
        hypothesis : Hypothesis
            The hypothesis to evaluate.
        context : Investigation
            The investigation providing evidence context.
        workspace_id : int

        Returns
        -------
        list of dict
            Audit entries produced by the evaluation.
        """
        logger.info(
            "RulesService.evaluate: actor=%s hypothesis=%s",
            ctx.actor,
            getattr(hypothesis, "id", "?"),
        )
        result = self._engine.evaluate(
            hypothesis=hypothesis,
            investigation=context,
            workspace_id=workspace_id,
        )
        self._audit_writer.record_firing(
            result=result,
            hypothesis=hypothesis,
            investigation=context,
            workspace_id=workspace_id,
        )
        return [
            {
                "rule_name": f.rule_name,
                "rule_source_file": f.rule_source_file,
                "rule_git_sha": f.rule_git_sha,
                "decision": {
                    "action": (
                        f.decision.action.value
                        if hasattr(f.decision.action, "value")
                        else str(f.decision.action)
                    ),
                    "reason": getattr(f.decision, "reason", ""),
                },
            }
            for f in result.firings
        ]

    def get_audit_trail(
        self,
        ctx: AnalystContext,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve the audit trail of rule firings.

        Parameters
        ----------
        ctx : AnalystContext
        filters : dict, optional
            Currently unused; reserved for future filtering by
            investigation_id, hypothesis_id, etc.

        Returns
        -------
        list of dict
            Raw audit records from the audit writer's memory log.
        """
        logger.info(
            "RulesService.get_audit_trail: actor=%s",
            ctx.actor,
        )
        return list(self._audit_writer.memory_log)
