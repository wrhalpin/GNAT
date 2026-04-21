# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.engine
==============================

AnalysisRuleEngine — evaluates rules against hypotheses and returns
decisions without mutating state. The orchestrator applies decisions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.rules.audit import git_file_is_clean, rule_file_sha
from gnat.analysis.rules.context import RuleContext
from gnat.analysis.rules.loader import RuleLoader
from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.rules.resolver import EvidenceResolver
from gnat.analysis.rules.result import RuleEvaluationResult, RuleFiring

logger = logging.getLogger(__name__)

ENGINE_VERSION = "1.0.0"


class AnalysisRuleEngine:
    """Evaluate rules against a hypothesis and return decisions."""

    def __init__(
        self,
        loader: RuleLoader,
        policy: RuleEnginePolicy,
        store: Any,
    ) -> None:
        self._loader = loader
        self._policy = policy
        self._store = store

    def evaluate(
        self,
        hypothesis: Any,
        investigation: Any,
        workspace_id: int,
    ) -> RuleEvaluationResult:
        if not self._policy.rule_evaluation_enabled:
            return RuleEvaluationResult()

        self._loader.reload_if_changed()
        rules = self._loader.rules or self._loader.load()

        resolver = EvidenceResolver(workspace_id=workspace_id, store=self._store)
        ctx = RuleContext(
            resolver=resolver,
            policy=self._policy,
            now=datetime.now(timezone.utc),
            workspace_id=workspace_id,
            engine_version=ENGINE_VERSION,
        )

        result = RuleEvaluationResult()
        transition_consumed = False

        for rule in rules:
            hyp_status = hypothesis.status
            status_val = hyp_status.value if hasattr(hyp_status, "value") else str(hyp_status)
            if rule.phase is not None and status_val != rule.phase:
                continue

            if (
                not self._policy.allow_dirty_rules
                and rule.source_file
                and not git_file_is_clean(rule.source_file)
            ):
                logger.warning(
                    "Skipping rule %s: source file %s has uncommitted changes",
                    rule.name,
                    rule.source_file,
                )
                continue

            try:
                if not rule.when_fn(hypothesis, ctx):
                    continue
                decision = rule.then_fn(hypothesis, ctx)
            except Exception as exc:  # noqa: BLE001
                logger.error("Rule %s raised during evaluation: %s", rule.name, exc)
                result.errors.append((rule.name, str(exc)))
                continue

            if decision is None:
                continue

            if decision.consumes_transition_slot():
                if transition_consumed:
                    continue
                transition_consumed = True

            firing = RuleFiring(
                rule_name=rule.name,
                rule_source_file=str(rule.source_file),
                rule_git_sha=rule_file_sha(rule.source_file) if rule.source_file else None,
                decision=decision,
            )
            result.firings.append(firing)

        return result
