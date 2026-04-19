# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.orchestrator
====================================

Bridges the rule engine and InvestigationService. Runs evaluation,
writes audit records (audit-first), then applies the primary decision.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.analysis.rules.audit import AuditWriter
from gnat.analysis.rules.decisions import SetStatusDecision
from gnat.analysis.rules.engine import AnalysisRuleEngine
from gnat.analysis.rules.policy import RuleEnginePolicy

logger = logging.getLogger(__name__)


class RuleOrchestrator:
    """Apply rule decisions via InvestigationService."""

    def __init__(
        self,
        engine: AnalysisRuleEngine,
        inv_service: Any,
        audit_writer: AuditWriter,
        policy: RuleEnginePolicy,
    ) -> None:
        self._engine = engine
        self._service = inv_service
        self._audit = audit_writer
        self._policy = policy

    def on_hypothesis_changed(
        self,
        investigation_id: str,
        hypothesis_id: str,
        workspace_id: int,
    ) -> None:
        if not self._policy.rule_evaluation_enabled:
            return

        inv = self._service.get(investigation_id)
        hyp_list = getattr(inv, "hypothesis", [])
        hyp = next((h for h in hyp_list if h.id == hypothesis_id), None)
        if hyp is None:
            logger.warning(
                "Hypothesis %s not found in investigation %s",
                hypothesis_id,
                investigation_id,
            )
            return

        result = self._engine.evaluate(hyp, inv, workspace_id)
        if not result.firings:
            return

        audit_ids = self._audit.record_firing(result, hyp, inv, workspace_id)

        primary = result.primary_decision
        if isinstance(primary, SetStatusDecision):
            try:
                self._service.update_hypothesis_status(
                    investigation_id=investigation_id,
                    hypothesis_id=hypothesis_id,
                    new_status=primary.target_status,
                    confidence=None,
                )
                for audit_id in audit_ids:
                    self._audit.mark_applied(audit_id)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to apply rule decision for hypothesis %s: %s",
                    hypothesis_id,
                    exc,
                )
                for audit_id in audit_ids:
                    self._audit.mark_applied(audit_id, error_message=str(exc))
