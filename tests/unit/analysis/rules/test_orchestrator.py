# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for RuleOrchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock

from gnat.analysis.investigations.models import HypothesisStatus
from gnat.analysis.rules.audit import AuditWriter
from gnat.analysis.rules.decisions import annotate, set_status
from gnat.analysis.rules.engine import AnalysisRuleEngine
from gnat.analysis.rules.orchestrator import RuleOrchestrator
from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.rules.result import RuleEvaluationResult, RuleFiring
from tests.unit.analysis.rules.conftest import make_hypothesis


def _make_orchestrator(
    result=None,
    enabled=True,
    service_error=None,
):
    engine = MagicMock(spec=AnalysisRuleEngine)
    engine.evaluate.return_value = result or RuleEvaluationResult()

    service = MagicMock()
    hyp = make_hypothesis()
    inv = MagicMock()
    inv.id = "inv-1"
    inv.hypothesis = [hyp]
    service.get.return_value = inv
    if service_error:
        service.update_hypothesis_status.side_effect = service_error

    audit = AuditWriter()
    policy = RuleEnginePolicy(rule_evaluation_enabled=enabled)

    orch = RuleOrchestrator(
        engine=engine,
        inv_service=service,
        audit_writer=audit,
        policy=policy,
    )
    return orch, service, audit, hyp


class TestRuleOrchestrator:
    def test_disabled_is_noop(self):
        orch, service, audit, hyp = _make_orchestrator(enabled=False)
        orch.on_hypothesis_changed("inv-1", hyp.id, workspace_id=1)
        service.get.assert_not_called()

    def test_missing_hypothesis_warns(self):
        orch, service, audit, hyp = _make_orchestrator()
        orch.on_hypothesis_changed("inv-1", "nonexistent", workspace_id=1)
        service.update_hypothesis_status.assert_not_called()

    def test_empty_result_no_audit(self):
        orch, service, audit, hyp = _make_orchestrator(result=RuleEvaluationResult())
        orch.on_hypothesis_changed("inv-1", hyp.id, workspace_id=1)
        assert len(audit.memory_log) == 0

    def test_set_status_applied(self):
        result = RuleEvaluationResult()
        result.firings.append(
            RuleFiring(
                rule_name="promote",
                rule_source_file="test.hy",
                rule_git_sha=None,
                decision=set_status("supported", "strong evidence"),
            )
        )
        orch, service, audit, hyp = _make_orchestrator(result=result)
        orch.on_hypothesis_changed("inv-1", hyp.id, workspace_id=1)
        service.update_hypothesis_status.assert_called_once_with(
            investigation_id="inv-1",
            hypothesis_id=hyp.id,
            new_status=HypothesisStatus.SUPPORTED,
            confidence=None,
        )
        assert len(audit.memory_log) == 1
        assert audit.memory_log[0]["applied"] is True

    def test_annotation_no_service_call(self):
        result = RuleEvaluationResult()
        result.firings.append(
            RuleFiring(
                rule_name="annotate",
                rule_source_file="test.hy",
                rule_git_sha=None,
                decision=annotate("flag", "v"),
            )
        )
        orch, service, audit, hyp = _make_orchestrator(result=result)
        orch.on_hypothesis_changed("inv-1", hyp.id, workspace_id=1)
        service.update_hypothesis_status.assert_not_called()
        assert len(audit.memory_log) == 1

    def test_service_error_recorded(self):
        result = RuleEvaluationResult()
        result.firings.append(
            RuleFiring(
                rule_name="promote",
                rule_source_file="test.hy",
                rule_git_sha=None,
                decision=set_status("supported"),
            )
        )
        orch, service, audit, hyp = _make_orchestrator(
            result=result,
            service_error=RuntimeError("db error"),
        )
        orch.on_hypothesis_changed("inv-1", hyp.id, workspace_id=1)
        assert audit.memory_log[0]["error_message"] == "db error"
        assert audit.memory_log[0]["applied"] is False

    def test_audit_first_pattern(self):
        result = RuleEvaluationResult()
        result.firings.append(
            RuleFiring(
                rule_name="promote",
                rule_source_file="test.hy",
                rule_git_sha=None,
                decision=set_status("supported"),
            )
        )
        orch, service, audit, hyp = _make_orchestrator(result=result)
        orch.on_hypothesis_changed("inv-1", hyp.id, workspace_id=1)
        assert len(audit.memory_log) == 1
        assert audit.memory_log[0]["id"] is not None
