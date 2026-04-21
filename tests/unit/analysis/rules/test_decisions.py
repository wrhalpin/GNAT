# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for decision types and factory functions."""

from __future__ import annotations

from gnat.analysis.investigations.models import HypothesisStatus
from gnat.analysis.rules.decisions import (
    DecisionAction,
    annotate,
    no_op,
    set_status,
)


class TestDecisions:
    def test_set_status_from_enum(self):
        d = set_status(HypothesisStatus.SUPPORTED, "strong evidence")
        assert d.action == DecisionAction.SET_STATUS
        assert d.target_status == HypothesisStatus.SUPPORTED
        assert d.reason == "strong evidence"
        assert d.should_mutate()
        assert d.consumes_transition_slot()

    def test_set_status_from_string(self):
        d = set_status("refuted", "contradicting data")
        assert d.target_status == HypothesisStatus.REFUTED

    def test_annotate_decision(self):
        d = annotate("flag", "needs-review", reason="low confidence")
        assert d.action == DecisionAction.ANNOTATE
        assert d.key == "flag"
        assert d.value == "needs-review"
        assert not d.should_mutate()
        assert not d.consumes_transition_slot()

    def test_no_op_decision(self):
        d = no_op("waiting for more evidence")
        assert d.action == DecisionAction.NO_OP
        assert not d.should_mutate()
        assert d.consumes_transition_slot()

    def test_decisions_are_frozen(self):
        d = set_status("supported")
        import pytest

        with pytest.raises(AttributeError):
            d.reason = "changed"

    def test_timestamp_populated(self):
        d = set_status("supported")
        assert d.timestamp is not None


class TestRuleEvaluationResult:
    def test_primary_decision_is_first_set_status(self):
        from gnat.analysis.rules.result import RuleEvaluationResult, RuleFiring

        result = RuleEvaluationResult()
        result.firings.append(
            RuleFiring(
                rule_name="annotate-rule",
                rule_source_file="a.hy",
                rule_git_sha=None,
                decision=annotate("k", "v"),
            )
        )
        result.firings.append(
            RuleFiring(
                rule_name="status-rule",
                rule_source_file="b.hy",
                rule_git_sha=None,
                decision=set_status("supported"),
            )
        )
        assert result.primary_decision is not None
        assert result.primary_decision.action == DecisionAction.SET_STATUS

    def test_primary_decision_none_when_only_annotations(self):
        from gnat.analysis.rules.result import RuleEvaluationResult, RuleFiring

        result = RuleEvaluationResult()
        result.firings.append(
            RuleFiring(
                rule_name="annotate-rule",
                rule_source_file="a.hy",
                rule_git_sha=None,
                decision=annotate("k", "v"),
            )
        )
        assert result.primary_decision is None

    def test_empty_result(self):
        from gnat.analysis.rules.result import RuleEvaluationResult

        result = RuleEvaluationResult()
        assert result.primary_decision is None
        assert result.firings == []
        assert result.errors == []
