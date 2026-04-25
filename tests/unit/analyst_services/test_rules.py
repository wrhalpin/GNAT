# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for :mod:`gnat.analyst_services.rules`."""

from __future__ import annotations

from unittest.mock import MagicMock

from gnat.analyst_services.context import AnalystContext
from gnat.analyst_services.rules import RulesService

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_ctx(actor: str = "analyst@test.com") -> AnalystContext:
    return AnalystContext(actor=actor, tenant="t1", request_id="req-1")


def _make_registered_rule(name: str = "test-rule", **overrides):
    """Create a mock RegisteredRule."""
    rule = MagicMock()
    defaults = {
        "name": name,
        "description": "A test rule",
        "phase": "open",
        "priority": 50,
        "tags": ["test"],
        "source_file": "/rules/test.hy",
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(rule, k, v)
    return rule


def _make_rule_firing(rule_name: str = "test-rule"):
    """Create a mock RuleFiring."""
    firing = MagicMock()
    firing.rule_name = rule_name
    firing.rule_source_file = "/rules/test.hy"
    firing.rule_git_sha = "abc123"
    firing.decision.action.value = "annotate"
    firing.decision.reason = "Test reason"
    return firing


# ── Tests: list_rules ────────────────────────────────────────────────────────


class TestListRules:
    def test_returns_rule_dicts(self):
        rule = _make_registered_rule(name="rule-1")
        mock_loader = MagicMock()
        mock_loader.rules = [rule]
        mock_loader.reload_if_changed.return_value = False

        svc = RulesService(engine=MagicMock(), loader=mock_loader, audit_writer=MagicMock())
        result = svc.list_rules(_make_ctx())
        assert len(result) == 1
        assert result[0]["name"] == "rule-1"
        assert result[0]["description"] == "A test rule"
        assert result[0]["priority"] == 50

    def test_loads_rules_if_none(self):
        mock_loader = MagicMock()
        mock_loader.rules = []
        rule = _make_registered_rule(name="loaded-rule")
        mock_loader.load.return_value = [rule]

        svc = RulesService(engine=MagicMock(), loader=mock_loader, audit_writer=MagicMock())
        result = svc.list_rules(_make_ctx())
        mock_loader.load.assert_called_once()
        assert len(result) == 1
        assert result[0]["name"] == "loaded-rule"

    def test_calls_reload_if_changed(self):
        mock_loader = MagicMock()
        rule = _make_registered_rule()
        mock_loader.rules = [rule]

        svc = RulesService(engine=MagicMock(), loader=mock_loader, audit_writer=MagicMock())
        svc.list_rules(_make_ctx())
        mock_loader.reload_if_changed.assert_called_once()


# ── Tests: evaluate ──────────────────────────────────────────────────────────


class TestEvaluate:
    def test_returns_audit_entries(self):
        firing = _make_rule_firing(rule_name="eval-rule")
        mock_result = MagicMock()
        mock_result.firings = [firing]

        mock_engine = MagicMock()
        mock_engine.evaluate.return_value = mock_result

        mock_audit = MagicMock()
        mock_audit.record_firing.return_value = [1]

        svc = RulesService(engine=mock_engine, loader=MagicMock(), audit_writer=mock_audit)
        hypothesis = MagicMock()
        hypothesis.id = "hyp-1"
        investigation = MagicMock()

        result = svc.evaluate(_make_ctx(), hypothesis, investigation)
        assert len(result) == 1
        assert result[0]["rule_name"] == "eval-rule"
        mock_engine.evaluate.assert_called_once()
        mock_audit.record_firing.assert_called_once()

    def test_delegates_to_engine(self):
        mock_result = MagicMock()
        mock_result.firings = []
        mock_engine = MagicMock()
        mock_engine.evaluate.return_value = mock_result
        mock_audit = MagicMock()

        svc = RulesService(engine=mock_engine, loader=MagicMock(), audit_writer=mock_audit)
        hypothesis = MagicMock()
        investigation = MagicMock()

        svc.evaluate(_make_ctx(), hypothesis, investigation, workspace_id=42)
        mock_engine.evaluate.assert_called_once_with(
            hypothesis=hypothesis,
            investigation=investigation,
            workspace_id=42,
        )


# ── Tests: get_audit_trail ───────────────────────────────────────────────────


class TestGetAuditTrail:
    def test_returns_memory_log(self):
        mock_audit = MagicMock()
        mock_audit.memory_log = [
            {"id": 1, "rule_name": "r1", "applied": False},
            {"id": 2, "rule_name": "r2", "applied": True},
        ]
        svc = RulesService(engine=MagicMock(), loader=MagicMock(), audit_writer=mock_audit)
        result = svc.get_audit_trail(_make_ctx())
        assert len(result) == 2
        assert result[0]["rule_name"] == "r1"

    def test_returns_empty_list_when_no_entries(self):
        mock_audit = MagicMock()
        mock_audit.memory_log = []
        svc = RulesService(engine=MagicMock(), loader=MagicMock(), audit_writer=mock_audit)
        result = svc.get_audit_trail(_make_ctx())
        assert result == []
