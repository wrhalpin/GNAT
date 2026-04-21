# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for YamlRuleEngine."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

yaml = pytest.importorskip("yaml")

from gnat.analysis.investigations.models import HypothesisStatus  # noqa: E402
from gnat.analysis.rules.decisions import DecisionAction  # noqa: E402
from gnat.analysis.rules.policy import RuleEnginePolicy  # noqa: E402
from gnat.analysis.rules.yaml_engine import YamlRuleEngine, YamlRuleLoader  # noqa: E402
from tests.unit.analysis.rules.conftest import make_hypothesis  # noqa: E402


def _store_mock():
    store = MagicMock()
    store.get_source_platform.return_value = None
    store.get_source_platforms_bulk.return_value = {}
    return store


SIMPLE_RULE_YAML = """\
rules:
  - name: test-promote
    phase: open
    priority: 100
    when:
      all:
        - supporting_count: { gte: 2 }
        - has_refutation: false
    then:
      set_status:
        target: supported
        reason: "Enough evidence"
"""

ANNOTATE_RULE_YAML = """\
rules:
  - name: test-annotate
    phase: open
    priority: 10
    when:
      all:
        - supporting_count: { lt: 2 }
    then:
      annotate:
        key: needs-evidence
        value: true
        reason: "Insufficient evidence"
"""


class TestYamlRuleLoader:
    def test_load_from_directory(self, tmp_path):
        (tmp_path / "rule.yaml").write_text(SIMPLE_RULE_YAML)
        loader = YamlRuleLoader(tmp_path)
        rules = loader.load()
        assert len(rules) == 1
        assert rules[0].name == "test-promote"
        assert rules[0].phase == "open"
        assert rules[0].priority == 100

    def test_load_yml_extension(self, tmp_path):
        (tmp_path / "rule.yml").write_text(SIMPLE_RULE_YAML)
        loader = YamlRuleLoader(tmp_path)
        rules = loader.load()
        assert len(rules) == 1

    def test_load_multiple_rules_per_file(self, tmp_path):
        combined = """\
rules:
  - name: rule-a
    phase: open
    priority: 100
    when:
      all:
        - supporting_count: { gte: 1 }
    then:
      set_status:
        target: supported
        reason: "a"
  - name: rule-b
    phase: open
    priority: 50
    when:
      all:
        - has_refutation: true
    then:
      set_status:
        target: refuted
        reason: "b"
"""
        (tmp_path / "multi.yaml").write_text(combined)
        loader = YamlRuleLoader(tmp_path)
        rules = loader.load()
        assert len(rules) == 2
        assert rules[0].priority >= rules[1].priority

    def test_empty_directory(self, tmp_path):
        loader = YamlRuleLoader(tmp_path)
        assert loader.load() == []

    def test_bad_yaml_logged_not_fatal(self, tmp_path):
        (tmp_path / "bad.yaml").write_text("not: valid: yaml: [")
        loader = YamlRuleLoader(tmp_path)
        rules = loader.load()
        assert rules == []

    def test_reload_detects_change(self, tmp_path):
        f = tmp_path / "rule.yaml"
        f.write_text(SIMPLE_RULE_YAML)
        loader = YamlRuleLoader(tmp_path)
        loader.load()
        assert loader.reload_if_changed() is False
        f.write_text(ANNOTATE_RULE_YAML)
        import os
        os.utime(f, (f.stat().st_mtime + 1, f.stat().st_mtime + 1))
        assert loader.reload_if_changed() is True


class TestYamlRuleEngine:
    def test_disabled_returns_empty(self, tmp_path):
        (tmp_path / "rule.yaml").write_text(SIMPLE_RULE_YAML)
        loader = YamlRuleLoader(tmp_path)
        policy = RuleEnginePolicy(rule_evaluation_enabled=False)
        engine = YamlRuleEngine(loader=loader, policy=policy, store=_store_mock())
        h = make_hypothesis()
        result = engine.evaluate(h, MagicMock(), 1)
        assert result.firings == []

    def test_rule_fires_on_match(self, tmp_path):
        (tmp_path / "rule.yaml").write_text(SIMPLE_RULE_YAML)
        loader = YamlRuleLoader(tmp_path)
        policy = RuleEnginePolicy(rule_evaluation_enabled=True, allow_dirty_rules=True)
        engine = YamlRuleEngine(loader=loader, policy=policy, store=_store_mock())
        h = make_hypothesis(supporting=["a", "b", "c"])
        result = engine.evaluate(h, MagicMock(), 1)
        assert len(result.firings) == 1
        assert result.primary_decision.action == DecisionAction.SET_STATUS

    def test_rule_skips_phase_mismatch(self, tmp_path):
        (tmp_path / "rule.yaml").write_text(SIMPLE_RULE_YAML)
        loader = YamlRuleLoader(tmp_path)
        policy = RuleEnginePolicy(rule_evaluation_enabled=True, allow_dirty_rules=True)
        engine = YamlRuleEngine(loader=loader, policy=policy, store=_store_mock())
        h = make_hypothesis(status=HypothesisStatus.SUPPORTED, supporting=["a", "b", "c"])
        result = engine.evaluate(h, MagicMock(), 1)
        assert len(result.firings) == 0

    def test_annotate_rule(self, tmp_path):
        (tmp_path / "rule.yaml").write_text(ANNOTATE_RULE_YAML)
        loader = YamlRuleLoader(tmp_path)
        policy = RuleEnginePolicy(rule_evaluation_enabled=True, allow_dirty_rules=True)
        engine = YamlRuleEngine(loader=loader, policy=policy, store=_store_mock())
        h = make_hypothesis(supporting=["a"])
        result = engine.evaluate(h, MagicMock(), 1)
        assert len(result.firings) == 1
        assert result.firings[0].decision.action == DecisionAction.ANNOTATE

    def test_transition_slot_consumed(self, tmp_path):
        two_rules = """\
rules:
  - name: first
    phase: open
    priority: 100
    when:
      all:
        - is_open: true
    then:
      set_status:
        target: supported
        reason: "first"
  - name: second
    phase: open
    priority: 50
    when:
      all:
        - is_open: true
    then:
      set_status:
        target: refuted
        reason: "second"
"""
        (tmp_path / "rules.yaml").write_text(two_rules)
        loader = YamlRuleLoader(tmp_path)
        policy = RuleEnginePolicy(rule_evaluation_enabled=True, allow_dirty_rules=True)
        engine = YamlRuleEngine(loader=loader, policy=policy, store=_store_mock())
        h = make_hypothesis()
        result = engine.evaluate(h, MagicMock(), 1)
        assert len(result.firings) == 1
        assert result.firings[0].rule_name == "first"
