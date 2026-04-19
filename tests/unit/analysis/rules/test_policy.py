# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for RuleEnginePolicy."""

from __future__ import annotations

import configparser

from gnat.analysis.rules.policy import RuleEnginePolicy


class TestRuleEnginePolicy:
    def test_defaults(self):
        p = RuleEnginePolicy()
        assert p.rule_evaluation_enabled is False
        assert p.ai_confidence_ceiling == 60
        assert p.minimum_evidence_for_support == 3
        assert p.stale_days_default == 30
        assert p.fresh_days_default == 7
        assert p.allow_dirty_rules is False
        assert p.rules_dir == "rules"

    def test_from_ini_present_section(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("""
[rules]
enabled = true
rules_dir = /opt/gnat/rules
ai_confidence_ceiling = 50
minimum_evidence_for_support = 5
stale_days_default = 60
fresh_days_default = 3
allow_dirty_rules = true
""")
        p = RuleEnginePolicy.from_ini(cfg)
        assert p.rule_evaluation_enabled is True
        assert p.rules_dir == "/opt/gnat/rules"
        assert p.ai_confidence_ceiling == 50
        assert p.minimum_evidence_for_support == 5
        assert p.stale_days_default == 60
        assert p.fresh_days_default == 3
        assert p.allow_dirty_rules is True

    def test_from_ini_missing_section(self):
        cfg = configparser.ConfigParser()
        p = RuleEnginePolicy.from_ini(cfg)
        assert p.rule_evaluation_enabled is False
        assert p.ai_confidence_ceiling == 60

    def test_from_ini_partial_section(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("""
[rules]
enabled = true
""")
        p = RuleEnginePolicy.from_ini(cfg)
        assert p.rule_evaluation_enabled is True
        assert p.ai_confidence_ceiling == 60

    def test_env_var_overrides_ini(self, monkeypatch):
        cfg = configparser.ConfigParser()
        cfg.read_string("""
[rules]
allow_dirty_rules = false
""")
        monkeypatch.setenv("GNAT_ALLOW_DIRTY_RULES", "1")
        p = RuleEnginePolicy.from_ini(cfg)
        assert p.allow_dirty_rules is True

    def test_env_var_not_set_respects_ini(self, monkeypatch):
        monkeypatch.delenv("GNAT_ALLOW_DIRTY_RULES", raising=False)
        cfg = configparser.ConfigParser()
        cfg.read_string("""
[rules]
allow_dirty_rules = false
""")
        p = RuleEnginePolicy.from_ini(cfg)
        assert p.allow_dirty_rules is False
