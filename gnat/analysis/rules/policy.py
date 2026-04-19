# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RuleEnginePolicy — configuration loaded from INI."""

from __future__ import annotations

import configparser
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RuleEnginePolicy:
    rule_evaluation_enabled: bool = False
    rules_dir: str = "rules"
    ai_confidence_ceiling: int = 60
    minimum_evidence_for_support: int = 3
    stale_days_default: int = 30
    fresh_days_default: int = 7
    allow_dirty_rules: bool = False

    @classmethod
    def from_ini(cls, config: configparser.ConfigParser) -> RuleEnginePolicy:
        policy = cls()
        if not config.has_section("rules"):
            return policy

        known_keys = {
            "enabled", "rules_dir", "ai_confidence_ceiling",
            "minimum_evidence_for_support", "stale_days_default",
            "fresh_days_default", "allow_dirty_rules",
        }
        for key in config.options("rules"):
            if key not in known_keys and key != "engine":
                logger.info("Unknown key in [rules] config: %s", key)

        policy.rule_evaluation_enabled = config.getboolean(
            "rules", "enabled", fallback=False
        )
        policy.rules_dir = config.get("rules", "rules_dir", fallback="rules")
        policy.ai_confidence_ceiling = config.getint(
            "rules", "ai_confidence_ceiling", fallback=60
        )
        policy.minimum_evidence_for_support = config.getint(
            "rules", "minimum_evidence_for_support", fallback=3
        )
        policy.stale_days_default = config.getint(
            "rules", "stale_days_default", fallback=30
        )
        policy.fresh_days_default = config.getint(
            "rules", "fresh_days_default", fallback=7
        )
        policy.allow_dirty_rules = config.getboolean(
            "rules", "allow_dirty_rules", fallback=False
        )

        if os.environ.get("GNAT_ALLOW_DIRTY_RULES") == "1":
            policy.allow_dirty_rules = True

        return policy
