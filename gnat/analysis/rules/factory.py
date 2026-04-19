# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.factory
===============================

Factory function for creating rule engine instances from INI config.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from gnat.analysis.rules.engine import AnalysisRuleEngine
from gnat.analysis.rules.loader import RuleLoader
from gnat.analysis.rules.policy import RuleEnginePolicy

_SUPPORTED_ENGINES = {"hy"}


def create_engine(
    config: Any,
    policy: RuleEnginePolicy | None = None,
    store: Any = None,
) -> AnalysisRuleEngine:
    """
    Create a rule engine from INI configuration.

    Parameters
    ----------
    config : configparser.ConfigParser
        GNAT configuration.
    policy : RuleEnginePolicy, optional
        If not provided, built from ``config`` via ``RuleEnginePolicy.from_ini``.
    store : WorkspaceStore, optional
        For evidence resolution. Can be None if rules don't use source helpers.
    """
    if policy is None:
        policy = RuleEnginePolicy.from_ini(config)

    engine_name = "hy"
    if hasattr(config, "get") and hasattr(config, "has_section") and config.has_section("rules"):
        engine_name = config.get("rules", "engine", fallback="hy")

    if engine_name not in _SUPPORTED_ENGINES:
        raise ValueError(
            f"Unknown rule engine {engine_name!r}. "
            f"Supported: {sorted(_SUPPORTED_ENGINES)}"
        )

    loader = RuleLoader(Path(policy.rules_dir))
    return AnalysisRuleEngine(loader=loader, policy=policy, store=store)
