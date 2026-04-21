# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.factory
===============================

Factory function for creating rule engine instances from INI config.
Supports hy (default), yaml, and prolog engines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from gnat.analysis.rules.policy import RuleEnginePolicy

_SUPPORTED_ENGINES = {"hy", "yaml", "prolog"}


def create_engine(
    config: Any,
    policy: RuleEnginePolicy | None = None,
    store: Any = None,
) -> Any:
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

    rules_dir = Path(policy.rules_dir)

    if engine_name == "yaml":
        from gnat.analysis.rules.yaml_engine import YamlRuleEngine, YamlRuleLoader

        loader = YamlRuleLoader(rules_dir)
        return YamlRuleEngine(loader=loader, policy=policy, store=store)

    if engine_name == "prolog":
        from gnat.analysis.rules.prolog_engine import PrologRuleEngine, PrologRuleLoader

        loader = PrologRuleLoader(rules_dir)
        return PrologRuleEngine(loader=loader, policy=policy, store=store)

    from gnat.analysis.rules.engine import AnalysisRuleEngine
    from gnat.analysis.rules.loader import RuleLoader

    loader = RuleLoader(rules_dir)
    return AnalysisRuleEngine(loader=loader, policy=policy, store=store)
