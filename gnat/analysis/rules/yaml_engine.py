# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.yaml_engine
===================================

YAML-based rule engine — declarative rules without code authoring.
Analysts define conditions referencing the 26 Python helpers by name.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gnat.analysis.rules.audit import git_file_is_clean, rule_file_sha
from gnat.analysis.rules.context import RuleContext
from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.rules.registry import RegisteredRule
from gnat.analysis.rules.resolver import EvidenceResolver
from gnat.analysis.rules.result import RuleEvaluationResult, RuleFiring
from gnat.analysis.rules.yaml_condition import compile_action, compile_condition

logger = logging.getLogger(__name__)

ENGINE_VERSION = "1.0.0-yaml"

_YAML_AVAILABLE = False
try:
    import yaml  # noqa: F401

    _YAML_AVAILABLE = True
except ImportError:
    pass


class YamlRuleLoader:
    """Load rules from YAML files."""

    def __init__(self, rules_dir: str | Path) -> None:
        self._rules_dir = Path(rules_dir)
        self._rules: list[RegisteredRule] = []
        self._mtimes: dict[Path, float] = {}

    @property
    def rules(self) -> list[RegisteredRule]:
        return list(self._rules)

    def load(self) -> list[RegisteredRule]:
        if not _YAML_AVAILABLE:
            logger.warning(
                "pyyaml is not installed — YAML rule loading skipped. "
                "Install with: pip install pyyaml"
            )
            return []

        self._rules = []
        if not self._rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", self._rules_dir)
            return []

        for yaml_file in sorted(self._rules_dir.rglob("*.yaml")):
            self._load_file(yaml_file)
        for yml_file in sorted(self._rules_dir.rglob("*.yml")):
            self._load_file(yml_file)

        self._rules.sort(key=lambda r: -r.priority)
        return list(self._rules)

    def reload_if_changed(self) -> bool:
        if not _YAML_AVAILABLE or not self._rules_dir.exists():
            return False

        patterns = list(self._rules_dir.rglob("*.yaml")) + list(self._rules_dir.rglob("*.yml"))
        current_files = set(patterns)
        tracked_files = set(self._mtimes.keys())

        if current_files != tracked_files:
            self.load()
            return True

        for f in current_files:
            if f.stat().st_mtime != self._mtimes.get(f):
                self.load()
                return True

        return False

    def _load_file(self, yaml_file: Path) -> None:
        import yaml as _yaml

        try:
            with open(yaml_file) as fh:
                data = _yaml.safe_load(fh)

            if not isinstance(data, dict) or "rules" not in data:
                logger.error("YAML rule file %s missing 'rules' key", yaml_file)
                return

            for rule_spec in data["rules"]:
                self._parse_rule(rule_spec, yaml_file)

            self._mtimes[yaml_file] = yaml_file.stat().st_mtime

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load YAML rule file %s: %s", yaml_file, exc)

    def _parse_rule(self, spec: dict[str, Any], source_file: Path) -> None:
        name = spec.get("name")
        if not name:
            raise ValueError(f"Rule in {source_file} missing 'name'")

        when_spec = spec.get("when")
        then_spec = spec.get("then")
        if not when_spec:
            raise ValueError(f"Rule {name!r} missing 'when'")
        if not then_spec:
            raise ValueError(f"Rule {name!r} missing 'then'")

        when_fn = compile_condition(when_spec)
        then_fn = compile_action(then_spec)

        self._rules.append(
            RegisteredRule(
                name=name,
                description=spec.get("description", ""),
                phase=spec.get("phase"),
                target_status=spec.get("target_status"),
                priority=int(spec.get("priority", 50)),
                tags=list(spec.get("tags") or []),
                when_fn=when_fn,
                then_fn=then_fn,
                source_file=str(source_file),
            )
        )


class YamlRuleEngine:
    """YAML-based rule engine implementing RuleEngineProtocol."""

    def __init__(
        self,
        loader: YamlRuleLoader,
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
                continue

            try:
                if not rule.when_fn(hypothesis, ctx):
                    continue
                decision = rule.then_fn(hypothesis, ctx)
            except Exception as exc:  # noqa: BLE001
                logger.error("YAML rule %s raised: %s", rule.name, exc)
                result.errors.append((rule.name, str(exc)))
                continue

            if decision is None:
                continue

            if decision.consumes_transition_slot():
                if transition_consumed:
                    continue
                transition_consumed = True

            result.firings.append(
                RuleFiring(
                    rule_name=rule.name,
                    rule_source_file=str(rule.source_file),
                    rule_git_sha=rule_file_sha(rule.source_file) if rule.source_file else None,
                    decision=decision,
                )
            )

        return result
