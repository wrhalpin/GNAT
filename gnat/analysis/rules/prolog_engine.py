# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.prolog_engine
====================================

Prolog-based rule engine — logic programming for complex inference.
Uses pyswip (SWI-Prolog bridge) for in-process evaluation.

Install with ``pip install "gnat[rules-prolog]"``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gnat.analysis.rules.audit import git_file_is_clean, rule_file_sha
from gnat.analysis.rules.context import RuleContext
from gnat.analysis.rules.decisions import annotate, no_op, set_status
from gnat.analysis.rules.helpers import (
    confidence as _cf,
)
from gnat.analysis.rules.helpers import (
    evidence as _ev,
)
from gnat.analysis.rules.helpers import (
    source as _sr,
)
from gnat.analysis.rules.helpers import (
    temporal as _tm,
)
from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.rules.registry import RegisteredRule
from gnat.analysis.rules.resolver import EvidenceResolver
from gnat.analysis.rules.result import RuleEvaluationResult, RuleFiring

logger = logging.getLogger(__name__)

ENGINE_VERSION = "1.0.0-prolog"
_HELPERS_PL = Path(__file__).parent / "prolog_helpers.pl"

_PYSWIP_AVAILABLE = False
try:
    from pyswip import Prolog as _Prolog  # noqa: F401

    _PYSWIP_AVAILABLE = True
except ImportError:
    pass


def _assert_hypothesis_facts(prolog: Any, h: Any, ctx: Any) -> None:
    """Assert temporary facts about a hypothesis into the Prolog KB."""
    status = h.status.value if hasattr(h.status, "value") else str(h.status)
    prolog.assertz(f"hypothesis_status({status})")
    prolog.assertz(f"supporting_count({_ev.supporting_count(h)})")
    prolog.assertz(f"refuting_count({_ev.refuting_count(h)})")
    prolog.assertz(f"stix_confidence({_cf.stix_confidence(h)})")
    prolog.assertz(f"days_since_update({_tm.days_since_update(h)})")
    prolog.assertz(f"age_days({_tm.age_days(h)})")

    rel = _cf.reliability_of(h)
    if rel:
        prolog.assertz(f"reliability('{rel}')")
    cred = _cf.credibility_of(h)
    if cred is not None:
        prolog.assertz(f"credibility({cred})")

    prolog.assertz(f"ai_confidence_ceiling({ctx.policy.ai_confidence_ceiling})")

    if _sr.ai_only(h, ctx):
        prolog.assertz("ai_only")
    if _sr.has_trusted_evidence(h, ctx):
        prolog.assertz("trusted_source_present")


def _retract_hypothesis_facts(prolog: Any) -> None:
    """Retract all temporary hypothesis facts."""
    for pred in [
        "hypothesis_status/1",
        "supporting_count/1",
        "refuting_count/1",
        "stix_confidence/1",
        "days_since_update/1",
        "age_days/1",
        "reliability/1",
        "credibility/1",
        "ai_confidence_ceiling/1",
        "ai_only/0",
        "trusted_source_present/0",
    ]:
        import contextlib

        with contextlib.suppress(Exception):
            prolog.retractall(pred.split("/")[0] + "(_)" if "/1" in pred else pred.split("/")[0])


def _parse_action(action_term: Any) -> Any:
    """Convert a Prolog action term to a Python Decision."""
    s = str(action_term)
    if s.startswith("set_status("):
        inner = s[len("set_status(") : -1]
        parts = inner.split(",", 1)
        target = parts[0].strip().strip("'")
        reason = parts[1].strip().strip("'") if len(parts) > 1 else ""
        return set_status(target, reason)
    if s.startswith("annotate("):
        inner = s[len("annotate(") : -1]
        parts = inner.split(",", 2)
        key = parts[0].strip().strip("'")
        value = parts[1].strip().strip("'") if len(parts) > 1 else ""
        reason = parts[2].strip().strip("'") if len(parts) > 2 else ""
        return annotate(key, value, reason)
    if s.startswith("no_op("):
        inner = s[len("no_op(") : -1]
        return no_op(inner.strip().strip("'"))
    return no_op(f"Unrecognized Prolog action: {s}")


class PrologRuleLoader:
    """Load rules from Prolog files."""

    def __init__(self, rules_dir: str | Path) -> None:
        self._rules_dir = Path(rules_dir)
        self._rules: list[RegisteredRule] = []
        self._mtimes: dict[Path, float] = {}
        self._prolog: Any = None

    @property
    def rules(self) -> list[RegisteredRule]:
        return list(self._rules)

    def load(self) -> list[RegisteredRule]:
        if not _PYSWIP_AVAILABLE:
            logger.warning(
                "pyswip is not installed — Prolog rule loading skipped. "
                "Install with: pip install 'gnat[rules-prolog]'"
            )
            return []

        from pyswip import Prolog

        self._prolog = Prolog()

        if _HELPERS_PL.exists():
            self._prolog.consult(str(_HELPERS_PL))

        self._rules = []
        if not self._rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", self._rules_dir)
            return []

        for pl_file in sorted(self._rules_dir.rglob("*.pl")):
            self._load_file(pl_file)

        self._rules.sort(key=lambda r: -r.priority)
        return list(self._rules)

    def reload_if_changed(self) -> bool:
        if not _PYSWIP_AVAILABLE or not self._rules_dir.exists():
            return False

        current_files = set(self._rules_dir.rglob("*.pl"))
        tracked_files = set(self._mtimes.keys())

        if current_files != tracked_files:
            self.load()
            return True

        for f in current_files:
            if f.stat().st_mtime != self._mtimes.get(f):
                self.load()
                return True

        return False

    def _load_file(self, pl_file: Path) -> None:
        try:
            self._prolog.consult(str(pl_file))
            self._mtimes[pl_file] = pl_file.stat().st_mtime

            results = list(self._prolog.query("rule(Name, Attrs)"))
            for result in results:
                name = str(result["Name"])
                attrs = result["Attrs"]
                self._register_rule(name, attrs, pl_file)

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load Prolog rule file %s: %s", pl_file, exc)

    def _register_rule(self, name: str, attrs: Any, source_file: Path) -> None:
        phase = None
        priority = 50
        description = ""
        tags: list[str] = []

        if isinstance(attrs, list):
            for attr in attrs:
                s = str(attr)
                if s.startswith("phase("):
                    phase = s[6:-1].strip("'")
                elif s.startswith("priority("):
                    priority = int(s[9:-1])
                elif s.startswith("description("):
                    description = s[12:-1].strip("'")

        prolog_ref = self._prolog
        rule_name = name

        def make_when(rn: str) -> Any:
            def when_fn(h: Any, ctx: Any) -> bool:
                _assert_hypothesis_facts(prolog_ref, h, ctx)
                try:
                    result = list(prolog_ref.query(f"when({rn})"))
                    return len(result) > 0
                finally:
                    _retract_hypothesis_facts(prolog_ref)

            return when_fn

        def make_then(rn: str) -> Any:
            def then_fn(h: Any, ctx: Any) -> Any:
                results = list(prolog_ref.query(f"then({rn}, Action)"))
                if results:
                    return _parse_action(results[0]["Action"])
                return no_op(f"No then/2 clause for {rn}")

            return then_fn

        self._rules.append(
            RegisteredRule(
                name=name,
                description=description,
                phase=phase,
                target_status=None,
                priority=priority,
                tags=tags,
                when_fn=make_when(rule_name),
                then_fn=make_then(rule_name),
                source_file=str(source_file),
            )
        )


class PrologRuleEngine:
    """Prolog-based rule engine implementing RuleEngineProtocol."""

    def __init__(
        self,
        loader: PrologRuleLoader,
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
                logger.error("Prolog rule %s raised: %s", rule.name, exc)
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
