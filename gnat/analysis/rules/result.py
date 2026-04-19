# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RuleEvaluationResult — what the engine returns."""

from __future__ import annotations

from dataclasses import dataclass, field

from gnat.analysis.rules.decisions import Decision


@dataclass(frozen=True)
class RuleFiring:
    rule_name: str
    rule_source_file: str
    rule_git_sha: str | None
    decision: Decision


@dataclass
class RuleEvaluationResult:
    firings: list[RuleFiring] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def primary_decision(self) -> Decision | None:
        for f in self.firings:
            if f.decision.consumes_transition_slot():
                return f.decision
        return None
