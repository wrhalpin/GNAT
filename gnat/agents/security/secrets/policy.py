# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.policy
=======================================

Policy utilities and helpers for the GNAT toolkit.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .models import SecretRef


@dataclass
class PolicyDecision:
    """PolicyDecision implementation."""
    allowed: bool
    reason: str = ""
    return_mode: str = "in_memory_only"
    require_approval: bool = False


@dataclass
class PolicyRule:
    """PolicyRule implementation."""
    path_prefix: str
    actions: Sequence[str]
    allowed_callers: Sequence[str]
    environments: Sequence[str] = field(default_factory=tuple)
    overwrite: bool = False
    require_approval: bool = False
    return_mode: str = "in_memory_only"

    def matches(self, ref: SecretRef, action: str, caller: str) -> bool:
        """Matches."""
        return (
            action in self.actions
            and caller in self.allowed_callers
            and ref.path.startswith(self.path_prefix)
        )


class SecretPolicyEngine:
    """SecretPolicyEngine implementation."""
    def __init__(self, rules: Iterable[PolicyRule] | None = None) -> None:
        """Initialize SecretPolicyEngine."""
        self._rules = list(rules or [])

    def add_rule(self, rule: PolicyRule) -> None:
        """Create a new rule."""
        self._rules.append(rule)

    def decide(
        self, ref: SecretRef, *, action: str, caller: str, overwrite: bool = False
    ) -> PolicyDecision:
        """Decide."""
        for rule in self._rules:
            if rule.matches(ref, action=action, caller=caller):
                if overwrite and not rule.overwrite:
                    return PolicyDecision(False, reason="overwrite not permitted by policy")
                return PolicyDecision(
                    True, "matched policy rule", rule.return_mode, rule.require_approval
                )
        return PolicyDecision(False, reason="no matching policy rule")
