# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Rule registry — populated by defrule macro during .hy file load."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class RegisteredRule:
    name: str
    description: str
    phase: str | None
    target_status: str | None
    priority: int
    tags: list[str]
    when_fn: Callable[..., bool]
    then_fn: Callable[..., Any]
    source_file: str


_rules: list[RegisteredRule] = []


def register_rule(rule_dict: dict[str, Any]) -> None:
    _rules.append(
        RegisteredRule(
            name=rule_dict["name"],
            description=rule_dict.get("description", ""),
            phase=rule_dict.get("phase"),
            target_status=rule_dict.get("target_status"),
            priority=rule_dict.get("priority", 50),
            tags=list(rule_dict.get("tags", [])),
            when_fn=rule_dict["when_fn"],
            then_fn=rule_dict["then_fn"],
            source_file=rule_dict.get("source_file", ""),
        )
    )


def drain_rules() -> list[RegisteredRule]:
    global _rules  # noqa: PLW0603
    result = _rules
    _rules = []
    return result


def clear_registry() -> None:
    global _rules  # noqa: PLW0603
    _rules = []
