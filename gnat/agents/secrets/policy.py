from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatch

from .exceptions import SecretPolicyError
from .models import SecretPurpose, SecretRef


@dataclass
class SecretAccessRule:
    action: str
    pattern: str
    allowed_purposes: list[SecretPurpose] = field(default_factory=list)
    allowed_requestors: list[str] = field(default_factory=list)
    require_explicit_overwrite: bool = True

    def matches(self, action: str, ref: SecretRef) -> bool:
        return self.action == action and fnmatch(ref.name, self.pattern)


class SecretsPolicy:
    """Very small policy engine for broker decisions.

    The policy is intentionally simple for Phase A so it is easy to reason about
    on a big screen and safe to extend later.
    """

    def __init__(self, rules: Iterable[SecretAccessRule] | None = None):
        self.rules = list(rules or [])

    @classmethod
    def default(cls) -> SecretsPolicy:
        return cls(
            rules=[
                SecretAccessRule(
                    action="get",
                    pattern="dev/*",
                    allowed_purposes=list(SecretPurpose),
                    allowed_requestors=["system", "ci", "developer", "runtime"],
                ),
                SecretAccessRule(
                    action="put",
                    pattern="dev/*",
                    allowed_purposes=[SecretPurpose.DEVELOPMENT, SecretPurpose.CI, SecretPurpose.RUNTIME],
                    allowed_requestors=["system", "developer", "ci"],
                    require_explicit_overwrite=False,
                ),
                SecretAccessRule(
                    action="get",
                    pattern="prod/*",
                    allowed_purposes=[SecretPurpose.RUNTIME, SecretPurpose.ROTATION],
                    allowed_requestors=["runtime", "rotation", "system"],
                ),
                SecretAccessRule(
                    action="put",
                    pattern="prod/*",
                    allowed_purposes=[SecretPurpose.ROTATION],
                    allowed_requestors=["rotation", "system"],
                ),
            ]
        )

    def authorize(self, action: str, ref: SecretRef, purpose: SecretPurpose, requestor: str, overwrite: bool = False) -> None:
        for rule in self.rules:
            if not rule.matches(action, ref):
                continue
            if rule.allowed_purposes and purpose not in rule.allowed_purposes:
                continue
            if rule.allowed_requestors and requestor not in rule.allowed_requestors:
                continue
            if action == "put" and overwrite and rule.require_explicit_overwrite and purpose != SecretPurpose.ROTATION:
                raise SecretPolicyError(
                    f"overwrite blocked for {ref.name}: only rotation flows may overwrite by default"
                )
            return
        raise SecretPolicyError(
            f"{requestor} is not allowed to {action} secret {ref.name} for purpose {purpose.value}"
        )
