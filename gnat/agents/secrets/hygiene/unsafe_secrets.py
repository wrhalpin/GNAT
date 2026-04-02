from __future__ import annotations

from typing import Iterable, List, Tuple

from ..models import UnsafeSecretFinding


class UnsafeSecretAnalyzer:
    """Very small heuristic layer for bad or risky secrets.

    This is intentionally simple in the scaffold: it is meant to highlight where
    stronger policies like entropy checks, known-default secret dictionaries, and
    connector-specific rules should land later.
    """

    def analyze(self, named_values: Iterable[Tuple[str, str]]) -> List[UnsafeSecretFinding]:
        findings: List[UnsafeSecretFinding] = []
        for name, value in named_values:
            if not value:
                findings.append(UnsafeSecretFinding(secret_name=name, reason="empty secret", severity="high"))
                continue
            lowered = value.lower()
            if len(value) < 12:
                findings.append(UnsafeSecretFinding(secret_name=name, reason="secret is too short", severity="medium"))
            if lowered in {"password", "changeme", "admin", "test", "secret"}:
                findings.append(UnsafeSecretFinding(secret_name=name, reason="secret uses an obvious default value", severity="high"))
            if name.startswith("prod/") and value.startswith("dev-"):
                findings.append(UnsafeSecretFinding(secret_name=name, reason="production secret appears to use a development token", severity="high"))
        return findings
