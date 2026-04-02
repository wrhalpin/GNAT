from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class UnsafePatternFinding:
    location: str
    rule: str
    message: str


class UnsafePatternDetector:
    def inspect_connector_config(self, config: dict[str, Any]) -> list[UnsafePatternFinding]:
        findings: list[UnsafePatternFinding] = []
        credentials = config.get("credentials", {})
        if not isinstance(credentials, dict):
            return findings
        for key, value in credentials.items():
            if isinstance(value, str):
                findings.append(
                    UnsafePatternFinding(
                        f"credentials.{key}",
                        "plain_text_secret",
                        "credential should use secret_ref instead of inline string",
                    )
                )
            elif isinstance(value, dict) and "value" in value:
                findings.append(
                    UnsafePatternFinding(
                        f"credentials.{key}",
                        "embedded_secret_value",
                        "credential dictionary embeds raw value instead of reference",
                    )
                )
        return findings
