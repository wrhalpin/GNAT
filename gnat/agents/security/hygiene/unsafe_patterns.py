from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List

@dataclass(slots=True)
class UnsafePatternFinding:
    location: str
    rule: str
    message: str

class UnsafePatternDetector:
    def inspect_connector_config(self, config: Dict[str, Any]) -> List[UnsafePatternFinding]:
        findings: List[UnsafePatternFinding] = []
        credentials = config.get("credentials", {})
        if not isinstance(credentials, dict): return findings
        for key, value in credentials.items():
            if isinstance(value, str):
                findings.append(UnsafePatternFinding(f"credentials.{key}", "plain_text_secret", "credential should use secret_ref instead of inline string"))
            elif isinstance(value, dict) and "value" in value:
                findings.append(UnsafePatternFinding(f"credentials.{key}", "embedded_secret_value", "credential dictionary embeds raw value instead of reference"))
        return findings
