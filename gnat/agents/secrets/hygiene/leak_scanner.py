from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ..models import LeakFinding

DEFAULT_RULES = {
    "generic_assignment": re.compile(
        r"""(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['"]?([A-Za-z0-9_\-\./+=]{8,})"""
    ),
    "azure_connection_string": re.compile(r"(?i)DefaultEndpointsProtocol=.*AccountKey=.*"),
    "private_key_header": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
}


class SecretLeakScanner:
    def __init__(self, rules=None, ignore_paths: Iterable[str] | None = None):
        self.rules = rules or DEFAULT_RULES
        self.ignore_paths = list(ignore_paths or [])

    def scan_text(self, text: str, path: str = "<memory>") -> list[LeakFinding]:
        findings: list[LeakFinding] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule_id, pattern in self.rules.items():
                match = pattern.search(line)
                if not match:
                    continue
                findings.append(
                    LeakFinding(
                        path=path,
                        line_number=line_number,
                        rule_id=rule_id,
                        confidence="high" if rule_id != "generic_assignment" else "medium",
                        matched_text_preview=line[:120],
                        remediation="Move the secret into the broker-backed vault and replace with a secret_ref.",
                    )
                )
        return findings

    def scan_paths(self, paths: Iterable[str]) -> list[LeakFinding]:
        findings: list[LeakFinding] = []
        for path_str in paths:
            path = Path(path_str)
            if any(part in self.ignore_paths for part in path.parts):
                continue
            if path.is_dir():
                for file_path in path.rglob("*"):
                    if file_path.is_file():
                        findings.extend(self.scan_text(file_path.read_text(errors="ignore"), str(file_path)))
            elif path.is_file():
                findings.extend(self.scan_text(path.read_text(encoding="utf-8", errors="ignore"), str(path)))
        return findings
