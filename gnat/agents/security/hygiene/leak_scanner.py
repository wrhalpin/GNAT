# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.hygiene.leak_scanner
=============================================

Leak scanner utilities and helpers for the GNAT toolkit.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass
class LeakFinding:
    """LeakFinding implementation."""
    path: str
    line_number: int
    severity: str
    rule: str
    snippet: str


class LeakScanner:
    """LeakScanner implementation."""
    DEFAULT_PATTERNS = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "private_key_header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "generic_token_assignment": re.compile(
            r"(api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE
        ),
    }

    def __init__(self, allowlist: Iterable[str] | None = None) -> None:
        """Initialize LeakScanner."""
        self.allowlist = set(allowlist or [])

    def scan_paths(self, paths: Iterable[str]) -> list[LeakFinding]:
        """Scan paths."""
        findings: list[LeakFinding] = []
        for root in paths:
            for path in Path(root).rglob("*"):
                if path.is_file() and not any(
                    part in {".git", ".venv", "__pycache__"} for part in path.parts
                ):
                    findings.extend(self._scan_file(path))
        return findings

    def _scan_file(self, path: Path) -> list[LeakFinding]:
        """Internal helper for scan file."""
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        out: list[LeakFinding] = []
        for i, line in enumerate(text.splitlines(), start=1):
            if line.strip() in self.allowlist:
                continue
            for rule, pattern in self.DEFAULT_PATTERNS.items():
                if pattern.search(line):
                    out.append(
                        LeakFinding(
                            str(path),
                            i,
                            "high" if rule != "generic_token_assignment" else "medium",
                            rule,
                            line.strip()[:200],
                        )
                    )
        return out
