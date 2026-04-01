"""Golden fixture and test verification helpers for repo maintenance."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from gnat.agents.repo_maintenance.models import VerificationCheck, VerificationResult
from gnat.agents.repo_maintenance.registry import ConnectorRegistry


class VerificationEngine:
    """Run targeted checks before opening a maintenance PR."""

    def __init__(self, registry: ConnectorRegistry, repo_root: str | Path = "."):
        self.registry = registry
        self.repo_root = Path(repo_root)

    def verify(self, connector: str) -> VerificationResult:
        spec = self.registry.get(connector)
        checks: list[VerificationCheck] = []

        for fixture in spec.golden_fixtures:
            checks.append(self._verify_golden_fixture(fixture))

        if spec.tests:
            checks.append(self._run_pytest(spec.tests))

        passed = all(check.passed for check in checks) if checks else True
        summary = "All verification checks passed." if passed else "One or more verification checks failed."
        return VerificationResult(connector=connector, passed=passed, checks=checks, summary=summary)

    def _verify_golden_fixture(self, fixture_path: str) -> VerificationCheck:
        full_path = self.repo_root / fixture_path
        if not full_path.exists():
            return VerificationCheck(
                name=f"golden:{fixture_path}",
                passed=False,
                details="Golden fixture file was not found.",
            )
        payload = json.loads(full_path.read_text(encoding="utf-8"))
        expected = payload.get("expected")
        actual = payload.get("actual", expected)
        passed = _canonical_json(actual) == _canonical_json(expected)
        return VerificationCheck(
            name=f"golden:{fixture_path}",
            passed=passed,
            details="Fixture output matches expected canonical JSON." if passed else "Fixture output drifted from expected canonical JSON.",
            artifacts=[fixture_path],
        )

    def _run_pytest(self, test_paths: list[str]) -> VerificationCheck:
        cmd = [sys.executable, "-m", "pytest", *test_paths, "-q", "--tb=short"]
        proc = subprocess.run(
            cmd,
            cwd=self.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        details = (proc.stdout or "") + (proc.stderr or "")
        return VerificationCheck(
            name="pytest",
            passed=proc.returncode == 0,
            details=details.strip()[:4000],
            artifacts=test_paths,
        )


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
