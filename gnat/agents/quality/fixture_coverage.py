from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class FixtureCoverageResult:
    connector_name: str
    fixture_count: int
    has_error_fixture: bool
    has_backward_fixture: bool
    warnings: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        score = min(self.fixture_count * 20, 60)
        if self.has_error_fixture:
            score += 20
        if self.has_backward_fixture:
            score += 20
        return score


class FixtureCoverageAgent:
    """Rates test/fixture depth for connectors and spots weak coverage."""

    def __init__(self, repo_root: str) -> None:
        self.repo_root = Path(repo_root)

    def evaluate_connector(self, connector_name: str, fixture_globs: Sequence[str]) -> FixtureCoverageResult:
        matched: list[Path] = []
        for pattern in fixture_globs:
            matched.extend(self.repo_root.glob(pattern))

        unique_paths = sorted({path.resolve() for path in matched})
        names = [Path(path).name.lower() for path in unique_paths]

        has_error_fixture = any("error" in name or "failure" in name for name in names)
        has_backward_fixture = any("legacy" in name or "backward" in name or "v1" in name for name in names)

        warnings: list[str] = []
        if not unique_paths:
            warnings.append("no fixtures found")
        if len(unique_paths) < 2:
            warnings.append("low fixture count")
        if not has_error_fixture:
            warnings.append("no error-path fixture detected")
        if not has_backward_fixture:
            warnings.append("no backward-compatibility fixture detected")

        return FixtureCoverageResult(
            connector_name=connector_name,
            fixture_count=len(unique_paths),
            has_error_fixture=has_error_fixture,
            has_backward_fixture=has_backward_fixture,
            warnings=warnings,
        )

    def evaluate_many(self, registry: dict[str, Sequence[str]]) -> list[FixtureCoverageResult]:
        return [self.evaluate_connector(connector_name, globs) for connector_name, globs in registry.items()]
