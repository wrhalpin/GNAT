from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence


@dataclass(slots=True)
class ConnectorContractProfile:
    connector_name: str
    connector_path: str
    required_files: Sequence[str] = field(default_factory=lambda: ("__init__.py",))
    recommended_files: Sequence[str] = field(default_factory=tuple)
    required_symbols: Sequence[str] = field(default_factory=tuple)
    required_docs: Sequence[str] = field(default_factory=tuple)


@dataclass(slots=True)
class ContractCheckResult:
    connector_name: str
    passed: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        state = "passed" if self.passed else "failed"
        return f"{self.connector_name}: {state} ({len(self.errors)} errors, {len(self.warnings)} warnings)"


class ContractAgent:
    """Shape and standards enforcement for GNAT connectors."""

    def __init__(self, repo_root: str) -> None:
        self.repo_root = Path(repo_root)

    def evaluate(self, profile: ConnectorContractProfile) -> ContractCheckResult:
        connector_dir = self.repo_root / profile.connector_path
        errors: List[str] = []
        warnings: List[str] = []

        if not connector_dir.exists():
            errors.append(f"connector path missing: {connector_dir}")
            return ContractCheckResult(profile.connector_name, False, errors, warnings)

        for rel_path in profile.required_files:
            if not (connector_dir / rel_path).exists():
                errors.append(f"required file missing: {rel_path}")

        for rel_path in profile.recommended_files:
            if not (connector_dir / rel_path).exists():
                warnings.append(f"recommended file missing: {rel_path}")

        symbols_source = self._concat_python_sources(connector_dir)
        for symbol in profile.required_symbols:
            if symbol not in symbols_source:
                errors.append(f"required symbol not found: {symbol}")

        for rel_doc in profile.required_docs:
            if not (self.repo_root / rel_doc).exists():
                warnings.append(f"required documentation missing: {rel_doc}")

        return ContractCheckResult(
            connector_name=profile.connector_name,
            passed=not errors,
            errors=errors,
            warnings=warnings,
        )

    def evaluate_many(self, profiles: Iterable[ConnectorContractProfile]) -> List[ContractCheckResult]:
        return [self.evaluate(profile) for profile in profiles]

    def _concat_python_sources(self, connector_dir: Path) -> str:
        buffer: List[str] = []
        for path in sorted(connector_dir.rglob("*.py")):
            try:
                buffer.append(path.read_text(encoding="utf-8"))
            except OSError:
                continue
        return "\n".join(buffer)
