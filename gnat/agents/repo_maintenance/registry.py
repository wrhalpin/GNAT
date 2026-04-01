"""Connector registry loader for repo-maintenance metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml

    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False


@dataclass
class ProbeSpec:
    """One version or schema probe defined in the registry."""

    probe_type: str
    target: str
    json_pointer: str | None = None
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ConnectorSpec:
    """Maintenance metadata for a GNAT connector."""

    name: str
    package_path: str
    client_class: str | None = None
    compatibility_strategy: str = "adapter"
    probes: list[ProbeSpec] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    golden_fixtures: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class ConnectorRegistry:
    """Loads and validates the connector maintenance registry."""

    def __init__(self, specs: dict[str, ConnectorSpec]):
        self._specs = specs

    def get(self, connector: str) -> ConnectorSpec:
        return self._specs[connector]

    def names(self) -> list[str]:
        return sorted(self._specs.keys())

    @classmethod
    def load(cls, path: str | Path) -> ConnectorRegistry:
        raw = _load_registry_file(Path(path))
        specs: dict[str, ConnectorSpec] = {}
        for name, item in raw.items():
            probes = [
                ProbeSpec(
                    probe_type=probe["type"],
                    target=probe["target"],
                    json_pointer=probe.get("json_pointer"),
                    method=probe.get("method", "GET"),
                    headers=probe.get("headers", {}),
                )
                for probe in item.get("probes", [])
            ]
            specs[name] = ConnectorSpec(
                name=name,
                package_path=item["package_path"],
                client_class=item.get("client_class"),
                compatibility_strategy=item.get("compatibility_strategy", "adapter"),
                probes=probes,
                files=item.get("files", []),
                golden_fixtures=item.get("golden_fixtures", []),
                tests=item.get("tests", []),
                notes=item.get("notes", []),
            )
        return cls(specs)


def _load_registry_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        if not _HAS_YAML:
            raise ImportError("PyYAML is required to read YAML registry files")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Connector registry must deserialize to a mapping")
    return data
