# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.resolver
================================

Resolves evidence STIX IDs to originating connector metadata (trust level,
source platform name). Queries WorkspaceStore directly; does not modify
STIX objects.

One resolver per rule evaluation. Caches lookups for the evaluation's
lifetime. Not thread-safe; rule evaluation is single-threaded by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from gnat.clients import CLIENT_REGISTRY
from gnat.core.domains import _TRUST_ORDER


@dataclass(frozen=True)
class ResolvedEvidence:
    stix_id: str
    source_platform: str | None
    trust_level: str
    is_known_connector: bool


class _StoreProtocol(Protocol):
    def get_source_platform(self, workspace_id: int, stix_id: str) -> str | None: ...
    def get_source_platforms_bulk(
        self, workspace_id: int, stix_ids: list[str]
    ) -> dict[str, str | None]: ...


class EvidenceResolver:
    """Resolve evidence STIX IDs to originating connector metadata."""

    DEFAULT_TRUST = "untrusted_external"

    def __init__(self, workspace_id: int, store: Any) -> None:
        self._workspace_id = workspace_id
        self._store = store
        self._cache: dict[str, ResolvedEvidence] = {}

    def resolve(self, stix_id: str) -> ResolvedEvidence:
        if stix_id in self._cache:
            return self._cache[stix_id]
        source_platform = self._store.get_source_platform(
            self._workspace_id, stix_id
        )
        resolved = self._build(stix_id, source_platform)
        self._cache[stix_id] = resolved
        return resolved

    def resolve_many(self, stix_ids: list[str]) -> dict[str, ResolvedEvidence]:
        missing = [sid for sid in stix_ids if sid not in self._cache]
        if missing:
            platforms = self._store.get_source_platforms_bulk(
                self._workspace_id, missing
            )
            for sid in missing:
                self._cache[sid] = self._build(sid, platforms.get(sid))
        return {sid: self._cache[sid] for sid in stix_ids}

    def _build(
        self, stix_id: str, source_platform: str | None
    ) -> ResolvedEvidence:
        if source_platform is None:
            return ResolvedEvidence(
                stix_id=stix_id,
                source_platform=None,
                trust_level=self.DEFAULT_TRUST,
                is_known_connector=False,
            )
        connector_cls = CLIENT_REGISTRY.get(source_platform)
        if connector_cls is None:
            return ResolvedEvidence(
                stix_id=stix_id,
                source_platform=source_platform,
                trust_level=self.DEFAULT_TRUST,
                is_known_connector=False,
            )
        trust = getattr(connector_cls, "TRUST_LEVEL", self.DEFAULT_TRUST)
        return ResolvedEvidence(
            stix_id=stix_id,
            source_platform=source_platform,
            trust_level=trust,
            is_known_connector=True,
        )


def trust_at_least(actual: str, minimum: str) -> bool:
    try:
        return _TRUST_ORDER.index(actual) >= _TRUST_ORDER.index(minimum)
    except ValueError:
        return False
