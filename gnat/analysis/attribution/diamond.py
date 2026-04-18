# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.diamond
=====================================

Diamond Model formalization — Adversary-Capability-Infrastructure-Victim.

Each :class:`DiamondVertex` represents a single observed ACIV tuple
linking a threat actor to capabilities, infrastructure, and victims
at a point in time. The :class:`DiamondAnalyzer` constructs these
tuples from campaign data and finds pivot points (infrastructure
shared across multiple tuples).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


@dataclass
class DiamondVertex:
    """
    A single Diamond Model event — one observed ACIV tuple.

    Each vertex captures a moment where an adversary used specific
    capabilities via specific infrastructure against specific victims.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    adversary: str | None = None
    capability: list[str] = field(default_factory=list)
    infrastructure: list[str] = field(default_factory=list)
    victim: list[str] = field(default_factory=list)
    confidence: int = 50
    timestamp: datetime | None = None
    source_event_ids: list[str] = field(default_factory=list)
    phase: str | None = None
    result: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "adversary": self.adversary,
            "capability": list(self.capability),
            "infrastructure": list(self.infrastructure),
            "victim": list(self.victim),
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_event_ids": list(self.source_event_ids),
            "phase": self.phase,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiamondVertex:
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(
            id=data.get("id") or str(uuid.uuid4()),
            adversary=data.get("adversary"),
            capability=list(data.get("capability") or []),
            infrastructure=list(data.get("infrastructure") or []),
            victim=list(data.get("victim") or []),
            confidence=int(data.get("confidence", 50)),
            timestamp=ts,
            source_event_ids=list(data.get("source_event_ids") or []),
            phase=data.get("phase"),
            result=data.get("result"),
        )


class DiamondAnalyzer:
    """Constructs and queries Diamond Model vertices."""

    @staticmethod
    def build_vertex(
        adversary: str | None = None,
        capability: list[str] | None = None,
        infrastructure: list[str] | None = None,
        victim: list[str] | None = None,
        *,
        confidence: int = 50,
        phase: str | None = None,
        result: str | None = None,
        timestamp: datetime | None = None,
        source_event_ids: list[str] | None = None,
    ) -> DiamondVertex:
        """Create a single ACIV tuple."""
        return DiamondVertex(
            adversary=adversary,
            capability=list(capability or []),
            infrastructure=list(infrastructure or []),
            victim=list(victim or []),
            confidence=confidence,
            phase=phase,
            result=result,
            timestamp=timestamp or _utcnow(),
            source_event_ids=list(source_event_ids or []),
        )

    @staticmethod
    def find_pivot_points(vertices: list[DiamondVertex]) -> list[str]:
        """
        Return infrastructure IDs that appear in more than one vertex.

        These are candidate pivot points — infrastructure shared across
        multiple Diamond events suggests a common operator.
        """
        infra_count: dict[str, int] = {}
        for v in vertices:
            for node_id in v.infrastructure:
                infra_count[node_id] = infra_count.get(node_id, 0) + 1
        return sorted(k for k, count in infra_count.items() if count > 1)

    @staticmethod
    def vertices_by_adversary(
        vertices: list[DiamondVertex],
    ) -> dict[str | None, list[DiamondVertex]]:
        """Group vertices by adversary."""
        groups: dict[str | None, list[DiamondVertex]] = {}
        for v in vertices:
            groups.setdefault(v.adversary, []).append(v)
        return groups

    @staticmethod
    def vertices_by_phase(
        vertices: list[DiamondVertex],
    ) -> dict[str | None, list[DiamondVertex]]:
        """Group vertices by kill-chain phase."""
        groups: dict[str | None, list[DiamondVertex]] = {}
        for v in vertices:
            groups.setdefault(v.phase, []).append(v)
        return groups
