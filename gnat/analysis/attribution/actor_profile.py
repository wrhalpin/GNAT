# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.actor_profile
===========================================

Enriched threat-actor profile model.

Companion to the bare STIX :class:`~gnat.orm.threat_actor.ThreatActor`
ORM object — adds capability matrix, targeting history, infrastructure
patterns, alias management with per-alias confidence, and MITRE ATT&CK
group cross-reference.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Supporting types
# ---------------------------------------------------------------------------


@dataclass
class ActorAlias:
    """A known alias for a threat actor, with provenance and confidence."""

    alias: str = ""
    source: str = ""
    confidence: int = 50
    first_seen: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "alias": self.alias,
            "source": self.source,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActorAlias:
        fs = data.get("first_seen")
        if isinstance(fs, str):
            fs = datetime.fromisoformat(fs)
        return cls(
            alias=data.get("alias", ""),
            source=data.get("source", ""),
            confidence=int(data.get("confidence", 50)),
            first_seen=fs,
        )


@dataclass
class TechniqueCapability:
    """An ATT&CK technique observed in use by this actor."""

    technique_id: str = ""
    tactic_id: str = ""
    proficiency: str = "observed"
    last_used: datetime | None = None
    confidence: int = 50

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "tactic_id": self.tactic_id,
            "proficiency": self.proficiency,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TechniqueCapability:
        lu = data.get("last_used")
        if isinstance(lu, str):
            lu = datetime.fromisoformat(lu)
        return cls(
            technique_id=data.get("technique_id", ""),
            tactic_id=data.get("tactic_id", ""),
            proficiency=data.get("proficiency", "observed"),
            last_used=lu,
            confidence=int(data.get("confidence", 50)),
        )


@dataclass
class TargetingEvent:
    """A timestamped record of this actor targeting a sector/geography."""

    timestamp: datetime = field(default_factory=_utcnow)
    sector: str = ""
    geography: str = ""
    campaign_id: str | None = None
    confidence: int = 50

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "sector": self.sector,
            "geography": self.geography,
            "campaign_id": self.campaign_id,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetingEvent:
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        else:
            ts = _utcnow()
        return cls(
            timestamp=ts,
            sector=data.get("sector", ""),
            geography=data.get("geography", ""),
            campaign_id=data.get("campaign_id"),
            confidence=int(data.get("confidence", 50)),
        )


@dataclass
class InfrastructurePattern:
    """A recurring infrastructure signature observed for this actor."""

    pattern_type: str = ""
    value: str = ""
    frequency: int = 1
    confidence: int = 50

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "value": self.value,
            "frequency": self.frequency,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InfrastructurePattern:
        return cls(
            pattern_type=data.get("pattern_type", ""),
            value=data.get("value", ""),
            frequency=int(data.get("frequency", 1)),
            confidence=int(data.get("confidence", 50)),
        )


# ---------------------------------------------------------------------------
# Main profile
# ---------------------------------------------------------------------------


@dataclass
class ActorProfile:
    """
    Enriched analytical model wrapping a STIX ThreatActor SDO.

    Does NOT modify the existing :class:`~gnat.orm.threat_actor.ThreatActor`
    ORM class — sits alongside it as a richer analytical companion.
    """

    id: str = field(default_factory=lambda: f"threat-actor--{uuid.uuid4()}")
    name: str = ""
    aliases: list[ActorAlias] = field(default_factory=list)
    description: str = ""
    threat_actor_types: list[str] = field(default_factory=list)
    sophistication_level: str = "intermediate"

    # Capability matrix
    capabilities: list[TechniqueCapability] = field(default_factory=list)

    # Targeting
    target_sectors: list[str] = field(default_factory=list)
    target_geographies: list[str] = field(default_factory=list)
    targeting_history: list[TargetingEvent] = field(default_factory=list)

    # Infrastructure
    preferred_infrastructure: list[InfrastructurePattern] = field(default_factory=list)

    # Attribution
    attributed_campaigns: list[str] = field(default_factory=list)

    # External references
    mitre_group_id: str | None = None
    external_references: list[dict[str, Any]] = field(default_factory=list)

    # Timestamps
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    # ── Alias management ──────────────────────────────────────────────────

    def add_alias(self, alias: str, source: str = "", confidence: int = 50) -> None:
        """Add an alias (deduplicated by alias string)."""
        for existing in self.aliases:
            if existing.alias.lower() == alias.lower():
                if confidence > existing.confidence:
                    existing.confidence = confidence
                    existing.source = source
                return
        self.aliases.append(
            ActorAlias(
                alias=alias,
                source=source,
                confidence=confidence,
                first_seen=_utcnow(),
            )
        )

    # ── Capability matrix ─────────────────────────────────────────────────

    def update_capability(
        self,
        technique_id: str,
        tactic_id: str = "",
        proficiency: str = "observed",
        confidence: int = 50,
    ) -> None:
        """Add or update an ATT&CK technique capability."""
        for cap in self.capabilities:
            if cap.technique_id == technique_id:
                if proficiency in ("proficient", "expert") or confidence > cap.confidence:
                    cap.proficiency = proficiency
                    cap.confidence = confidence
                    cap.tactic_id = tactic_id or cap.tactic_id
                cap.last_used = _utcnow()
                return
        self.capabilities.append(
            TechniqueCapability(
                technique_id=technique_id,
                tactic_id=tactic_id,
                proficiency=proficiency,
                last_used=_utcnow(),
                confidence=confidence,
            )
        )

    # ── Targeting ─────────────────────────────────────────────────────────

    def record_targeting(
        self,
        sector: str,
        geography: str = "",
        campaign_id: str | None = None,
        confidence: int = 50,
    ) -> None:
        """Record a targeting observation."""
        self.targeting_history.append(
            TargetingEvent(
                sector=sector,
                geography=geography,
                campaign_id=campaign_id,
                confidence=confidence,
            )
        )
        if sector and sector not in self.target_sectors:
            self.target_sectors.append(sector)
        if geography and geography not in self.target_geographies:
            self.target_geographies.append(geography)

    # ── Similarity ────────────────────────────────────────────────────────

    def ttp_overlap(self, other: ActorProfile) -> float:
        """Return Jaccard similarity of technique IDs (0.0–1.0)."""
        mine = {c.technique_id for c in self.capabilities}
        theirs = {c.technique_id for c in other.capabilities}
        if not mine and not theirs:
            return 0.0
        return len(mine & theirs) / len(mine | theirs)

    # ── Serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "aliases": [a.to_dict() for a in self.aliases],
            "description": self.description,
            "threat_actor_types": list(self.threat_actor_types),
            "sophistication_level": self.sophistication_level,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "target_sectors": list(self.target_sectors),
            "target_geographies": list(self.target_geographies),
            "targeting_history": [t.to_dict() for t in self.targeting_history],
            "preferred_infrastructure": [p.to_dict() for p in self.preferred_infrastructure],
            "attributed_campaigns": list(self.attributed_campaigns),
            "mitre_group_id": self.mitre_group_id,
            "external_references": list(self.external_references),
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActorProfile:
        def _dt(key: str) -> datetime | None:
            v = data.get(key)
            if isinstance(v, str):
                return datetime.fromisoformat(v)
            return None

        created = _dt("created_at") or _utcnow()
        updated = _dt("updated_at") or _utcnow()

        return cls(
            id=data.get("id") or f"threat-actor--{uuid.uuid4()}",
            name=data.get("name", ""),
            aliases=[ActorAlias.from_dict(a) for a in (data.get("aliases") or [])],
            description=data.get("description", ""),
            threat_actor_types=list(data.get("threat_actor_types") or []),
            sophistication_level=data.get("sophistication_level", "intermediate"),
            capabilities=[
                TechniqueCapability.from_dict(c) for c in (data.get("capabilities") or [])
            ],
            target_sectors=list(data.get("target_sectors") or []),
            target_geographies=list(data.get("target_geographies") or []),
            targeting_history=[
                TargetingEvent.from_dict(t) for t in (data.get("targeting_history") or [])
            ],
            preferred_infrastructure=[
                InfrastructurePattern.from_dict(p)
                for p in (data.get("preferred_infrastructure") or [])
            ],
            attributed_campaigns=list(data.get("attributed_campaigns") or []),
            mitre_group_id=data.get("mitre_group_id"),
            external_references=list(data.get("external_references") or []),
            first_observed=_dt("first_observed"),
            last_observed=_dt("last_observed"),
            created_at=created,
            updated_at=updated,
        )
