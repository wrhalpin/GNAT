# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.models
====================================

Pure-Python dataclasses for the campaign and attribution object model.

No SQLAlchemy or database dependency — persistence is handled by
:class:`~gnat.analysis.attribution.storage.CampaignStore`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _new_id() -> str:
    return f"campaign--{uuid.uuid4()}"


class CampaignStatus(str, Enum):
    """Lifecycle status of a campaign."""

    SUSPECTED = "suspected"
    ACTIVE = "active"
    DORMANT = "dormant"
    CONCLUDED = "concluded"


@dataclass
class CampaignProfile:
    """
    Enriched analytical model wrapping a STIX Campaign SDO.

    Carries all GNAT-side metadata beyond what the bare ORM
    ``Campaign`` object holds: sub-campaign hierarchy, linked
    clusters/investigations/indicators, attribution hypotheses,
    kill-chain progression, Diamond Model vertices, and confidence.
    """

    id: str = field(default_factory=_new_id)
    name: str = ""
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    objective: str = ""
    status: CampaignStatus = CampaignStatus.SUSPECTED
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # Hierarchy
    parent_campaign_id: str | None = None
    sub_campaign_ids: list[str] = field(default_factory=list)

    # Linking
    cluster_ids: list[str] = field(default_factory=list)
    investigation_ids: list[str] = field(default_factory=list)
    indicator_ids: list[str] = field(default_factory=list)
    threat_actor_id: str | None = None

    # Tags & classification
    tags: list[str] = field(default_factory=list)
    classification: str = "amber"

    # Metadata
    created_by: str = "analyst"
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "aliases": list(self.aliases),
            "description": self.description,
            "objective": self.objective,
            "status": self.status.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "parent_campaign_id": self.parent_campaign_id,
            "sub_campaign_ids": list(self.sub_campaign_ids),
            "cluster_ids": list(self.cluster_ids),
            "investigation_ids": list(self.investigation_ids),
            "indicator_ids": list(self.indicator_ids),
            "threat_actor_id": self.threat_actor_id,
            "tags": list(self.tags),
            "classification": self.classification,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CampaignProfile:
        first_seen = data.get("first_seen")
        if isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen)
        last_seen = data.get("last_seen")
        if isinstance(last_seen, str):
            last_seen = datetime.fromisoformat(last_seen)
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        else:
            created_at = _utcnow()
        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        else:
            updated_at = _utcnow()

        return cls(
            id=data.get("id") or _new_id(),
            name=data.get("name", ""),
            aliases=list(data.get("aliases") or []),
            description=data.get("description", ""),
            objective=data.get("objective", ""),
            status=CampaignStatus(data.get("status", "suspected")),
            first_seen=first_seen,
            last_seen=last_seen,
            parent_campaign_id=data.get("parent_campaign_id"),
            sub_campaign_ids=list(data.get("sub_campaign_ids") or []),
            cluster_ids=list(data.get("cluster_ids") or []),
            investigation_ids=list(data.get("investigation_ids") or []),
            indicator_ids=list(data.get("indicator_ids") or []),
            threat_actor_id=data.get("threat_actor_id"),
            tags=list(data.get("tags") or []),
            classification=data.get("classification", "amber"),
            created_by=data.get("created_by", "analyst"),
            created_at=created_at,
            updated_at=updated_at,
        )
