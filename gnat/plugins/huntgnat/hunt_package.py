# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.hunt_package
=====================================

Hunt packages — bundles that tie hypothesis, evidence, detection rules,
and ATT&CK coverage together into a single analyst-managed unit.

A hunt package is modeled as a STIX Grouping with
``context="x-huntgnat-hunt-package"`` and carries metadata in
``x_gnat_`` custom properties.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from gnat.plugins.huntgnat.models import TranslationResult


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class PackageStatus(str, Enum):
    DRAFT = "draft"
    PEER_REVIEWED = "peer-reviewed"
    ACTIVE = "active"
    RETIRED = "retired"


_VALID_TRANSITIONS: dict[PackageStatus, frozenset[PackageStatus]] = {
    PackageStatus.DRAFT: frozenset({PackageStatus.PEER_REVIEWED, PackageStatus.RETIRED}),
    PackageStatus.PEER_REVIEWED: frozenset({PackageStatus.ACTIVE, PackageStatus.DRAFT}),
    PackageStatus.ACTIVE: frozenset({PackageStatus.RETIRED}),
    PackageStatus.RETIRED: frozenset(),
}


@dataclass
class HuntPackage:
    """
    A hunt package bundling hypothesis, evidence, rules, and ATT&CK
    coverage into a single analyst-managed object.
    """

    id: str = field(default_factory=lambda: f"grouping--{uuid.uuid4()}")
    name: str = ""
    description: str = ""
    narrative: str = ""
    status: PackageStatus = PackageStatus.DRAFT
    owner: str = "analyst"
    confidence: int = 50

    # Linked STIX IDs
    hypothesis_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    indicator_ids: list[str] = field(default_factory=list)
    attack_pattern_ids: list[str] = field(default_factory=list)
    campaign_id: str | None = None

    # Rules produced by HuntGNAT translators
    rules: list[TranslationResult] = field(default_factory=list)

    # ATT&CK coverage
    techniques_covered: list[str] = field(default_factory=list)
    data_sources_expected: list[str] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    classification: str = "amber"
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    def transition(self, new_status: PackageStatus) -> None:
        valid = _VALID_TRANSITIONS.get(self.status, frozenset())
        if new_status not in valid:
            raise ValueError(
                f"invalid transition {self.status.value} → {new_status.value}; "
                f"allowed: {[s.value for s in valid]}"
            )
        self.status = new_status
        self.updated_at = _utcnow()

    def add_rule(self, rule: TranslationResult) -> None:
        self.rules.append(rule)
        self.updated_at = _utcnow()

    def link_technique(self, technique_id: str) -> None:
        if technique_id not in self.techniques_covered:
            self.techniques_covered.append(technique_id)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def coverage_summary(self) -> dict[str, Any]:
        return {
            "techniques_covered": len(self.techniques_covered),
            "rules_generated": self.rule_count,
            "data_sources_expected": len(self.data_sources_expected),
            "languages": list({r.language.value for r in self.rules}),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "grouping",
            "id": self.id,
            "context": "x-huntgnat-hunt-package",
            "name": self.name,
            "description": self.description,
            "x_gnat_narrative_md": self.narrative,
            "x_gnat_lifecycle_status": self.status.value,
            "x_gnat_owner": self.owner,
            "x_gnat_confidence": self.confidence,
            "object_refs": (
                self.hypothesis_ids
                + self.evidence_ids
                + self.indicator_ids
                + self.attack_pattern_ids
            ),
            "x_gnat_rule_ids": [r.rule_id for r in self.rules],
            "x_gnat_techniques_covered": list(self.techniques_covered),
            "x_gnat_data_sources_expected": list(self.data_sources_expected),
            "x_gnat_campaign_id": self.campaign_id,
            "tags": list(self.tags),
            "classification": self.classification,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "coverage_summary": self.coverage_summary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HuntPackage:
        created = data.get("created_at")
        if isinstance(created, str):
            created = datetime.fromisoformat(created)
        else:
            created = _utcnow()
        updated = data.get("updated_at")
        if isinstance(updated, str):
            updated = datetime.fromisoformat(updated)
        else:
            updated = _utcnow()

        return cls(
            id=data.get("id") or f"grouping--{uuid.uuid4()}",
            name=data.get("name", ""),
            description=data.get("description", ""),
            narrative=data.get("x_gnat_narrative_md", ""),
            status=PackageStatus(data.get("x_gnat_lifecycle_status", "draft")),
            owner=data.get("x_gnat_owner", "analyst"),
            confidence=int(data.get("x_gnat_confidence", 50)),
            hypothesis_ids=list(data.get("hypothesis_ids") or []),
            evidence_ids=list(data.get("evidence_ids") or []),
            indicator_ids=list(data.get("indicator_ids") or []),
            attack_pattern_ids=list(data.get("attack_pattern_ids") or []),
            campaign_id=data.get("x_gnat_campaign_id"),
            techniques_covered=list(data.get("x_gnat_techniques_covered") or []),
            data_sources_expected=list(data.get("x_gnat_data_sources_expected") or []),
            tags=list(data.get("tags") or []),
            classification=data.get("classification", "amber"),
            created_at=created,
            updated_at=updated,
        )
