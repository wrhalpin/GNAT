# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.deployment
====================================

Rule deployment tracking and drift detection.

Tracks where detection rules have been deployed, detects when the
on-platform copy diverges from the canonical HuntGNAT copy, and
ingests firing events as STIX Sighting SDOs.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class DeploymentPlatform(str, Enum):
    SPLUNK = "splunk"
    SENTINEL = "sentinel"
    CROWDSTRIKE = "crowdstrike"
    ELASTIC = "elastic"


class DeploymentStatus(str, Enum):
    DEPLOYED = "deployed"
    DISABLED = "disabled"
    REMOVED = "removed"
    DRIFTED = "drifted"


@dataclass
class Deployment:
    """Tracks a single rule's deployment to a target platform."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    platform: DeploymentPlatform = DeploymentPlatform.SPLUNK
    platform_rule_id: str = ""
    status: DeploymentStatus = DeploymentStatus.DEPLOYED
    deployed_at: datetime = field(default_factory=_utcnow)
    deployed_by: str = "analyst"
    last_reconciled_at: datetime | None = None
    canonical_hash: str = ""
    remote_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "platform": self.platform.value,
            "platform_rule_id": self.platform_rule_id,
            "status": self.status.value,
            "deployed_at": self.deployed_at.isoformat(),
            "deployed_by": self.deployed_by,
            "last_reconciled_at": (
                self.last_reconciled_at.isoformat()
                if self.last_reconciled_at
                else None
            ),
            "canonical_hash": self.canonical_hash,
            "remote_hash": self.remote_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Deployment:
        da = data.get("deployed_at")
        if isinstance(da, str):
            da = datetime.fromisoformat(da)
        else:
            da = _utcnow()
        lr = data.get("last_reconciled_at")
        if isinstance(lr, str):
            lr = datetime.fromisoformat(lr)
        return cls(
            id=data.get("id") or str(uuid.uuid4()),
            rule_id=data.get("rule_id", ""),
            platform=DeploymentPlatform(data.get("platform", "splunk")),
            platform_rule_id=data.get("platform_rule_id", ""),
            status=DeploymentStatus(data.get("status", "deployed")),
            deployed_at=da,
            deployed_by=data.get("deployed_by", "analyst"),
            last_reconciled_at=lr,
            canonical_hash=data.get("canonical_hash", ""),
            remote_hash=data.get("remote_hash", ""),
        )


@dataclass
class DriftEvent:
    """Recorded when a deployed rule diverges from canonical."""

    deployment_id: str = ""
    rule_id: str = ""
    platform: str = ""
    canonical_hash: str = ""
    remote_hash: str = ""
    detected_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "deployment_id": self.deployment_id,
            "rule_id": self.rule_id,
            "platform": self.platform,
            "canonical_hash": self.canonical_hash,
            "remote_hash": self.remote_hash,
            "detected_at": self.detected_at.isoformat(),
        }


class DriftDetector:
    """Compares canonical rule hashes against on-platform copies."""

    @staticmethod
    def check(
        deployment: Deployment,
        remote_rule_body: str,
    ) -> DriftEvent | None:
        """
        Compare the canonical hash against the remote rule body.

        Returns a :class:`DriftEvent` if divergent, ``None`` if matched.
        Does NOT auto-correct — drift is observed, never corrected.
        """
        remote_hash = hashlib.sha256(
            remote_rule_body.encode("utf-8")
        ).hexdigest()

        deployment.last_reconciled_at = _utcnow()
        deployment.remote_hash = remote_hash

        if remote_hash != deployment.canonical_hash:
            deployment.status = DeploymentStatus.DRIFTED
            return DriftEvent(
                deployment_id=deployment.id,
                rule_id=deployment.rule_id,
                platform=deployment.platform.value,
                canonical_hash=deployment.canonical_hash,
                remote_hash=remote_hash,
            )
        return None


@dataclass
class Sighting:
    """
    A STIX Sighting SDO recording detection firings.

    Produced when a platform fires a rule that HuntGNAT deployed.
    """

    id: str = field(default_factory=lambda: f"sighting--{uuid.uuid4()}")
    sighting_of_ref: str = ""
    where_sighted_refs: list[str] = field(default_factory=list)
    count: int = 1
    first_seen: datetime = field(default_factory=_utcnow)
    last_seen: datetime = field(default_factory=_utcnow)
    deployment_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "sighting",
            "id": self.id,
            "sighting_of_ref": self.sighting_of_ref,
            "where_sighted_refs": list(self.where_sighted_refs),
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "x_gnat_deployment_id": self.deployment_id,
        }
