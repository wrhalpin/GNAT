# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.infrastructure
============================================

Infrastructure role classification — labels graph nodes as C2,
staging, exfiltration, delivery, proxy, or credential-harvest
infrastructure based on kill-chain hints, port/protocol patterns,
and STIX infrastructure_types.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class InfrastructureRole(str, Enum):
    """Role classification for attacker infrastructure nodes."""

    C2 = "c2"
    STAGING = "staging"
    EXFILTRATION = "exfiltration"
    DELIVERY = "delivery"
    PROXY = "proxy"
    CREDENTIAL_HARVEST = "credential_harvest"
    UNKNOWN = "unknown"


@dataclass
class InfrastructureNode:
    """A network indicator annotated with its inferred operational role."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    indicator_id: str = ""
    ioc_type: str = ""
    ioc_value: str = ""
    role: InfrastructureRole = InfrastructureRole.UNKNOWN
    role_confidence: int = 50
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    campaigns: list[str] = field(default_factory=list)
    hosting_provider: str | None = None
    asn: str | None = None
    registrar: str | None = None
    auto_classified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "indicator_id": self.indicator_id,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "role": self.role.value,
            "role_confidence": self.role_confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "campaigns": list(self.campaigns),
            "hosting_provider": self.hosting_provider,
            "asn": self.asn,
            "registrar": self.registrar,
            "auto_classified": self.auto_classified,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InfrastructureNode:
        fs = data.get("first_seen")
        if isinstance(fs, str):
            fs = datetime.fromisoformat(fs)
        ls = data.get("last_seen")
        if isinstance(ls, str):
            ls = datetime.fromisoformat(ls)
        return cls(
            id=data.get("id") or str(uuid.uuid4()),
            indicator_id=data.get("indicator_id", ""),
            ioc_type=data.get("ioc_type", ""),
            ioc_value=data.get("ioc_value", ""),
            role=InfrastructureRole(data.get("role", "unknown")),
            role_confidence=int(data.get("role_confidence", 50)),
            first_seen=fs,
            last_seen=ls,
            campaigns=list(data.get("campaigns") or []),
            hosting_provider=data.get("hosting_provider"),
            asn=data.get("asn"),
            registrar=data.get("registrar"),
            auto_classified=bool(data.get("auto_classified", False)),
        )


# Kill-chain tactic → infrastructure role mapping
_TACTIC_ROLE_MAP: dict[str, InfrastructureRole] = {
    "TA0001": InfrastructureRole.DELIVERY,
    "TA0011": InfrastructureRole.C2,
    "TA0010": InfrastructureRole.EXFILTRATION,
    "TA0042": InfrastructureRole.STAGING,
    "TA0006": InfrastructureRole.CREDENTIAL_HARVEST,
}

AI_CONFIDENCE_CEILING = 60


class InfrastructureClassifier:
    """Rule-based infrastructure role classifier."""

    @staticmethod
    def classify(
        ioc_type: str,
        ioc_value: str,
        *,
        kill_chain_phases: list[str] | None = None,
        infrastructure_types: list[str] | None = None,
        ports: list[int] | None = None,
        source: str = "analyst",
    ) -> InfrastructureRole:
        """
        Classify an indicator's infrastructure role.

        Uses kill-chain phase hints, STIX infrastructure_types, and
        port/protocol patterns. AI-generated classifications are
        capped at confidence 60.
        """
        # STIX infrastructure_types take priority
        if infrastructure_types:
            for it in infrastructure_types:
                lower = it.lower()
                if "command-and-control" in lower or "c2" in lower:
                    return InfrastructureRole.C2
                if "staging" in lower:
                    return InfrastructureRole.STAGING
                if "exfiltration" in lower:
                    return InfrastructureRole.EXFILTRATION
                if "phishing" in lower or "delivery" in lower:
                    return InfrastructureRole.DELIVERY

        # Kill-chain phase hints
        if kill_chain_phases:
            for phase in kill_chain_phases:
                role = _TACTIC_ROLE_MAP.get(phase)
                if role:
                    return role

        # Port-based heuristics
        if ports:
            c2_ports = {443, 8443, 4443, 8080, 80}
            if set(ports) & c2_ports:
                return InfrastructureRole.C2

        return InfrastructureRole.UNKNOWN

    @staticmethod
    def find_shared_infrastructure(
        nodes: list[InfrastructureNode],
    ) -> list[InfrastructureNode]:
        """Return nodes that appear in more than one campaign."""
        return [n for n in nodes if len(n.campaigns) > 1]
