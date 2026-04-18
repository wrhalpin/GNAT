# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.killchain
=======================================

ATT&CK kill-chain progression tracking per campaign.

Maps observed ATT&CK techniques to the standard 14-phase kill chain,
computes coverage percentage, identifies gaps, and compares
progressions across campaigns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

KILL_CHAIN_ORDER: list[str] = [
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
]

TACTIC_NAMES: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}


@dataclass
class KillChainPhaseEntry:
    """A single observed kill-chain phase within a campaign."""

    tactic_id: str = ""
    tactic_name: str = ""
    techniques_observed: list[str] = field(default_factory=list)
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    confidence: int = 50
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "techniques_observed": list(self.techniques_observed),
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KillChainPhaseEntry:
        fo = data.get("first_observed")
        if isinstance(fo, str):
            fo = datetime.fromisoformat(fo)
        lo = data.get("last_observed")
        if isinstance(lo, str):
            lo = datetime.fromisoformat(lo)
        return cls(
            tactic_id=data.get("tactic_id", ""),
            tactic_name=data.get("tactic_name", ""),
            techniques_observed=list(data.get("techniques_observed") or []),
            first_observed=fo,
            last_observed=lo,
            confidence=int(data.get("confidence", 50)),
            evidence_ids=list(data.get("evidence_ids") or []),
        )


@dataclass
class KillChainProgression:
    """The observed kill-chain progression for a campaign."""

    campaign_id: str = ""
    phases: list[KillChainPhaseEntry] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        """Percentage of the 14-phase kill chain that has observations."""
        if not KILL_CHAIN_ORDER:
            return 0.0
        observed = {p.tactic_id for p in self.phases if p.techniques_observed}
        return len(observed) / len(KILL_CHAIN_ORDER) * 100

    @property
    def deepest_phase(self) -> str:
        """The most advanced tactic observed (furthest in kill chain)."""
        observed = {p.tactic_id for p in self.phases if p.techniques_observed}
        for tactic_id in reversed(KILL_CHAIN_ORDER):
            if tactic_id in observed:
                return tactic_id
        return ""

    @property
    def gaps(self) -> list[str]:
        """Tactic IDs with no observations."""
        observed = {p.tactic_id for p in self.phases if p.techniques_observed}
        return [t for t in KILL_CHAIN_ORDER if t not in observed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "phases": [p.to_dict() for p in self.phases],
            "coverage_pct": round(self.coverage_pct, 1),
            "deepest_phase": self.deepest_phase,
            "gaps": self.gaps,
        }


class KillChainTracker:
    """Builds and queries kill-chain progressions."""

    @staticmethod
    def build_progression(
        campaign_id: str,
        technique_tactic_pairs: list[tuple[str, str]],
    ) -> KillChainProgression:
        """
        Build a progression from (technique_id, tactic_id) pairs.

        Parameters
        ----------
        campaign_id : str
        technique_tactic_pairs : list of (technique_id, tactic_id)
            e.g. [("T1566.001", "TA0001"), ("T1059.003", "TA0002")]
        """
        phase_map: dict[str, list[str]] = {}
        for technique_id, tactic_id in technique_tactic_pairs:
            phase_map.setdefault(tactic_id, []).append(technique_id)

        phases = []
        for tactic_id in KILL_CHAIN_ORDER:
            techniques = sorted(set(phase_map.get(tactic_id, [])))
            phases.append(
                KillChainPhaseEntry(
                    tactic_id=tactic_id,
                    tactic_name=TACTIC_NAMES.get(tactic_id, ""),
                    techniques_observed=techniques,
                )
            )
        return KillChainProgression(campaign_id=campaign_id, phases=phases)

    @staticmethod
    def compare(a: KillChainProgression, b: KillChainProgression) -> float:
        """
        Jaccard similarity of observed tactic sets (0.0–1.0).

        Useful for comparing two campaigns' kill-chain profiles.
        """
        set_a = {p.tactic_id for p in a.phases if p.techniques_observed}
        set_b = {p.tactic_id for p in b.phases if p.techniques_observed}
        if not set_a and not set_b:
            return 0.0
        return len(set_a & set_b) / len(set_a | set_b)
