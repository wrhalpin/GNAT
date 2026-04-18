# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.hypothesis
========================================

Competing-attribution hypothesis management.

An :class:`AttributionHypothesis` asserts that a specific threat actor
is behind a specific campaign, with supporting/contradicting evidence
and a confidence score tracked over time. Multiple hypotheses can
co-exist for the same campaign; :class:`AttributionEngine` manages
creation, evidence accrual, scoring, and resolution.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.confidence import (
    ConfidenceScore,
    InformationCredibility,
    SourceReliability,
)
from gnat.analysis.investigations.models import HypothesisStatus

AI_CONFIDENCE_CEILING = 60


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class AttributionEvidence:
    """A single piece of evidence supporting or contradicting an attribution."""

    evidence_type: str
    description: str
    artifact_ids: list[str] = field(default_factory=list)
    weight: int = 10
    source: str = "analyst"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "description": self.description,
            "artifact_ids": list(self.artifact_ids),
            "weight": self.weight,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttributionEvidence:
        return cls(
            evidence_type=data.get("evidence_type", ""),
            description=data.get("description", ""),
            artifact_ids=list(data.get("artifact_ids") or []),
            weight=int(data.get("weight", 10)),
            source=data.get("source", "analyst"),
        )


@dataclass
class ConfidenceSnapshot:
    """Point-in-time confidence record for audit trail."""

    timestamp: datetime
    stix_confidence: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "stix_confidence": self.stix_confidence,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConfidenceSnapshot:
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        else:
            ts = _utcnow()
        return cls(
            timestamp=ts,
            stix_confidence=int(data.get("stix_confidence", 0)),
            reason=data.get("reason", ""),
        )


@dataclass
class AttributionHypothesis:
    """
    A hypothesis asserting that a threat actor is behind a campaign.

    Multiple hypotheses can exist per campaign. The
    :class:`AttributionEngine` manages their lifecycle from OPEN through
    SUPPORTED / REFUTED / INCONCLUSIVE.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    threat_actor_id: str = ""
    threat_actor_name: str = ""
    status: HypothesisStatus = HypothesisStatus.OPEN
    rationale: str = ""
    source: str = "analyst"

    supporting_evidence: list[AttributionEvidence] = field(default_factory=list)
    contradicting_evidence: list[AttributionEvidence] = field(default_factory=list)
    confidence_history: list[ConfidenceSnapshot] = field(default_factory=list)

    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)
    resolved_at: datetime | None = None
    resolved_by: str | None = None

    @property
    def stix_confidence(self) -> int:
        """Current STIX 0-100 confidence, derived from evidence weights."""
        support = sum(e.weight for e in self.supporting_evidence)
        contra = sum(e.weight for e in self.contradicting_evidence)
        raw = max(0, min(100, support - contra))
        if self.source == "ai_copilot":
            return min(raw, AI_CONFIDENCE_CEILING)
        return raw

    @property
    def confidence_score(self) -> ConfidenceScore:
        """Full Admiralty Scale confidence score."""
        stix = self.stix_confidence
        if stix >= 70:
            cred = InformationCredibility.PROBABLY_TRUE
        elif stix >= 40:
            cred = InformationCredibility.POSSIBLY_TRUE
        else:
            cred = InformationCredibility.DOUBTFUL
        return ConfidenceScore(
            source_reliability=SourceReliability.C_FAIRLY_RELIABLE,
            information_credibility=cred,
            stix_confidence=stix,
            rationale=self.rationale,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "threat_actor_id": self.threat_actor_id,
            "threat_actor_name": self.threat_actor_name,
            "status": self.status.value,
            "rationale": self.rationale,
            "source": self.source,
            "stix_confidence": self.stix_confidence,
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
            "contradicting_evidence": [e.to_dict() for e in self.contradicting_evidence],
            "confidence_history": [s.to_dict() for s in self.confidence_history],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttributionHypothesis:
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
        resolved = data.get("resolved_at")
        if isinstance(resolved, str):
            resolved = datetime.fromisoformat(resolved)

        return cls(
            id=data.get("id") or str(uuid.uuid4()),
            campaign_id=data.get("campaign_id", ""),
            threat_actor_id=data.get("threat_actor_id", ""),
            threat_actor_name=data.get("threat_actor_name", ""),
            status=HypothesisStatus(data.get("status", "open")),
            rationale=data.get("rationale", ""),
            source=data.get("source", "analyst"),
            supporting_evidence=[
                AttributionEvidence.from_dict(e)
                for e in (data.get("supporting_evidence") or [])
            ],
            contradicting_evidence=[
                AttributionEvidence.from_dict(e)
                for e in (data.get("contradicting_evidence") or [])
            ],
            confidence_history=[
                ConfidenceSnapshot.from_dict(s)
                for s in (data.get("confidence_history") or [])
            ],
            created_at=created,
            updated_at=updated,
            resolved_at=resolved,
            resolved_by=data.get("resolved_by"),
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AttributionEngine:
    """
    Manages the lifecycle of attribution hypotheses for campaigns.

    Stateless — all state lives in the hypothesis objects themselves,
    which are persisted by the caller (typically :class:`CampaignService`).
    """

    def propose(
        self,
        campaign_id: str,
        threat_actor_id: str,
        threat_actor_name: str = "",
        *,
        rationale: str = "",
        evidence: list[AttributionEvidence] | None = None,
        source: str = "analyst",
    ) -> AttributionHypothesis:
        """Create a new attribution hypothesis."""
        h = AttributionHypothesis(
            campaign_id=campaign_id,
            threat_actor_id=threat_actor_id,
            threat_actor_name=threat_actor_name,
            rationale=rationale,
            source=source,
            supporting_evidence=list(evidence or []),
        )
        h.confidence_history.append(
            ConfidenceSnapshot(
                timestamp=_utcnow(),
                stix_confidence=h.stix_confidence,
                reason="initial proposal",
            )
        )
        return h

    def add_supporting_evidence(
        self,
        hypothesis: AttributionHypothesis,
        evidence: AttributionEvidence,
    ) -> AttributionHypothesis:
        """Add supporting evidence and record a confidence snapshot."""
        hypothesis.supporting_evidence.append(evidence)
        hypothesis.updated_at = _utcnow()
        hypothesis.confidence_history.append(
            ConfidenceSnapshot(
                timestamp=_utcnow(),
                stix_confidence=hypothesis.stix_confidence,
                reason=f"added supporting: {evidence.evidence_type}",
            )
        )
        return hypothesis

    def add_contradicting_evidence(
        self,
        hypothesis: AttributionHypothesis,
        evidence: AttributionEvidence,
    ) -> AttributionHypothesis:
        """Add contradicting evidence and record a confidence snapshot."""
        hypothesis.contradicting_evidence.append(evidence)
        hypothesis.updated_at = _utcnow()
        hypothesis.confidence_history.append(
            ConfidenceSnapshot(
                timestamp=_utcnow(),
                stix_confidence=hypothesis.stix_confidence,
                reason=f"added contradicting: {evidence.evidence_type}",
            )
        )
        return hypothesis

    def resolve(
        self,
        hypothesis: AttributionHypothesis,
        status: HypothesisStatus,
        *,
        resolved_by: str = "analyst",
    ) -> AttributionHypothesis:
        """Move a hypothesis from OPEN to a resolved state."""
        if hypothesis.status != HypothesisStatus.OPEN:
            raise ValueError(
                f"hypothesis {hypothesis.id} is already resolved "
                f"({hypothesis.status.value})"
            )
        if status == HypothesisStatus.OPEN:
            raise ValueError("cannot resolve to OPEN")
        hypothesis.status = status
        hypothesis.resolved_at = _utcnow()
        hypothesis.resolved_by = resolved_by
        hypothesis.updated_at = _utcnow()
        hypothesis.confidence_history.append(
            ConfidenceSnapshot(
                timestamp=_utcnow(),
                stix_confidence=hypothesis.stix_confidence,
                reason=f"resolved as {status.value} by {resolved_by}",
            )
        )
        return hypothesis

    @staticmethod
    def pick_winner(
        hypotheses: list[AttributionHypothesis],
    ) -> AttributionHypothesis | None:
        """Return the highest-confidence SUPPORTED hypothesis, or None."""
        supported = [
            h for h in hypotheses if h.status == HypothesisStatus.SUPPORTED
        ]
        if not supported:
            return None
        return max(supported, key=lambda h: h.stix_confidence)
