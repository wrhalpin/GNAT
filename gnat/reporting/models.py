# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reporting.models
======================

Pure-Python dataclasses for the Report object model.

A :class:`Report` is a structured intelligence product produced from one or
more :class:`~gnat.analysis.investigations.Investigation` objects.  It has a
formal lifecycle (DRAFT → REVIEW → APPROVED → PUBLISHED → ARCHIVED) and
serialises to a STIX 2.1 ``report`` SDO when published.

Key types
---------
- :class:`Report` — the top-level intelligence product
- :class:`Finding` — a key analytical finding with confidence and evidence
- :class:`EvidenceLink` — a statement-to-artifact binding
- :class:`Attribution` — threat actor attribution with MITRE ATT&CK mapping
- :class:`ReportSection` — a titled section of report body content
- :class:`ChangelogEntry` — version history entry

Status enumerations
-------------------
- :class:`ReportType` — INCIDENT_REPORT / THREAT_ACTOR_PROFILE / CAMPAIGN_ANALYSIS / etc.
- :class:`ReportStatus` — DRAFT / REVIEW / APPROVED / PUBLISHED / ARCHIVED
- :class:`EvidenceLinkType` — SUPPORTS / CONTRADICTS / CONTEXTUALIZES
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from gnat.analysis.confidence import ConfidenceScore
from gnat.analysis.tlp import TLPLevel

# ── Enumerations ──────────────────────────────────────────────────────────────


class ReportType(str, Enum):
    """Intelligence product type."""

    INCIDENT_REPORT = "incident_report"
    THREAT_ACTOR_PROFILE = "threat_actor_profile"
    CAMPAIGN_ANALYSIS = "campaign_analysis"
    DAILY_BRIEF = "daily_brief"
    VULNERABILITY_ADVISORY = "vulnerability_advisory"
    FINISHED_INTELLIGENCE = "finished_intelligence"


class ReportStatus(str, Enum):
    """Lifecycle state of a Report."""

    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class EvidenceLinkType(str, Enum):
    """How an artifact relates to a statement."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXTUALIZES = "contextualizes"


# ── Valid state machine transitions ───────────────────────────────────────────

REPORT_TRANSITIONS: dict[ReportStatus, frozenset[ReportStatus]] = {
    ReportStatus.DRAFT: frozenset({ReportStatus.REVIEW, ReportStatus.ARCHIVED}),
    ReportStatus.REVIEW: frozenset(
        {ReportStatus.DRAFT, ReportStatus.APPROVED, ReportStatus.ARCHIVED}
    ),
    ReportStatus.APPROVED: frozenset(
        {ReportStatus.PUBLISHED, ReportStatus.DRAFT, ReportStatus.ARCHIVED}
    ),
    ReportStatus.PUBLISHED: frozenset({ReportStatus.ARCHIVED}),
    ReportStatus.ARCHIVED: frozenset(),  # terminal
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _now() -> datetime:
    """Internal helper for now."""
    return datetime.now(tz=timezone.utc)


def _uuid() -> str:
    """Internal helper for uuid."""
    return str(uuid.uuid4())


# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class EvidenceLink:
    """
    A statement-to-artifact binding supporting (or contradicting) a Finding.

    Parameters
    ----------
    id : str
        UUID for this evidence link.
    statement : str
        The claim this artifact supports, contradicts, or contextualises.
    artifact_type : str
        STIX object type of the linked artifact (e.g. ``"indicator"``).
    artifact_id : str
        STIX ID or platform-specific ID of the artifact.
    artifact_source : str
        Platform name that contributed this artifact (e.g. ``"threatq"``).
    link_type : EvidenceLinkType
        How the artifact relates to the statement.
    confidence : ConfidenceScore, optional
        Confidence for this specific evidence link.
    """

    statement: str
    artifact_type: str
    artifact_id: str
    artifact_source: str
    id: str = field(default_factory=_uuid)
    link_type: EvidenceLinkType = EvidenceLinkType.SUPPORTS
    confidence: ConfidenceScore | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "id": self.id,
            "statement": self.statement,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "artifact_source": self.artifact_source,
            "link_type": self.link_type.value,
            "confidence": self.confidence.to_dict() if self.confidence else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceLink:
        """Create an instance from DICT data."""
        return cls(
            id=data["id"],
            statement=data["statement"],
            artifact_type=data["artifact_type"],
            artifact_id=data["artifact_id"],
            artifact_source=data["artifact_source"],
            link_type=EvidenceLinkType(data.get("link_type", "supports")),
            confidence=ConfidenceScore.from_dict(data["confidence"])
            if data.get("confidence")
            else None,
        )


@dataclass
class Finding:
    """
    A key analytical finding within a Report.

    Parameters
    ----------
    id : str
        UUID for this finding.
    statement : str
        The analytical conclusion.
    confidence : ConfidenceScore, optional
        Confidence in this finding.
    supporting_evidence : list of str
        IDs of :class:`EvidenceLink` objects that support this finding.
    mitre_techniques : list of str
        ATT&CK technique IDs relevant to this finding (e.g. ``["T1059.003"]``).
    """

    statement: str
    id: str = field(default_factory=_uuid)
    confidence: ConfidenceScore | None = None
    supporting_evidence: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "id": self.id,
            "statement": self.statement,
            "confidence": self.confidence.to_dict() if self.confidence else None,
            "supporting_evidence": self.supporting_evidence,
            "mitre_techniques": self.mitre_techniques,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Create an instance from DICT data."""
        return cls(
            id=data["id"],
            statement=data["statement"],
            confidence=ConfidenceScore.from_dict(data["confidence"])
            if data.get("confidence")
            else None,
            supporting_evidence=data.get("supporting_evidence", []),
            mitre_techniques=data.get("mitre_techniques", []),
        )


@dataclass
class Attribution:
    """
    Threat actor attribution for a Report.

    Parameters
    ----------
    threat_actor_name : str
        Display name of the attributed threat actor.
    confidence : ConfidenceScore
        Attribution confidence.
    rationale : str
        Explanation of the attribution basis.
    threat_actor_id : str, optional
        STIX ThreatActor SDO ID.
    mitre_group_id : str, optional
        MITRE ATT&CK group ID (e.g. ``"G0007"`` for APT28).
    """

    threat_actor_name: str
    confidence: ConfidenceScore
    rationale: str
    threat_actor_id: str | None = None
    mitre_group_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "threat_actor_name": self.threat_actor_name,
            "confidence": self.confidence.to_dict(),
            "rationale": self.rationale,
            "threat_actor_id": self.threat_actor_id,
            "mitre_group_id": self.mitre_group_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Attribution:
        """Create an instance from DICT data."""
        return cls(
            threat_actor_name=data["threat_actor_name"],
            confidence=ConfidenceScore.from_dict(data["confidence"]),
            rationale=data.get("rationale", ""),
            threat_actor_id=data.get("threat_actor_id"),
            mitre_group_id=data.get("mitre_group_id"),
        )


@dataclass
class ReportSection:
    """
    A titled section of report body content.

    Parameters
    ----------
    title : str
        Section heading.
    content : str
        Markdown-formatted section body.
    order : int
        Display order (lower = earlier in document).
    """

    title: str
    content: str = ""
    order: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {"title": self.title, "content": self.content, "order": self.order}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReportSection:
        """Create an instance from DICT data."""
        return cls(
            title=data["title"],
            content=data.get("content", ""),
            order=data.get("order", 0),
        )


@dataclass
class ChangelogEntry:
    """
    A version history entry for a Report.

    Parameters
    ----------
    version : int
        Report version number.
    changed_by : str
        Analyst who made this change.
    changed_at : datetime
    summary : str
        Short description of what changed.
    """

    version: int
    changed_by: str
    summary: str
    changed_at: datetime = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "version": self.version,
            "changed_by": self.changed_by,
            "summary": self.summary,
            "changed_at": self.changed_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChangelogEntry:
        """Create an instance from DICT data."""
        return cls(
            version=data["version"],
            changed_by=data["changed_by"],
            summary=data.get("summary", ""),
            changed_at=datetime.fromisoformat(data["changed_at"]),
        )


@dataclass
class Report:
    """
    A structured intelligence product.

    A Report has a formal lifecycle (DRAFT → REVIEW → APPROVED → PUBLISHED →
    ARCHIVED).  When published it serialises to a STIX 2.1 ``report`` SDO.

    Parameters
    ----------
    id : str
        UUID for this report.
    title : str
        Report title.
    report_type : ReportType
        Category of intelligence product.
    status : ReportStatus
        Current lifecycle state.
    classification : TLPLevel
        TLP classification.
    authors : list of str
        Analyst identifiers.
    reviewers : list of str
        Reviewer identifiers.
    executive_summary : str
        Markdown-formatted executive summary.
    key_findings : list of Finding
        Key analytical conclusions.
    body_sections : list of ReportSection
        Full report body, ordered by ``section.order``.
    recommendations : list of str
        Action recommendations.
    attribution : Attribution, optional
        Threat actor attribution, if applicable.
    overall_confidence : ConfidenceScore, optional
        Overall report confidence.
    evidence_links : list of EvidenceLink
        Statement-to-artifact bindings.
    linked_investigation : str, optional
        ID of the Investigation this report was produced from.
    version : int
        Report version number (incremented on each publish).
    changelog : list of ChangelogEntry
        Version history.
    parent_report_id : str, optional
        ID of the previous published version (for report updates).
    distribution_list : list of str
        Recipients for dissemination.
    tags : list of str
        Free-text tags.
    stix_report_ref : str, optional
        STIX Report SDO ID, set when the report is published.
    stix_bundle_json : str, optional
        JSON-serialised STIX bundle, set when the report is published.
    published_at : datetime, optional
        Publication timestamp.
    created_at : datetime
    updated_at : datetime

    Examples
    --------
    >>> report = Report(
    ...     title       = "BLACKCAT Ransomware — April 2026",
    ...     report_type = ReportType.INCIDENT_REPORT,
    ...     authors     = ["analyst@example.com"],
    ... )
    >>> report.status
    <ReportStatus.DRAFT: 'draft'>
    >>> report.can_transition_to(ReportStatus.REVIEW)
    True
    """

    title: str
    report_type: ReportType
    id: str = field(default_factory=_uuid)
    status: ReportStatus = ReportStatus.DRAFT
    classification: TLPLevel = TLPLevel.AMBER
    authors: list[str] = field(default_factory=list)
    reviewers: list[str] = field(default_factory=list)
    executive_summary: str = ""
    key_findings: list[Finding] = field(default_factory=list)
    body_sections: list[ReportSection] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    attribution: Attribution | None = None
    overall_confidence: ConfidenceScore | None = None
    evidence_links: list[EvidenceLink] = field(default_factory=list)
    linked_investigation: str | None = None
    version: int = 1
    changelog: list[ChangelogEntry] = field(default_factory=list)
    parent_report_id: str | None = None
    distribution_list: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    stix_report_ref: str | None = None
    stix_bundle_json: str | None = None
    published_at: datetime | None = None
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)

    @property
    def is_published(self) -> bool:
        """True if the report has reached PUBLISHED status."""
        return self.status == ReportStatus.PUBLISHED

    def can_transition_to(self, new_status: ReportStatus) -> bool:
        """Return True if a transition from current status to *new_status* is valid."""
        return new_status in REPORT_TRANSITIONS.get(self.status, frozenset())

    @property
    def ordered_sections(self) -> list[ReportSection]:
        """Body sections sorted by their ``order`` field."""
        return sorted(self.body_sections, key=lambda s: s.order)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict suitable for JSON storage."""
        return {
            "id": self.id,
            "title": self.title,
            "report_type": self.report_type.value,
            "status": self.status.value,
            "classification": self.classification.value,
            "authors": self.authors,
            "reviewers": self.reviewers,
            "executive_summary": self.executive_summary,
            "key_findings": [f.to_dict() for f in self.key_findings],
            "body_sections": [s.to_dict() for s in self.body_sections],
            "recommendations": self.recommendations,
            "attribution": self.attribution.to_dict() if self.attribution else None,
            "overall_confidence": self.overall_confidence.to_dict()
            if self.overall_confidence
            else None,
            "evidence_links": [e.to_dict() for e in self.evidence_links],
            "linked_investigation": self.linked_investigation,
            "version": self.version,
            "changelog": [c.to_dict() for c in self.changelog],
            "parent_report_id": self.parent_report_id,
            "distribution_list": self.distribution_list,
            "tags": self.tags,
            "stix_report_ref": self.stix_report_ref,
            "stix_bundle_json": self.stix_bundle_json,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Report:
        """Deserialise from a plain dict produced by :meth:`to_dict`."""
        return cls(
            id=data["id"],
            title=data["title"],
            report_type=ReportType(data["report_type"]),
            status=ReportStatus(data.get("status", "draft")),
            classification=TLPLevel(data.get("classification", "amber")),
            authors=data.get("authors", []),
            reviewers=data.get("reviewers", []),
            executive_summary=data.get("executive_summary", ""),
            key_findings=[Finding.from_dict(f) for f in data.get("key_findings", [])],
            body_sections=[ReportSection.from_dict(s) for s in data.get("body_sections", [])],
            recommendations=data.get("recommendations", []),
            attribution=Attribution.from_dict(data["attribution"])
            if data.get("attribution")
            else None,
            overall_confidence=ConfidenceScore.from_dict(data["overall_confidence"])
            if data.get("overall_confidence")
            else None,
            evidence_links=[EvidenceLink.from_dict(e) for e in data.get("evidence_links", [])],
            linked_investigation=data.get("linked_investigation"),
            version=data.get("version", 1),
            changelog=[ChangelogEntry.from_dict(c) for c in data.get("changelog", [])],
            parent_report_id=data.get("parent_report_id"),
            distribution_list=data.get("distribution_list", []),
            tags=data.get("tags", []),
            stix_report_ref=data.get("stix_report_ref"),
            stix_bundle_json=data.get("stix_bundle_json"),
            published_at=datetime.fromisoformat(data["published_at"])
            if data.get("published_at")
            else None,
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
        )
