# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.investigations.models
=====================================

Pure-Python dataclasses for the Investigation object model.

These classes carry no SQLAlchemy or database dependency — persistence is
handled separately by :mod:`.storage`.  They can be instantiated, passed
around, and serialised without any database connection.

Key types
---------
- :class:`Investigation` — the top-level analyst workspace
- :class:`Hypothesis` — a falsifiable statement under investigation
- :class:`AnalystNote` — freeform markdown note attached to an investigation
- :class:`InvestigationTask` — actionable task with kanban-style status
- :class:`InvestigationScope` — temporal and thematic scope constraints

Status enumerations
-------------------
- :class:`InvestigationStatus` — OPEN → IN_PROGRESS → REVIEW → CLOSED
- :class:`HypothesisStatus` — OPEN / SUPPORTED / REFUTED / INCONCLUSIVE
- :class:`TaskStatus` — TODO / IN_PROGRESS / DONE / BLOCKED
- :class:`TaskPriority` — LOW / MEDIUM / HIGH / CRITICAL
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

class InvestigationStatus(str, Enum):
    """Life-cycle status of an Investigation."""
    OPEN        = "open"
    IN_PROGRESS = "in_progress"
    REVIEW      = "review"
    CLOSED      = "closed"


class HypothesisStatus(str, Enum):
    """Evaluation status of a Hypothesis."""
    OPEN         = "open"
    SUPPORTED    = "supported"
    REFUTED      = "refuted"
    INCONCLUSIVE = "inconclusive"


class TaskStatus(str, Enum):
    """Kanban-style status for an InvestigationTask."""
    TODO        = "todo"
    IN_PROGRESS = "in_progress"
    DONE        = "done"
    BLOCKED     = "blocked"


class TaskPriority(str, Enum):
    """Priority level for an InvestigationTask."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ── Valid state machine transitions ───────────────────────────────────────────

INVESTIGATION_TRANSITIONS: dict[InvestigationStatus, frozenset[InvestigationStatus]] = {
    InvestigationStatus.OPEN:        frozenset({InvestigationStatus.IN_PROGRESS}),
    InvestigationStatus.IN_PROGRESS: frozenset({InvestigationStatus.REVIEW, InvestigationStatus.CLOSED}),
    InvestigationStatus.REVIEW:      frozenset({InvestigationStatus.IN_PROGRESS, InvestigationStatus.CLOSED}),
    InvestigationStatus.CLOSED:      frozenset(),  # terminal
}


# ── Helper ────────────────────────────────────────────────────────────────────

def _now() -> datetime:
    """Internal helper for now."""
    return datetime.now(tz=timezone.utc)


def _uuid() -> str:
    """Internal helper for uuid."""
    return str(uuid.uuid4())


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class InvestigationScope:
    """
    Temporal and thematic scope constraints for an Investigation.

    Parameters
    ----------
    date_range_start : datetime, optional
        Earliest activity date of interest.
    date_range_end : datetime, optional
        Latest activity date of interest.
    target_sectors : list of str
        Industry verticals in scope (e.g. ``["financial", "healthcare"]``).
    target_geographies : list of str
        Country codes or region names in scope.
    ioc_types : list of str
        STIX indicator types in scope (e.g. ``["domain-name", "ipv4-addr"]``).
    keywords : list of str
        Free-text keywords used during automated seed expansion.
    """

    date_range_start:    datetime | None = None
    date_range_end:      datetime | None = None
    target_sectors:      list[str]       = field(default_factory=list)
    target_geographies:  list[str]       = field(default_factory=list)
    ioc_types:           list[str]       = field(default_factory=list)
    keywords:            list[str]       = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "date_range_start":   self.date_range_start.isoformat() if self.date_range_start else None,
            "date_range_end":     self.date_range_end.isoformat() if self.date_range_end else None,
            "target_sectors":     self.target_sectors,
            "target_geographies": self.target_geographies,
            "ioc_types":          self.ioc_types,
            "keywords":           self.keywords,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InvestigationScope":
        """Create an instance from DICT data."""
        return cls(
            date_range_start    = datetime.fromisoformat(data["date_range_start"])
                                  if data.get("date_range_start") else None,
            date_range_end      = datetime.fromisoformat(data["date_range_end"])
                                  if data.get("date_range_end") else None,
            target_sectors      = data.get("target_sectors", []),
            target_geographies  = data.get("target_geographies", []),
            ioc_types           = data.get("ioc_types", []),
            keywords            = data.get("keywords", []),
        )


@dataclass
class Hypothesis:
    """
    A falsifiable analytical statement attached to an Investigation.

    Parameters
    ----------
    id : str
        UUID for this hypothesis.
    statement : str
        The falsifiable claim, e.g. "BLACKCAT operator is responsible for
        the April 2026 ransomware campaign."
    confidence : ConfidenceScore, optional
        Current confidence in the hypothesis.
    status : HypothesisStatus
        Evaluation status.
    supporting_evidence : list of str
        Artifact IDs (indicator IDs, observable IDs, note IDs) that support
        this hypothesis.
    refuting_evidence : list of str
        Artifact IDs that contradict this hypothesis.
    created_at : datetime
    updated_at : datetime
    """

    statement:           str
    id:                  str                  = field(default_factory=_uuid)
    confidence:          ConfidenceScore | None = None
    status:              HypothesisStatus     = HypothesisStatus.OPEN
    supporting_evidence: list[str]            = field(default_factory=list)
    refuting_evidence:   list[str]            = field(default_factory=list)
    created_at:          datetime             = field(default_factory=_now)
    updated_at:          datetime             = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "id":                  self.id,
            "statement":           self.statement,
            "confidence":          self.confidence.to_dict() if self.confidence else None,
            "status":              self.status.value,
            "supporting_evidence": self.supporting_evidence,
            "refuting_evidence":   self.refuting_evidence,
            "created_at":          self.created_at.isoformat(),
            "updated_at":          self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Hypothesis":
        """Create an instance from DICT data."""
        return cls(
            id                  = data["id"],
            statement           = data["statement"],
            confidence          = ConfidenceScore.from_dict(data["confidence"])
                                  if data.get("confidence") else None,
            status              = HypothesisStatus(data.get("status", "open")),
            supporting_evidence = data.get("supporting_evidence", []),
            refuting_evidence   = data.get("refuting_evidence", []),
            created_at          = datetime.fromisoformat(data["created_at"]),
            updated_at          = datetime.fromisoformat(data["updated_at"]),
        )


@dataclass
class AnalystNote:
    """
    A freeform markdown note attached to an Investigation.

    Parameters
    ----------
    id : str
        UUID for this note.
    content : str
        Markdown-formatted note body.
    author : str
        Analyst identifier (username or email).
    created_at : datetime
    linked_artifacts : list of str
        Optional artifact IDs this note annotates.
    """

    content:          str
    author:           str
    id:               str        = field(default_factory=_uuid)
    created_at:       datetime   = field(default_factory=_now)
    linked_artifacts: list[str]  = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "id":               self.id,
            "content":          self.content,
            "author":           self.author,
            "created_at":       self.created_at.isoformat(),
            "linked_artifacts": self.linked_artifacts,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalystNote":
        """Create an instance from DICT data."""
        return cls(
            id               = data["id"],
            content          = data["content"],
            author           = data["author"],
            created_at       = datetime.fromisoformat(data["created_at"]),
            linked_artifacts = data.get("linked_artifacts", []),
        )


@dataclass
class InvestigationTask:
    """
    An actionable task within an Investigation.

    Parameters
    ----------
    id : str
        UUID for this task.
    title : str
        Short task description.
    description : str
        Detailed task body (markdown).
    status : TaskStatus
        Current kanban state.
    priority : TaskPriority
        Task urgency.
    assigned_to : str, optional
        Analyst identifier.
    due_date : datetime, optional
        Target completion date.
    created_at : datetime
    updated_at : datetime
    """

    title:        str
    id:           str              = field(default_factory=_uuid)
    description:  str              = ""
    status:       TaskStatus       = TaskStatus.TODO
    priority:     TaskPriority     = TaskPriority.MEDIUM
    assigned_to:  str | None       = None
    due_date:     datetime | None  = None
    created_at:   datetime         = field(default_factory=_now)
    updated_at:   datetime         = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert this object to DICT format."""
        return {
            "id":          self.id,
            "title":       self.title,
            "description": self.description,
            "status":      self.status.value,
            "priority":    self.priority.value,
            "assigned_to": self.assigned_to,
            "due_date":    self.due_date.isoformat() if self.due_date else None,
            "created_at":  self.created_at.isoformat(),
            "updated_at":  self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InvestigationTask":
        """Create an instance from DICT data."""
        return cls(
            id          = data["id"],
            title       = data["title"],
            description = data.get("description", ""),
            status      = TaskStatus(data.get("status", "todo")),
            priority    = TaskPriority(data.get("priority", "medium")),
            assigned_to = data.get("assigned_to"),
            due_date    = datetime.fromisoformat(data["due_date"]) if data.get("due_date") else None,
            created_at  = datetime.fromisoformat(data["created_at"]),
            updated_at  = datetime.fromisoformat(data["updated_at"]),
        )


@dataclass
class Investigation:
    """
    The top-level analyst workspace for a security investigation.

    An Investigation tracks the full lifecycle of an analyst's work on a
    specific security event or threat: from initial scoping through
    hypothesis development, evidence collection, task management, and
    final closure.

    Parameters
    ----------
    id : str
        UUID for this investigation.
    title : str
        Short descriptive title.
    description : str
        Markdown-formatted investigation description and background.
    status : InvestigationStatus
        Current lifecycle state.
    classification : TLPLevel
        TLP classification for this investigation.
    created_by : str
        Analyst who created this investigation.
    assigned_to : list of str
        Analysts currently assigned to this investigation.
    scope : InvestigationScope
        Temporal and thematic scope constraints.
    hypothesis : list of Hypothesis
        Analytical hypotheses under evaluation.
    notes : list of AnalystNote
        Freeform markdown notes.
    tasks : list of InvestigationTask
        Actionable tasks.
    indicators : list of str
        Normalized indicator IDs linked to this investigation.
    observables : list of str
        Observable IDs linked to this investigation.
    threat_actors : list of str
        STIX ThreatActor IDs linked to this investigation.
    campaigns : list of str
        STIX Campaign IDs linked to this investigation.
    reports : list of str
        Report IDs produced from this investigation.
    tags : list of str
        Free-text tags for search and filtering.
    source_connectors : list of str
        Platform names that contributed data (e.g. ``["xsoar", "threatq"]``).
    stix_bundle_ref : str, optional
        STIX bundle ID if this investigation has been exported.
    created_at : datetime
    updated_at : datetime

    Examples
    --------
    >>> inv = Investigation(
    ...     title       = "Ransomware triage — April 2026",
    ...     created_by  = "analyst@example.com",
    ...     description = "Investigating suspected BLACKCAT intrusion.",
    ... )
    >>> inv.status
    <InvestigationStatus.OPEN: 'open'>
    """

    title:             str
    created_by:        str
    id:                str                    = field(default_factory=_uuid)
    description:       str                    = ""
    status:            InvestigationStatus    = InvestigationStatus.OPEN
    classification:    TLPLevel               = TLPLevel.AMBER
    assigned_to:       list[str]              = field(default_factory=list)
    scope:             InvestigationScope     = field(default_factory=InvestigationScope)
    hypothesis:        list[Hypothesis]       = field(default_factory=list)
    notes:             list[AnalystNote]      = field(default_factory=list)
    tasks:             list[InvestigationTask] = field(default_factory=list)
    indicators:        list[str]              = field(default_factory=list)
    observables:       list[str]              = field(default_factory=list)
    threat_actors:     list[str]              = field(default_factory=list)
    campaigns:         list[str]              = field(default_factory=list)
    reports:           list[str]              = field(default_factory=list)
    tags:              list[str]              = field(default_factory=list)
    source_connectors: list[str]              = field(default_factory=list)
    stix_bundle_ref:   str | None             = None
    created_at:        datetime               = field(default_factory=_now)
    updated_at:        datetime               = field(default_factory=_now)

    def can_transition_to(self, new_status: InvestigationStatus) -> bool:
        """Return True if a transition from current status to *new_status* is valid."""
        return new_status in INVESTIGATION_TRANSITIONS.get(self.status, frozenset())

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict suitable for JSON storage."""
        return {
            "id":                self.id,
            "title":             self.title,
            "description":       self.description,
            "status":            self.status.value,
            "classification":    self.classification.value,
            "created_by":        self.created_by,
            "assigned_to":       self.assigned_to,
            "scope":             self.scope.to_dict(),
            "hypothesis":        [h.to_dict() for h in self.hypothesis],
            "notes":             [n.to_dict() for n in self.notes],
            "tasks":             [t.to_dict() for t in self.tasks],
            "indicators":        self.indicators,
            "observables":       self.observables,
            "threat_actors":     self.threat_actors,
            "campaigns":         self.campaigns,
            "reports":           self.reports,
            "tags":              self.tags,
            "source_connectors": self.source_connectors,
            "stix_bundle_ref":   self.stix_bundle_ref,
            "created_at":        self.created_at.isoformat(),
            "updated_at":        self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Investigation":
        """Deserialise from a plain dict produced by :meth:`to_dict`."""
        return cls(
            id                = data["id"],
            title             = data["title"],
            description       = data.get("description", ""),
            status            = InvestigationStatus(data.get("status", "open")),
            classification    = TLPLevel(data.get("classification", "amber")),
            created_by        = data.get("created_by", ""),
            assigned_to       = data.get("assigned_to", []),
            scope             = InvestigationScope.from_dict(data.get("scope", {})),
            hypothesis        = [Hypothesis.from_dict(h) for h in data.get("hypothesis", [])],
            notes             = [AnalystNote.from_dict(n) for n in data.get("notes", [])],
            tasks             = [InvestigationTask.from_dict(t) for t in data.get("tasks", [])],
            indicators        = data.get("indicators", []),
            observables       = data.get("observables", []),
            threat_actors     = data.get("threat_actors", []),
            campaigns         = data.get("campaigns", []),
            reports           = data.get("reports", []),
            tags              = data.get("tags", []),
            source_connectors = data.get("source_connectors", []),
            stix_bundle_ref   = data.get("stix_bundle_ref"),
            created_at        = datetime.fromisoformat(data["created_at"]),
            updated_at        = datetime.fromisoformat(data["updated_at"]),
        )
