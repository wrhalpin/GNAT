"""
gnat.analysis.timeline
========================

:class:`TimelineEvent` model and :class:`TimelineBuilder` service for
assembling chronological views of investigation and campaign activity.

Timeline data is derived on demand from
:class:`~gnat.analysis.investigations.Investigation` objects,
:class:`~gnat.investigations.model.EvidenceGraph` nodes, and raw platform
records — it is not stored redundantly.

Usage::

    from gnat.analysis.timeline import TimelineBuilder, TimelineEvent

    builder = TimelineBuilder()
    events  = builder.from_investigation(investigation)
    for event in events:
        print(event.timestamp.isoformat(), event.title)

    # Or from an EvidenceGraph
    events = builder.from_evidence_graph(graph)
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from gnat.analysis.confidence import ConfidenceScore

logger = logging.getLogger(__name__)


class TimelineEventType(str, Enum):
    """Classification of timeline event origin and significance."""
    INDICATOR_FIRST_SEEN  = "indicator_first_seen"
    INDICATOR_LAST_SEEN   = "indicator_last_seen"
    ATTACK_PHASE          = "attack_phase"
    VICTIM_IDENTIFIED     = "victim_identified"
    INCIDENT_OPENED       = "incident_opened"
    INCIDENT_CLOSED       = "incident_closed"
    INVESTIGATION_OPENED  = "investigation_opened"
    INVESTIGATION_CLOSED  = "investigation_closed"
    ANALYST_NOTE          = "analyst_note"
    TASK_COMPLETED        = "task_completed"
    REPORT_PUBLISHED      = "report_published"
    ALERT                 = "alert"
    OBSERVABLE            = "observable"
    OTHER                 = "other"


class TimestampPrecision(str, Enum):
    """Precision of a timeline timestamp (for uncertain historical dates)."""
    EXACT  = "exact"
    HOUR   = "hour"
    DAY    = "day"
    MONTH  = "month"
    YEAR   = "year"


@dataclass
class TimelineEvent:
    """
    A single event on an investigation or campaign timeline.

    Parameters
    ----------
    id : str
        UUID for this event.
    timestamp : datetime
        Event timestamp (UTC).
    title : str
        Short event description.
    event_type : TimelineEventType
        Classification of the event.
    precision : TimestampPrecision
        How precise the timestamp is (default EXACT).
    description : str
        Detailed markdown description.
    linked_artifacts : list of str
        Artifact IDs (indicator, observable, note) related to this event.
    source : str
        Platform or analyst that generated this event.
    confidence : ConfidenceScore, optional
        Confidence in this event's timing or attribution.
    """

    timestamp:         datetime
    title:             str
    event_type:        TimelineEventType   = TimelineEventType.OTHER
    id:                str                 = field(default_factory=lambda: str(uuid.uuid4()))
    precision:         TimestampPrecision  = TimestampPrecision.EXACT
    description:       str                 = ""
    linked_artifacts:  list[str]           = field(default_factory=list)
    source:            str                 = ""
    confidence:        ConfidenceScore | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":                self.id,
            "timestamp":         self.timestamp.isoformat(),
            "precision":         self.precision.value,
            "title":             self.title,
            "event_type":        self.event_type.value,
            "description":       self.description,
            "linked_artifacts":  self.linked_artifacts,
            "source":            self.source,
            "confidence":        self.confidence.to_dict() if self.confidence else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimelineEvent":
        return cls(
            id               = data["id"],
            timestamp        = datetime.fromisoformat(data["timestamp"]),
            precision        = TimestampPrecision(data.get("precision", "exact")),
            title            = data["title"],
            event_type       = TimelineEventType(data.get("event_type", "other")),
            description      = data.get("description", ""),
            linked_artifacts = data.get("linked_artifacts", []),
            source           = data.get("source", ""),
            confidence       = ConfidenceScore.from_dict(data["confidence"])
                               if data.get("confidence") else None,
        )


class TimelineBuilder:
    """
    Derive a sorted :class:`TimelineEvent` list from investigation artifacts.

    The builder queries linked objects and constructs events on demand —
    timeline data is not stored separately.

    Examples
    --------
    >>> builder = TimelineBuilder()
    >>> events  = builder.from_investigation(investigation)
    >>> len(events) > 0
    True
    """

    def from_investigation(self, investigation: Any) -> list[TimelineEvent]:
        """
        Build a timeline from an :class:`~gnat.analysis.investigations.Investigation`.

        Extracts events from:
        - Investigation creation (INVESTIGATION_OPENED)
        - Status transitions recorded in analyst notes
        - Task completions (TASK_COMPLETED)
        - Analyst notes (ANALYST_NOTE)
        - Investigation closure (INVESTIGATION_CLOSED)

        Parameters
        ----------
        investigation : Investigation

        Returns
        -------
        list of TimelineEvent
            Sorted chronologically (oldest first).
        """
        events: list[TimelineEvent] = []

        # Investigation opened
        events.append(TimelineEvent(
            timestamp   = investigation.created_at,
            title       = f"Investigation opened: {investigation.title}",
            event_type  = TimelineEventType.INVESTIGATION_OPENED,
            source      = investigation.created_by,
            description = investigation.description or "",
        ))

        # Analyst notes
        for note in investigation.notes:
            events.append(TimelineEvent(
                timestamp   = note.created_at,
                title       = f"Analyst note by {note.author}",
                event_type  = TimelineEventType.ANALYST_NOTE,
                source      = note.author,
                description = note.content,
                linked_artifacts = note.linked_artifacts,
            ))

        # Completed tasks
        for task in investigation.tasks:
            if hasattr(task, "updated_at") and task.status.value == "done":
                events.append(TimelineEvent(
                    timestamp   = task.updated_at,
                    title       = f"Task completed: {task.title}",
                    event_type  = TimelineEventType.TASK_COMPLETED,
                    source      = task.assigned_to or "unassigned",
                ))

        # Investigation closed
        from gnat.analysis.investigations.models import InvestigationStatus
        if investigation.status == InvestigationStatus.CLOSED:
            events.append(TimelineEvent(
                timestamp   = investigation.updated_at,
                title       = f"Investigation closed: {investigation.title}",
                event_type  = TimelineEventType.INVESTIGATION_CLOSED,
                source      = investigation.created_by,
            ))

        return sorted(events, key=lambda e: e.timestamp)

    def from_evidence_graph(self, graph: Any) -> list[TimelineEvent]:
        """
        Build a timeline from an :class:`~gnat.investigations.model.EvidenceGraph`.

        Extracts events from all EvidenceNode ``time_window`` fields and
        ``stix`` metadata.

        Parameters
        ----------
        graph : EvidenceGraph

        Returns
        -------
        list of TimelineEvent
            Sorted chronologically.
        """
        events: list[TimelineEvent] = []

        for node in graph.nodes.values():
            # Use time_window[0] (first_observed) if available
            ts_str = None
            if node.time_window and node.time_window[0]:
                ts_str = node.time_window[0]
            elif node.stix:
                ts_str = node.stix.get("first_observed") or node.stix.get("created")

            if not ts_str:
                continue

            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            stix = node.stix or {}
            name = (
                stix.get("name")
                or stix.get("value")
                or getattr(node, "node_id", "")
            )

            from gnat.investigations.model import NodeType
            etype = {
                NodeType.INCIDENT:        TimelineEventType.INCIDENT_OPENED,
                NodeType.OBSERVABLE:      TimelineEventType.INDICATOR_FIRST_SEEN,
                NodeType.FINDING:         TimelineEventType.ALERT,
                NodeType.TASK:            TimelineEventType.TASK_COMPLETED,
                NodeType.TIMELINE_EVENT:  TimelineEventType.OTHER,
            }.get(node.node_type, TimelineEventType.OTHER)

            events.append(TimelineEvent(
                timestamp  = ts,
                title      = str(name),
                event_type = etype,
                source     = node.platform,
                linked_artifacts = list(node.ioc_values or []),
            ))

        return sorted(events, key=lambda e: e.timestamp)

    def from_raw(
        self,
        records: list[dict[str, Any]],
        timestamp_field: str = "timestamp",
        title_field:     str = "title",
        source:          str = "unknown",
    ) -> list[TimelineEvent]:
        """
        Build a timeline from a list of raw dicts.

        Parameters
        ----------
        records : list of dict
        timestamp_field : str
            Key in each record containing the ISO 8601 timestamp.
        title_field : str
            Key in each record containing the event title.
        source : str
            Platform or analyst label applied to all events.

        Returns
        -------
        list of TimelineEvent
        """
        events: list[TimelineEvent] = []
        for rec in records:
            ts_str = rec.get(timestamp_field)
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
            events.append(TimelineEvent(
                timestamp  = ts,
                title      = str(rec.get(title_field, "Event")),
                event_type = TimelineEventType.OTHER,
                source     = source,
                description = str(rec.get("description", "")),
            ))
        return sorted(events, key=lambda e: e.timestamp)
