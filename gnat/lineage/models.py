"""
gnat.lineage.models
====================

Event-sourced data lineage model.

Each :class:`LineageEvent` is an immutable append-only record describing
a single operation on a STIX object (ingestion, enrichment, export, etc.).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class LineageEventType(str, Enum):
    """Types of operations that generate lineage events."""

    INGESTED = "ingested"
    ENRICHED = "enriched"
    NORMALIZED = "normalized"
    LINKED = "linked"
    EXPORTED = "exported"
    REPORTED = "reported"
    DELETED = "deleted"


@dataclass
class LineageEvent:
    """
    An immutable lineage event recording one operation on a STIX object.

    Parameters
    ----------
    event_type : LineageEventType
        The operation that occurred.
    object_id : str
        STIX object ID (e.g. ``"indicator--abc"``) or internal ID.
    object_type : str
        STIX type (e.g. ``"indicator"``, ``"report"``) or arbitrary label.
    actor : str
        Connector name, analyst email, or workflow identifier.
    source : str
        Platform, module, or data source that triggered the event.
    id : str
        UUID4 event identifier (auto-generated).
    timestamp : datetime
        When the event occurred (UTC, auto-generated).
    metadata : dict
        Arbitrary context dict (platform version, export format, etc.).
    """

    event_type: LineageEventType
    object_id: str
    object_type: str
    actor: str
    source: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "object_id": self.object_id,
            "object_type": self.object_type,
            "actor": self.actor,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
