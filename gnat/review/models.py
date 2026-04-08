"""
gnat.review.models
===================
Data model for the AI-extracted intel review queue.

Every object produced by a GNAT AI agent carries ``x_source_type="ai_extracted"``
and ``confidence ≤ ai_confidence_ceiling`` (default 60).  Before such objects
can be promoted to the shared staging workspace (and eventually the curated
library), an analyst must explicitly approve them through this review queue.

Lifecycle
---------

::

    AI agent writes object to personal workspace
            ↓
    review_service.submit(stix_obj, workspace, submitted_by=...)
            ↓
    ReviewItem.status = PENDING  (visible in TUI / CLI / REST)
            ↓  analyst approves / rejects / modifies
    APPROVED → review_service.promote() copies object to staging,
               sets x_source_type="analyst_verified", applies confidence override
    REJECTED → object stays in personal workspace, ReviewItem marked REJECTED
    MODIFIED → analyst edits metadata then approves (combines modify + approve)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class ReviewStatus(str, Enum):
    """Lifecycle states for a review queue item."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"  # approved with analyst-supplied metadata changes


@dataclass
class ReviewItem:
    """
    A single entry in the AI-extracted intel review queue.

    Attributes
    ----------
    id : str
        UUID4 identifier for this review item.
    stix_id : str
        STIX identifier of the object under review (``type--UUID4``).
    stix_type : str
        STIX object type (e.g. ``"indicator"``, ``"malware"``).
    stix_data : dict
        Full STIX object dict as stored at submission time.
    source_workspace : str
        Name of the personal workspace the object came from.
    target_workspace : str
        Name of the staging workspace to promote approved objects into.
        Defaults to ``"_ctmsak_staging"``.
    submitted_by : str
        Analyst or agent that submitted this item for review.
    submitted_at : datetime
        UTC timestamp of submission.
    status : ReviewStatus
        Current review state.
    reviewed_by : str or None
        Analyst who performed the review action.
    reviewed_at : datetime or None
        UTC timestamp when the review action was taken.
    reviewer_notes : str or None
        Free-text notes from the reviewing analyst.
    confidence_override : int or None
        If set, the analyst overrides the AI confidence score on promotion.
        Must be in [0, 100].
    modified_properties : dict
        Key/value pairs the analyst wants to change on the STIX object before
        promoting it.  Merged over the original ``stix_data`` on promotion.
    promoted_at : datetime or None
        Set when the object is actually written to the target workspace.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    stix_id: str = ""
    stix_type: str = ""
    stix_data: dict = field(default_factory=dict)
    source_workspace: str = ""
    target_workspace: str = "_ctmsak_staging"
    submitted_by: str = ""
    submitted_at: datetime = field(default_factory=_utcnow)
    status: ReviewStatus = ReviewStatus.PENDING
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    reviewer_notes: str | None = None
    confidence_override: int | None = None
    modified_properties: dict = field(default_factory=dict)
    promoted_at: datetime | None = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (for JSON storage / API responses)."""
        return {
            "id": self.id,
            "stix_id": self.stix_id,
            "stix_type": self.stix_type,
            "stix_data": self.stix_data,
            "source_workspace": self.source_workspace,
            "target_workspace": self.target_workspace,
            "submitted_by": self.submitted_by,
            "submitted_at": self.submitted_at.isoformat(),
            "status": self.status.value,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "reviewer_notes": self.reviewer_notes,
            "confidence_override": self.confidence_override,
            "modified_properties": self.modified_properties,
            "promoted_at": self.promoted_at.isoformat() if self.promoted_at else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ReviewItem":
        """Deserialise from a plain dict."""

        def _dt(v: str | None) -> datetime | None:
            if not v:
                return None
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

        return cls(
            id=d["id"],
            stix_id=d["stix_id"],
            stix_type=d["stix_type"],
            stix_data=d.get("stix_data", {}),
            source_workspace=d.get("source_workspace", ""),
            target_workspace=d.get("target_workspace", "_ctmsak_staging"),
            submitted_by=d.get("submitted_by", ""),
            submitted_at=_dt(d.get("submitted_at")) or _utcnow(),
            status=ReviewStatus(d.get("status", "pending")),
            reviewed_by=d.get("reviewed_by"),
            reviewed_at=_dt(d.get("reviewed_at")),
            reviewer_notes=d.get("reviewer_notes"),
            confidence_override=d.get("confidence_override"),
            modified_properties=d.get("modified_properties", {}),
            promoted_at=_dt(d.get("promoted_at")),
        )
