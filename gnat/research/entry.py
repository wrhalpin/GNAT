# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.research.entry
=======================

:class:`ResearchEntry` — the unit of knowledge stored in the research library.

Each entry wraps one or more STIX objects from a completed research session
together with provenance metadata: who researched it, when, whether it has
been curated, and when it expires.

TTL categories
--------------
Freshness is topic-category-dependent.  The defaults reflect how quickly
each type of threat intelligence typically goes stale:

+----------------+-------------+--------------------------------------------------+
| Category       | Default TTL | Rationale                                        |
+================+=============+==================================================+
| ``indicator``  | 24 hours    | IOCs rotate or get taken down quickly            |
+----------------+-------------+--------------------------------------------------+
| ``vulnerability`` | 72 hours | Exploitability status changes within days        |
+----------------+-------------+--------------------------------------------------+
| ``campaign``   | 14 days     | Campaign activity evolves over weeks             |
+----------------+-------------+--------------------------------------------------+
| ``threat_actor`` | 30 days   | Actor TTPs and infrastructure change slowly      |
+----------------+-------------+--------------------------------------------------+
| ``other``      | 7 days      | Conservative fallback for uncategorised topics   |
+----------------+-------------+--------------------------------------------------+

All TTLs are overridable via the ``[research_library]`` INI section::

    [research_library]
    ttl_indicator    = 12    # hours
    ttl_vulnerability = 48
    ttl_campaign     = 7
    ttl_threat_actor = 60
    ttl_other        = 3
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

# ---------------------------------------------------------------------------
# TTL defaults (hours)
# ---------------------------------------------------------------------------

DEFAULT_TTLS: dict[str, int] = {
    "indicator": 24,
    "vulnerability": 72,
    "campaign": 14 * 24,  # 14 days
    "threat_actor": 30 * 24,  # 30 days
    "other": 7 * 24,  # 7 days
}

# Keywords in topic strings that map to each category
_TOPIC_KEYWORDS: dict[str, list[str]] = {
    "indicator": ["ioc", "ip", "domain", "hash", "url", "indicator", "blocklist"],
    "vulnerability": ["cve", "vuln", "exploit", "patch", "advisory", "rce", "lpe"],
    "threat_actor": [
        "apt",
        "threat actor",
        "group",
        "unc",
        "ta",
        "g0",
        "lazarus",
        "cozy bear",
        "fancy bear",
        "volt typhoon",
        "scattered spider",
    ],
    "campaign": ["campaign", "operation", "intrusion", "incident", "breach"],
}


def categorise_topic(topic: str) -> str:
    """
    Infer a TTL category from a topic string.

    Checks for keyword presence (case-insensitive) in the order:
    ``indicator`` → ``vulnerability`` → ``campaign`` → ``threat_actor``.
    Falls back to ``other``.

    Parameters
    ----------
    topic : str
        The research topic string.

    Returns
    -------
    str
        One of ``"indicator"``, ``"vulnerability"``, ``"campaign"``,
        ``"threat_actor"``, or ``"other"``.
    """
    t = topic.lower()
    for category, keywords in _TOPIC_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            return category
    return "other"


def topic_key(topic: str) -> str:
    """
    Normalised key for deduplication — lowercase, stripped, whitespace-collapsed.

    Parameters
    ----------
    topic : str
        Raw topic string.

    Returns
    -------
    str
        Stable key for deduplication comparisons.
    """
    return " ".join(topic.lower().strip().split())


def topic_fingerprint(topic: str) -> str:
    """
    Short SHA-256 fingerprint of a topic key.  Used as a filename-safe
    identifier when storing entries in flat-file stores.

    Parameters
    ----------
    topic : str
        Raw topic string.

    Returns
    -------
    str
        First 16 hex characters of the SHA-256 of the normalised topic.
    """
    key = topic_key(topic)
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# ResearchEntry
# ---------------------------------------------------------------------------


@dataclass
class ResearchEntry:
    """
    A unit of curated research stored in the shared library.

    Parameters
    ----------
    topic : str
        The research topic (e.g. ``"APT29"``, ``"CVE-2024-3400"``).
    stix_objects : list of dict
        STIX dicts of the objects produced by this research session.
    researcher : str
        Identifier of the analyst or system that produced this entry.
        Free-form string — could be a username, workstation name, or
        ``"automated"`` for scheduler-driven research.
    promoted_at : datetime
        UTC timestamp when the entry was promoted from a personal workspace
        to the staging area.
    note : str, optional
        Optional analyst annotation explaining why this research is worth
        sharing and what was found.  Displayed to other analysts querying
        the library.
    source_workspace : str
        Name of the personal workspace this entry came from.
    category : str
        TTL category (auto-inferred from topic if not provided).
    expires_at : datetime, optional
        When this entry should be considered stale.  Auto-computed from
        category TTL if not provided.
    curator_status : str
        ``"pending"`` (in staging, awaiting curation),
        ``"curated"`` (in library, reviewed),
        ``"archived"`` (superseded by a newer entry, kept for history).
    curated_at : datetime, optional
        When the curation job promoted this entry to the library.
    entry_id : str
        Stable unique identifier (fingerprint of topic + promoted_at).
    metadata : dict
        Arbitrary additional context.
    """

    topic: str
    stix_objects: list[dict[str, Any]]
    researcher: str
    promoted_at: datetime
    note: str = ""
    source_workspace: str = ""
    category: str = ""
    expires_at: datetime | None = None
    curator_status: str = "pending"
    curated_at: datetime | None = None
    entry_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.category:
            self.category = categorise_topic(self.topic)
        if not self.entry_id:
            self.entry_id = self._compute_id()

    def _compute_id(self) -> str:
        raw = f"{topic_key(self.topic)}:{self.promoted_at.isoformat()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    # ── Freshness ──────────────────────────────────────────────────────────

    def set_ttl(self, ttl_hours: int) -> None:
        """Set ``expires_at`` based on *ttl_hours* from ``promoted_at``."""
        self.expires_at = self.promoted_at + timedelta(hours=ttl_hours)

    @property
    def is_fresh(self) -> bool:
        """``True`` if the entry has not yet expired."""
        if self.expires_at is None:
            return True
        return datetime.now(timezone.utc) < self.expires_at

    @property
    def age_hours(self) -> float:
        """Hours since this entry was promoted."""
        delta = datetime.now(timezone.utc) - self.promoted_at
        return delta.total_seconds() / 3600

    @property
    def hours_until_expiry(self) -> float | None:
        """Hours remaining until expiry, or ``None`` if no TTL set."""
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0.0, delta.total_seconds() / 3600)

    # ── Status helpers ─────────────────────────────────────────────────────

    @property
    def is_pending(self) -> bool:
        return self.curator_status == "pending"

    @property
    def is_curated(self) -> bool:
        return self.curator_status == "curated"

    @property
    def is_archived(self) -> bool:
        return self.curator_status == "archived"

    def mark_curated(self) -> None:
        self.curator_status = "curated"
        self.curated_at = datetime.now(timezone.utc)

    def mark_archived(self) -> None:
        self.curator_status = "archived"

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for storage."""
        return {
            "entry_id": self.entry_id,
            "topic": self.topic,
            "topic_key": topic_key(self.topic),
            "category": self.category,
            "researcher": self.researcher,
            "note": self.note,
            "source_workspace": self.source_workspace,
            "promoted_at": self.promoted_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "curator_status": self.curator_status,
            "curated_at": self.curated_at.isoformat() if self.curated_at else None,
            "stix_object_count": len(self.stix_objects),
            "stix_objects": self.stix_objects,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResearchEntry:
        """Reconstruct a ``ResearchEntry`` from a stored dict."""

        def _parse_dt(s: str | None) -> datetime | None:
            if not s:
                return None
            return datetime.fromisoformat(s)

        entry = cls(
            topic=data["topic"],
            stix_objects=data.get("stix_objects", []),
            researcher=data.get("researcher", ""),
            promoted_at=_parse_dt(data["promoted_at"]) or datetime.now(timezone.utc),
            note=data.get("note", ""),
            source_workspace=data.get("source_workspace", ""),
            category=data.get("category", ""),
            expires_at=_parse_dt(data.get("expires_at")),
            curator_status=data.get("curator_status", "pending"),
            curated_at=_parse_dt(data.get("curated_at")),
            entry_id=data.get("entry_id", ""),
            metadata=data.get("metadata", {}),
        )
        return entry

    def summary(self) -> dict[str, Any]:
        """Lightweight summary dict for listing without full STIX payloads."""
        return {
            "entry_id": self.entry_id,
            "topic": self.topic,
            "category": self.category,
            "researcher": self.researcher,
            "note": self.note[:200] if self.note else "",
            "promoted_at": self.promoted_at.isoformat(),
            "age_hours": round(self.age_hours, 1),
            "is_fresh": self.is_fresh,
            "hours_until_expiry": (
                round(self.hours_until_expiry, 1) if self.hours_until_expiry is not None else None
            ),
            "curator_status": self.curator_status,
            "stix_object_count": len(self.stix_objects),
            "source_workspace": self.source_workspace,
        }

    def __repr__(self) -> str:  # pragma: no cover
        fresh = "fresh" if self.is_fresh else "STALE"
        return (
            f"ResearchEntry(topic={self.topic!r}, category={self.category!r}, "
            f"researcher={self.researcher!r}, {fresh}, "
            f"objects={len(self.stix_objects)}, status={self.curator_status!r})"
        )
