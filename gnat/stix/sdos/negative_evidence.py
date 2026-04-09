# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.stix.sdos.negative_evidence
=================================

Custom STIX 2.1 SDO representing a negative enrichment result.

A :class:`NegativeEvidenceRecord` is written when a connector returns no
results for a lookup.  It prevents redundant re-queries within a configurable
TTL window and contributes (negatively) to hypothesis confidence scoring.

STIX type: ``x-gnat-negative-evidence``

Usage
-----
::

    from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

    rec = NegativeEvidenceRecord(
        target_ref="indicator--abc123",
        queried_connector="VirusTotalClient",
        ttl_seconds=3600,
    )
    print(rec.is_expired())   # False immediately after creation
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from gnat.orm.base import STIXBase, _utcnow


class NegativeEvidenceRecord(STIXBase):
    """
    Custom STIX 2.1 SDO — ``x-gnat-negative-evidence``.

    Records that a connector returned no results for a specific lookup.
    Callers should check :meth:`is_expired` before re-querying — if the
    record is fresh, skip the query entirely.

    Parameters
    ----------
    target_ref : str
        STIX ID of the object that was queried (e.g. an ``indicator`` id).
    queried_connector : str
        Class name of the connector that returned no results.
    ttl_seconds : int
        Seconds after creation before this record expires and a re-query
        is permitted.  Default ``3600`` (1 hour).
    query_timestamp : str, optional
        ISO 8601 UTC timestamp of the failed query.  Defaults to now.
    """

    stix_type = "x-gnat-negative-evidence"
    schema_version = 1

    def __init__(
        self,
        target_ref: str = "",
        queried_connector: str = "",
        ttl_seconds: int = 3600,
        query_timestamp: str | None = None,
        client: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize NegativeEvidenceRecord."""
        super().__init__(client=client, **kwargs)
        self._properties["target_ref"] = target_ref
        self._properties["queried_connector"] = queried_connector
        self._properties["ttl_seconds"] = int(ttl_seconds)
        self._properties["query_timestamp"] = query_timestamp or _utcnow()

    # ── TTL helpers ────────────────────────────────────────────────────────────

    def is_expired(self) -> bool:
        """
        Return ``True`` if the TTL has elapsed since ``query_timestamp``.

        A re-query is safe only when this returns ``True``.
        """
        ts_str = self._properties.get("query_timestamp", "")
        if not ts_str:
            return True
        try:
            ts = datetime.fromisoformat(ts_str.rstrip("Z"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - ts).total_seconds()
            return elapsed >= self._properties.get("ttl_seconds", 3600)
        except (ValueError, TypeError):
            return True

    def seconds_remaining(self) -> float:
        """Return seconds until TTL expiry (0 if already expired)."""
        ts_str = self._properties.get("query_timestamp", "")
        if not ts_str:
            return 0.0
        try:
            ts = datetime.fromisoformat(ts_str.rstrip("Z"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - ts).total_seconds()
            remaining = self._properties.get("ttl_seconds", 3600) - elapsed
            return max(0.0, remaining)
        except (ValueError, TypeError):
            return 0.0

    # ── Serialization ──────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a STIX-compatible dict."""
        return {
            "type": self.stix_type,
            "id": self.id,
            "spec_version": self.spec_version,
            "created": self.created,
            "modified": self.modified,
            "target_ref": self._properties.get("target_ref", ""),
            "queried_connector": self._properties.get("queried_connector", ""),
            "ttl_seconds": self._properties.get("ttl_seconds", 3600),
            "query_timestamp": self._properties.get("query_timestamp", ""),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], client: Optional[Any] = None) -> NegativeEvidenceRecord:
        """Deserialise from a STIX dict."""
        return cls(
            target_ref=data.get("target_ref", ""),
            queried_connector=data.get("queried_connector", ""),
            ttl_seconds=int(data.get("ttl_seconds", 3600)),
            query_timestamp=data.get("query_timestamp"),
            client=client,
            id=data.get("id"),
            created=data.get("created"),
            modified=data.get("modified"),
            spec_version=data.get("spec_version", "2.1"),
        )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"NegativeEvidenceRecord("
            f"connector={self._properties.get('queried_connector')!r}, "
            f"target={self._properties.get('target_ref')!r}, "
            f"expired={self.is_expired()})"
        )
