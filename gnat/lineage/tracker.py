"""
gnat.lineage.tracker
=====================

:class:`LineageTracker` provides convenience methods for recording cross-cutting
lineage events throughout the GNAT pipeline.

Pass ``store=None`` to create a no-op tracker (useful in tests or when
persistence is not configured).

Usage::

    from gnat.lineage import LineageTracker

    tracker = LineageTracker(store=store)

    # After ingesting an indicator
    tracker.record_ingest("indicator--abc", "indicator", "threatq", "alice@example.com")

    # After enriching
    tracker.record_enrichment("indicator--abc", "indicator", "virustotal", "alice@example.com",
                              metadata={"hits": 5})

    # After exporting
    tracker.record_export("indicator--abc", "indicator", "stix", "alice@example.com",
                          metadata={"format": "stix_bundle"})
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.lineage.models import LineageEvent, LineageEventType

logger = logging.getLogger(__name__)


class LineageTracker:
    """
    Convenience wrapper around :class:`~.store.LineageStore`.

    Parameters
    ----------
    store : LineageStore | None
        The persistence backend.  When ``None`` all ``record_*`` calls are
        no-ops (but still log at DEBUG level).
    default_actor : str
        Actor name used when *actor* is not explicitly provided.
    """

    def __init__(self, store: Any = None, default_actor: str = "system") -> None:
        self._store        = store
        self.default_actor = default_actor

    # ── Generic append ────────────────────────────────────────────────────────

    def record(
        self,
        event_type:  LineageEventType,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        metadata:    dict[str, Any] | None = None,
    ) -> LineageEvent | None:
        """
        Append a lineage event.

        Returns the created :class:`~.models.LineageEvent`, or ``None``
        if no store is configured.
        """
        event = LineageEvent(
            event_type  = event_type,
            object_id   = object_id,
            object_type = object_type,
            actor       = actor or self.default_actor,
            source      = source,
            metadata    = metadata or {},
        )
        logger.debug(
            "LineageTracker: %s %s by %s via %s",
            event_type.value, object_id, event.actor, source,
        )
        if self._store is not None:
            try:
                self._store.append(event)
            except Exception as exc:
                logger.warning("LineageTracker: failed to persist event: %s", exc)
        return event

    # ── Convenience methods ───────────────────────────────────────────────────

    def record_ingest(
        self,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        **metadata: Any,
    ) -> LineageEvent | None:
        """Record an INGESTED event."""
        return self.record(
            LineageEventType.INGESTED, object_id, object_type, source,
            actor=actor, metadata=metadata or {},
        )

    def record_enrichment(
        self,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        **metadata: Any,
    ) -> LineageEvent | None:
        """Record an ENRICHED event."""
        return self.record(
            LineageEventType.ENRICHED, object_id, object_type, source,
            actor=actor, metadata=metadata or {},
        )

    def record_normalization(
        self,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        **metadata: Any,
    ) -> LineageEvent | None:
        """Record a NORMALIZED event."""
        return self.record(
            LineageEventType.NORMALIZED, object_id, object_type, source,
            actor=actor, metadata=metadata or {},
        )

    def record_link(
        self,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        **metadata: Any,
    ) -> LineageEvent | None:
        """Record a LINKED event."""
        return self.record(
            LineageEventType.LINKED, object_id, object_type, source,
            actor=actor, metadata=metadata or {},
        )

    def record_export(
        self,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        **metadata: Any,
    ) -> LineageEvent | None:
        """Record an EXPORTED event."""
        return self.record(
            LineageEventType.EXPORTED, object_id, object_type, source,
            actor=actor, metadata=metadata or {},
        )

    def record_report(
        self,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        **metadata: Any,
    ) -> LineageEvent | None:
        """Record a REPORTED event."""
        return self.record(
            LineageEventType.REPORTED, object_id, object_type, source,
            actor=actor, metadata=metadata or {},
        )

    def record_deletion(
        self,
        object_id:   str,
        object_type: str,
        source:      str,
        actor:       str | None  = None,
        **metadata: Any,
    ) -> LineageEvent | None:
        """Record a DELETED event."""
        return self.record(
            LineageEventType.DELETED, object_id, object_type, source,
            actor=actor, metadata=metadata or {},
        )
