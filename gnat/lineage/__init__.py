"""
gnat.lineage
=============

Cross-cutting data lineage tracking for the GNAT platform.

Records an append-only audit trail of every significant operation on a STIX
object: ingestion, enrichment, normalization, linking, export, reporting, and
deletion.

Quick start::

    from gnat.lineage import LineageTracker, LineageEventType
    from gnat.lineage.store import LineageStore

    # Production: persist to DB
    store   = LineageStore("sqlite:///~/.gnat/gnat.db")
    tracker = LineageTracker(store)

    tracker.record_ingest("indicator--abc", "indicator", "threatq", "alice@example.com")
    tracker.record_export("indicator--abc", "indicator", "stix-export", "alice@example.com",
                          format="stix_bundle")

    events = store.query("indicator--abc")

    # Test / no-op mode:
    tracker = LineageTracker(store=None)
    tracker.record_ingest("indicator--x", "indicator", "test", "ci")  # silent no-op
"""

from gnat.lineage.models import LineageEvent, LineageEventType
from gnat.lineage.tracker import LineageTracker

__all__ = [
    "LineageEvent",
    "LineageEventType",
    "LineageTracker",
]
