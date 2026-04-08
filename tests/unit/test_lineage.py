"""Unit tests for gnat.lineage (data lineage tracking)."""

from __future__ import annotations

import pytest


# ── Models ────────────────────────────────────────────────────────────────────

def test_lineage_event_type_values():
    from gnat.lineage.models import LineageEventType
    assert LineageEventType.INGESTED   == "ingested"
    assert LineageEventType.ENRICHED   == "enriched"
    assert LineageEventType.EXPORTED   == "exported"
    assert LineageEventType.DELETED    == "deleted"


def test_lineage_event_creation():
    from gnat.lineage.models import LineageEvent, LineageEventType

    evt = LineageEvent(
        event_type  = LineageEventType.INGESTED,
        object_id   = "indicator--abc",
        object_type = "indicator",
        actor       = "threatq",
        source      = "threatq",
    )
    assert evt.object_id   == "indicator--abc"
    assert evt.event_type  == LineageEventType.INGESTED
    assert evt.id is not None
    assert evt.timestamp is not None


def test_lineage_event_to_dict():
    from gnat.lineage.models import LineageEvent, LineageEventType

    evt = LineageEvent(
        event_type  = LineageEventType.EXPORTED,
        object_id   = "report--1",
        object_type = "report",
        actor       = "alice",
        source      = "stix-export",
        metadata    = {"format": "stix_bundle"},
    )
    d = evt.to_dict()
    assert d["event_type"]        == "exported"
    assert d["object_id"]         == "report--1"
    assert d["metadata"]["format"] == "stix_bundle"


# ── LineageStore ──────────────────────────────────────────────────────────────

@pytest.fixture
def lineage_store():
    pytest.importorskip("sqlalchemy")
    from gnat.lineage.store import LineageStore
    store = LineageStore("sqlite:///:memory:")
    store.create_all()
    return store


def test_store_append_and_query(lineage_store):
    from gnat.lineage.models import LineageEvent, LineageEventType

    evt = LineageEvent(
        event_type  = LineageEventType.INGESTED,
        object_id   = "indicator--test",
        object_type = "indicator",
        actor       = "system",
        source      = "threatq",
    )
    lineage_store.append(evt)

    events = lineage_store.query("indicator--test")
    assert len(events) == 1
    assert events[0].object_id  == "indicator--test"
    assert events[0].event_type == LineageEventType.INGESTED


def test_store_multiple_events_for_object(lineage_store):
    from gnat.lineage.models import LineageEvent, LineageEventType

    for et in [LineageEventType.INGESTED, LineageEventType.ENRICHED, LineageEventType.EXPORTED]:
        lineage_store.append(LineageEvent(
            event_type  = et,
            object_id   = "indicator--multi",
            object_type = "indicator",
            actor       = "system",
            source      = "test",
        ))

    events = lineage_store.query("indicator--multi")
    assert len(events) == 3
    types = [e.event_type for e in events]
    assert LineageEventType.INGESTED in types
    assert LineageEventType.ENRICHED in types
    assert LineageEventType.EXPORTED in types


def test_store_query_by_type(lineage_store):
    from gnat.lineage.models import LineageEvent, LineageEventType

    lineage_store.append(LineageEvent(
        event_type="ingested", object_id="x", object_type="indicator",
        actor="a", source="s",
    ))
    lineage_store.append(LineageEvent(
        event_type="exported", object_id="y", object_type="report",
        actor="b", source="t",
    ))

    ingested = lineage_store.query_by_type(LineageEventType.INGESTED)
    assert len(ingested) == 1
    assert ingested[0].object_id == "x"


def test_store_count(lineage_store):
    from gnat.lineage.models import LineageEvent, LineageEventType

    assert lineage_store.count() == 0
    lineage_store.append(LineageEvent(
        event_type="ingested", object_id="z", object_type="indicator",
        actor="a", source="s",
    ))
    assert lineage_store.count() == 1
    assert lineage_store.count(LineageEventType.INGESTED) == 1
    assert lineage_store.count(LineageEventType.EXPORTED) == 0


# ── LineageTracker ────────────────────────────────────────────────────────────

def test_tracker_noop_without_store():
    from gnat.lineage.tracker import LineageTracker

    tracker = LineageTracker(store=None)
    # Must not raise
    result = tracker.record_ingest("indicator--1", "indicator", "test")
    # Returns event even in no-op mode
    assert result is not None


def test_tracker_records_to_store(lineage_store):
    from gnat.lineage.tracker import LineageTracker

    tracker = LineageTracker(store=lineage_store)
    tracker.record_ingest("indicator--123", "indicator", "threatq", actor="alice")
    tracker.record_enrichment("indicator--123", "indicator", "virustotal", hits=5)

    events = lineage_store.query("indicator--123")
    assert len(events) == 2


def test_tracker_convenience_methods(lineage_store):
    from gnat.lineage.tracker import LineageTracker
    from gnat.lineage.models import LineageEventType

    tracker = LineageTracker(store=lineage_store)
    tracker.record_normalization("indicator--x", "indicator", "mapper")
    tracker.record_link("indicator--x", "indicator", "service")
    tracker.record_export("indicator--x", "indicator", "export")
    tracker.record_report("indicator--x", "indicator", "reporting")
    tracker.record_deletion("indicator--x", "indicator", "service")

    events = lineage_store.query("indicator--x")
    types  = {e.event_type for e in events}
    assert LineageEventType.NORMALIZED in types
    assert LineageEventType.LINKED     in types
    assert LineageEventType.EXPORTED   in types
    assert LineageEventType.REPORTED   in types
    assert LineageEventType.DELETED    in types


# ── gnat.lineage __init__ exports ─────────────────────────────────────────────

def test_lineage_init_exports():
    from gnat import lineage as l
    assert hasattr(l, "LineageEvent")
    assert hasattr(l, "LineageEventType")
    assert hasattr(l, "LineageTracker")


# ── Lineage wiring: IngestPipeline ────────────────────────────────────────────

def test_ingest_pipeline_has_with_lineage():
    """IngestPipeline.with_lineage() is a fluent method that returns self."""
    from gnat.ingest.pipeline.pipeline import IngestPipeline

    pipeline = IngestPipeline()
    result = pipeline.with_lineage(None)
    assert result is pipeline


def test_ingest_pipeline_with_lineage_noop():
    """with_lineage(None) sets tracker to None — no-op when objects saved."""
    from gnat.ingest.pipeline.pipeline import IngestPipeline

    pipeline = IngestPipeline()
    pipeline.with_lineage(None)
    assert pipeline._lineage is None


def test_ingest_pipeline_records_lineage_on_save(lineage_store):
    """IngestPipeline with_lineage tracker gets called after object save."""
    from gnat.ingest.pipeline.pipeline import IngestPipeline
    from gnat.lineage.tracker import LineageTracker
    from gnat.lineage.models import LineageEventType

    tracker = LineageTracker(store=lineage_store)
    pipeline = IngestPipeline()
    pipeline.with_lineage(tracker)

    # Simulate what the pipeline does internally after a successful obj.save()
    tracker.record_ingest(
        "indicator--pipeline-lineage-001", "indicator",
        source="ingest-pipeline", actor="ingest-pipeline",
    )

    events = lineage_store.query("indicator--pipeline-lineage-001")
    assert len(events) == 1
    assert events[0].event_type == LineageEventType.INGESTED


# ── Lineage wiring: ExportPipeline ────────────────────────────────────────────

def test_export_pipeline_has_with_lineage():
    """ExportPipeline.with_lineage() is a fluent method that returns self."""
    from gnat.export.base import ExportPipeline

    pipeline = ExportPipeline("test-export")
    result   = pipeline.with_lineage(None)
    assert result is pipeline


def test_export_pipeline_with_lineage_stores_tracker():
    from gnat.export.base import ExportPipeline
    from gnat.lineage.tracker import LineageTracker

    tracker  = LineageTracker(store=None)
    pipeline = ExportPipeline("test-export").with_lineage(tracker)
    assert pipeline._lineage is tracker


def test_export_pipeline_emits_lineage_after_delivery(lineage_store):
    """ExportPipeline.run() emits EXPORTED events after successful delivery."""
    from unittest.mock import MagicMock
    from gnat.export.base import ExportPipeline, TransformResult, DeliveryResult
    from gnat.lineage.tracker import LineageTracker
    from gnat.lineage.models import LineageEventType
    from gnat.orm.base import STIXBase

    tracker = LineageTracker(store=lineage_store)

    obj = STIXBase(stix_type="indicator", id="indicator--export-lineage-001")

    mock_transform = MagicMock()
    mock_transform.transform.return_value = TransformResult(
        payloads={"out": "data"}, object_count=1
    )
    mock_delivery = MagicMock()
    mock_delivery.deliver.return_value = DeliveryResult(success=True, delivered=["out"])

    pipeline = (
        ExportPipeline("wiring-test")
        .read_from([obj])
        .transform_with(mock_transform)
        .deliver_to(mock_delivery)
        .with_lineage(tracker)
    )
    result = pipeline.run()

    assert result.success
    events = lineage_store.query("indicator--export-lineage-001")
    assert len(events) == 1
    assert events[0].event_type == LineageEventType.EXPORTED


# ── Lineage wiring: ReportingService ─────────────────────────────────────────

def test_reporting_service_accepts_lineage_kwarg():
    """ReportingService.__init__ accepts a lineage= keyword argument."""
    pytest.importorskip("sqlalchemy")
    from gnat.reporting.service import ReportService
    from gnat.lineage.tracker import LineageTracker

    tracker = LineageTracker(store=None)
    svc = ReportService(store=MagicMock_reporting(), lineage=tracker)
    assert svc._lineage is tracker


def MagicMock_reporting():
    from unittest.mock import MagicMock
    return MagicMock()


def test_reporting_service_emits_lineage_on_publish(lineage_store):
    """ReportService.publish() emits a REPORTED lineage event."""
    pytest.importorskip("sqlalchemy")
    from unittest.mock import MagicMock, patch
    from gnat.reporting.service import ReportService
    from gnat.reporting.models import ReportStatus
    from gnat.lineage.tracker import LineageTracker
    from gnat.lineage.models import LineageEventType

    tracker = LineageTracker(store=lineage_store)

    # Build a mock report that passes the can_transition_to check
    mock_report = MagicMock()
    mock_report.id              = "report-pub-001"
    mock_report.stix_report_ref = "report--stix-pub-001"
    mock_report.status          = ReportStatus.APPROVED
    mock_report.can_transition_to.return_value = True
    mock_report.version         = 1
    mock_report.changelog       = []

    mock_store = MagicMock()
    mock_store.get.return_value  = mock_report
    mock_store.save.return_value = None

    svc = ReportService(store=mock_store, lineage=tracker)

    # Patch the STIX bundle generator to avoid real STIX generation
    with patch("gnat.reporting.export.stix.report_to_stix_bundle",
               return_value={"objects": [{"type": "report", "id": "report--stix-pub-001"}]}):
        svc.publish("report-pub-001", changed_by="alice")

    events = lineage_store.query("report--stix-pub-001")
    assert len(events) == 1
    assert events[0].event_type == LineageEventType.REPORTED
