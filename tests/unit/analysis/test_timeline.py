"""
Unit tests for gnat.analysis.timeline
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from gnat.analysis.timeline import TimelineBuilder, TimelineEvent, TimelineEventType


def _dt(days_ago: int = 0) -> datetime:
    return datetime.now(tz=timezone.utc) - timedelta(days=days_ago)


def _make_investigation(
    status:    str = "open",
    n_notes:   int = 2,
    n_tasks:   int = 1,
) -> MagicMock:
    from gnat.analysis.investigations.models import InvestigationStatus
    inv = MagicMock()
    inv.id          = "inv-1"
    inv.title       = "Test Investigation"
    inv.description = "Description"
    inv.created_by  = "alice"
    inv.status      = InvestigationStatus.CLOSED if status == "closed" else InvestigationStatus.OPEN
    inv.created_at  = _dt(10)
    inv.updated_at  = _dt(1)
    inv.closed_at   = _dt(0) if status == "closed" else None

    notes = []
    for i in range(n_notes):
        note = MagicMock()
        note.id              = f"note-{i}"
        note.content         = f"Analyst note {i}"
        note.author          = "alice"
        note.created_at      = _dt(8 - i)
        note.linked_artifacts = []
        notes.append(note)
    inv.notes = notes

    tasks = []
    for i in range(n_tasks):
        task = MagicMock()
        task.id          = f"task-{i}"
        task.title       = f"Task {i}"
        task.status      = MagicMock(value="done")
        task.updated_at  = _dt(5 - i)
        task.assigned_to = "alice"
        tasks.append(task)
    inv.tasks = tasks

    return inv


class TestTimelineBuilder:
    def test_from_investigation_returns_list(self):
        builder = TimelineBuilder()
        inv     = _make_investigation()
        events  = builder.from_investigation(inv)
        assert isinstance(events, list)
        assert len(events) > 0

    def test_from_investigation_has_opened_event(self):
        builder = TimelineBuilder()
        inv     = _make_investigation()
        events  = builder.from_investigation(inv)
        types   = [e.event_type for e in events]
        assert TimelineEventType.INVESTIGATION_OPENED in types

    def test_from_investigation_includes_notes(self):
        builder = TimelineBuilder()
        inv     = _make_investigation(n_notes=3, status="open")
        events  = builder.from_investigation(inv)
        note_events = [e for e in events if e.event_type == TimelineEventType.ANALYST_NOTE]
        assert len(note_events) == 3

    def test_from_investigation_includes_completed_tasks(self):
        builder = TimelineBuilder()
        inv     = _make_investigation(n_tasks=2)
        events  = builder.from_investigation(inv)
        task_events = [e for e in events if e.event_type == TimelineEventType.TASK_COMPLETED]
        assert len(task_events) == 2

    def test_from_investigation_closed_event(self):
        builder = TimelineBuilder()
        inv     = _make_investigation(status="closed")
        events  = builder.from_investigation(inv)
        types   = [e.event_type for e in events]
        assert TimelineEventType.INVESTIGATION_CLOSED in types

    def test_from_investigation_sorted_chronologically(self):
        builder = TimelineBuilder()
        inv     = _make_investigation(n_notes=3, n_tasks=2)
        events  = builder.from_investigation(inv)
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps)

    def test_from_raw_basic(self):
        builder = TimelineBuilder()
        raw = [
            {"ts": _dt(5).isoformat(), "msg": "alpha", "src": "siem"},
            {"ts": _dt(3).isoformat(), "msg": "beta",  "src": "siem"},
        ]
        events = builder.from_raw(raw, timestamp_field="ts", title_field="msg", source="siem")
        assert len(events) == 2
        assert events[0].title == "alpha"
        assert events[1].title == "beta"

    def test_from_raw_skips_bad_timestamps(self):
        builder = TimelineBuilder()
        raw = [
            {"ts": "not-a-date", "msg": "bad"},
            {"ts": _dt(1).isoformat(), "msg": "good"},
        ]
        events = builder.from_raw(raw, timestamp_field="ts", title_field="msg", source="x")
        assert len(events) == 1
        assert events[0].title == "good"

    def test_from_raw_empty(self):
        builder = TimelineBuilder()
        events = builder.from_raw([], timestamp_field="ts", title_field="title", source="x")
        assert events == []

    def test_event_to_dict(self):
        event = TimelineEvent(
            timestamp  = _dt(1),
            event_type = TimelineEventType.ANALYST_NOTE,
            title      = "Test note",
            source     = "investigation",
        )
        d = event.to_dict()
        assert d["event_type"] == "analyst_note"
        assert d["title"] == "Test note"
        assert "timestamp" in d

    def test_from_evidence_graph(self):
        builder = TimelineBuilder()
        # Build a minimal graph mock matching the actual implementation's attribute names
        node1 = MagicMock()
        node1.node_id     = "n1"
        node1.node_type   = "indicator"
        node1.label       = "1.2.3.4"
        node1.time_window = (_dt(7).isoformat(), _dt(1).isoformat())
        node1.stix        = None

        node2 = MagicMock()
        node2.node_id     = "n2"
        node2.node_type   = "observable"
        node2.label       = "evil.com"
        node2.time_window = None
        _stix = {"first_observed": _dt(5).isoformat(), "name": "evil.com"}
        node2.stix        = _stix

        graph = MagicMock()
        graph.nodes = {"n1": node1, "n2": node2}

        events = builder.from_evidence_graph(graph)
        assert len(events) >= 1

    def test_event_type_values_are_strings(self):
        for et in TimelineEventType:
            assert isinstance(et.value, str)
