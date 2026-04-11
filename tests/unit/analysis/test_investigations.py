# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for gnat.analysis.investigations."""

import pytest

from gnat.analysis.confidence import ConfidenceScore
from gnat.analysis.investigations import (
    AnalystNote,
    Hypothesis,
    HypothesisStatus,
    Investigation,
    InvestigationError,
    InvestigationScope,
    InvestigationService,
    InvestigationStatus,
    InvestigationStore,
    InvestigationTask,
    TaskPriority,
    TaskStatus,
)
from gnat.analysis.tlp import TLPLevel


@pytest.fixture
def store(tmp_path):
    """In-memory SQLite investigation store."""
    pytest.importorskip(
        "sqlalchemy", reason="gnat[persist] extras not installed"
    )
    s = InvestigationStore("sqlite:///:memory:")
    s.create_all()
    return s


@pytest.fixture
def service(store):
    return InvestigationService(store)


@pytest.fixture
def inv(service):
    return service.create(
        title      = "Ransomware Apr 2026",
        created_by = "analyst@example.com",
        tags       = ["ransomware", "blackcat"],
    )


# ── Investigation model ───────────────────────────────────────────────────────

class TestInvestigationModel:
    def test_defaults(self):
        inv = Investigation(title="Test", created_by="analyst")
        assert inv.status         == InvestigationStatus.OPEN
        assert inv.classification == TLPLevel.AMBER
        assert inv.hypothesis     == []
        assert inv.notes          == []
        assert inv.tasks          == []

    def test_roundtrip_serialization(self):
        inv = Investigation(
            title          = "Test Investigation",
            created_by     = "analyst@example.com",
            classification = TLPLevel.RED,
            tags           = ["apt28", "phishing"],
        )
        inv.hypothesis.append(Hypothesis(statement="APT28 used spear-phishing."))
        inv.notes.append(AnalystNote(content="Initial triage.", author="analyst"))
        inv.tasks.append(InvestigationTask(title="Isolate workstation"))

        data     = inv.to_dict()
        restored = Investigation.from_dict(data)

        assert restored.id             == inv.id
        assert restored.title          == inv.title
        assert restored.classification == inv.classification
        assert restored.tags           == inv.tags
        assert len(restored.hypothesis) == 1
        assert len(restored.notes)      == 1
        assert len(restored.tasks)      == 1

    def test_can_transition_to_valid(self):
        inv = Investigation(title="T", created_by="a")
        assert inv.can_transition_to(InvestigationStatus.IN_PROGRESS) is True

    def test_can_transition_to_invalid(self):
        inv = Investigation(title="T", created_by="a")
        # Cannot jump from OPEN directly to REVIEW or CLOSED
        assert inv.can_transition_to(InvestigationStatus.REVIEW)  is False
        assert inv.can_transition_to(InvestigationStatus.CLOSED)  is False

    def test_closed_is_terminal(self):
        inv = Investigation(title="T", created_by="a")
        inv.status = InvestigationStatus.CLOSED
        for status in InvestigationStatus:
            assert inv.can_transition_to(status) is False


# ── InvestigationScope ────────────────────────────────────────────────────────

class TestInvestigationScope:
    def test_roundtrip(self):
        from datetime import datetime, timezone
        scope = InvestigationScope(
            target_sectors     = ["financial"],
            target_geographies = ["US", "UK"],
            ioc_types          = ["ipv4-addr"],
            keywords           = ["ransomware", "blackcat"],
            date_range_start   = datetime(2026, 4, 1, tzinfo=timezone.utc),
        )
        data     = scope.to_dict()
        restored = InvestigationScope.from_dict(data)

        assert restored.target_sectors      == scope.target_sectors
        assert restored.target_geographies  == scope.target_geographies
        assert restored.ioc_types           == scope.ioc_types
        assert restored.keywords            == scope.keywords
        assert restored.date_range_start    == scope.date_range_start


# ── Hypothesis ────────────────────────────────────────────────────────────────

class TestHypothesis:
    def test_default_status(self):
        hyp = Hypothesis(statement="Test")
        assert hyp.status == HypothesisStatus.OPEN

    def test_roundtrip(self):
        hyp = Hypothesis(
            statement  = "Threat actor reused C2.",
            confidence = ConfidenceScore.high(),
            status     = HypothesisStatus.SUPPORTED,
        )
        hyp.supporting_evidence.append("indicator--abc")

        data     = hyp.to_dict()
        restored = Hypothesis.from_dict(data)

        assert restored.id                   == hyp.id
        assert restored.statement            == hyp.statement
        assert restored.status               == hyp.status
        assert restored.supporting_evidence  == hyp.supporting_evidence
        assert restored.confidence.stix_confidence == 75


# ── InvestigationTask ─────────────────────────────────────────────────────────

class TestInvestigationTask:
    def test_defaults(self):
        task = InvestigationTask(title="Do something")
        assert task.status   == TaskStatus.TODO
        assert task.priority == TaskPriority.MEDIUM

    def test_roundtrip(self):
        task = InvestigationTask(
            title       = "Collect memory dump",
            priority    = TaskPriority.HIGH,
            assigned_to = "analyst2@example.com",
        )
        data     = task.to_dict()
        restored = InvestigationTask.from_dict(data)

        assert restored.id          == task.id
        assert restored.title       == task.title
        assert restored.priority    == task.priority
        assert restored.assigned_to == task.assigned_to


# ── InvestigationService ──────────────────────────────────────────────────────

class TestInvestigationService:
    def test_create_and_get(self, service, inv):
        retrieved = service.get(inv.id)
        assert retrieved.title      == "Ransomware Apr 2026"
        assert retrieved.created_by == "analyst@example.com"
        assert "ransomware" in retrieved.tags

    def test_get_not_found(self, service):
        with pytest.raises(InvestigationError):
            service.get("non-existent-id")

    def test_transition_open_to_in_progress(self, service, inv):
        updated = service.transition(inv.id, InvestigationStatus.IN_PROGRESS)
        assert updated.status == InvestigationStatus.IN_PROGRESS

    def test_transition_invalid(self, service, inv):
        with pytest.raises(InvestigationError, match="Cannot transition"):
            service.transition(inv.id, InvestigationStatus.REVIEW)

    def test_transition_with_note(self, service, inv):
        updated = service.transition(
            inv.id,
            InvestigationStatus.IN_PROGRESS,
            note   = "Started active investigation.",
            author = "analyst@example.com",
        )
        assert len(updated.notes) == 1
        assert "Started active investigation." in updated.notes[0].content

    def test_add_note(self, service, inv):
        note = service.add_note(
            inv.id,
            content          = "C2 confirmed on port 443.",
            author           = "analyst@example.com",
            linked_artifacts = ["indicator--abc"],
        )
        assert note.content == "C2 confirmed on port 443."

        updated = service.get(inv.id)
        assert len(updated.notes) == 1
        assert updated.notes[0].linked_artifacts == ["indicator--abc"]

    def test_add_task(self, service, inv):
        task = service.add_task(
            inv.id,
            title    = "Memory dump",
            priority = TaskPriority.HIGH,
        )
        assert task.priority == TaskPriority.HIGH

        updated = service.get(inv.id)
        assert len(updated.tasks) == 1

    def test_update_task_status(self, service, inv):
        task = service.add_task(inv.id, title="Task A")
        service.update_task_status(inv.id, task.id, TaskStatus.IN_PROGRESS)
        updated = service.get(inv.id)
        assert updated.tasks[0].status == TaskStatus.IN_PROGRESS

    def test_update_task_status_not_found(self, service, inv):
        with pytest.raises(InvestigationError, match="not found"):
            service.update_task_status(inv.id, "bad-task-id", TaskStatus.DONE)

    def test_add_hypothesis(self, service, inv):
        hyp = service.add_hypothesis(
            inv.id,
            statement  = "BLACKCAT reused C2.",
            confidence = ConfidenceScore.medium(),
        )
        assert hyp.status == HypothesisStatus.OPEN

        updated = service.get(inv.id)
        assert len(updated.hypothesis) == 1

    def test_update_hypothesis_status(self, service, inv):
        hyp = service.add_hypothesis(inv.id, statement="Test hypothesis.")
        service.update_hypothesis_status(
            inv.id, hyp.id, HypothesisStatus.SUPPORTED,
            confidence = ConfidenceScore.high(),
        )
        updated = service.get(inv.id)
        assert updated.hypothesis[0].status == HypothesisStatus.SUPPORTED
        assert updated.hypothesis[0].confidence.stix_confidence == 75

    def test_link_indicators(self, service, inv):
        service.link_indicators(inv.id, ["indicator--abc", "indicator--def"])
        updated = service.get(inv.id)
        assert "indicator--abc" in updated.indicators
        assert "indicator--def" in updated.indicators

    def test_link_indicators_deduplicates(self, service, inv):
        service.link_indicators(inv.id, ["indicator--abc"])
        service.link_indicators(inv.id, ["indicator--abc", "indicator--xyz"])
        updated = service.get(inv.id)
        assert updated.indicators.count("indicator--abc") == 1
        assert len(updated.indicators) == 2

    def test_add_tags_deduplicates(self, service, inv):
        service.add_tags(inv.id, ["ransomware", "new-tag"])
        updated = service.get(inv.id)
        assert updated.tags.count("ransomware") == 1
        assert "new-tag" in updated.tags

    def test_delete(self, service, inv):
        service.delete(inv.id)
        with pytest.raises(InvestigationError):
            service.get(inv.id)

    def test_delete_not_found(self, service):
        with pytest.raises(InvestigationError):
            service.delete("nonexistent")

    def test_list_by_status(self, service):
        service.create(title="Inv A", created_by="analyst")
        service.create(title="Inv B", created_by="analyst")
        inv_c = service.create(title="Inv C", created_by="analyst")
        service.transition(inv_c.id, InvestigationStatus.IN_PROGRESS)

        open_list = service.list(status=InvestigationStatus.OPEN)
        assert all(i.status == InvestigationStatus.OPEN for i in open_list)
        assert len(open_list) == 2

    def test_summary(self, service, inv):
        service.add_task(inv.id, title="T1")
        service.add_hypothesis(inv.id, statement="H1")
        service.add_note(inv.id, content="Note 1", author="analyst")

        s = service.summary(inv.id)
        assert s["task_count"]       == 1
        assert s["hypothesis_count"] == 1
        assert s["note_count"]       == 1
        assert s["indicator_count"]  == 0
        assert "classification"      in s
