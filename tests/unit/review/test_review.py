"""
tests/unit/review/test_review.py
==================================
Unit tests for gnat.review — AI-extracted intel review queue.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store():
    pytest.importorskip("sqlalchemy")
    from gnat.review.store import ReviewQueueStore
    s = ReviewQueueStore("sqlite:///:memory:")
    s.create_all()
    return s


@pytest.fixture
def svc(store):
    from gnat.review.service import ReviewService
    return ReviewService(store)


def _stix(type_="indicator", **extra):
    return {
        "type": type_,
        "id": f"{type_}--1d8d7c3e-abc1-4a7e-9f15-000000000001",
        "spec_version": "2.1",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "x_source_type": "ai_extracted",
        "confidence": 45,
        **extra,
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestReviewStatus:
    def test_values(self):
        from gnat.review.models import ReviewStatus
        assert ReviewStatus.PENDING  == "pending"
        assert ReviewStatus.APPROVED == "approved"
        assert ReviewStatus.REJECTED == "rejected"
        assert ReviewStatus.MODIFIED == "modified"


class TestReviewItem:
    def test_defaults(self):
        from gnat.review.models import ReviewItem, ReviewStatus
        item = ReviewItem()
        assert item.status == ReviewStatus.PENDING
        assert item.id is not None
        assert item.submitted_at is not None

    def test_to_dict_roundtrip(self):
        from gnat.review.models import ReviewItem, ReviewStatus
        item = ReviewItem(
            stix_id="indicator--abc",
            stix_type="indicator",
            stix_data={"type": "indicator"},
            source_workspace="ws1",
            submitted_by="agent",
        )
        d = item.to_dict()
        assert d["stix_id"] == "indicator--abc"
        assert d["status"]  == "pending"
        assert d["stix_data"]["type"] == "indicator"

        restored = ReviewItem.from_dict(d)
        assert restored.id == item.id
        assert restored.status == ReviewStatus.PENDING
        assert restored.stix_id == "indicator--abc"

    def test_from_dict_handles_missing_optional_fields(self):
        from gnat.review.models import ReviewItem
        item = ReviewItem.from_dict({
            "id": "00000000-0000-4000-8000-000000000001",
            "stix_id": "x",
            "stix_type": "indicator",
            "status": "pending",
        })
        assert item.reviewed_by is None
        assert item.confidence_override is None


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class TestReviewQueueStore:
    def test_save_and_get(self, store):
        from gnat.review.models import ReviewItem
        item = ReviewItem(stix_id="indicator--1", stix_type="indicator",
                          stix_data={}, source_workspace="ws", submitted_by="a")
        store.save(item)
        fetched = store.get(item.id)
        assert fetched is not None
        assert fetched.stix_id == "indicator--1"

    def test_get_returns_none_for_unknown(self, store):
        assert store.get("00000000-0000-4000-8000-nonexistent") is None

    def test_update_existing(self, store):
        from gnat.review.models import ReviewItem, ReviewStatus
        item = ReviewItem(stix_id="x", stix_type="indicator",
                          stix_data={}, source_workspace="ws", submitted_by="a")
        store.save(item)
        item.status = ReviewStatus.APPROVED
        store.save(item)
        fetched = store.get(item.id)
        assert fetched.status == ReviewStatus.APPROVED

    def test_list_by_status(self, store):
        from gnat.review.models import ReviewItem, ReviewStatus
        for i in range(3):
            item = ReviewItem(stix_id=f"ind--{i}", stix_type="indicator",
                              stix_data={}, source_workspace="ws", submitted_by="a")
            store.save(item)
        # Approve one
        items = store.list(status="pending")
        assert len(items) == 3
        items[0].status = ReviewStatus.APPROVED
        store.save(items[0])

        assert store.count("pending") == 2
        assert store.count("approved") == 1

    def test_list_by_stix_type(self, store):
        from gnat.review.models import ReviewItem
        for t in ("indicator", "malware", "indicator"):
            item = ReviewItem(stix_id=f"{t}--x", stix_type=t,
                              stix_data={}, source_workspace="ws", submitted_by="a")
            store.save(item)
        results = store.list(stix_type="indicator")
        assert all(r.stix_type == "indicator" for r in results)
        assert len(results) == 2

    def test_delete(self, store):
        from gnat.review.models import ReviewItem
        item = ReviewItem(stix_id="x", stix_type="indicator",
                          stix_data={}, source_workspace="ws", submitted_by="a")
        store.save(item)
        assert store.delete(item.id)
        assert store.get(item.id) is None

    def test_delete_nonexistent_returns_false(self, store):
        assert not store.delete("nonexistent-id")

    def test_stats_empty(self, store):
        stats = store.stats()
        assert stats == {"pending": 0, "approved": 0, "rejected": 0, "modified": 0}

    def test_stats_with_items(self, store):
        from gnat.review.models import ReviewItem, ReviewStatus
        for _ in range(2):
            item = ReviewItem(stix_id="x", stix_type="indicator",
                              stix_data={}, source_workspace="ws", submitted_by="a")
            store.save(item)
        stats = store.stats()
        assert stats["pending"] == 2


# ---------------------------------------------------------------------------
# Service — submit
# ---------------------------------------------------------------------------

class TestReviewServiceSubmit:
    def test_submit_creates_pending_item(self, svc):
        from gnat.review.models import ReviewStatus
        item = svc.submit(_stix(), source_workspace="ws1", submitted_by="agent")
        assert item.status == ReviewStatus.PENDING
        assert item.stix_id == _stix()["id"]
        assert item.submitted_by == "agent"

    def test_submit_missing_id_raises(self, svc):
        from gnat.review.service import ReviewError
        with pytest.raises(ReviewError):
            svc.submit({"type": "indicator"}, source_workspace="ws", submitted_by="a")

    def test_submit_missing_type_raises(self, svc):
        from gnat.review.service import ReviewError
        with pytest.raises(ReviewError):
            svc.submit({"id": "indicator--abc"}, source_workspace="ws", submitted_by="a")

    def test_submit_persists(self, svc, store):
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        assert store.get(item.id) is not None

    def test_submit_custom_target_workspace(self, svc):
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a",
                          target_workspace="custom-staging")
        assert item.target_workspace == "custom-staging"


# ---------------------------------------------------------------------------
# Service — approve
# ---------------------------------------------------------------------------

class TestReviewServiceApprove:
    def test_approve_pending(self, svc):
        from gnat.review.models import ReviewStatus
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        approved = svc.approve(item.id, reviewed_by="alice")
        assert approved.status == ReviewStatus.APPROVED
        assert approved.reviewed_by == "alice"
        assert approved.reviewed_at is not None

    def test_approve_with_notes_and_confidence(self, svc):
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        approved = svc.approve(item.id, reviewed_by="alice",
                               notes="Confirmed", confidence_override=80)
        assert approved.reviewer_notes == "Confirmed"
        assert approved.confidence_override == 80

    def test_approve_already_rejected_raises(self, svc):
        from gnat.review.service import ReviewError
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.reject(item.id, reviewed_by="bob")
        with pytest.raises(ReviewError, match="status"):
            svc.approve(item.id, reviewed_by="alice")

    def test_approve_invalid_confidence_raises(self, svc):
        from gnat.review.service import ReviewError
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        with pytest.raises(ReviewError, match="confidence"):
            svc.approve(item.id, reviewed_by="alice", confidence_override=150)

    def test_approve_nonexistent_raises(self, svc):
        from gnat.review.service import ReviewError
        with pytest.raises(ReviewError):
            svc.approve("no-such-id", reviewed_by="alice")


# ---------------------------------------------------------------------------
# Service — reject
# ---------------------------------------------------------------------------

class TestReviewServiceReject:
    def test_reject_pending(self, svc):
        from gnat.review.models import ReviewStatus
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        rejected = svc.reject(item.id, reviewed_by="bob", reason="False positive")
        assert rejected.status == ReviewStatus.REJECTED
        assert rejected.reviewer_notes == "False positive"

    def test_reject_already_approved_raises(self, svc):
        from gnat.review.service import ReviewError
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.approve(item.id, reviewed_by="alice")
        with pytest.raises(ReviewError):
            svc.reject(item.id, reviewed_by="bob")


# ---------------------------------------------------------------------------
# Service — modify
# ---------------------------------------------------------------------------

class TestReviewServiceModify:
    def test_modify_pending(self, svc):
        from gnat.review.models import ReviewStatus
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        modified = svc.modify(item.id, modified_by="carol",
                              modified_properties={"name": "Override Name"},
                              notes="Adjusted name")
        assert modified.status == ReviewStatus.MODIFIED
        assert modified.modified_properties["name"] == "Override Name"

    def test_modify_then_approve(self, svc):
        from gnat.review.models import ReviewStatus
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.modify(item.id, modified_by="carol",
                   modified_properties={"confidence": 75})
        approved = svc.approve(item.id, reviewed_by="carol")
        assert approved.status == ReviewStatus.APPROVED

    def test_modify_rejected_raises(self, svc):
        from gnat.review.service import ReviewError
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.reject(item.id, reviewed_by="bob")
        with pytest.raises(ReviewError, match="rejected"):
            svc.modify(item.id, modified_by="carol", modified_properties={})


# ---------------------------------------------------------------------------
# Service — promote
# ---------------------------------------------------------------------------

class TestReviewServicePromote:
    def test_promote_approved_no_manager(self, svc):
        """Promote with no workspace_manager does no-op write but marks promoted."""
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.approve(item.id, reviewed_by="alice")
        promoted = svc.promote(item.id, workspace_manager=None)
        assert promoted["x_source_type"] == "analyst_verified"
        assert promoted["x_reviewed_by"] == "alice"
        # Confidence from original object (45)
        assert promoted.get("confidence") == 45
        # Verify item is marked as promoted in store
        refreshed = svc.get(item.id)
        assert refreshed.promoted_at is not None

    def test_promote_applies_confidence_override(self, svc):
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.approve(item.id, reviewed_by="alice", confidence_override=85)
        promoted = svc.promote(item.id, workspace_manager=None)
        assert promoted["confidence"] == 85

    def test_promote_applies_modified_properties(self, svc):
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.modify(item.id, modified_by="carol",
                   modified_properties={"name": "Analyst Verified IP"})
        svc.approve(item.id, reviewed_by="carol")
        promoted = svc.promote(item.id, workspace_manager=None)
        assert promoted["name"] == "Analyst Verified IP"

    def test_promote_unapproved_raises(self, svc):
        from gnat.review.service import ReviewError
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        with pytest.raises(ReviewError, match="APPROVED"):
            svc.promote(item.id, workspace_manager=None)

    def test_promote_twice_raises(self, svc):
        from gnat.review.service import ReviewError
        item = svc.submit(_stix(), source_workspace="ws", submitted_by="a")
        svc.approve(item.id, reviewed_by="alice")
        svc.promote(item.id, workspace_manager=None)
        with pytest.raises(ReviewError, match="already been promoted"):
            svc.promote(item.id, workspace_manager=None)

    def test_promote_removes_ai_ceiling_marker(self, svc):
        stix = _stix()
        stix["x_ai_ceiling"] = 60
        item = svc.submit(stix, source_workspace="ws", submitted_by="a")
        svc.approve(item.id, reviewed_by="alice")
        promoted = svc.promote(item.id, workspace_manager=None)
        assert "x_ai_ceiling" not in promoted


# ---------------------------------------------------------------------------
# Service — bulk ops
# ---------------------------------------------------------------------------

class TestBulkOps:
    def test_bulk_approve(self, svc):
        from gnat.review.models import ReviewStatus
        ids = []
        for i in range(3):
            stix = {**_stix(), "id": f"indicator--1d8d7c3e-abc1-4a7e-9f15-{i:012d}"}
            item = svc.submit(stix, source_workspace="ws", submitted_by="a")
            ids.append(item.id)
        results = svc.bulk_approve(ids, reviewed_by="alice")
        assert len(results) == 3
        assert all(r.status == ReviewStatus.APPROVED for r in results)

    def test_bulk_reject(self, svc):
        from gnat.review.models import ReviewStatus
        ids = []
        for i in range(2):
            stix = {**_stix(), "id": f"indicator--1d8d7c3e-abc1-4a7e-9f15-{i:012d}"}
            item = svc.submit(stix, source_workspace="ws", submitted_by="a")
            ids.append(item.id)
        svc.bulk_reject(ids, reviewed_by="bob")
        for item_id in ids:
            assert svc.get(item_id).status == ReviewStatus.REJECTED


# ---------------------------------------------------------------------------
# Service — stats / list
# ---------------------------------------------------------------------------

class TestServiceStats:
    def test_stats_empty(self, svc):
        stats = svc.stats()
        assert stats["pending"] == 0
        assert stats["total"] == 0

    def test_stats_after_actions(self, svc):
        for i in range(3):
            stix = {**_stix(), "id": f"indicator--1d8d7c3e-abc1-4a7e-9f15-{i:012d}"}
            item = svc.submit(stix, source_workspace="ws", submitted_by="a")
            if i == 0:
                svc.approve(item.id, reviewed_by="alice")
            elif i == 1:
                svc.reject(item.id, reviewed_by="bob")
        stats = svc.stats()
        assert stats["pending"] == 1
        assert stats["approved"] == 1
        assert stats["rejected"] == 1
        assert stats["total"] == 3

    def test_list_pagination(self, svc):
        for i in range(5):
            stix = {**_stix(), "id": f"indicator--1d8d7c3e-abc1-4a7e-9f15-{i:012d}"}
            svc.submit(stix, source_workspace="ws", submitted_by="a")
        page1 = svc.list(page=1, page_size=3)
        page2 = svc.list(page=2, page_size=3)
        assert len(page1) == 3
        assert len(page2) == 2


# ---------------------------------------------------------------------------
# Package exports
# ---------------------------------------------------------------------------

class TestPackageExports:
    def test_all_exports(self):
        from gnat.review import ReviewItem, ReviewStatus, ReviewService, ReviewError, ReviewQueueStore
        assert all([ReviewItem, ReviewStatus, ReviewService, ReviewError, ReviewQueueStore])
