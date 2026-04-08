"""Unit tests for TAXII 2.1 write endpoints."""

from __future__ import annotations

import pytest


# ── Collection write flags ─────────────────────────────────────────────────────

def test_amber_collection_can_write():
    from gnat.dissemination.taxii.collections import COLLECTIONS
    assert COLLECTIONS["tlp-amber"].can_write is True


def test_red_collection_can_write():
    from gnat.dissemination.taxii.collections import COLLECTIONS
    assert COLLECTIONS["tlp-red"].can_write is True


def test_white_collection_cannot_write():
    from gnat.dissemination.taxii.collections import COLLECTIONS
    assert COLLECTIONS["tlp-white"].can_write is False


def test_green_collection_cannot_write():
    from gnat.dissemination.taxii.collections import COLLECTIONS
    assert COLLECTIONS["tlp-green"].can_write is False


# ── STIX ingest helper ─────────────────────────────────────────────────────────

def test_ingest_stix_objects_reports():
    from gnat.dissemination.taxii.server import _ingest_stix_objects

    ingested_ids = []

    class FakeStore:
        def ingest_stix(self, obj):
            ingested_ids.append(obj["id"])

    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "report", "id": "report--1", "spec_version": "2.1",
             "name": "T1", "published": "", "object_refs": []},
            {"type": "indicator", "id": "indicator--1", "spec_version": "2.1"},
        ]
    }

    ingested, skipped = _ingest_stix_objects(bundle, FakeStore())
    assert ingested == 1
    assert skipped  == 1
    assert ingested_ids == ["report--1"]


def test_ingest_stix_objects_no_store():
    from gnat.dissemination.taxii.server import _ingest_stix_objects

    class StoreMissingMethod:
        pass  # no ingest_stix()

    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "report", "id": "report--2", "spec_version": "2.1",
             "name": "T2", "published": "", "object_refs": []},
        ]
    }
    ingested, skipped = _ingest_stix_objects(bundle, StoreMissingMethod())
    # No ingest_stix → still counted as ingested (logged)
    assert ingested == 1
    assert skipped  == 0


def test_ingest_stix_objects_exception_counted_as_skipped():
    from gnat.dissemination.taxii.server import _ingest_stix_objects

    class FailingStore:
        def ingest_stix(self, obj):
            raise RuntimeError("db error")

    bundle = {"type": "bundle", "objects": [
        {"type": "report", "id": "report--3", "spec_version": "2.1",
         "name": "T3", "published": "", "object_refs": []},
    ]}
    ingested, skipped = _ingest_stix_objects(bundle, FailingStore())
    assert ingested == 0
    assert skipped  == 1


# ── Soft-delete helper ────────────────────────────────────────────────────────

def test_soft_delete_via_direct_api():
    from gnat.dissemination.taxii.server import _soft_delete_object

    deleted_ids = []

    class DirectStore:
        def delete_by_stix_id(self, stix_id):
            deleted_ids.append(stix_id)
            return True

    result = _soft_delete_object("report--1", DirectStore())
    assert result is True
    assert deleted_ids == ["report--1"]


def test_soft_delete_fallback_scan():
    from gnat.dissemination.taxii.server import _soft_delete_object

    class FakeReport:
        id      = "uuid-abc"
        stix_id = "report--fallback"

    deleted_ids = []

    class ScanStore:
        def list(self, page_size=100):
            return [FakeReport()]

        def delete(self, pk):
            deleted_ids.append(pk)

    result = _soft_delete_object("report--fallback", ScanStore())
    assert result is True
    assert deleted_ids == ["uuid-abc"]


def test_soft_delete_not_found():
    from gnat.dissemination.taxii.server import _soft_delete_object

    class EmptyStore:
        def list(self, page_size=100):
            return []

    result = _soft_delete_object("report--missing", EmptyStore())
    assert result is False


# ── TAXII server builds without error ─────────────────────────────────────────

def test_build_taxii_router_accepts_policy_engine():
    pytest.importorskip("fastapi")
    from gnat.dissemination.taxii.server import build_taxii_router
    from gnat.dissemination.api.auth import APIKeyStore
    from gnat.policy.engine import PolicyEngine

    store  = APIKeyStore()
    engine = PolicyEngine()

    class FakeReportStore:
        def list(self, **kw): return []

    router = build_taxii_router(FakeReportStore(), store, policy_engine=engine)
    assert router is not None
