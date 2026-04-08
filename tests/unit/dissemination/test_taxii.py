"""
Unit tests for gnat.dissemination.taxii (collections + server)
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from gnat.analysis.tlp import TLPLevel
from gnat.dissemination.taxii.collections import (
    COLLECTION_BY_ID,
    COLLECTIONS,
    TAXIICollection,
    collections_for_key,
    tlp_filter_for_collection,
)


# ── TAXIICollection ───────────────────────────────────────────────────────────

class TestTAXIICollection:
    def test_all_four_collections_exist(self):
        assert "tlp-white" in COLLECTIONS
        assert "tlp-green" in COLLECTIONS
        assert "tlp-amber" in COLLECTIONS
        assert "tlp-red"   in COLLECTIONS

    def test_collection_ids_are_stable_uuids(self):
        col = COLLECTIONS["tlp-amber"]
        # UUID is deterministic — re-importing produces same value
        from gnat.dissemination.taxii.collections import _cid
        assert col.id == _cid("tlp-amber")

    def test_collection_by_id_maps_all(self):
        assert len(COLLECTION_BY_ID) == len(COLLECTIONS)

    def test_to_taxii_dict_has_required_fields(self):
        col = COLLECTIONS["tlp-green"]
        d   = col.to_taxii_dict()
        assert "id"          in d
        assert "title"       in d
        assert "description" in d
        assert "can_read"    in d
        assert "can_write"   in d
        assert "media_types" in d

    def test_can_read_true_write_enabled_for_amber_and_red(self):
        # All collections are readable
        for col in COLLECTIONS.values():
            assert col.can_read is True
        # Write is enabled only for TLP:AMBER and TLP:RED (Phase 3B)
        assert COLLECTIONS["tlp-white"].can_write is False
        assert COLLECTIONS["tlp-green"].can_write is False
        assert COLLECTIONS["tlp-amber"].can_write is True
        assert COLLECTIONS["tlp-red"].can_write   is True

    def test_is_accessible_white_key_sees_white_only(self):
        white_col = COLLECTIONS["tlp-white"]
        green_col = COLLECTIONS["tlp-green"]
        assert     white_col.is_accessible(TLPLevel.WHITE)
        assert not green_col.is_accessible(TLPLevel.WHITE)

    def test_is_accessible_amber_key_sees_lower_levels(self):
        amber_key = TLPLevel.AMBER
        assert COLLECTIONS["tlp-white"].is_accessible(amber_key)
        assert COLLECTIONS["tlp-green"].is_accessible(amber_key)
        assert COLLECTIONS["tlp-amber"].is_accessible(amber_key)
        assert not COLLECTIONS["tlp-red"].is_accessible(amber_key)

    def test_is_accessible_red_key_sees_all(self):
        red_key = TLPLevel.RED
        for col in COLLECTIONS.values():
            assert col.is_accessible(red_key)


class TestCollectionsForKey:
    def test_white_key_returns_one_collection(self):
        cols = collections_for_key(TLPLevel.WHITE)
        assert len(cols) == 1
        assert cols[0].tlp_level == TLPLevel.WHITE

    def test_green_key_returns_two(self):
        cols = collections_for_key(TLPLevel.GREEN)
        assert len(cols) == 2

    def test_amber_key_returns_three(self):
        cols = collections_for_key(TLPLevel.AMBER)
        assert len(cols) == 3

    def test_red_key_returns_four(self):
        cols = collections_for_key(TLPLevel.RED)
        assert len(cols) == 4


class TestTLPFilterForCollection:
    def test_white_collection_only_includes_white(self):
        col_id = COLLECTIONS["tlp-white"].id
        tlps   = tlp_filter_for_collection(col_id)
        assert "white" in tlps
        assert "green" not in tlps

    def test_amber_collection_includes_amber_green_white(self):
        col_id = COLLECTIONS["tlp-amber"].id
        tlps   = tlp_filter_for_collection(col_id)
        assert "white" in tlps
        assert "green" in tlps
        assert "amber" in tlps
        assert "red"   not in tlps

    def test_red_collection_includes_all(self):
        col_id = COLLECTIONS["tlp-red"].id
        tlps   = tlp_filter_for_collection(col_id)
        assert "white" in tlps
        assert "green" in tlps
        assert "amber" in tlps
        assert "red"   in tlps

    def test_unknown_collection_id_returns_empty(self):
        tlps = tlp_filter_for_collection("00000000-0000-0000-0000-000000000000")
        assert tlps == []


# ── TAXII server (unit — no actual HTTP) ─────────────────────────────────────

class TestTAXIIServerHelpers:
    """Test helpers in the server module without starting a full ASGI server."""

    def test_encode_decode_cursor(self):
        from gnat.dissemination.taxii.server import _encode_cursor, _decode_cursor
        for offset in [0, 50, 100, 999]:
            assert _decode_cursor(_encode_cursor(offset)) == offset

    def test_decode_cursor_invalid_returns_zero(self):
        from gnat.dissemination.taxii.server import _decode_cursor
        assert _decode_cursor("!!!invalid!!!") == 0

    def test_get_tlp_value_from_tlp_level(self):
        from gnat.dissemination.taxii.server import _get_tlp_value
        r = MagicMock()
        r.classification = TLPLevel.AMBER
        assert _get_tlp_value(r) == "amber"

    def test_get_tlp_value_string_classification(self):
        from gnat.dissemination.taxii.server import _get_tlp_value
        r = MagicMock()
        r.classification = "GREEN"
        assert _get_tlp_value(r) == "green"

    def test_report_to_stix_envelope_cached(self):
        import json
        from gnat.dissemination.taxii.server import _report_to_stix_envelope
        bundle = {
            "type": "bundle",
            "id":   "bundle--x",
            "objects": [
                {"type": "report", "id": "report--1", "name": "My Report",
                 "published": "2025-01-01T00:00:00Z", "created": "2025-01-01T00:00:00Z",
                 "modified": "2025-01-01T00:00:00Z", "spec_version": "2.1",
                 "object_refs": []},
            ],
        }
        r = MagicMock()
        r.stix_bundle_json = json.dumps(bundle)
        r.id               = "rpt-1"
        stix_obj = _report_to_stix_envelope(r)
        assert stix_obj["type"] == "report"
        assert stix_obj["id"]   == "report--1"

    def test_report_to_stix_envelope_fallback(self):
        from gnat.dissemination.taxii.server import _report_to_stix_envelope
        r = MagicMock()
        r.stix_bundle_json = None
        r.id               = "rpt-99"
        r.title            = "Fallback Report"
        r.executive_summary = "Summary"
        r.published_at     = datetime(2025, 6, 1, tzinfo=timezone.utc)
        r.stix_id          = None   # explicitly None so fallback is used
        stix_obj = _report_to_stix_envelope(r)
        assert stix_obj["type"] == "report"
        assert "rpt-99" in stix_obj["id"]
        assert stix_obj["name"] == "Fallback Report"

    def test_fetch_reports_filters_by_tlp(self):
        from gnat.dissemination.taxii.server import _fetch_reports
        r1 = MagicMock()
        r1.classification = TLPLevel.WHITE
        r1.published_at   = datetime(2025, 1, 1, tzinfo=timezone.utc)

        r2 = MagicMock()
        r2.classification = TLPLevel.RED
        r2.published_at   = datetime(2025, 1, 2, tzinfo=timezone.utc)

        store = MagicMock()
        store.list.return_value = [r1, r2]

        result = _fetch_reports(store, tlp_values=["white"], added_after=None)
        assert len(result) == 1
        assert result[0].classification == TLPLevel.WHITE

    def test_fetch_reports_added_after_filter(self):
        from gnat.dissemination.taxii.server import _fetch_reports
        old_dt  = datetime(2024, 1, 1, tzinfo=timezone.utc)
        new_dt  = datetime(2025, 6, 1, tzinfo=timezone.utc)

        r_old = MagicMock()
        r_old.classification = TLPLevel.WHITE
        r_old.published_at   = old_dt

        r_new = MagicMock()
        r_new.classification = TLPLevel.WHITE
        r_new.published_at   = new_dt

        store = MagicMock()
        store.list.return_value = [r_old, r_new]

        result = _fetch_reports(store, tlp_values=["white"],
                                added_after="2025-01-01T00:00:00+00:00")
        assert len(result) == 1
        assert result[0].published_at == new_dt
