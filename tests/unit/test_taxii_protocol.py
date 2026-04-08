# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/test_taxii_protocol.py
==================================
Unit tests for the shared TAXII 2.1 protocol helpers in
``gnat.taxii._protocol``.
"""

from __future__ import annotations

import base64

import pytest


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_taxii_media_type(self):
        from gnat.taxii._protocol import TAXII_MEDIA_TYPE

        assert TAXII_MEDIA_TYPE == "application/taxii+json;version=2.1"

    def test_stix_media_type(self):
        from gnat.taxii._protocol import STIX_MEDIA_TYPE

        assert STIX_MEDIA_TYPE == "application/stix+json;version=2.1"

    def test_constants_are_different(self):
        from gnat.taxii._protocol import STIX_MEDIA_TYPE, TAXII_MEDIA_TYPE

        assert TAXII_MEDIA_TYPE != STIX_MEDIA_TYPE


# ---------------------------------------------------------------------------
# Cursor encoding / decoding
# ---------------------------------------------------------------------------


class TestCursorEncoding:
    def test_encode_returns_string(self):
        from gnat.taxii._protocol import encode_cursor

        assert isinstance(encode_cursor(0), str)

    def test_round_trip_zero(self):
        from gnat.taxii._protocol import decode_cursor, encode_cursor

        assert decode_cursor(encode_cursor(0)) == 0

    def test_round_trip_positive(self):
        from gnat.taxii._protocol import decode_cursor, encode_cursor

        for offset in [1, 42, 100, 999, 10_000]:
            assert decode_cursor(encode_cursor(offset)) == offset

    def test_encoded_value_is_valid_urlsafe_base64(self):
        from gnat.taxii._protocol import encode_cursor

        token = encode_cursor(50)
        # Should not raise
        base64.urlsafe_b64decode(token)

    def test_decode_invalid_token_returns_zero(self):
        from gnat.taxii._protocol import decode_cursor

        assert decode_cursor("!!!not-base64!!!") == 0

    def test_decode_non_integer_base64_returns_zero(self):
        from gnat.taxii._protocol import decode_cursor

        bad = base64.urlsafe_b64encode(b"hello").decode()
        assert decode_cursor(bad) == 0

    def test_decode_empty_string_returns_zero(self):
        from gnat.taxii._protocol import decode_cursor

        assert decode_cursor("") == 0


# ---------------------------------------------------------------------------
# taxii_response
# ---------------------------------------------------------------------------


class TestTaxiiResponse:
    def test_returns_json_response_with_correct_media_type(self):
        pytest.importorskip("fastapi")
        from gnat.taxii._protocol import TAXII_MEDIA_TYPE, taxii_response

        resp = taxii_response({"key": "value"})
        # FastAPI JSONResponse stores media_type on the object
        assert resp.media_type == TAXII_MEDIA_TYPE

    def test_default_status_code_is_200(self):
        pytest.importorskip("fastapi")
        from gnat.taxii._protocol import taxii_response

        resp = taxii_response({})
        assert resp.status_code == 200

    def test_custom_status_code(self):
        pytest.importorskip("fastapi")
        from gnat.taxii._protocol import taxii_response

        resp = taxii_response({}, status_code=202)
        assert resp.status_code == 202


# ---------------------------------------------------------------------------
# utcnow_iso
# ---------------------------------------------------------------------------


class TestUtcnowIso:
    def test_returns_string(self):
        from gnat.taxii._protocol import utcnow_iso

        result = utcnow_iso()
        assert isinstance(result, str)

    def test_contains_timezone_marker(self):
        from gnat.taxii._protocol import utcnow_iso

        result = utcnow_iso()
        # isoformat with timezone.utc includes '+00:00'
        assert "+00:00" in result

    def test_millisecond_precision(self):
        from gnat.taxii._protocol import utcnow_iso

        result = utcnow_iso()
        # millisecond precision produces exactly 3 decimal digits
        # e.g. "2026-04-08T18:00:00.123+00:00"
        time_part = result.split("T")[1]
        assert "." in time_part


# ---------------------------------------------------------------------------
# make_stix_bundle
# ---------------------------------------------------------------------------


class TestMakeStixBundle:
    def test_type_field(self):
        from gnat.taxii._protocol import make_stix_bundle

        bundle = make_stix_bundle([])
        assert bundle["type"] == "bundle"

    def test_spec_version_field(self):
        from gnat.taxii._protocol import make_stix_bundle

        bundle = make_stix_bundle([])
        assert bundle["spec_version"] == "2.1"

    def test_id_starts_with_bundle_prefix(self):
        from gnat.taxii._protocol import make_stix_bundle

        bundle = make_stix_bundle([])
        assert bundle["id"].startswith("bundle--")

    def test_id_is_unique_across_calls(self):
        from gnat.taxii._protocol import make_stix_bundle

        ids = {make_stix_bundle([])["id"] for _ in range(10)}
        assert len(ids) == 10

    def test_objects_field_matches_input(self):
        from gnat.taxii._protocol import make_stix_bundle

        objs = [{"type": "indicator", "id": "indicator--1"}]
        bundle = make_stix_bundle(objs)
        assert bundle["objects"] == objs

    def test_empty_objects(self):
        from gnat.taxii._protocol import make_stix_bundle

        bundle = make_stix_bundle([])
        assert bundle["objects"] == []


# ---------------------------------------------------------------------------
# make_discovery_body
# ---------------------------------------------------------------------------


class TestMakeDiscoveryBody:
    def test_required_fields_present(self):
        from gnat.taxii._protocol import make_discovery_body

        body = make_discovery_body(
            title="Test Server",
            description="A test",
            contact="test@example.com",
            default_root="/taxii2/roots/gnat/",
            api_roots=["/taxii2/roots/gnat/"],
        )
        assert body["title"] == "Test Server"
        assert body["description"] == "A test"
        assert body["contact"] == "test@example.com"
        assert body["default"] == "/taxii2/roots/gnat/"
        assert body["api_roots"] == ["/taxii2/roots/gnat/"]

    def test_api_roots_is_list(self):
        from gnat.taxii._protocol import make_discovery_body

        body = make_discovery_body("T", "D", "", "/r/", ["/r/", "/s/"])
        assert isinstance(body["api_roots"], list)
        assert len(body["api_roots"]) == 2

    def test_empty_contact_allowed(self):
        from gnat.taxii._protocol import make_discovery_body

        body = make_discovery_body("T", "D", "", "/r/", ["/r/"])
        assert body["contact"] == ""


# ---------------------------------------------------------------------------
# make_api_root_body
# ---------------------------------------------------------------------------


class TestMakeApiRootBody:
    def test_required_fields_present(self):
        from gnat.taxii._protocol import TAXII_MEDIA_TYPE, make_api_root_body

        body = make_api_root_body(title="Root", description="Desc")
        assert body["title"] == "Root"
        assert body["description"] == "Desc"
        assert body["versions"] == [TAXII_MEDIA_TYPE]
        assert "max_content_length" in body

    def test_default_max_content_length_is_10mib(self):
        from gnat.taxii._protocol import make_api_root_body

        body = make_api_root_body("T", "D")
        assert body["max_content_length"] == 10_485_760  # 10 MiB

    def test_custom_max_content_length(self):
        from gnat.taxii._protocol import make_api_root_body

        body = make_api_root_body("T", "D", max_content_length=5_000_000)
        assert body["max_content_length"] == 5_000_000

    def test_versions_contains_taxii_media_type(self):
        from gnat.taxii._protocol import TAXII_MEDIA_TYPE, make_api_root_body

        body = make_api_root_body("T", "D")
        assert TAXII_MEDIA_TYPE in body["versions"]


# ---------------------------------------------------------------------------
# Package-level re-exports
# ---------------------------------------------------------------------------


class TestPackageReexports:
    """Verify gnat.taxii.__init__ re-exports all public helpers."""

    def test_all_symbols_importable_from_package(self):
        import gnat.taxii as pkg

        for name in [
            "TAXII_MEDIA_TYPE",
            "STIX_MEDIA_TYPE",
            "encode_cursor",
            "decode_cursor",
            "taxii_response",
            "utcnow_iso",
            "make_stix_bundle",
            "make_discovery_body",
            "make_api_root_body",
        ]:
            assert hasattr(pkg, name), f"gnat.taxii missing: {name}"
