"""
tests/integration/test_docker_taxii.py
========================================

Docker-harness integration tests for the GNAT TAXII 2.1 server.

The TAXII server is a pure-Python subprocess (no container needed).
These tests exercise the full HTTP round-trip: discovery → collection
create → object POST → object GET → manifest → single-object fetch.

All tests are marked ``@pytest.mark.docker`` and skipped unless
``--run-docker`` is passed to pytest.

Run::

    pytest tests/integration/test_docker_taxii.py --run-docker -v
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.docker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TAXII_TYPE = "application/taxii+json;version=2.1"
_STIX_TYPE = "application/stix+json;version=2.1"

_SAMPLE_INDICATOR = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--12345678-1234-5678-1234-567812345678",
    "name": "Malicious IP",
    "pattern": "[ipv4-addr:value = '198.51.100.1']",
    "pattern_type": "stix",
    "valid_from": "2024-01-01T00:00:00Z",
    "indicator_types": ["malicious-activity"],
    "created": "2024-01-01T00:00:00Z",
    "modified": "2024-01-01T00:00:00Z",
}

_SAMPLE_BUNDLE = {
    "type": "bundle",
    "id": "bundle--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "spec_version": "2.1",
    "objects": [_SAMPLE_INDICATOR],
}


def _make_request(
    url: str,
    *,
    api_key: str | None = None,
    method: str = "GET",
    body: dict | None = None,
    accept: str = _TAXII_TYPE,
) -> tuple[int, dict]:
    """Send an HTTP request, return (status_code, parsed_json_body)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", accept)
    if api_key:
        req.add_header("X-TAXII-API-Key", api_key)
    if data:
        req.add_header("Content-Type", _STIX_TYPE)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            body_bytes = exc.read()
            return exc.code, json.loads(body_bytes)
        except Exception:
            return exc.code, {}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_discovery_no_auth(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        status, body = _make_request(f"{base}/taxii2/")
        assert status == 200
        assert "title" in body
        assert "api_roots" in body

    def test_discovery_content_type(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        req = urllib.request.Request(f"{base}/taxii2/")
        req.add_header("Accept", _TAXII_TYPE)
        with urllib.request.urlopen(req, timeout=10) as resp:
            ct = resp.headers.get("Content-Type", "")
        assert "taxii+json" in ct

    def test_api_root_info(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        status, body = _make_request(f"{base}/taxii2/gnat/")
        assert status == 200
        assert "title" in body
        assert "versions" in body
        assert "2.1" in body["versions"]

    def test_collections_require_auth(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        status, _ = _make_request(f"{base}/taxii2/gnat/collections/")
        assert status == 401

    def test_collections_wrong_key(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        status, _ = _make_request(
            f"{base}/taxii2/gnat/collections/",
            api_key="wrong-key",
        )
        assert status == 401

    def test_collections_correct_key(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]
        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/",
            api_key=key,
        )
        assert status == 200
        assert "collections" in body


class TestCollectionRoundtrip:
    """POST objects into a collection and read them back."""

    def test_post_and_get_objects(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]

        collection_id = "roundtrip-test-collection"

        # POST a STIX bundle
        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/",
            api_key=key,
            method="POST",
            body=_SAMPLE_BUNDLE,
        )
        assert status == 202, f"Expected 202, got {status}: {body}"
        assert body.get("status") in ("pending", "complete")

        # GET objects back
        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/",
            api_key=key,
        )
        assert status == 200
        objects = body.get("objects", [])
        assert len(objects) >= 1
        ids = [o["id"] for o in objects]
        assert _SAMPLE_INDICATOR["id"] in ids

    def test_post_bundle_status_fields(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]

        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/status-test/objects/",
            api_key=key,
            method="POST",
            body=_SAMPLE_BUNDLE,
        )
        assert status == 202
        for field in ("id", "status", "request_timestamp", "total_count", "success_count"):
            assert field in body, f"Missing field: {field}"

    def test_get_single_object(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]
        collection_id = "single-obj-test"
        obj_id = _SAMPLE_INDICATOR["id"]

        # Ensure object exists
        _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/",
            api_key=key,
            method="POST",
            body=_SAMPLE_BUNDLE,
        )

        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/{obj_id}/",
            api_key=key,
        )
        assert status == 200
        objects = body.get("objects", [])
        assert any(o["id"] == obj_id for o in objects)

    def test_get_unknown_object_404(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]

        status, _ = _make_request(
            f"{base}/taxii2/gnat/collections/no-such-collection/objects/indicator--ffffffff-ffff-ffff-ffff-ffffffffffff/",
            api_key=key,
        )
        assert status == 404

    def test_manifest(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]
        collection_id = "manifest-test"

        _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/",
            api_key=key,
            method="POST",
            body=_SAMPLE_BUNDLE,
        )

        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/manifest/",
            api_key=key,
        )
        assert status == 200
        assert "objects" in body
        entries = body["objects"]
        assert len(entries) >= 1
        entry = entries[0]
        assert "id" in entry
        assert "date_added" in entry
        assert "version" in entry

    def test_object_versions(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]
        collection_id = "versions-test"
        obj_id = _SAMPLE_INDICATOR["id"]

        _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/",
            api_key=key,
            method="POST",
            body=_SAMPLE_BUNDLE,
        )

        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/{obj_id}/versions/",
            api_key=key,
        )
        assert status == 200
        assert "versions" in body
        assert len(body["versions"]) >= 1


class TestPagination:
    """Verify pagination cursors work end-to-end."""

    def _build_bundle(self, count: int) -> dict:
        objects = []
        for i in range(count):
            hex_i = format(i, "04x")
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--00000000-0000-0000-0000-{hex_i:>012}",
                    "name": f"IOC-{i}",
                    "pattern": f"[ipv4-addr:value = '10.0.{i // 256}.{i % 256}']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "indicator_types": ["malicious-activity"],
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                }
            )
        return {
            "type": "bundle",
            "id": "bundle--11111111-1111-1111-1111-111111111111",
            "spec_version": "2.1",
            "objects": objects,
        }

    def test_pagination_next_cursor(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]
        collection_id = "pagination-test"

        bundle = self._build_bundle(25)
        _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/",
            api_key=key,
            method="POST",
            body=bundle,
        )

        # Fetch page 1 with limit=10
        status, body = _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/?limit=10",
            api_key=key,
        )
        assert status == 200
        assert len(body.get("objects", [])) == 10
        assert "next" in body  # cursor present

    def test_pagination_full_traversal(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]
        collection_id = "pagination-full"

        total = 15
        bundle = self._build_bundle(total)
        _make_request(
            f"{base}/taxii2/gnat/collections/{collection_id}/objects/",
            api_key=key,
            method="POST",
            body=bundle,
        )

        collected = []
        url = f"{base}/taxii2/gnat/collections/{collection_id}/objects/?limit=5"
        pages = 0
        while url:
            status, body = _make_request(url, api_key=key)
            assert status == 200
            collected.extend(body.get("objects", []))
            next_cursor = body.get("next")
            if next_cursor:
                url = f"{base}/taxii2/gnat/collections/{collection_id}/objects/?limit=5&next={next_cursor}"
            else:
                url = None
            pages += 1
            assert pages <= 10, "Pagination loop detected"

        assert len(collected) == total


class TestInvalidRequests:
    def test_post_non_bundle(self, gnat_taxii_server):
        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]

        status, _ = _make_request(
            f"{base}/taxii2/gnat/collections/bad-post/objects/",
            api_key=key,
            method="POST",
            body={"type": "indicator", "id": "indicator--aabbccdd-1234-5678-abcd-112233445566"},
        )
        assert status == 422

    def test_post_invalid_json_returns_error(self, gnat_taxii_server):
        """Sending malformed JSON should yield 400 or 422."""
        import urllib.request

        base = gnat_taxii_server["base_url"]
        key = gnat_taxii_server["api_key"]

        req = urllib.request.Request(
            f"{base}/taxii2/gnat/collections/bad-json/objects/",
            data=b"NOT JSON {{{{",
            method="POST",
        )
        req.add_header("Accept", _TAXII_TYPE)
        req.add_header("X-TAXII-API-Key", key)
        req.add_header("Content-Type", _STIX_TYPE)

        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as exc:
            assert exc.code in (400, 422)
