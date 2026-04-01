"""
tests/unit/test_taxii_server.py
================================
Unit tests for the GNAT TAXII 2.1 server.

Tests cover:
1.  Discovery endpoint — no auth required
2.  API root info endpoint — no auth required
3.  Auth guard — missing key, wrong key, correct key
4.  Collections list — empty and populated
5.  Collection detail — found and 404
6.  Objects GET — basic, pagination, filters (match[type], added_after)
7.  Objects POST — valid bundle, bad bundle, invalid JSON
8.  Manifest — basic and pagination
9.  Single object GET — found and 404
10. Object versions — found and 404
11. _encode_cursor / _decode_cursor round-trip
12. build_taxii_app with no API key (auth disabled)
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Skip entire module when FastAPI / TestClient not installed
# ---------------------------------------------------------------------------
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from gnat.serve.taxii.app import (  # noqa: E402
    _decode_cursor,
    _encode_cursor,
    build_taxii_app,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KEY = "test-taxii-key-xyz"
_TAXII_MEDIA = "application/taxii+json;version=2.1"


def _make_stix_obj(stix_id: str, stix_type: str = "indicator") -> MagicMock:
    """Build a mock STIXBase object."""
    obj = MagicMock()
    obj.id = stix_id
    obj.stix_type = stix_type
    obj.to_dict.return_value = {
        "type": stix_type,
        "id": stix_id,
        "spec_version": "2.1",
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-01-02T00:00:00.000Z",
    }
    return obj


def _make_workspace(name: str, objects: list | None = None) -> MagicMock:
    """Build a mock workspace that iterates over *objects*."""
    ws = MagicMock()
    ws.__iter__ = MagicMock(return_value=iter(objects or []))
    ws.objects = {obj.id: obj for obj in (objects or [])}
    ws.dirty = set()
    ws.commit = MagicMock()
    return ws


def _make_manager(workspaces: dict | None = None) -> MagicMock:
    """
    Build a mock WorkspaceManager.

    Parameters
    ----------
    workspaces : dict
        Mapping of workspace name → list of STIXBase mocks.
    """
    workspaces = workspaces or {}
    manager = MagicMock()
    manager.list.return_value = [{"name": n, "description": ""} for n in workspaces]

    def _open(name):
        if name not in workspaces:
            raise KeyError(name)
        return _make_workspace(name, workspaces[name])

    def _get_or_create(name):
        if name not in workspaces:
            workspaces[name] = []
        ws = _make_workspace(name, workspaces[name])
        ws.objects = {}
        ws.dirty = set()
        return ws

    manager.open.side_effect = _open
    manager.get_or_create.side_effect = _get_or_create
    return manager


def _client(manager=None, api_key=_KEY) -> TestClient:
    if manager is None:
        manager = _make_manager()
    app = build_taxii_app(manager, api_key=api_key)
    return TestClient(app, raise_server_exceptions=False)


def _authed(client: TestClient, method: str, path: str, **kwargs):
    """Perform an authenticated request."""
    headers = kwargs.pop("headers", {})
    headers["X-Api-Key"] = _KEY
    return getattr(client, method)(path, headers=headers, **kwargs)


# ---------------------------------------------------------------------------
# 1. _encode_cursor / _decode_cursor round-trip
# ---------------------------------------------------------------------------


class TestCursorEncoding:
    def test_encode_decode_zero(self):
        assert _decode_cursor(_encode_cursor(0)) == 0

    def test_encode_decode_positive(self):
        assert _decode_cursor(_encode_cursor(42)) == 42
        assert _decode_cursor(_encode_cursor(1000)) == 1000

    def test_decode_invalid_returns_zero(self):
        assert _decode_cursor("!!!not-base64!!!") == 0

    def test_decode_non_int_returns_zero(self):
        bad = base64.urlsafe_b64encode(b"hello").decode()
        assert _decode_cursor(bad) == 0


# ---------------------------------------------------------------------------
# 2. Discovery (no auth)
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_discovery_no_auth_required(self):
        c = _client()
        r = c.get("/taxii2/")
        assert r.status_code == 200

    def test_discovery_content_type(self):
        c = _client()
        r = c.get("/taxii2/")
        assert _TAXII_MEDIA in r.headers.get("content-type", "")

    def test_discovery_body_fields(self):
        c = _client()
        body = r = c.get("/taxii2/").json()
        assert "title" in body
        assert "api_roots" in body
        assert any("gnat" in root for root in body["api_roots"])

    def test_discovery_uses_title_param(self):
        manager = _make_manager()
        app = build_taxii_app(manager, api_key=_KEY, title="My TAXII")
        c = TestClient(app, raise_server_exceptions=False)
        body = c.get("/taxii2/").json()
        assert body["title"] == "My TAXII"

    def test_discovery_includes_contact(self):
        manager = _make_manager()
        app = build_taxii_app(manager, api_key=_KEY, contact="admin@example.com")
        c = TestClient(app, raise_server_exceptions=False)
        body = c.get("/taxii2/").json()
        assert body["contact"] == "admin@example.com"


# ---------------------------------------------------------------------------
# 3. API Root info (no auth)
# ---------------------------------------------------------------------------


class TestAPIRootInfo:
    def test_api_root_no_auth_required(self):
        c = _client()
        r = c.get("/taxii2/roots/gnat/")
        assert r.status_code == 200

    def test_api_root_body_fields(self):
        c = _client()
        body = c.get("/taxii2/roots/gnat/").json()
        assert "title" in body
        assert "versions" in body
        assert "max_content_length" in body


# ---------------------------------------------------------------------------
# 4. Auth guard
# ---------------------------------------------------------------------------


class TestAuth:
    def test_missing_key_returns_401(self):
        c = _client()
        r = c.get("/taxii2/roots/gnat/collections/")
        assert r.status_code == 401

    def test_wrong_key_returns_401(self):
        c = _client()
        r = c.get(
            "/taxii2/roots/gnat/collections/",
            headers={"X-Api-Key": "wrong-key"},
        )
        assert r.status_code == 401

    def test_correct_key_returns_200(self):
        c = _client()
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/")
        assert r.status_code == 200

    def test_no_api_key_config_allows_any_request(self):
        """When api_key='', auth is disabled — all requests succeed."""
        manager = _make_manager()
        app = build_taxii_app(manager, api_key="")
        c = TestClient(app, raise_server_exceptions=False)
        r = c.get("/taxii2/roots/gnat/collections/")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 5. Collections list
# ---------------------------------------------------------------------------


class TestCollectionsList:
    def test_empty_manager(self):
        c = _client()
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/")
        assert r.status_code == 200
        body = r.json()
        assert body["collections"] == []

    def test_populated_manager(self):
        obj = _make_stix_obj("indicator--aaa")
        manager = _make_manager({"alpha": [obj], "beta": []})
        c = _client(manager)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/")
        body = r.json()
        names = [col["id"] for col in body["collections"]]
        assert "alpha" in names
        assert "beta" in names

    def test_collection_fields(self):
        manager = _make_manager({"ws1": []})
        c = _client(manager)
        body = _authed(c, "get", "/taxii2/roots/gnat/collections/").json()
        col = body["collections"][0]
        assert col["id"] == "ws1"
        assert col["can_read"] is True
        assert col["can_write"] is True

    def test_manager_error_returns_empty(self):
        """If manager.list() raises, return empty collections list."""
        manager = MagicMock()
        manager.list.side_effect = RuntimeError("db down")
        app = build_taxii_app(manager, api_key=_KEY)
        c = TestClient(app, raise_server_exceptions=False)
        r = c.get(
            "/taxii2/roots/gnat/collections/",
            headers={"X-Api-Key": _KEY},
        )
        assert r.status_code == 200
        assert r.json()["collections"] == []


# ---------------------------------------------------------------------------
# 6. Collection detail
# ---------------------------------------------------------------------------


class TestCollectionDetail:
    def test_found(self):
        manager = _make_manager({"myws": []})
        c = _client(manager)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/myws/")
        assert r.status_code == 200
        assert r.json()["id"] == "myws"

    def test_not_found_returns_404(self):
        c = _client(_make_manager())
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/nonexistent/")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# 7. Objects GET
# ---------------------------------------------------------------------------


class TestObjectsGet:
    def _setup(self, n: int = 3):
        objs = [_make_stix_obj(f"indicator--{i:03d}") for i in range(n)]
        manager = _make_manager({"col": objs})
        return _client(manager)

    def test_basic_get_returns_bundle(self):
        c = self._setup(2)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/objects/")
        assert r.status_code == 200
        body = r.json()
        assert body["type"] == "bundle"
        assert body["spec_version"] == "2.1"
        assert len(body["objects"]) == 2

    def test_pagination_limit(self):
        c = self._setup(5)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/objects/?limit=2")
        body = r.json()
        assert len(body["objects"]) == 2
        assert "next" in body  # more pages exist

    def test_pagination_next_cursor(self):
        c = self._setup(5)
        r1 = _authed(c, "get", "/taxii2/roots/gnat/collections/col/objects/?limit=2")
        cursor = r1.json()["next"]
        r2 = _authed(
            c,
            "get",
            f"/taxii2/roots/gnat/collections/col/objects/?limit=2&next={cursor}",
        )
        body2 = r2.json()
        assert len(body2["objects"]) == 2

    def test_last_page_has_no_next(self):
        c = self._setup(2)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/objects/?limit=10")
        body = r.json()
        assert "next" not in body

    def test_match_type_filter(self):
        objs = [
            _make_stix_obj("indicator--001", "indicator"),
            _make_stix_obj("malware--001", "malware"),
        ]
        manager = _make_manager({"col": objs})
        c = _client(manager)
        r = _authed(
            c,
            "get",
            "/taxii2/roots/gnat/collections/col/objects/",
            params={"match[type]": "indicator"},
        )
        body = r.json()
        assert all(o["type"] == "indicator" for o in body["objects"])

    def test_added_after_filter(self):
        objs = [
            _make_stix_obj("indicator--old"),
            _make_stix_obj("indicator--new"),
        ]
        # Patch the 'created' field of the old object to be older
        objs[0].to_dict.return_value["created"] = "2020-01-01T00:00:00.000Z"
        objs[0].to_dict.return_value["modified"] = "2020-01-01T00:00:00.000Z"
        manager = _make_manager({"col": objs})
        c = _client(manager)
        r = _authed(
            c,
            "get",
            "/taxii2/roots/gnat/collections/col/objects/",
            params={"added_after": "2023-01-01T00:00:00.000Z"},
        )
        body = r.json()
        ids = [o["id"] for o in body["objects"]]
        assert "indicator--old" not in ids
        assert "indicator--new" in ids

    def test_unknown_collection_returns_404(self):
        c = _client(_make_manager())
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/noexist/objects/")
        assert r.status_code == 404

    def test_response_has_taxii_content_type(self):
        c = self._setup(1)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/objects/")
        assert _TAXII_MEDIA in r.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# 8. Objects POST
# ---------------------------------------------------------------------------


class TestObjectsPost:
    def _bundle(self, *obj_dicts) -> dict:
        return {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": list(obj_dicts),
        }

    def _raw_indicator(self, stix_id: str = "indicator--111") -> dict:
        return {
            "type": "indicator",
            "id": stix_id,
            "spec_version": "2.1",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "test",
            "pattern": "[domain-name:value = 'evil.com']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00.000Z",
        }

    def test_add_bundle_returns_202(self):
        manager = _make_manager({"col": []})
        c = _client(manager)
        bundle = self._bundle(self._raw_indicator())
        r = _authed(
            c,
            "post",
            "/taxii2/roots/gnat/collections/col/objects/",
            json=bundle,
        )
        assert r.status_code == 202

    def test_add_bundle_status_resource_fields(self):
        manager = _make_manager({"col": []})
        c = _client(manager)
        bundle = self._bundle(self._raw_indicator())
        body = _authed(
            c,
            "post",
            "/taxii2/roots/gnat/collections/col/objects/",
            json=bundle,
        ).json()
        assert "id" in body
        assert "status" in body
        assert body["total_count"] == 1

    def test_non_bundle_returns_422(self):
        manager = _make_manager({"col": []})
        c = _client(manager)
        r = _authed(
            c,
            "post",
            "/taxii2/roots/gnat/collections/col/objects/",
            json={"type": "indicator", "id": "indicator--x"},
        )
        assert r.status_code == 422

    def test_invalid_json_returns_400(self):
        manager = _make_manager({"col": []})
        c = _client(manager)
        r = c.post(
            "/taxii2/roots/gnat/collections/col/objects/",
            content=b"not json at all",
            headers={"X-Api-Key": _KEY, "Content-Type": "application/json"},
        )
        assert r.status_code == 400

    def test_post_to_new_collection_creates_it(self):
        """POSTing to a non-existent collection creates it via get_or_create."""
        manager = _make_manager({})
        c = _client(manager)
        bundle = self._bundle(self._raw_indicator())
        r = _authed(
            c,
            "post",
            "/taxii2/roots/gnat/collections/newcol/objects/",
            json=bundle,
        )
        assert r.status_code == 202
        manager.get_or_create.assert_called_once_with("newcol")


# ---------------------------------------------------------------------------
# 9. Manifest
# ---------------------------------------------------------------------------


class TestManifest:
    def test_basic_manifest(self):
        objs = [_make_stix_obj(f"indicator--{i:03d}") for i in range(3)]
        manager = _make_manager({"col": objs})
        c = _client(manager)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/manifest/")
        assert r.status_code == 200
        body = r.json()
        assert "objects" in body
        assert len(body["objects"]) == 3

    def test_manifest_entry_fields(self):
        objs = [_make_stix_obj("indicator--001")]
        manager = _make_manager({"col": objs})
        c = _client(manager)
        body = _authed(c, "get", "/taxii2/roots/gnat/collections/col/manifest/").json()
        entry = body["objects"][0]
        assert "id" in entry
        assert "date_added" in entry
        assert "version" in entry
        assert "media_type" in entry

    def test_manifest_pagination(self):
        objs = [_make_stix_obj(f"indicator--{i:03d}") for i in range(5)]
        manager = _make_manager({"col": objs})
        c = _client(manager)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/manifest/?limit=2")
        body = r.json()
        assert len(body["objects"]) == 2
        assert "next" in body

    def test_manifest_unknown_collection_returns_404(self):
        c = _client(_make_manager())
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/noexist/manifest/")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# 10. Single object GET
# ---------------------------------------------------------------------------


class TestSingleObject:
    def test_found_returns_bundle(self):
        obj = _make_stix_obj("indicator--abc")
        manager = _make_manager({"col": [obj]})
        c = _client(manager)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/objects/indicator--abc/")
        assert r.status_code == 200
        body = r.json()
        assert body["type"] == "bundle"
        assert len(body["objects"]) == 1
        assert body["objects"][0]["id"] == "indicator--abc"

    def test_unknown_object_returns_404(self):
        manager = _make_manager({"col": []})
        c = _client(manager)
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/col/objects/indicator--nope/")
        assert r.status_code == 404

    def test_unknown_collection_returns_404(self):
        c = _client(_make_manager())
        r = _authed(c, "get", "/taxii2/roots/gnat/collections/noexist/objects/indicator--x/")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# 11. Object versions
# ---------------------------------------------------------------------------


class TestObjectVersions:
    def test_found_returns_versions(self):
        obj = _make_stix_obj("indicator--v1")
        manager = _make_manager({"col": [obj]})
        c = _client(manager)
        r = _authed(
            c,
            "get",
            "/taxii2/roots/gnat/collections/col/objects/indicator--v1/versions/",
        )
        assert r.status_code == 200
        body = r.json()
        assert "versions" in body
        assert len(body["versions"]) == 1

    def test_unknown_object_returns_404(self):
        manager = _make_manager({"col": []})
        c = _client(manager)
        r = _authed(
            c,
            "get",
            "/taxii2/roots/gnat/collections/col/objects/indicator--missing/versions/",
        )
        assert r.status_code == 404

    def test_unknown_collection_returns_404(self):
        c = _client(_make_manager())
        r = _authed(
            c,
            "get",
            "/taxii2/roots/gnat/collections/noexist/objects/indicator--x/versions/",
        )
        assert r.status_code == 404
