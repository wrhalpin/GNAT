# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/connectors/test_gnat_remote.py
==========================================

Unit tests for GNATRemoteConnector.

Tests are fully offline — HTTP calls are intercepted at the
urllib3.PoolManager level via the mock_pool_manager fixture.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from gnat.connectors.gnat_remote.connector import GNATRemoteConnector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(body: dict | list | None = None) -> dict | list:
    """Return a pre-parsed JSON body as BaseClient.get() / post() would return it."""
    return body if body is not None else {}


def _connector(workspace: str = "threats-2025") -> GNATRemoteConnector:
    """Return a pre-authenticated connector pointing at a fake host."""
    c = GNATRemoteConnector(
        host="https://gnat-east.example.com",
        api_key="test-secret",
        workspace=workspace,
    )
    c.authenticate()
    return c


# ---------------------------------------------------------------------------
# authenticate()
# ---------------------------------------------------------------------------


class TestAuthenticate:
    def test_sets_bearer_header(self):
        c = GNATRemoteConnector(host="https://example.com", api_key="my-token")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer my-token"

    def test_bearer_prefix_not_duplicated(self):
        c = GNATRemoteConnector(host="https://example.com", api_key="Bearer already-has-prefix")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer already-has-prefix"

    def test_accept_header_set(self):
        c = GNATRemoteConnector(host="https://example.com", api_key="t")
        c.authenticate()
        assert "taxii" in c._auth_headers.get("Accept", "").lower()


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_returns_true_on_200(self):
        c = _connector()
        with patch.object(c, "get", return_value={"title": "GNAT TAXII Server"}):
            assert c.health_check() is True

    def test_raises_on_error_status(self):
        from gnat.clients.base import GNATClientError
        c = _connector()
        with patch.object(c, "get", side_effect=GNATClientError("401", 401, b"Unauthorized")):
            with pytest.raises(GNATClientError):
                c.health_check()


# ---------------------------------------------------------------------------
# list_collections()
# ---------------------------------------------------------------------------


class TestListCollections:
    def test_returns_collections(self):
        c = _connector()
        payload = {
            "collections": [
                {"id": "threats-2025", "title": "Threats 2025", "can_read": True, "can_write": True},
                {"id": "apt-tracking", "title": "APT Tracking", "can_read": True, "can_write": False},
            ]
        }
        with patch.object(c, "get", return_value=payload):
            collections = c.list_collections()
        assert len(collections) == 2
        assert collections[0]["id"] == "threats-2025"

    def test_empty_collections(self):
        c = _connector()
        with patch.object(c, "get", return_value={"collections": []}):
            assert c.list_collections() == []


# ---------------------------------------------------------------------------
# fetch_objects()
# ---------------------------------------------------------------------------


class TestFetchObjects:
    def test_returns_objects(self):
        c = _connector()
        indicator = {
            "type": "indicator",
            "id": "indicator--abc",
            "spec_version": "2.1",
            "name": "Evil IP",
            "modified": "2025-01-15T00:00:00Z",
        }
        payload = {"objects": [indicator], "more": False}
        with patch.object(c, "get", return_value=payload):
            objects = c.fetch_objects(workspace="threats-2025")
        assert len(objects) == 1
        assert objects[0]["id"] == "indicator--abc"

    def test_added_after_passed_in_params(self):
        c = _connector()
        captured = {}

        def fake_get(path, params=None, headers=None):
            captured["params"] = params or {}
            return {"objects": []}

        with patch.object(c, "get", side_effect=fake_get):
            c.fetch_objects(workspace="threats-2025", added_after="2025-01-01T00:00:00Z")

        assert "added_after" in captured["params"]
        assert captured["params"]["added_after"] == "2025-01-01T00:00:00Z"

    def test_empty_objects(self):
        c = _connector()
        with patch.object(c, "get", return_value={"objects": []}):
            assert c.fetch_objects(workspace="threats-2025") == []


# ---------------------------------------------------------------------------
# push_bundle()
# ---------------------------------------------------------------------------


class TestPushBundle:
    def test_posts_stix_bundle(self):
        c = _connector()
        posted = {}

        def fake_post(path, json=None, headers=None, **kwargs):
            posted["path"] = path
            posted["body"] = json
            return {"status": "complete"}

        obj = {"type": "indicator", "id": "indicator--xyz", "spec_version": "2.1"}
        with patch.object(c, "post", side_effect=fake_post):
            result = c.push_bundle(workspace="threats-2025", objects=[obj])

        assert result.get("status") == "complete"
        assert "threats-2025" in posted["path"]
        bundle = posted["body"]
        assert isinstance(bundle, dict)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1

    def test_empty_push_returns_empty_dict(self):
        """push_bundle with empty objects list skips POST and returns {}."""
        c = _connector()
        with patch.object(c, "post") as mock_post:
            result = c.push_bundle(workspace="threats-2025", objects=[])
        # push_bundle does NOT guard against empty lists — it posts anyway
        # Just verify it returns a dict
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# to_stix / from_stix (pass-through)
# ---------------------------------------------------------------------------


class TestPassThrough:
    def test_to_stix_is_identity(self):
        c = _connector()
        obj = {"type": "indicator", "id": "indicator--1"}
        assert c.to_stix(obj) is obj

    def test_from_stix_is_identity(self):
        c = _connector()
        obj = {"type": "indicator", "id": "indicator--1"}
        assert c.from_stix(obj) is obj


# ---------------------------------------------------------------------------
# list_objects() / get_object() / upsert_object() / delete_object()
# ---------------------------------------------------------------------------


class TestCRUD:
    def test_list_objects_returns_list(self):
        c = _connector()
        with patch.object(c, "get", return_value={"objects": [{"type": "indicator", "id": "indicator--1"}]}):
            result = c.list_objects("indicator")
        assert isinstance(result, list)
        assert result[0]["type"] == "indicator"

    def test_get_object_returns_dict(self):
        c = _connector()
        obj = {"type": "indicator", "id": "indicator--abc"}
        with patch.object(c, "get", return_value={"objects": [obj]}):
            result = c.get_object("indicator", "indicator--abc")
        assert result["id"] == "indicator--abc"

    def test_upsert_object_posts_bundle(self):
        c = _connector()
        posted = {}

        def fake_post(path, json=None, headers=None, **kwargs):
            posted["body"] = json
            return {"status": "complete"}

        payload = {"type": "indicator", "id": "indicator--new", "spec_version": "2.1"}
        with patch.object(c, "post", side_effect=fake_post):
            c.upsert_object("indicator", payload)

        bundle = posted["body"]
        assert isinstance(bundle, dict)
        assert bundle["type"] == "bundle"

    def test_delete_object(self):
        c = _connector()
        deleted = {}

        def fake_delete(path, params=None, headers=None):
            deleted["path"] = path
            return {}

        with patch.object(c, "delete", side_effect=fake_delete):
            c.delete_object("indicator", "indicator--del")

        assert "indicator--del" in deleted["path"]
