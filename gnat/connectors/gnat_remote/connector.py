# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.gnat_remote.connector
=======================================

Connector for a remote GNAT instance accessed via its TAXII 2.1 server.

Authentication
--------------
Bearer token issued by the remote GNAT instance::

    [federation.peer.acme-east]
    taxii_url = https://gnat-east.acme.com/taxii2/
    api_key   = Bearer your-remote-api-key

STIX Type Mapping
-----------------
All STIX types are supported — objects are passed through without
translation since both sides speak STIX 2.1 natively.

Key Endpoints Used
------------------
* ``GET  /taxii2/``                                    — discovery (unauthenticated)
* ``GET  /taxii2/roots/gnat/collections/``             — list workspaces
* ``GET  /taxii2/roots/gnat/collections/{ws}/objects/`` — fetch objects
* ``POST /taxii2/roots/gnat/collections/{ws}/objects/`` — push bundle
* ``DELETE /taxii2/roots/gnat/collections/{ws}/objects/{id}/`` — delete object
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION

_API_ROOT = "/taxii2/roots/gnat"
_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
_STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class GNATRemoteConnector(BaseClient, ConnectorMixin):
    """
    TAXII 2.1 client for a remote GNAT instance.

    Used by the federation layer to pull objects from and push objects to
    peer GNAT deployments.  Both sides speak STIX 2.1 natively, so
    ``to_stix`` / ``from_stix`` are pass-throughs.

    Parameters
    ----------
    host : str
        Base URL of the remote GNAT instance (e.g. ``"https://gnat.acme.com"``).
    api_key : str
        Bearer token issued by the remote instance.  Include ``"Bearer "``
        prefix if desired — normalised automatically.
    workspace : str, optional
        Default workspace (TAXII collection) for single-workspace operations.
        Required for ``get_object``, ``upsert_object``, ``delete_object``.
    """

    stix_type_map: dict[str, str] = {}  # All STIX types supported natively

    def __init__(
        self,
        host: str = "",
        api_key: str = "",
        workspace: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize GNATRemoteConnector."""
        super().__init__(host=host, **kwargs)
        raw = api_key.strip()
        self._api_key = raw if raw.startswith("Bearer ") else f"Bearer {raw}" if raw else ""
        self._workspace = workspace

    # ── Authentication ────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Bearer token and TAXII Accept header."""
        self._auth_headers["Authorization"] = self._api_key
        self._auth_headers["Accept"] = _TAXII_MEDIA_TYPE

    # ── ConnectorMixin ────────────────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Verify connectivity via the unauthenticated TAXII discovery endpoint.

        Returns
        -------
        bool
            ``True`` if the remote server responds successfully.
        """
        self.get("/taxii2/", headers={"Accept": _TAXII_MEDIA_TYPE})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single STIX object from the default workspace.

        Parameters
        ----------
        stix_type : str
            STIX type (used only for routing; remote filters by id).
        object_id : str
            Full STIX ID (``"<type>--<uuid>"``).

        Returns
        -------
        dict
            The STIX object dict.
        """
        ws = self._require_workspace()
        bundle = self.get(
            f"{_API_ROOT}/collections/{ws}/objects/{object_id}/",
            headers={"Accept": _TAXII_MEDIA_TYPE},
        )
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        if not objects:
            raise GNATClientError(f"Object {object_id!r} not found in workspace {ws!r}", status=404)
        return objects[0]

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List STIX objects from a workspace with optional filters.

        Parameters
        ----------
        stix_type : str
            Filter by this STIX type (passed as ``match[type]``).
        filters : dict, optional
            Supported keys:

            * ``workspace`` — override default workspace
            * ``added_after`` — ISO 8601 timestamp for incremental pull
            * ``match_id`` — exact STIX ID filter
            * ``next_page`` — TAXII pagination cursor
        page_size : int
            Maximum objects per call (default 100).

        Returns
        -------
        list[dict]
            List of STIX object dicts.
        """
        filters = dict(filters or {})
        ws = filters.pop("workspace", None) or self._require_workspace()
        params: dict[str, Any] = {"limit": min(page_size, 100)}
        if stix_type:
            params["match[type]"] = stix_type
        if filters.get("added_after"):
            params["added_after"] = filters["added_after"]
        if filters.get("match_id"):
            params["match[id]"] = filters["match_id"]
        if filters.get("next_page"):
            params["next"] = filters["next_page"]

        result = self.get(
            f"{_API_ROOT}/collections/{ws}/objects/",
            params=params,
            headers={"Accept": _TAXII_MEDIA_TYPE},
        )
        if isinstance(result, dict):
            return result.get("objects", [])
        return []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Push a single STIX object (or a pre-built bundle) to a remote workspace.

        Parameters
        ----------
        stix_type : str
            STIX type of the object (used only when ``payload`` is a plain object).
        payload : dict
            Either a STIX object dict or a full ``{"type": "bundle", ...}`` dict.
            ``workspace`` key (if present) overrides the default workspace.

        Returns
        -------
        dict
            TAXII status record returned by the remote server.
        """
        ws = payload.pop("workspace", None) or self._require_workspace()

        if payload.get("type") == "bundle":
            bundle = payload
        else:
            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": CURRENT_SPEC_VERSION,
                "objects": [payload],
            }

        resp = self.post(
            f"{_API_ROOT}/collections/{ws}/objects/",
            json=bundle,
            headers={
                "Accept": _TAXII_MEDIA_TYPE,
                "Content-Type": _STIX_MEDIA_TYPE,
            },
        )
        return resp if isinstance(resp, dict) else {"status": "complete"}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """
        Delete a STIX object from the default workspace.

        Parameters
        ----------
        stix_type : str
            Ignored (TAXII routes by ID).
        object_id : str
            Full STIX ID to delete.
        """
        ws = self._require_workspace()
        self.delete(f"{_API_ROOT}/collections/{ws}/objects/{object_id}/")

    # ── Remote-specific helpers ───────────────────────────────────────────

    def list_collections(self) -> list[dict[str, Any]]:
        """
        List all TAXII collections (workspaces) on the remote instance.

        Returns
        -------
        list[dict]
            List of collection metadata dicts with at least ``"id"`` and ``"title"``.
        """
        result = self.get(
            f"{_API_ROOT}/collections/",
            headers={"Accept": _TAXII_MEDIA_TYPE},
        )
        if isinstance(result, dict):
            return result.get("collections", [])
        return []

    def push_bundle(self, workspace: str, objects: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Push a list of STIX objects as a bundle to a named workspace.

        Parameters
        ----------
        workspace : str
            Target collection / workspace name.
        objects : list[dict]
            STIX 2.1 object dicts.

        Returns
        -------
        dict
            TAXII status record.
        """
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": objects,
        }
        resp = self.post(
            f"{_API_ROOT}/collections/{workspace}/objects/",
            json=bundle,
            headers={
                "Accept": _TAXII_MEDIA_TYPE,
                "Content-Type": _STIX_MEDIA_TYPE,
            },
        )
        return resp if isinstance(resp, dict) else {"status": "complete"}

    def fetch_objects(
        self,
        workspace: str,
        added_after: str | None = None,
        stix_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Convenience method: fetch objects from a named workspace with filters.

        Parameters
        ----------
        workspace : str
            Collection / workspace name.
        added_after : str, optional
            ISO 8601 timestamp; only objects added after this are returned.
        stix_type : str, optional
            Filter by STIX type.
        limit : int
            Max objects to return (cap 100).

        Returns
        -------
        list[dict]
            STIX 2.1 object dicts.
        """
        params: dict[str, Any] = {"limit": min(limit, 100)}
        if added_after:
            params["added_after"] = added_after
        if stix_type:
            params["match[type]"] = stix_type
        result = self.get(
            f"{_API_ROOT}/collections/{workspace}/objects/",
            params=params,
            headers={"Accept": _TAXII_MEDIA_TYPE},
        )
        if isinstance(result, dict):
            return result.get("objects", [])
        return []

    # ── STIX translation (pass-through) ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Pass-through — remote objects are already STIX 2.1."""
        return native

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Pass-through — GNAT speaks STIX natively."""
        return stix_dict

    # ── Internal helpers ──────────────────────────────────────────────────

    def _require_workspace(self) -> str:
        if not self._workspace:
            raise GNATClientError(
                "No workspace configured. Pass workspace= to GNATRemoteConnector "
                "or include 'workspace' in the filters/payload dict."
            )
        return self._workspace

    # ── urllib3 HTTP overrides to handle TAXII headers ───────────────────

    def post(  # type: ignore[override]
        self,
        path: str,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
    ) -> Any:
        """Post with optional extra headers merged in."""
        return super().post(path, json=json, data=data, params=params, headers=headers, files=files)

    def get(  # type: ignore[override]
        self,
        path: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Get with optional extra headers merged in."""
        return super().get(path, params=params, headers=headers)

    def delete(  # type: ignore[override]
        self,
        path: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Delete with optional extra headers merged in."""
        return super().delete(path, params=params, headers=headers)
