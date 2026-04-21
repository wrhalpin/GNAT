# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.recordedfuture.v3

Recorded Future Connect API v3 client.

## New in v3 vs v2

- Alert endpoint moves to `/v3/alerts` with `nextPageToken` cursor
  pagination instead of offset-based paging.
- Risk evidence key is `risk.evidenceDetails` (v2: `risk.evidence`).
- Playbook Alerts exposed under `/v3/playbook-alert`.
- Fusion file access exposed under `/v3/fusion/files`.

Authentication is unchanged -- `X-RFToken` header (same as v2).

INI config::

[recordedfuture]
host        = https://api.recordedfuture.com
api_token   = <token>
api_version = v3        ; default

"""

from __future__ import annotations

from typing import Any

from gnat.connectors.recordedfuture.client import RecordedFutureClient as RecordedFutureBase


class RecordedFutureClientV3(RecordedFutureBase):
    """Recorded Future Connect API v3 client."""

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION = "v3"
    API_PREFIX = "/v3"
    COST_UNIT: int = 1

    # ------------------------------------------------------------------
    # Alert API v3  (cursor-paginated; overrides v2 offset behaviour)
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Fetch alerts via the v3 Alert API with ``nextPageToken`` pagination.

        Collects pages transparently until *limit* records are gathered
        or the API signals no further pages.

        Supports both known response envelope shapes::

            # Shape A (primary)
            {"data": {"results": [...], "nextPageToken": "..."}}

            # Shape B (alternate)
            {"data": {"alerts": [...], "pagination": {"nextPageToken": "..."}}}
        """
        params: dict[str, Any] = {"limit": min(limit, 100)}
        if filters:
            params.update(filters)

        results: list[dict[str, Any]] = []
        while True:
            resp = self.get("/v3/alerts", params=params)
            if not isinstance(resp, dict):
                break

            data = resp.get("data", {})
            # Support both "results" (primary) and "alerts" (alternate) key
            page = data.get("results") or data.get("alerts", [])
            results.extend(page)

            if len(results) >= limit:
                break

            # Support both top-level and nested pagination token paths
            token: str | None = data.get("nextPageToken") or data.get("pagination", {}).get(
                "nextPageToken"
            )
            if not token:
                break

            params = {
                "nextPageToken": token,
                "limit": min(limit - len(results), 100),
            }

        return results[:limit]

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Fetch a single alert by ID."""
        resp = self.get(f"/v3/alerts/{alert_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    # ------------------------------------------------------------------
    # Playbook Alerts  (v3 only)
    # ------------------------------------------------------------------

    _PLAYBOOK_BASE = "/v3/playbook-alert"

    def list_playbook_alerts(
        self,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Fetch Playbook Alerts with ``nextPageToken`` pagination.

        Supports both known response envelope shapes (same as :meth:`list_alerts`).
        """
        params: dict[str, Any] = {"limit": min(limit, 100)}
        if filters:
            params.update(filters)

        results: list[dict[str, Any]] = []
        while True:
            resp = self.get(self._PLAYBOOK_BASE, params=params)
            if not isinstance(resp, dict):
                break

            data = resp.get("data", {})
            page = data.get("results") or data.get("alerts", [])
            results.extend(page)

            if len(results) >= limit:
                break

            token: str | None = data.get("nextPageToken") or data.get("pagination", {}).get(
                "nextPageToken"
            )
            if not token:
                break

            params = {
                "nextPageToken": token,
                "limit": min(limit - len(results), 100),
            }

        return results[:limit]

    def get_playbook_alert(self, alert_id: str) -> dict[str, Any]:
        """Fetch a single Playbook Alert by ID."""
        resp = self.get(f"{self._PLAYBOOK_BASE}/{alert_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def update_playbook_alert(
        self,
        alert_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Update a Playbook Alert (e.g. status, priority, assignee).

        Tries PATCH first (RFC 7396 partial update); falls back to PUT on
        405 Method Not Allowed in case the instance runs an older RF API version.
        """
        url = f"{self._PLAYBOOK_BASE}/{alert_id}"
        try:
            resp = self.patch(url, json=payload)
        except Exception:  # noqa: BLE001
            resp = self.put(url, json=payload)
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_playbook_alert_categories(self) -> list[dict[str, Any]]:
        """Return available Playbook Alert category definitions."""
        resp = self.get(f"{self._PLAYBOOK_BASE}/categories")
        if not isinstance(resp, dict):
            return []
        data = resp.get("data", {})
        return data.get("results") or data.get("categories", [])

    # ------------------------------------------------------------------
    # Fusion Files  (v3 only)
    # ------------------------------------------------------------------

    _FUSION_BASE = "/v3/fusion/files"

    def list_fusion_files(
        self,
        path: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        List available Fusion files.

        Parameters
        ----------
        path : str, optional
            Directory path to filter results (passed as ``path`` query param).
        """
        params: dict[str, Any] = {}
        if path:
            params["path"] = path
        resp = self.get(self._FUSION_BASE, params=params)
        if not isinstance(resp, dict):
            return []
        data = resp.get("data", {})
        return data.get("results") or data.get("files", [])

    def get_fusion_file(self, file_path: str) -> bytes:
        """
        Download a Fusion file by path.

        Returns raw bytes — callers are responsible for parsing
        (CSV, JSON, STIX bundle, etc.).  Handles both raw-bytes responses
        and JSON-envelope responses where the content is base64 or embedded.
        """
        resp = self.get(self._FUSION_BASE, params={"path": file_path})
        if isinstance(resp, bytes):
            return resp
        if isinstance(resp, dict):
            data = resp.get("data", {})
            if isinstance(data, bytes):
                return data
            if isinstance(data, dict):
                # Some RF endpoints embed content as a string field
                content = data.get("content") or data.get("body", "")
                return content.encode() if isinstance(content, str) else b""
            return b""
        return b""

    # ------------------------------------------------------------------
    # v3 risk evidence key override
    # ------------------------------------------------------------------

    def get_risk_evidence(self, native: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Return the risk evidence list from a native RF object.

        v3 uses ``risk.evidenceDetails``; v2 uses ``risk.evidence``.
        """
        return native.get("risk", {}).get("evidenceDetails", [])
