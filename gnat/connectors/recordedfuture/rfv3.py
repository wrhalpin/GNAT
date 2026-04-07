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

    API_VERSION = "v3"
    API_PREFIX = "/v3"

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

        Response envelope (TODO: verify against RF v3 docs)::

            {
                "data": {
                    "results":       [ { ...alert... }, ... ],
                    "nextPageToken": "<opaque-string>|null"
                }
            }

        TODO: confirm ``data.results`` key name -- may be ``"alerts"``.
        TODO: confirm ``data.nextPageToken`` path -- may be top-level or
              under ``data.pagination.nextPageToken``.
        """
        params: dict[str, Any] = {"limit": min(limit, 100)}
        if filters:
            params.update(filters)

        results: list[dict[str, Any]] = []
        while True:
            resp = self.get("/v3/alerts", params=params)
            if not isinstance(resp, dict):
                break

            page = resp.get("data", {}).get("results", [])
            results.extend(page)

            if len(results) >= limit:
                break

            # TODO: verify exact token key path (see docstring above)
            token: str | None = resp.get("data", {}).get("nextPageToken")
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

        TODO: confirm endpoint path and response envelope against RF v3
        docs -- assumed identical shape to Alert API v3.
        """
        params: dict[str, Any] = {"limit": min(limit, 100)}
        if filters:
            params.update(filters)

        results: list[dict[str, Any]] = []
        while True:
            resp = self.get(self._PLAYBOOK_BASE, params=params)
            if not isinstance(resp, dict):
                break

            page = resp.get("data", {}).get("results", [])
            results.extend(page)

            if len(results) >= limit:
                break

            token: str | None = resp.get("data", {}).get("nextPageToken")
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

        TODO: confirm HTTP verb (PATCH vs PUT) against RF v3 docs.
        """
        resp = self.patch(f"{self._PLAYBOOK_BASE}/{alert_id}", json=payload)
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_playbook_alert_categories(self) -> list[dict[str, Any]]:
        """Return available Playbook Alert category definitions."""
        resp = self.get(f"{self._PLAYBOOK_BASE}/categories")
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

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

        Args:
            path: Optional directory path to filter results.

        TODO: confirm query param name for path filtering against RF v3
        docs.
        """
        params: dict[str, Any] = {}
        if path:
            params["path"] = path
        resp = self.get(self._FUSION_BASE, params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def get_fusion_file(self, file_path: str) -> bytes:
        """
        Download a Fusion file by path.

        Returns raw bytes -- callers are responsible for parsing
        (CSV, JSON, STIX bundle, etc.).

        TODO: confirm whether this endpoint returns JSON envelope or raw
        bytes directly.
        """
        resp = self.get(self._FUSION_BASE, params={"path": file_path})
        if isinstance(resp, bytes):
            return resp
        if isinstance(resp, dict):
            return resp.get("data", b"")
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
