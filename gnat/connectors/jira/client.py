# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.jira.client
==============================
Jira Cloud / Server REST API v3 connector.

Authentication
--------------
API token (Basic auth with email + token) — recommended for Jira Cloud::

    [jira]
    host      = https://yourorg.atlassian.net
    email     = user@example.com
    api_token = <api-token>
    auth_type = api_token

OAuth2 bearer token (Jira Data Center / Server)::

    [jira]
    host      = https://jira.corp.example.com
    api_key   = <bearer-token>
    auth_type = api_key

STIX Type Mapping
-----------------
+-------------------+-------------------------------------+
| STIX Type         | Jira Resource                       |
+===================+=====================================+
| note              | issue (comment / observation)       |
+-------------------+-------------------------------------+
| course-of-action  | issue (remediation / action item)   |
+-------------------+-------------------------------------+
| indicator         | issue (threat indicator reference)  |
+-------------------+-------------------------------------+

Incident Linking
----------------
Use :meth:`annotate_ticket` to attach a STIX-derived comment to an
existing Jira issue::

    client.annotate_ticket("PROJ-123", stix_obj)

This calls ``POST /rest/api/3/issue/{key}/comment`` with an Atlassian
Document Format (ADF) body derived from *stix_obj*.
"""

from __future__ import annotations

import base64
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

# Jira REST API v3 base path
_API_V3 = "/rest/api/3"


class JiraClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Jira REST API v3 (Cloud and Server/Data Center).

    Parameters
    ----------
    host : str
        Jira base URL, e.g. ``"https://yourorg.atlassian.net"``.
    email : str
        Email address for API-token Basic auth (Jira Cloud).
    api_token : str
        API token (combined with *email* for Basic auth).
    api_key : str
        Bearer token (alternative to email+api_token for Server/DC).
    verify_ssl : bool
        TLS certificate verification.  Default ``True``.
    timeout : float
        Request timeout in seconds.  Default ``30``.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v3"
    API_PREFIX: str = "/rest/api"

    stix_type_map: dict[str, str] = {
        "note": "issue",
        "course-of-action": "issue",
        "indicator": "issue",
    }

    def __init__(
        self,
        host: str = "",
        email: str = "",
        api_token: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize JiraClient."""
        super().__init__(host=host, **kwargs)
        self._email = email
        self._api_token = api_token
        self._api_key = api_key

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Inject auth headers.

        Uses Basic auth (email + API token) when *email* and *api_token*
        are supplied; falls back to Bearer token when only *api_key* is set.
        """
        if self._email and self._api_token:
            creds = base64.b64encode(f"{self._email}:{self._api_token}".encode()).decode()
            self._auth_headers["Authorization"] = f"Basic {creds}"
        elif self._api_key:
            self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """
        Verify connectivity by calling the Jira server-info endpoint.

        Returns
        -------
        bool
            ``True`` if the instance responds with HTTP 2xx.

        Raises
        ------
        GNATClientError
            On connection failure or non-2xx response.
        """
        try:
            self.get(f"{_API_V3}/serverInfo")
            return True
        except Exception as exc:
            raise GNATClientError(f"Jira health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs: Any) -> dict[str, Any]:
        """
        Fetch a single Jira issue by key or numeric ID.

        Parameters
        ----------
        stix_type : str
            STIX type (``"note"``, ``"course-of-action"``, ``"indicator"``).
        object_id : str
            Jira issue key (``"PROJ-123"``) or issue ID.
        """
        resp = self.get(f"{_API_V3}/issue/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str = "note",
        jql: str = "",
        limit: int = 50,
        start_at: int = 0,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        Search Jira issues via JQL.

        Parameters
        ----------
        stix_type : str
            STIX type filter (currently informational — all issues returned).
        jql : str
            Jira Query Language expression, e.g.
            ``'project = SEC AND labels = "threat-intel"'``.
        limit : int
            Maximum results.  Default 50.
        start_at : int
            Pagination offset.  Default 0.
        """
        payload = {
            "jql": jql or "order by created DESC",
            "maxResults": limit,
            "startAt": start_at,
            "fields": [
                "summary",
                "description",
                "status",
                "assignee",
                "priority",
                "labels",
                "created",
                "updated",
                "issuetype",
            ],
        }
        resp = self.post(f"{_API_V3}/issue/search", json=payload)
        return resp.get("issues", []) if isinstance(resp, dict) else []

    def upsert_object(
        self,
        stix_type: str,
        payload: dict[str, Any],
        issue_key: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Create or update a Jira issue from a STIX object or raw payload.

        Parameters
        ----------
        stix_type : str
            STIX type — drives the Jira issue type selection.
        payload : dict
            STIX SDO or pre-built Jira fields dict.
        issue_key : str, optional
            If provided, updates the existing issue (``PUT``);
            otherwise creates a new issue (``POST``).
        """
        jira_payload = self._stix_to_jira(stix_type, payload)
        if issue_key:
            self.put(f"{_API_V3}/issue/{issue_key}", json=jira_payload)
            # Jira PUT /issue returns 204 No Content; return the key
            return {"key": issue_key}
        resp = self.post(f"{_API_V3}/issue", json=jira_payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str, **kwargs: Any) -> None:
        """Delete a Jira issue by key or ID."""
        self.delete(f"{_API_V3}/issue/{object_id}")

    def to_stix(self, native_object: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a Jira issue dict to STIX 2.1 ``note`` or ``course-of-action``.

        Parameters
        ----------
        native_object : dict
            Jira issue dict (the ``fields`` sub-dict is handled automatically).
        """
        issue_id = native_object.get("id", "")
        key = native_object.get("key", issue_id)
        fields = native_object.get("fields", native_object)
        summary = fields.get("summary", "")
        desc = self._adf_to_text(fields.get("description") or {})
        created = fields.get("created", "")
        updated = fields.get("updated", created)
        issuetype = (fields.get("issuetype") or {}).get("name", "").lower()

        stix_type = "course-of-action" if "action" in issuetype else "note"
        return {
            "type": stix_type,
            "id": f"{stix_type}--{issue_id}",
            "created": created,
            "modified": updated,
            "name": summary,
            "content": desc,
            "x_jira_key": key,
            "x_jira_status": (fields.get("status") or {}).get("name", ""),
            "x_jira_priority": (fields.get("priority") or {}).get("name", ""),
            "x_jira_labels": fields.get("labels", []),
            "x_jira_assignee": (fields.get("assignee") or {}).get("displayName", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> str:
        """
        Convert a STIX SDO to a Jira JQL query string.

        Builds a JQL expression that searches for issues referencing the
        STIX object's name, description, or STIX ID in summary / description.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 SDO.

        Returns
        -------
        str
            JQL query string.
        """
        name = stix_dict.get("name", "")
        stix_id = stix_dict.get("id", "")
        parts = []
        if name:
            parts.append(f'summary ~ "{name}"')
        if stix_id:
            parts.append(f'text ~ "{stix_id}"')
        return " OR ".join(parts) if parts else "order by created DESC"

    # ── Extra helpers ─────────────────────────────────────────────────────

    def annotate_ticket(
        self,
        issue_key: str,
        stix_obj: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Attach a STIX-derived comment to an existing Jira issue.

        Posts a structured comment in Atlassian Document Format (ADF)
        containing the STIX object type, ID, name, and description.

        Parameters
        ----------
        issue_key : str
            Jira issue key, e.g. ``"PROJ-123"``.
        stix_obj : dict
            STIX 2.1 SDO.

        Returns
        -------
        dict
            Raw Jira API response (the created comment resource).

        Raises
        ------
        GNATClientError
            If the comment POST fails.
        """
        stix_type = stix_obj.get("type", "unknown")
        stix_id = stix_obj.get("id", "")
        name = stix_obj.get("name", stix_obj.get("description", stix_id))
        desc = stix_obj.get("description", "")

        body = self._build_adf_comment(stix_type, stix_id, name, desc)
        resp = self.post(f"{_API_V3}/issue/{issue_key}/comment", json={"body": body})
        return resp if isinstance(resp, dict) else {}

    def search_by_label(self, label: str, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return issues tagged with a specific Jira label.

        Parameters
        ----------
        label : str
            Jira label to search for (e.g. ``"threat-intel"``).
        limit : int
            Max results.  Default 50.
        """
        return self.list_objects(jql=f'labels = "{label}" ORDER BY created DESC', limit=limit)

    # ── Private helpers ───────────────────────────────────────────────────

    def _stix_to_jira(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Build a Jira create/update fields payload from a STIX SDO."""
        name = payload.get("name", payload.get("id", ""))
        desc = payload.get("description", payload.get("content", ""))
        pattern = payload.get("pattern", "")

        issue_type = {
            "note": "Task",
            "course-of-action": "Task",
            "indicator": "Task",
        }.get(stix_type, "Task")

        body_text = desc or (f"Pattern: {pattern}" if pattern else "")
        return {
            "fields": {
                "summary": name[:255] if name else f"GNAT {stix_type}",
                "issuetype": {"name": issue_type},
                "description": self._build_adf_paragraph(body_text),
                "labels": ["gnat", "threat-intelligence", stix_type],
            }
        }

    @staticmethod
    def _build_adf_paragraph(text: str) -> dict[str, Any]:
        """Wrap plain text in minimal Atlassian Document Format (ADF)."""
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": text or " "}],
                }
            ],
        }

    @staticmethod
    def _build_adf_comment(stix_type: str, stix_id: str, name: str, desc: str) -> dict[str, Any]:
        """Build a structured ADF comment block for a STIX annotation."""
        lines = [
            "[GNAT] Linked STIX object",
            f"Type: {stix_type}",
            f"ID: {stix_id}",
            f"Name/Value: {name}",
        ]
        if desc:
            lines.append(f"Description: {desc}")

        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": line}],
                }
                for line in lines
            ],
        }

    @staticmethod
    def _adf_to_text(adf: dict[str, Any]) -> str:
        """Extract plain text from an ADF document (best-effort)."""
        if not isinstance(adf, dict):
            return str(adf) if adf else ""
        texts = []
        for block in adf.get("content", []):
            for inline in block.get("content", []):
                if inline.get("type") == "text":
                    texts.append(inline.get("text", ""))
        return " ".join(texts)
