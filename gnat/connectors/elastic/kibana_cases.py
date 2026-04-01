"""
gnat.connectors.elastic.kibana_cases

Kibana Cases API commands.

Cases provide incident management within Kibana Security,
allowing analysts to track investigation workflows, attach
alerts, add comments, and manage case status.

## Case fields

id          -- Kibana internal case UUID
title       -- case title
description -- initial description
status      -- 'open' | 'in-progress' | 'closed'
severity    -- 'low' | 'medium' | 'high' | 'critical'
tags        -- list of tag strings
assignees   -- list of {uid: <kibana_user_id>}
connector   -- ITSM connector config (Jira, ServiceNow, etc.)
created_at  -- ISO 8601 creation time
updated_at  -- ISO 8601 last update time
comments    -- attached alert/comment list (separate endpoint)

## References

- https://www.elastic.co/guide/en/kibana/current/cases-api.html
"""

from .client import ElasticClient

_CASES_BASE = "api/cases"


class KibanaCasesCommands:
    """
    Kibana Cases (incident management) operations.

    Parameters
    ----------
    client : ElasticClient
        Authenticated HTTP client.
    """

    def __init__(self, client: ElasticClient) -> None:
        self._client = client

    # ── Case CRUD ──────────────────────────────────────────────────────────

    def list_cases(
        self,
        status: str | None = None,
        severity: str | None = None,
        tags: list[str] | None = None,
        page: int = 1,
        per_page: int = 20,
        sort_field: str = "created_at",
        sort_order: str = "desc",
    ) -> dict:
        """
        List cases with optional filters.

        Parameters
        ----------
        status : str | None
            'open', 'in-progress', or 'closed'.
        severity : str | None
            'low', 'medium', 'high', or 'critical'.
        tags : list[str] | None
            Filter by tags (AND logic).
        page : int
            Page number (1-based).
        per_page : int
            Cases per page.
        sort_field : str
            Sort by: 'created_at', 'updated_at', 'title', 'status'.
        sort_order : str
            'asc' or 'desc'.

        Returns
        -------
        dict
            ``{"cases": [...], "total": N}``
        """
        params: dict = {
            "page": page,
            "perPage": per_page,
            "sortField": sort_field,
            "sortOrder": sort_order,
        }
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        if tags:
            params["tags"] = tags

        return self._client.kibana_get(_CASES_BASE, params=params)

    def get_case(self, case_id: str) -> dict:
        """
        Retrieve a case by ID.

        Parameters
        ----------
        case_id : str
            Kibana case UUID.

        Returns
        -------
        dict
            Case record.
        """
        return self._client.kibana_get(f"{_CASES_BASE}/{case_id}")

    def create_case(
        self,
        title: str,
        description: str,
        severity: str = "low",
        tags: list[str] | None = None,
        assignees: list[dict] | None = None,
        connector: dict | None = None,
    ) -> dict:
        """
        Create a new case.

        Parameters
        ----------
        title : str
            Case title.
        description : str
            Initial case description.
        severity : str
            'low', 'medium', 'high', or 'critical'.
        tags : list[str] | None
            Tags to attach.
        assignees : list[dict] | None
            List of ``{"uid": "<kibana_user_id>"}`` dicts.
        connector : dict | None
            ITSM connector config. Use the no-connector default if None.

        Returns
        -------
        dict
            Created case with Kibana-assigned ID.
        """
        body: dict = {
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or [],
            "assignees": assignees or [],
            "connector": connector
            or {
                "id": "none",
                "name": "none",
                "type": ".none",
                "fields": None,
            },
            "settings": {"syncAlerts": True},
        }
        return self._client.kibana_post(_CASES_BASE, body=body)

    def update_case(
        self,
        case_id: str,
        version: str,
        updates: dict,
    ) -> dict:
        """
        Update case fields (requires current version for optimistic locking).

        Parameters
        ----------
        case_id : str
            Kibana case UUID.
        version : str
            Current case version (from get_case response).
        updates : dict
            Fields to update, e.g. ``{"status": "closed", "severity": "high"}``.

        Returns
        -------
        dict
            Updated case.
        """
        body = {"cases": [{**updates, "id": case_id, "version": version}]}
        return self._client.kibana_patch(_CASES_BASE, body=body)

    def close_case(self, case_id: str, version: str) -> dict:
        """Close a case."""
        return self.update_case(case_id, version, {"status": "closed"})

    def delete_cases(self, case_ids: list[str]) -> dict:
        """
        Delete one or more cases.

        Parameters
        ----------
        case_ids : list[str]
            List of case UUIDs to delete.

        Returns
        -------
        dict
            Deletion response.
        """
        params = {"ids": case_ids}
        return self._client.kibana_delete(_CASES_BASE, params=params)

    # ── Comments and alerts ────────────────────────────────────────────────

    def list_comments(self, case_id: str) -> list[dict]:
        """
        List all comments and attached alerts for a case.

        Parameters
        ----------
        case_id : str
            Kibana case UUID.

        Returns
        -------
        list[dict]
            Comment records.
        """
        response = self._client.kibana_get(f"{_CASES_BASE}/{case_id}/comments")
        return response.get("comments", [])

    def add_comment(self, case_id: str, comment: str) -> dict:
        """
        Add a text comment to a case.

        Parameters
        ----------
        case_id : str
            Case UUID.
        comment : str
            Comment text (supports Markdown).

        Returns
        -------
        dict
            Created comment.
        """
        body = {"comment": comment, "type": "user"}
        return self._client.kibana_post(f"{_CASES_BASE}/{case_id}/comments", body=body)

    def attach_alert_to_case(
        self,
        case_id: str,
        alert_id: str,
        alert_index: str,
        rule_id: str,
        rule_name: str,
    ) -> dict:
        """
        Attach a Kibana security alert to a case.

        Parameters
        ----------
        case_id : str
            Case UUID.
        alert_id : str
            Alert _id from .alerts-security.* index.
        alert_index : str
            Alert index name (e.g. '.alerts-security.default-000001').
        rule_id : str
            Detection rule_id that generated the alert.
        rule_name : str
            Detection rule display name.

        Returns
        -------
        dict
            Comment/attachment record.
        """
        body = {
            "alertId": alert_id,
            "index": alert_index,
            "rule": {"id": rule_id, "name": rule_name},
            "type": "alert",
        }
        return self._client.kibana_post(f"{_CASES_BASE}/{case_id}/comments", body=body)

    # ── Statistics ─────────────────────────────────────────────────────────

    def get_case_stats(self) -> dict:
        """
        Return overall case statistics (counts by status).

        Returns
        -------
        dict
            ``{"open": N, "in-progress": N, "closed": N}``
        """
        response = self._client.kibana_get(f"{_CASES_BASE}/status")
        return response
