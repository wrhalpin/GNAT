"""
gnat.connectors.sentinel.incidents
========================================
Incident management commands for the Microsoft Sentinel connector.

Sentinel incidents are the primary security investigation object.
Each incident aggregates one or more alerts, has a lifecycle (New →
Active → Closed), an owner, severity, and related entities.

Key incident fields
-------------------
  name / incidentNumber — unique identifier
  title                 — incident display title
  description           — detailed description
  severity              — 'High', 'Medium', 'Low', 'Informational'
  status                — 'New', 'Active', 'Closed'
  classification        — 'TruePositive', 'FalsePositive',
                          'BenignPositive', 'Undetermined'
  classificationReason  — reason for classification
  owner.assignedTo      — assigned analyst UPN
  createdTimeUtc        — ISO 8601 creation time
  lastModifiedTimeUtc   — ISO 8601 last modified
  firstActivityTimeUtc  — first observed activity
  lastActivityTimeUtc   — last observed activity
  labels                — list of label strings
  relatedAnalyticRuleIds — linked detection rule IDs

References
----------
- https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents
"""

from typing import Iterator
from .client import SentinelClient


_SEVERITY_MAP = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1}


class SentinelIncidentCommands:
    """Incident management operations."""

    def __init__(self, client: SentinelClient) -> None:
        self._client = client

    def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        filter_val: str | None = None,
        order_by: str = "properties/createdTimeUtc desc",
        limit: int | None = None,
    ) -> list[dict]:
        """
        List incidents with optional OData filters.

        Parameters
        ----------
        status : str | None
            'New', 'Active', or 'Closed'.
        severity : str | None
            'High', 'Medium', 'Low', or 'Informational'.
        filter_val : str | None
            OData $filter expression (appended to status/severity filters).
        order_by : str
            OData $orderby expression.
        limit : int | None
            Max incidents to return.

        Returns
        -------
        list[dict]
        """
        odata_parts: list[str] = []
        if status:
            odata_parts.append(f"properties/status eq '{status}'")
        if severity:
            odata_parts.append(f"properties/severity eq '{severity}'")
        if filter_val:
            odata_parts.append(filter_val)

        params: dict = {"$orderby": order_by}
        if odata_parts:
            params["$filter"] = " and ".join(odata_parts)

        items = []
        for item in self._client.paginate(
            "incidents", params=params,
            page_size=min(limit or self._client.config.max_results, 100),
        ):
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def iter_all_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
    ) -> Iterator[dict]:
        """Generator yielding all incidents matching filters."""
        odata_parts = []
        if status:
            odata_parts.append(f"properties/status eq '{status}'")
        if severity:
            odata_parts.append(f"properties/severity eq '{severity}'")
        params: dict = {"$orderby": "properties/createdTimeUtc asc"}
        if odata_parts:
            params["$filter"] = " and ".join(odata_parts)
        yield from self._client.paginate("incidents", params=params)

    def get_incident(self, incident_id: str) -> dict:
        """Retrieve a single incident by ID or name."""
        return self._client.get(f"incidents/{incident_id}")

    def create_incident(
        self,
        title: str,
        severity: str = "Medium",
        status: str = "New",
        description: str = "",
        labels: list[str] | None = None,
        owner_upn: str | None = None,
    ) -> dict:
        """
        Create a new incident.

        Parameters
        ----------
        title : str
        severity : str
            'High', 'Medium', 'Low', or 'Informational'.
        status : str
            'New', 'Active', or 'Closed'.
        description : str
        labels : list[str] | None
        owner_upn : str | None
            Assign to this user's UPN.

        Returns
        -------
        dict
            Created incident resource.
        """
        import uuid
        incident_id = str(uuid.uuid4())
        props: dict = {
            "title": title,
            "severity": severity,
            "status": status,
            "description": description,
        }
        if labels:
            props["labels"] = [{"labelName": l} for l in labels]
        if owner_upn:
            props["owner"] = {"assignedTo": owner_upn}
        return self._client.put(
            f"incidents/{incident_id}",
            body={"properties": props},
        )

    def update_incident(self, incident_id: str, updates: dict) -> dict:
        """
        Partially update an incident (merge patch).

        Parameters
        ----------
        incident_id : str
        updates : dict
            Properties to update under the ``properties`` envelope.

        Returns
        -------
        dict
        """
        # Fetch current etag for optimistic concurrency
        current = self._client.get(f"incidents/{incident_id}")
        etag = current.get("etag", "")
        body = {**current, "properties": {**current.get("properties", {}), **updates}}
        _headers_extra = {"If-Match": etag} if etag else {}
        # Use put for Sentinel incidents (patch not always supported)
        return self._client.put(f"incidents/{incident_id}", body=body)

    def close_incident(
        self,
        incident_id: str,
        classification: str = "TruePositive",
        classification_reason: str | None = None,
        closing_comment: str = "",
    ) -> dict:
        """
        Close an incident with a classification.

        Parameters
        ----------
        incident_id : str
        classification : str
            'TruePositive', 'FalsePositive', 'BenignPositive', 'Undetermined'.
        classification_reason : str | None
            Required for TruePositive/FalsePositive.
        closing_comment : str
        """
        updates: dict = {
            "status": "Closed",
            "classification": classification,
            "closingComment": closing_comment,
        }
        if classification_reason:
            updates["classificationReason"] = classification_reason
        return self.update_incident(incident_id, updates)

    def add_comment(self, incident_id: str, message: str) -> dict:
        """Add a comment to an incident."""
        import uuid
        comment_id = str(uuid.uuid4())
        return self._client.put(
            f"incidents/{incident_id}/comments/{comment_id}",
            body={"properties": {"message": message}},
        )

    def list_comments(self, incident_id: str) -> list[dict]:
        """List all comments on an incident."""
        return list(self._client.paginate(f"incidents/{incident_id}/comments"))

    def list_entities(self, incident_id: str) -> list[dict]:
        """List entities (IPs, hosts, users, etc.) associated with an incident."""
        result = self._client.post(f"incidents/{incident_id}/entities")
        return result.get("entities", [])

    def get_incident_count(
        self,
        status: str | None = None,
        severity: str | None = None,
    ) -> int:
        """Return total count of incidents matching filters."""
        return sum(1 for _ in self.iter_all_incidents(status=status, severity=severity))

    @staticmethod
    def normalise_incident(incident: dict) -> dict:
        """Flatten a Sentinel incident resource to GNAT normalised format."""
        props = incident.get("properties", {})
        owner = props.get("owner", {})
        sev_str = props.get("severity", "Low")
        return {
            "id": incident.get("name"),
            "number": props.get("incidentNumber"),
            "title": props.get("title"),
            "description": props.get("description", ""),
            "severity": _SEVERITY_MAP.get(sev_str, 1),
            "severity_label": sev_str.lower(),
            "status": props.get("status"),
            "classification": props.get("classification"),
            "owner": owner.get("assignedTo"),
            "created": props.get("createdTimeUtc"),
            "modified": props.get("lastModifiedTimeUtc"),
            "first_activity": props.get("firstActivityTimeUtc"),
            "last_activity": props.get("lastActivityTimeUtc"),
            "labels": [l.get("labelName", "") for l in props.get("labels", [])],
            "alert_count": props.get("additionalData", {}).get("alertsCount", 0),
            "_raw": incident,
        }
