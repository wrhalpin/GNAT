"""
gnat.connectors.misp.events
=================================
Event management commands for the MISP connector.

MISP events are the primary container for threat intelligence.
Each event aggregates attributes (IOCs), tags, galaxies, and metadata.
Events map roughly to STIX 2.1 report SDOs.

Key event fields
----------------
  id            — integer event ID
  uuid          — UUID (stable across MISP instances)
  info          — event title/description
  date          — event date (YYYY-MM-DD)
  threat_level_id — 1=High, 2=Medium, 3=Low, 4=Undefined
  analysis      — 0=Initial, 1=Ongoing, 2=Completed
  distribution  — 0=Org, 1=Community, 2=Connected, 3=All
  published     — bool
  org_id        — creating organisation ID
  orgc_id       — creating community org ID
  attribute_count — number of attributes
  Attribute     — list of attribute dicts (when fetched with attributes)
  Tag           — list of tag dicts
  Galaxy        — list of galaxy cluster dicts

Threat level mapping → GNAT severity
-----------------------------------------
  1 (High)       → 3
  2 (Medium)     → 2
  3 (Low)        → 1
  4 (Undefined)  → 0

References
----------
- https://www.misp-project.org/openapi/#tag/Events
"""

from collections.abc import Iterator
from datetime import datetime, timezone

from .client import MISPClient
from .exceptions import MISPNotFoundError

_THREAT_TO_SEVERITY = {1: 3, 2: 2, 3: 1, 4: 0}
_SEVERITY_LABELS = {3: "high", 2: "medium", 1: "low", 0: "unknown"}


class MISPEventCommands:
    """MISP Event management operations."""

    def __init__(self, client: MISPClient) -> None:
        self._client = client

    # ── List / search ──────────────────────────────────────────────────────

    def list_events(
        self,
        limit: int | None = None,
        page: int = 1,
        published: bool | None = None,
        threat_level_id: int | None = None,
        org: str | None = None,
        tags: list[str] | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        with_attributes: bool = False,
    ) -> list[dict]:
        """
        List MISP events with optional filters.

        Parameters
        ----------
        limit : int | None
            Max events to return. Defaults to config.max_results.
        page : int
            Page number (1-based).
        published : bool | None
            Filter by published status.
        threat_level_id : int | None
            1=High, 2=Medium, 3=Low, 4=Undefined.
        org : str | None
            Filter by organisation name.
        tags : list[str] | None
            Filter by tag names (AND logic).
        date_from : str | None
            Earliest event date (YYYY-MM-DD).
        date_to : str | None
            Latest event date (YYYY-MM-DD).
        with_attributes : bool
            Include attributes in response.

        Returns
        -------
        list[dict]
            Event dicts (unwrapped from response envelope).
        """
        body: dict = {
            "returnFormat": "json",
            "limit": limit or self._client.config.max_results,
            "page": page,
        }
        if published is not None:
            body["published"] = 1 if published else 0
        if threat_level_id is not None:
            body["threat_level_id"] = threat_level_id
        if org:
            body["org"] = org
        if tags:
            body["tags"] = tags
        if date_from:
            body["date_from"] = date_from
        if date_to:
            body["date_to"] = date_to
        if with_attributes:
            body["includeAttachments"] = True

        response = self._client.post_json("events/restSearch", body=body)
        return self._unwrap_events(response)

    def iter_all_events(
        self,
        published: bool | None = None,
        threat_level_id: int | None = None,
        tags: list[str] | None = None,
        date_from: str | None = None,
    ) -> Iterator[dict]:
        """
        Generator yielding all events, paginating automatically.

        Parameters
        ----------
        published : bool | None
        threat_level_id : int | None
        tags : list[str] | None
        date_from : str | None

        Yields
        ------
        dict
            Event dicts.
        """
        base_body: dict = {"returnFormat": "json"}
        if published is not None:
            base_body["published"] = 1 if published else 0
        if threat_level_id is not None:
            base_body["threat_level_id"] = threat_level_id
        if tags:
            base_body["tags"] = tags
        if date_from:
            base_body["date_from"] = date_from

        yield from self._client.paginate(
            "events/restSearch", body=base_body, response_key="Event"
        )

    def get_event(self, event_id: int | str) -> dict:
        """
        Retrieve a single event by ID or UUID.

        Parameters
        ----------
        event_id : int | str
            MISP event integer ID or UUID.

        Returns
        -------
        dict
            Event dict.

        Raises
        ------
        MISPNotFoundError
        """
        response = self._client.get_json(f"events/view/{event_id}")
        if isinstance(response, dict):
            return response.get("Event", response)
        raise MISPNotFoundError(f"Event {event_id} not found.", status_code=404)

    def search_events(self, value: str, type_attr: str | None = None) -> list[dict]:
        """
        Search events containing a specific attribute value.

        Parameters
        ----------
        value : str
            Value to search for (IP, domain, hash, etc.).
        type_attr : str | None
            Attribute type to restrict search (e.g. 'ip-src', 'domain').

        Returns
        -------
        list[dict]
            Matching event dicts.
        """
        body: dict = {"returnFormat": "json", "value": value}
        if type_attr:
            body["type"] = type_attr
        response = self._client.post_json("events/restSearch", body=body)
        return self._unwrap_events(response)

    # ── CRUD ───────────────────────────────────────────────────────────────

    def create_event(
        self,
        info: str,
        threat_level_id: int | None = None,
        analysis: int | None = None,
        distribution: int | None = None,
        date: str | None = None,
        published: bool = False,
    ) -> dict:
        """
        Create a new MISP event.

        Parameters
        ----------
        info : str
            Event title / description.
        threat_level_id : int | None
            1=High, 2=Medium, 3=Low, 4=Undefined.
        analysis : int | None
            0=Initial, 1=Ongoing, 2=Completed.
        distribution : int | None
            0=Org, 1=Community, 2=Connected, 3=All.
        date : str | None
            Event date as YYYY-MM-DD. Defaults to today.
        published : bool
            Whether to publish the event immediately.

        Returns
        -------
        dict
            Created event dict.
        """
        if date is None:
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        event: dict = {
            "info": info,
            "date": date,
            "published": published,
            "threat_level_id": threat_level_id
                if threat_level_id is not None
                else self._client.config.default_threat_level,
            "analysis": analysis
                if analysis is not None
                else self._client.config.default_analysis,
            "distribution": distribution
                if distribution is not None
                else self._client.config.default_distribution,
        }
        response = self._client.post_json("events/add", body={"Event": event})
        if isinstance(response, dict):
            return response.get("Event", response)
        return response

    def update_event(self, event_id: int | str, updates: dict) -> dict:
        """
        Update an existing event.

        Parameters
        ----------
        event_id : int | str
        updates : dict
            Fields to update inside the Event envelope.

        Returns
        -------
        dict
        """
        response = self._client.post_json(
            f"events/edit/{event_id}", body={"Event": updates}
        )
        if isinstance(response, dict):
            return response.get("Event", response)
        return response

    def delete_event(self, event_id: int | str) -> dict:
        """Delete an event by ID."""
        return self._client.delete_json(f"events/delete/{event_id}")

    def publish_event(self, event_id: int | str) -> dict:
        """Publish an event (make it visible to the community)."""
        return self._client.post_json(f"events/publish/{event_id}")

    def add_tag_to_event(self, event_id: int | str, tag: str) -> dict:
        """
        Add a tag to an event.

        Parameters
        ----------
        event_id : int | str
        tag : str
            Tag name (e.g. 'tlp:white', 'misp-galaxy:threat-actor="APT1"').
        """
        return self._client.post_json(
            "tags/attachTagToObject",
            body={"uuid": str(event_id), "tag": tag},
        )

    # ── STIX export ────────────────────────────────────────────────────────

    def export_event_stix2(self, event_id: int | str) -> dict:
        """
        Export a single event as a STIX 2.1 bundle using MISP's native export.

        Parameters
        ----------
        event_id : int | str

        Returns
        -------
        dict
            STIX 2.1 bundle dict.
        """
        response = self._client.post_json(
            "events/restSearch",
            body={
                "returnFormat": "stix2",
                "eventid": str(event_id),
            },
        )
        return response if isinstance(response, dict) else {}

    def export_events_stix2(
        self,
        tags: list[str] | None = None,
        date_from: str | None = None,
        threat_level_id: int | None = None,
    ) -> dict:
        """
        Export multiple events as a merged STIX 2.1 bundle.

        Parameters
        ----------
        tags : list[str] | None
        date_from : str | None
        threat_level_id : int | None

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        body: dict = {"returnFormat": "stix2"}
        if tags:
            body["tags"] = tags
        if date_from:
            body["date_from"] = date_from
        if threat_level_id is not None:
            body["threat_level_id"] = threat_level_id

        response = self._client.post_json("events/restSearch", body=body)
        return response if isinstance(response, dict) else {}

    # ── Normalisation ──────────────────────────────────────────────────────

    @staticmethod
    def normalise_event(event: dict) -> dict:
        """Flatten a MISP event dict to GNAT normalised format."""
        threat_level = int(event.get("threat_level_id", 4))
        severity = _THREAT_TO_SEVERITY.get(threat_level, 0)
        tags = [t.get("name", "") for t in event.get("Tag", [])]
        return {
            "id": event.get("id"),
            "uuid": event.get("uuid"),
            "info": event.get("info"),
            "date": event.get("date"),
            "threat_level_id": threat_level,
            "severity": severity,
            "severity_label": _SEVERITY_LABELS.get(severity, "unknown"),
            "analysis": int(event.get("analysis", 0)),
            "distribution": int(event.get("distribution", 0)),
            "published": event.get("published", False),
            "attribute_count": int(event.get("attribute_count", 0)),
            "org_id": event.get("org_id"),
            "orgc_id": event.get("orgc_id"),
            "timestamp": event.get("timestamp"),
            "tags": tags,
            "_raw": event,
        }

    @staticmethod
    def _unwrap_events(response) -> list[dict]:
        """Normalise various MISP response shapes to a plain list of Event dicts."""
        if isinstance(response, list):
            return [item.get("Event", item) for item in response]
        if isinstance(response, dict):
            items = response.get("response", []) or response.get("value", [])
            if isinstance(items, list):
                return [item.get("Event", item) for item in items]
        return []
