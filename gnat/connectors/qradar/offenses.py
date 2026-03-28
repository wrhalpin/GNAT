"""
gnat.connectors.qradar.offenses
=====================================
Offense management commands for the QRadar connector.

Offenses are QRadar's primary security incident concept. An offense
aggregates correlated events and flows that match a correlation rule,
producing a single actionable security incident.

Key offense fields
-------------------
  id                       — unique offense integer ID
  description              — offense description (often rule name)
  offense_type             — integer type code (0=Source IP, 1=Dest IP, etc.)
  offense_source           — the source value (IP, username, etc.)
  status                   — 'OPEN', 'HIDDEN', or 'CLOSED'
  magnitude                — severity 0–10 (higher = more severe)
  severity                 — 0–10
  credibility              — 0–10
  relevance                — 0–10
  event_count              — total events associated
  flow_count               — total flows associated
  device_count             — number of log sources involved
  category_count           — number of high-level categories
  start_time               — epoch milliseconds
  last_updated_time        — epoch milliseconds
  close_time               — epoch milliseconds (if closed)
  closing_reason_id        — reason for closure
  assigned_to              — username of assigned analyst
  source_address_ids       — list of source address IDs
  destination_networks     — list of destination network names
  categories               — list of offense category strings
  rules                    — rules that contributed to this offense
  domain_id                — QRadar domain

Offense type codes
------------------
  0  — Source IP
  1  — Destination IP
  2  — Event name
  3  — Username
  4  — MAC address
  5  — Log source
  6  — Hostname
  7  — Port
  8  — Rule group
  9  — MAC/Hostname pair
  10 — Log source type
  11 — Post NAT source IP
  12 — Post NAT destination IP
  13 — GTI address
  14 — Username and source IP pair

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-siem-offenses
"""

from typing import Iterator

from .client import QRadarClient
from .exceptions import QRadarNotFoundError


# Offense type code → human-readable label
OFFENSE_TYPE_LABELS = {
    0: "Source IP", 1: "Destination IP", 2: "Event Name",
    3: "Username", 4: "MAC Address", 5: "Log Source",
    6: "Hostname", 7: "Port", 8: "Rule Group",
    9: "MAC/Hostname", 10: "Log Source Type", 11: "Post NAT Source IP",
    12: "Post NAT Destination IP", 13: "GTI Address",
    14: "Username/Source IP",
}

# Magnitude → GNAT severity (0–4)
def _magnitude_to_severity(magnitude: int) -> int:
    if magnitude >= 9:
        return 4   # critical
    if magnitude >= 7:
        return 3   # high
    if magnitude >= 5:
        return 2   # medium
    if magnitude >= 3:
        return 1   # low
    return 0       # informational

_SEVERITY_LABELS = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}


class QRadarOffenseCommands:
    """
    Offense management operations.

    Parameters
    ----------
    client : QRadarClient
        Authenticated HTTP client.
    """

    def __init__(self, client: QRadarClient) -> None:
        self._client = client

    # ── List and retrieve ──────────────────────────────────────────────────

    def list_offenses(
        self,
        status: str | None = None,
        filter: str | None = None,
        fields: str | None = None,
        sort: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List offenses with optional filters.

        Parameters
        ----------
        status : str | None
            'OPEN', 'HIDDEN', or 'CLOSED'. Defaults to config.offense_status.
        filter : str | None
            QRadar filter expression, e.g. ``"magnitude>5 and status=OPEN"``.
        fields : str | None
            Comma-separated field names to return (reduces response size).
        sort : str | None
            Sort expression, e.g. ``"+magnitude"`` or ``"-last_updated_time"``.
        limit : int | None
            Max offenses to return.

        Returns
        -------
        list[dict]
            Offense records.
        """
        params: dict = {}
        effective_status = status or self._client.config.offense_status
        if effective_status:
            params["filter"] = f"status={effective_status}"
        if filter:
            # Merge with status filter if both provided
            if "filter" in params:
                params["filter"] = f"({params['filter']}) and ({filter})"
            else:
                params["filter"] = filter
        if fields:
            params["fields"] = fields
        if sort:
            params["sort"] = sort

        page_size = min(limit or self._client.config.max_results, 500)
        items = []
        for item in self._client.paginate(
            "siem/offenses", params=params, page_size=page_size
        ):
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def iter_all_offenses(
        self,
        status: str | None = None,
        filter: str | None = None,
        fields: str | None = None,
    ) -> Iterator[dict]:
        """
        Generator yielding all offenses matching the given filters.

        Parameters
        ----------
        status : str | None
            Offense status filter.
        filter : str | None
            Additional QRadar filter expression.
        fields : str | None
            Fields to return.

        Yields
        ------
        dict
            Offense records.
        """
        params: dict = {}
        effective_status = status or self._client.config.offense_status
        if effective_status:
            params["filter"] = f"status={effective_status}"
        if filter:
            if "filter" in params:
                params["filter"] = f"({params['filter']}) and ({filter})"
            else:
                params["filter"] = filter
        if fields:
            params["fields"] = fields

        yield from self._client.paginate("siem/offenses", params=params)

    def get_offense(self, offense_id: int) -> dict:
        """
        Retrieve a single offense by ID.

        Parameters
        ----------
        offense_id : int
            QRadar offense ID.

        Returns
        -------
        dict
            Offense record.

        Raises
        ------
        QRadarNotFoundError
            If no offense with this ID exists.
        """
        result = self._client.get(f"siem/offenses/{offense_id}")
        if not result:
            raise QRadarNotFoundError(
                f"Offense {offense_id} not found.",
                status_code=404,
            )
        return result

    def get_offense_count(
        self,
        status: str | None = None,
        filter: str | None = None,
    ) -> int:
        """
        Return the total count of offenses matching the given filters.

        Parameters
        ----------
        status : str | None
            Status filter.
        filter : str | None
            Additional filter expression.

        Returns
        -------
        int
            Total offense count.
        """
        params: dict = {}
        effective_status = status or self._client.config.offense_status
        if effective_status:
            params["filter"] = f"status={effective_status}"
        if filter:
            if "filter" in params:
                params["filter"] = f"({params['filter']}) and ({filter})"
            else:
                params["filter"] = filter
        return self._client.get_total_count("siem/offenses", params=params)

    # ── Status management ──────────────────────────────────────────────────

    def update_offense(
        self,
        offense_id: int,
        status: str | None = None,
        assigned_to: str | None = None,
        closing_reason_id: int | None = None,
        follow_up: bool | None = None,
        protected: bool | None = None,
    ) -> dict:
        """
        Update offense fields (status, assignment, flags).

        Parameters
        ----------
        offense_id : int
            Offense to update.
        status : str | None
            New status: 'OPEN', 'HIDDEN', or 'CLOSED'.
        assigned_to : str | None
            QRadar username to assign to.
        closing_reason_id : int | None
            Required when setting status to 'CLOSED'. Use
            list_closing_reasons() to get valid IDs.
        follow_up : bool | None
            Set/clear the follow-up flag.
        protected : bool | None
            Set/clear the protected flag.

        Returns
        -------
        dict
            Updated offense record.
        """
        params: dict = {}
        if status:
            params["status"] = status
        if assigned_to:
            params["assigned_to"] = assigned_to
        if closing_reason_id is not None:
            params["closing_reason_id"] = closing_reason_id
        if follow_up is not None:
            params["follow_up"] = str(follow_up).lower()
        if protected is not None:
            params["protected"] = str(protected).lower()

        return self._client.post(f"siem/offenses/{offense_id}", params=params)

    def close_offense(
        self,
        offense_id: int,
        closing_reason_id: int,
    ) -> dict:
        """
        Close an offense with a closing reason.

        Parameters
        ----------
        offense_id : int
            Offense to close.
        closing_reason_id : int
            Closing reason ID (from list_closing_reasons()).

        Returns
        -------
        dict
            Updated offense.
        """
        return self.update_offense(
            offense_id,
            status="CLOSED",
            closing_reason_id=closing_reason_id,
        )

    def hide_offense(self, offense_id: int) -> dict:
        """Hide an offense (suppress from default view)."""
        return self.update_offense(offense_id, status="HIDDEN")

    def reopen_offense(self, offense_id: int) -> dict:
        """Reopen a closed or hidden offense."""
        return self.update_offense(offense_id, status="OPEN")

    # ── Notes ──────────────────────────────────────────────────────────────

    def list_notes(self, offense_id: int) -> list[dict]:
        """
        List analyst notes for an offense.

        Parameters
        ----------
        offense_id : int
            Offense ID.

        Returns
        -------
        list[dict]
            Note records with id, note_text, create_time, username.
        """
        return list(
            self._client.paginate(f"siem/offenses/{offense_id}/notes")
        )

    def add_note(self, offense_id: int, note_text: str) -> dict:
        """
        Add an analyst note to an offense.

        Parameters
        ----------
        offense_id : int
            Offense ID.
        note_text : str
            Note content.

        Returns
        -------
        dict
            Created note record.
        """
        return self._client.post(
            f"siem/offenses/{offense_id}/notes",
            params={"note_text": note_text},
        )

    # ── Closing reasons ────────────────────────────────────────────────────

    def list_closing_reasons(self) -> list[dict]:
        """
        List available offense closing reasons.

        Returns
        -------
        list[dict]
            Closing reason records with id and text.
        """
        return list(self._client.paginate("siem/offense_closing_reasons"))

    # ── Source addresses ───────────────────────────────────────────────────

    def get_source_addresses(self, source_address_ids: list[int]) -> list[dict]:
        """
        Resolve source address IDs to IP strings.

        Parameters
        ----------
        source_address_ids : list[int]
            Address IDs from offense source_address_ids field.

        Returns
        -------
        list[dict]
            Address records with id and source_ip.
        """
        if not source_address_ids:
            return []
        ids_filter = " or ".join(f"id={i}" for i in source_address_ids[:20])
        return list(
            self._client.paginate(
                "siem/source_addresses",
                params={"filter": ids_filter},
            )
        )

    # ── Normalisation helper ───────────────────────────────────────────────

    @staticmethod
    def normalise_offense(offense: dict) -> dict:
        """
        Flatten a QRadar offense record to GNAT normalised format.

        Converts epoch milliseconds to ISO 8601 strings and maps
        QRadar magnitude to GNAT severity (0–4).

        Parameters
        ----------
        offense : dict
            Raw QRadar offense dict.

        Returns
        -------
        dict
            Normalised offense dict.
        """
        magnitude = int(offense.get("magnitude", 0))
        severity = _magnitude_to_severity(magnitude)
        offense_type = int(offense.get("offense_type", 0))

        return {
            "id": offense.get("id"),
            "description": offense.get("description", ""),
            "status": offense.get("status"),
            "magnitude": magnitude,
            "severity": severity,
            "severity_label": _SEVERITY_LABELS.get(severity, "unknown"),
            "credibility": offense.get("credibility"),
            "relevance": offense.get("relevance"),
            "offense_type": offense_type,
            "offense_type_label": OFFENSE_TYPE_LABELS.get(offense_type, "Unknown"),
            "offense_source": offense.get("offense_source"),
            "event_count": offense.get("event_count", 0),
            "flow_count": offense.get("flow_count", 0),
            "device_count": offense.get("device_count", 0),
            "start_time": _epoch_ms_to_iso(offense.get("start_time")),
            "last_updated_time": _epoch_ms_to_iso(offense.get("last_updated_time")),
            "close_time": _epoch_ms_to_iso(offense.get("close_time")),
            "assigned_to": offense.get("assigned_to"),
            "categories": offense.get("categories", []),
            "source_address_ids": offense.get("source_address_ids", []),
            "destination_networks": offense.get("destination_networks", []),
            "domain_id": offense.get("domain_id"),
            "_raw": offense,
        }


def _epoch_ms_to_iso(epoch_ms: int | None) -> str | None:
    """Convert QRadar epoch milliseconds timestamp to ISO 8601 string."""
    if not epoch_ms:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"
