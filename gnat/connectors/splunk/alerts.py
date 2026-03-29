"""
gnat.connectors.splunk.alerts

Alert and notable event commands for the Splunk connector.

Covers two alert surfaces:

1. Core Splunk Alerts (/alerts/fired_alerts, /saved/searches/<name>/history)
- List fired alerts across the instance
- Retrieve alert history for a specific saved search
- Acknowledge / suppress alerts
1. Splunk Enterprise Security Notable Events
- Requires es_enabled = true in config
- Notables live in the notable index and are managed via the
  ES REST endpoints under /servicesNS/…/SplunkEnterpriseSecuritySuite/
- CRUD on notable event status (new -> in progress -> closed -> resolved)

## Alert severity mapping (ES -> GNAT)

ES urgency string -> integer severity for GNAT incident model:
critical  -> 4
high      -> 3
medium    -> 2
low       -> 1
informational -> 0

## References

- https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTalerts
- https://docs.splunk.com/Documentation/ES/latest/API/NotableEvents
  """

import urllib.parse

from .client import SplunkClient
from .exceptions import SplunkThreatIntelError

# ── Severity mapping ──────────────────────────────────────────────────────────

_ES_URGENCY_TO_SEVERITY: dict[str, int] = {
"critical": 4,
"high": 3,
"medium": 2,
"low": 1,
"informational": 0,
"unknown": 0,
}

# ES notable status IDs (Splunk internal)

_NOTABLE_STATUS = {
"new": "0",
"in_progress": "1",
"pending": "2",
"resolved": "3",
"closed": "4",
}

class SplunkAlertCommands:
    """
    Alert and notable event operations.

    Parameters
    ----------
    client : SplunkClient
        Authenticated HTTP client.
    """

    def __init__(self, client: SplunkClient) -> None:
        self._client = client

    # ── Core alerts ────────────────────────────────────────────────────────

    def list_fired_alerts(self, count: int = 100) -> list[dict]:
        """
        List all fired alert instances across the instance.

        Returns a flat list of fired alert records, each containing
        the saved search name, trigger time, severity, and result count.

        Parameters
        ----------
        count : int
            Maximum alerts to return.

        Returns
        -------
        list[dict]
            Fired alert records.
        """
        results = []
        for entry in self._client.paginate(
            "alerts/fired_alerts",
            namespaced=True,
            page_size=min(count, 100),
        ):
            content = entry.get("content", {})
            results.append({
                "name": entry.get("name"),
                "saved_search_name": content.get("savedsearch_name"),
                "trigger_time": content.get("trigger_time"),
                "trigger_time_rendered": content.get("trigger_time_rendered"),
                "severity": content.get("severity"),
                "result_count": content.get("result_count"),
                "sid": content.get("sid"),
            })
            if len(results) >= count:
                break
        return results

    def get_alert_history(
        self,
        saved_search_name: str,
        count: int = 25,
    ) -> list[dict]:
        """
        Retrieve the dispatch history for a specific saved search alert.

        Parameters
        ----------
        saved_search_name : str
            Name of the saved search to query.
        count : int
            Max history records to return.

        Returns
        -------
        list[dict]
            Dispatch history records.
        """
        safe = urllib.parse.quote(saved_search_name, safe="")
        response = self._client.get(
            f"saved/searches/{safe}/history",
            params={"count": count},
            namespaced=True,
        )
        records = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            records.append({
                "sid": entry.get("name"),
                "dispatch_state": content.get("dispatchState"),
                "event_count": content.get("eventCount"),
                "result_count": content.get("resultCount"),
                "run_duration": content.get("runDuration"),
                "ttl": content.get("ttl"),
                "is_done": content.get("isDone"),
                "is_failed": content.get("isFailed"),
            })
        return records

    def get_alert_metadata(self, saved_search_name: str) -> dict:
        """
        Retrieve alert trigger configuration for a saved search.

        Returns the alert trigger conditions, throttling, actions,
        and severity configured on the saved search.

        Parameters
        ----------
        saved_search_name : str
            Saved search / alert name.

        Returns
        -------
        dict
            Alert metadata.
        """
        safe = urllib.parse.quote(saved_search_name, safe="")
        response = self._client.get(
            f"saved/searches/{safe}",
            namespaced=True,
        )
        entries = response.get("entry", [])
        if not entries:
            from .exceptions import SplunkNotFoundError
            raise SplunkNotFoundError(
                f"Alert '{saved_search_name}' not found.",
                status_code=404,
            )
        content = entries[0].get("content", {})
        return {
            "name": entries[0].get("name"),
            "search": content.get("search"),
            "cron_schedule": content.get("cron_schedule"),
            "alert_type": content.get("alert_type"),
            "alert_comparator": content.get("alert_comparator"),
            "alert_threshold": content.get("alert_threshold"),
            "alert_severity": content.get("alert.severity"),
            "alert_suppress": content.get("alert.suppress"),
            "alert_suppress_period": content.get("alert.suppress.period"),
            "is_scheduled": content.get("is_scheduled"),
            "disabled": content.get("disabled"),
        }

    # ── Enterprise Security notable events ─────────────────────────────────

    def _require_es(self) -> None:
        if not self._client.config.es_enabled:
            raise SplunkThreatIntelError(
                "Enterprise Security notable event commands require "
                "'es_enabled = true' in [splunk] config."
            )

    def search_notables(
        self,
        status: str | None = None,
        urgency: str | None = None,
        owner: str | None = None,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int | None = None,
    ) -> list[dict]:
        """
        Search ES notable events via SPL against the notable index.

        Parameters
        ----------
        status : str | None
            Filter by notable status: 'new', 'in_progress', 'resolved', 'closed'.
        urgency : str | None
            Filter by urgency: 'critical', 'high', 'medium', 'low'.
        owner : str | None
            Filter by assigned owner username.
        earliest_time : str
            Search window start.
        latest_time : str
            Search window end.
        max_results : int | None
            Result cap. Defaults to config.max_results.

        Returns
        -------
        list[dict]
            Notable event records normalised for GNAT.
        """
        self._require_es()

        filters = ['index=notable']
        if status and status in _NOTABLE_STATUS:
            filters.append(f'status={_NOTABLE_STATUS[status]}')
        if urgency:
            filters.append(f'urgency={urgency}')
        if owner:
            filters.append(f'owner="{owner}"')

        spl = (
            "search "
            + " ".join(filters)
            + " | table event_id rule_name urgency status owner "
              "_time src dest user rule_description"
        )

        from .search import SplunkSearchCommands
        searcher = SplunkSearchCommands(self._client)
        rows = searcher.run_search(
            spl,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )
        return [self._normalise_notable(r) for r in rows]

    def update_notable_status(
        self,
        event_ids: list[str],
        status: str,
        comment: str = "",
        owner: str | None = None,
        urgency: str | None = None,
    ) -> dict:
        """
        Update the status of one or more notable events.

        Parameters
        ----------
        event_ids : list[str]
            Notable event IDs to update.
        status : str
            Target status: 'new', 'in_progress', 'pending', 'resolved', 'closed'.
        comment : str
            Analyst comment to attach to the status change.
        owner : str | None
            Reassign to this Splunk username.
        urgency : str | None
            Override urgency: 'critical', 'high', 'medium', 'low'.

        Returns
        -------
        dict
            Splunk ES API response.
        """
        self._require_es()

        if status not in _NOTABLE_STATUS:
            raise ValueError(
                f"Invalid status '{status}'. "
                f"Valid values: {list(_NOTABLE_STATUS)}"
            )

        data: dict = {
            "ruleUIDs[]": event_ids,
            "status": _NOTABLE_STATUS[status],
            "comment": comment,
        }
        if owner:
            data["newOwner"] = owner
        if urgency:
            data["urgency"] = urgency

        # ES notable update endpoint lives under the ES app namespace
        orig_app = self._client.config.app_context
        self._client.config.__dict__["app_context"] = "SplunkEnterpriseSecuritySuite"
        try:
            return self._client.post(
                "notable_update",
                data=data,
                namespaced=True,
            )
        finally:
            self._client.config.__dict__["app_context"] = orig_app

    def get_notable_by_id(self, event_id: str) -> dict | None:
        """
        Retrieve a single notable event by its event_id.

        Parameters
        ----------
        event_id : str
            The ``event_id`` field of the notable.

        Returns
        -------
        dict | None
            Notable event dict, or None if not found.
        """
        self._require_es()
        results = self.search_notables()
        for notable in results:
            if notable.get("event_id") == event_id:
                return notable
        return None

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _normalise_notable(row: dict) -> dict:
        """Map Splunk ES notable fields to GNAT normalised format."""
        urgency = (row.get("urgency") or "unknown").lower()
        return {
            "event_id": row.get("event_id"),
            "rule_name": row.get("rule_name"),
            "urgency": urgency,
            "severity": _ES_URGENCY_TO_SEVERITY.get(urgency, 0),
            "status": row.get("status"),
            "owner": row.get("owner"),
            "timestamp": row.get("_time"),
            "src": row.get("src"),
            "dest": row.get("dest"),
            "user": row.get("user"),
            "description": row.get("rule_description"),
            "_raw": row,
        }
