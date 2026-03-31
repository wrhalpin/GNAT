"""
gnat.connectors.qradar.ariel
==================================
Ariel search (AQL query) commands for the QRadar connector.

Ariel is QRadar's query engine for event and flow data. It uses
AQL (Ariel Query Language), a SQL-like query syntax.

Ariel job lifecycle
--------------------
  1. POST /api/ariel/searches       — create job, returns search_id + status
  2. GET  /api/ariel/searches/{id}  — poll until status is COMPLETED or ERROR
  3. GET  /api/ariel/searches/{id}/results — retrieve results

Job status values
-----------------
  WAIT       — queued but not yet started
  EXECUTE    — currently running
  SORTING    — post-execution sorting
  COMPLETED  — done, results available
  ERROR      — failed (inspect error_messages)
  CANCELLED  — cancelled by user or timeout

AQL query examples
------------------
  SELECT sourceip, destinationip, eventcount
  FROM events
  WHERE category=4001
  LAST 1 HOURS

  SELECT DISTINCT sourceip
  FROM events
  WHERE logsourceid=73 AND eventcount > 100
  START '2024-01-01 00:00:00' STOP '2024-01-02 00:00:00'

  SELECT * FROM flows WHERE sourcebytes > 1000000 LAST 30 MINUTES

Result pagination
-----------------
Ariel results use the same Range header pagination as the REST API.
Results contain:
  {"cursor_id": "...", "total_events": N, "events": [...]}
  (or "flows" instead of "events" for flow queries)

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-ariel-searches
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=language-ariel-query
"""

import re
import time
from collections.abc import Iterator

from .client import QRadarClient
from .exceptions import QRadarAPIError, QRadarArielError

# Allowlist pattern for AQL field identifiers.  Permits bare identifiers,
# AQL built-in functions (DATEFORMAT, QIDNAME, CATEGORYNAME, etc.), and
# quoted aliases produced by "expr AS alias" forms.
_AQL_FIELD_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"   # bare identifier / function name
    r"(\([^)]*\))?$"              # optional single-level call args
    r"|^[A-Za-z_][A-Za-z0-9_]*"  # leading identifier …
    r"(\([^)]*\))?"               # … optional call …
    r"\s+AS\s+[A-Za-z_][A-Za-z0-9_]*$",  # … AS alias
    re.IGNORECASE,
)


def _validate_aql_fields(fields: list) -> None:
    """Raise ValueError if any entry in *fields* contains characters that are
    unsafe in an AQL SELECT clause (prevents AQL injection).

    Only bare identifiers, ``FUNCTION(...)`` expressions, and
    ``expr AS alias`` forms are accepted.
    """
    for field in fields:
        if not _AQL_FIELD_RE.match(field.strip()):
            raise ValueError(
                f"Unsafe AQL field expression rejected: {field!r}. "
                "Only identifiers, function calls, and 'expr AS alias' forms are allowed."
            )


# Job poll settings
_POLL_INTERVAL_SECS = 2.0
_POLL_MAX_WAIT_SECS = 300.0   # 5 minutes default max wait
_TERMINAL_STATUSES = {"COMPLETED", "ERROR", "CANCELLED"}


class QRadarArielCommands:
    """
    Ariel AQL search job management.

    Parameters
    ----------
    client : QRadarClient
        Authenticated HTTP client.
    """

    def __init__(self, client: QRadarClient) -> None:
        self._client = client

    # ── High-level search helpers ──────────────────────────────────────────

    def execute(
        self,
        aql: str,
        timeout_secs: float = _POLL_MAX_WAIT_SECS,
        result_page_size: int | None = None,
    ) -> list[dict]:
        """
        Execute an AQL query and return all results.

        Convenience method that handles the full job lifecycle:
        create → poll → fetch results.

        Parameters
        ----------
        aql : str
            AQL query string.
        timeout_secs : float
            Maximum seconds to wait for job completion.
        result_page_size : int | None
            Page size for result retrieval. Defaults to config.max_results.

        Returns
        -------
        list[dict]
            Query result rows (events or flows).

        Raises
        ------
        QRadarArielError
            If the job errors, is cancelled, or times out.
        """
        search_id = self.create_search(aql)
        self.wait_for_completion(search_id, timeout_secs=timeout_secs)
        return list(self.iter_results(search_id, page_size=result_page_size))

    def execute_and_normalise(
        self,
        aql: str,
        timeout_secs: float = _POLL_MAX_WAIT_SECS,
    ) -> list[dict]:
        """
        Execute AQL and return normalised result rows.

        Parameters
        ----------
        aql : str
            AQL query string.
        timeout_secs : float
            Max wait time in seconds.

        Returns
        -------
        list[dict]
            Normalised event/flow records.
        """
        rows = self.execute(aql, timeout_secs=timeout_secs)
        return [self.normalise_event_row(r) for r in rows]

    # ── Job lifecycle ──────────────────────────────────────────────────────

    def create_search(self, aql: str) -> str:
        """
        Submit an AQL query and return the search_id.

        Parameters
        ----------
        aql : str
            AQL query string.

        Returns
        -------
        str
            Ariel search_id UUID.

        Raises
        ------
        QRadarArielError
            If the query is rejected (e.g. syntax error).
        """
        try:
            result = self._client.post(
                "ariel/searches",
                params={"query_expression": aql},
            )
        except QRadarAPIError as exc:
            raise QRadarArielError(
                f"AQL search submission failed: {exc}",
                status=getattr(exc, "qradar_code", None),
            ) from exc

        search_id = result.get("search_id") or result.get("cursor_id")
        if not search_id:
            raise QRadarArielError(
                "AQL search created but no search_id returned.",
                status=result.get("status"),
            )
        return str(search_id)

    def get_search_status(self, search_id: str) -> dict:
        """
        Get the current status of an Ariel search job.

        Parameters
        ----------
        search_id : str
            Ariel search_id.

        Returns
        -------
        dict
            Job status record with fields:
            search_id, status, progress, completed, error_messages,
            query_string, save_results, record_count.
        """
        return self._client.get(f"ariel/searches/{search_id}")

    def wait_for_completion(
        self,
        search_id: str,
        timeout_secs: float = _POLL_MAX_WAIT_SECS,
        poll_interval: float = _POLL_INTERVAL_SECS,
    ) -> dict:
        """
        Poll an Ariel search job until it reaches a terminal status.

        Parameters
        ----------
        search_id : str
            Ariel search_id.
        timeout_secs : float
            Maximum seconds to wait.
        poll_interval : float
            Seconds between poll attempts.

        Returns
        -------
        dict
            Final job status record.

        Raises
        ------
        QRadarArielError
            If the job errors, is cancelled, or times out.
        """
        deadline = time.time() + timeout_secs

        while True:
            status_record = self.get_search_status(search_id)
            status = status_record.get("status", "WAIT")

            if status == "COMPLETED":
                return status_record

            if status == "ERROR":
                errors = status_record.get("error_messages", [])
                raise QRadarArielError(
                    f"Ariel search {search_id} failed.",
                    search_id=search_id,
                    status="ERROR",
                    error_messages=[str(e) for e in errors],
                )

            if status == "CANCELLED":
                raise QRadarArielError(
                    f"Ariel search {search_id} was cancelled.",
                    search_id=search_id,
                    status="CANCELLED",
                )

            if time.time() >= deadline:
                raise QRadarArielError(
                    f"Ariel search {search_id} timed out after {timeout_secs}s "
                    f"(last status: {status}).",
                    search_id=search_id,
                    status=status,
                )

            time.sleep(poll_interval)

    def cancel_search(self, search_id: str) -> dict:
        """
        Cancel a running Ariel search job.

        Parameters
        ----------
        search_id : str
            Ariel search_id.

        Returns
        -------
        dict
            Updated job status.
        """
        return self._client.delete(f"ariel/searches/{search_id}")

    # ── Result retrieval ───────────────────────────────────────────────────

    def iter_results(
        self,
        search_id: str,
        page_size: int | None = None,
    ) -> Iterator[dict]:
        """
        Generator that yields all result rows from a completed search.

        Uses Range header pagination to fetch results in pages.

        Parameters
        ----------
        search_id : str
            Ariel search_id (must be in COMPLETED status).
        page_size : int | None
            Rows per page. Defaults to config.max_results.

        Yields
        ------
        dict
            Individual event or flow row dicts.
        """
        size = page_size or self._client.config.max_results
        start = 0
        total: int | None = None

        while True:
            end = start + size - 1
            range_val = f"items={start}-{end}"

            response = self._client._raw_request(
                "GET",
                self._client.config.endpoint(f"ariel/searches/{search_id}/results"),
                extra_headers={"Range": range_val},
            )

            # Parse Content-Range for total
            content_range = response.headers.get("Content-Range", "")
            if content_range and total is None:
                total = self._client._parse_content_range_total(content_range)

            body = self._client._parse_json_response(response, search_id)

            # Ariel results are under 'events' or 'flows' key
            rows = body.get("events") or body.get("flows") or []
            yield from rows

            start += len(rows)
            if not rows:
                break
            if total is not None and start >= total:
                break

    def get_results_page(
        self,
        search_id: str,
        start: int = 0,
        end: int = 49,
    ) -> dict:
        """
        Retrieve a specific page of Ariel search results.

        Parameters
        ----------
        search_id : str
            Completed search_id.
        start : int
            First row index (0-based).
        end : int
            Last row index (inclusive).

        Returns
        -------
        dict
            Results body with 'events' or 'flows' list.
        """
        return self._client.get(
            f"ariel/searches/{search_id}/results",
            range_header=f"items={start}-{end}",
        )

    # ── Saved searches ─────────────────────────────────────────────────────

    def list_saved_searches(self) -> list[dict]:
        """
        List saved Ariel searches (stored queries).

        Returns
        -------
        list[dict]
            Saved search records with id, name, aql.
        """
        return list(self._client.paginate("ariel/saved_searches"))

    def get_saved_search(self, saved_search_id: str) -> dict:
        """
        Get a saved Ariel search by ID.

        Parameters
        ----------
        saved_search_id : str
            Saved search ID.

        Returns
        -------
        dict
            Saved search record.
        """
        return self._client.get(f"ariel/saved_searches/{saved_search_id}")

    # ── AQL query builder helpers ──────────────────────────────────────────

    @staticmethod
    def build_event_query(
        fields: list[str] | None = None,
        where: str | None = None,
        time_range: str = "LAST 1 HOURS",
        limit: int | None = None,
    ) -> str:
        """
        Build a simple AQL event query.

        Parameters
        ----------
        fields : list[str] | None
            Fields to SELECT. Defaults to common security fields.
        where : str | None
            WHERE clause content (without the 'WHERE' keyword).
        time_range : str
            Time range expression: 'LAST N HOURS/DAYS/MINUTES' or
            'START x STOP y'.
        limit : int | None
            LIMIT clause value.

        Returns
        -------
        str
            AQL query string.
        """
        default_fields = [
            "DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') AS starttime",
            "logsourceid", "logsourcename(logsourceid) AS logsource",
            "category", "CATEGORYNAME(category) AS categoryname",
            "severity", "sourceip", "destinationip", "sourceport",
            "destinationport", "protocol", "username", "qid",
            "QIDNAME(qid) AS eventname", "eventcount",
        ]
        effective_fields = fields or default_fields
        _validate_aql_fields(effective_fields)
        select_fields = ", ".join(effective_fields)
        aql = f"SELECT {select_fields} FROM events"  # nosec B608 — fields validated by _validate_aql_fields
        if where:
            aql += f" WHERE {where}"
        aql += f" {time_range}"
        if limit:
            aql += f" LIMIT {limit}"
        return aql

    @staticmethod
    def build_flow_query(
        fields: list[str] | None = None,
        where: str | None = None,
        time_range: str = "LAST 1 HOURS",
        limit: int | None = None,
    ) -> str:
        """Build a simple AQL flow query."""
        default_fields = [
            "DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') AS starttime",
            "sourceip", "destinationip", "sourceport", "destinationport",
            "protocol", "sourcebytes", "destinationbytes",
            "sourcepayload", "destinationpayload",
        ]
        effective_fields = fields or default_fields
        _validate_aql_fields(effective_fields)
        select_fields = ", ".join(effective_fields)
        aql = f"SELECT {select_fields} FROM flows"  # nosec B608 — fields validated by _validate_aql_fields
        if where:
            aql += f" WHERE {where}"
        aql += f" {time_range}"
        if limit:
            aql += f" LIMIT {limit}"
        return aql

    # ── Normalisation helper ───────────────────────────────────────────────

    @staticmethod
    def normalise_event_row(row: dict) -> dict:
        """
        Flatten an Ariel event row to GNAT normalised format.

        Parameters
        ----------
        row : dict
            Raw Ariel event result row.

        Returns
        -------
        dict
            Normalised event dict.
        """
        return {
            "timestamp": row.get("starttime"),
            "log_source_id": row.get("logsourceid"),
            "log_source": row.get("logsource"),
            "category": row.get("category"),
            "category_name": row.get("categoryname"),
            "severity": row.get("severity"),
            "src_ip": row.get("sourceip"),
            "dst_ip": row.get("destinationip"),
            "src_port": row.get("sourceport"),
            "dst_port": row.get("destinationport"),
            "protocol": row.get("protocol"),
            "username": row.get("username"),
            "event_name": row.get("eventname"),
            "event_count": row.get("eventcount"),
            "_raw": row,
        }
