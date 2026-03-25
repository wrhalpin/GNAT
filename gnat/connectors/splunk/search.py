# “””
ctm_sak.connectors.splunk.search

SPL search job commands for the Splunk connector.

Covers the full search job lifecycle:
create → poll → fetch results → cancel/finalize

## Splunk search job flow

1. POST /search/jobs              → returns sid (search ID)
1. GET  /search/jobs/<sid>        → poll dispatchState until DONE/FAILED
1. GET  /search/jobs/<sid>/results → fetch result rows
1. DELETE /search/jobs/<sid>      → cleanup (optional)

All search results are returned as list[dict] where each dict
represents one result row with Splunk field names as keys.

## Blocking vs async

`run_search()` is synchronous and blocks until the job completes.
`create_search_job()` + `poll_job()` + `fetch_results()`
provide the async building blocks for callers that need non-blocking
behaviour.

## References

- https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch
  “””

import time
from typing import Iterator

from .client import SplunkClient
from .exceptions import SplunkSearchError

# ── Job dispatch state constants ──────────────────────────────────────────────

_TERMINAL_STATES = {“DONE”, “FAILED”}
_POLL_INTERVAL_SECONDS = 2.0
_POLL_MAX_WAIT_SECONDS = 300.0   # 5 min default; override via timeout param

class SplunkSearchCommands:
“””
SPL search operations.

```
Parameters
----------
client : SplunkClient
    The authenticated HTTP client.
"""

def __init__(self, client: SplunkClient) -> None:
    self._client = client

# ── High-level convenience ─────────────────────────────────────────────

def run_search(
    self,
    spl: str,
    earliest_time: str = "-24h",
    latest_time: str = "now",
    max_results: int | None = None,
    timeout: float = _POLL_MAX_WAIT_SECONDS,
    preview: bool = False,
    **kwargs,
) -> list[dict]:
    """
    Execute a blocking SPL search and return all results.

    Parameters
    ----------
    spl : str
        The SPL search string (with or without leading ``search``).
    earliest_time : str
        Splunk time modifier for the start of the search window.
    latest_time : str
        Splunk time modifier for the end of the search window.
    max_results : int | None
        Cap on returned results. Defaults to config.max_results.
    timeout : float
        Max seconds to wait for job completion before raising.
    preview : bool
        If True, return partial results from an in-progress job.
    **kwargs
        Additional parameters forwarded to the search job POST body.

    Returns
    -------
    list[dict]
        Result rows as dicts of {field: value}.

    Raises
    ------
    SplunkSearchError
        If the job fails or times out.
    """
    limit = max_results or self._client.config.max_results
    sid = self.create_search_job(
        spl,
        earliest_time=earliest_time,
        latest_time=latest_time,
        **kwargs,
    )
    try:
        self.poll_job(sid, timeout=timeout)
        return self.fetch_results(sid, count=limit)
    except SplunkSearchError:
        raise
    finally:
        if not preview:
            self.cancel_job(sid)

def run_oneshot(
    self,
    spl: str,
    earliest_time: str = "-24h",
    latest_time: str = "now",
    max_results: int | None = None,
) -> list[dict]:
    """
    Execute a blocking one-shot search (no persistent job artifact).

    One-shot searches are faster for simple queries but have a
    hard limit of 50,000 results. For large result sets use
    ``run_search()`` instead.

    Parameters
    ----------
    spl : str
        SPL search string.
    earliest_time : str
        Search window start.
    latest_time : str
        Search window end.
    max_results : int | None
        Result cap (max 50,000 for one-shot).

    Returns
    -------
    list[dict]
        Result rows.
    """
    limit = min(max_results or self._client.config.max_results, 50_000)
    data = {
        "search": spl,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "count": limit,
        "output_mode": "json",
    }
    response = self._client.post(
        "search/jobs/oneshot",
        data=data,
        namespaced=True,
    )
    return response.get("results", [])

# ── Job lifecycle ──────────────────────────────────────────────────────

def create_search_job(
    self,
    spl: str,
    earliest_time: str = "-24h",
    latest_time: str = "now",
    **kwargs,
) -> str:
    """
    Create an asynchronous search job.

    Parameters
    ----------
    spl : str
        SPL search string.
    earliest_time : str
        Search window start.
    latest_time : str
        Search window end.
    **kwargs
        Additional POST body parameters (e.g. ``rf``, ``status_buckets``).

    Returns
    -------
    str
        The search job SID.

    Raises
    ------
    SplunkSearchError
        If the job cannot be created.
    """
    data = {
        "search": spl,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        **kwargs,
    }
    response = self._client.post("search/jobs", data=data, namespaced=True)
    sid = response.get("sid")
    if not sid:
        raise SplunkSearchError(
            "Splunk did not return a search job SID.",
            dispatch_state="UNKNOWN",
        )
    return sid

def poll_job(
    self,
    sid: str,
    timeout: float = _POLL_MAX_WAIT_SECONDS,
) -> str:
    """
    Block until the search job reaches a terminal state.

    Parameters
    ----------
    sid : str
        Search job SID returned by ``create_search_job``.
    timeout : float
        Max seconds to wait. Raises on expiry.

    Returns
    -------
    str
        Final dispatch state (``'DONE'`` on success).

    Raises
    ------
    SplunkSearchError
        If the job fails or the wait times out.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = self._client.get(
            f"search/jobs/{sid}",
            params={"output_mode": "json"},
            namespaced=False,
        )
        entry = response.get("entry", [{}])[0]
        content = entry.get("content", {})
        dispatch_state = content.get("dispatchState", "UNKNOWN")

        if dispatch_state == "DONE":
            return dispatch_state

        if dispatch_state == "FAILED":
            messages = content.get("messages", {})
            raise SplunkSearchError(
                "Search job failed.",
                job_sid=sid,
                dispatch_state="FAILED",
            )

        time.sleep(_POLL_INTERVAL_SECONDS)

    raise SplunkSearchError(
        f"Search job timed out after {timeout}s.",
        job_sid=sid,
        dispatch_state="TIMEOUT",
    )

def fetch_results(
    self,
    sid: str,
    count: int = 0,
    offset: int = 0,
    field_list: list[str] | None = None,
) -> list[dict]:
    """
    Fetch results from a completed search job.

    Parameters
    ----------
    sid : str
        Search job SID.
    count : int
        Max results to return (0 = all up to the job's result count).
    offset : int
        Result offset for pagination.
    field_list : list[str] | None
        If given, only these fields are returned.

    Returns
    -------
    list[dict]
        Result rows.
    """
    params: dict = {
        "output_mode": "json",
        "count": count,
        "offset": offset,
    }
    if field_list:
        params["f"] = ",".join(field_list)

    response = self._client.get(
        f"search/jobs/{sid}/results",
        params=params,
        namespaced=False,
    )
    return response.get("results", [])

def iter_results(
    self,
    sid: str,
    page_size: int = 1000,
    field_list: list[str] | None = None,
) -> Iterator[dict]:
    """
    Generator that pages through all results of a completed job.

    Parameters
    ----------
    sid : str
        Search job SID.
    page_size : int
        Results per page.
    field_list : list[str] | None
        Fields to return.

    Yields
    ------
    dict
        Individual result rows.
    """
    offset = 0
    while True:
        page = self.fetch_results(
            sid,
            count=page_size,
            offset=offset,
            field_list=field_list,
        )
        yield from page
        if len(page) < page_size:
            break
        offset += page_size

def cancel_job(self, sid: str) -> None:
    """
    Delete / cancel a search job.

    Parameters
    ----------
    sid : str
        Search job SID to cancel.
    """
    try:
        self._client.delete(f"search/jobs/{sid}", namespaced=False)
    except Exception:
        pass  # Best-effort cleanup.

# ── Saved searches ─────────────────────────────────────────────────────

def list_saved_searches(self, count: int = 100) -> list[dict]:
    """
    List saved searches in the configured app context.

    Parameters
    ----------
    count : int
        Max results per page.

    Returns
    -------
    list[dict]
        Saved search metadata entries.
    """
    results = []
    for entry in self._client.paginate(
        "saved/searches",
        params={"count": count},
        namespaced=True,
        page_size=count,
    ):
        results.append({
            "name": entry.get("name"),
            "search": entry.get("content", {}).get("search"),
            "cron_schedule": entry.get("content", {}).get("cron_schedule"),
            "is_scheduled": entry.get("content", {}).get("is_scheduled"),
            "disabled": entry.get("content", {}).get("disabled"),
        })
    return results

def get_saved_search(self, name: str) -> dict:
    """
    Retrieve metadata for a single saved search by name.

    Parameters
    ----------
    name : str
        Saved search name.

    Returns
    -------
    dict
        Saved search content dict.
    """
    import urllib.parse as _up
    safe_name = _up.quote(name, safe="")
    response = self._client.get(
        f"saved/searches/{safe_name}",
        namespaced=True,
    )
    entries = response.get("entry", [])
    if not entries:
        from .exceptions import SplunkNotFoundError
        raise SplunkNotFoundError(
            f"Saved search '{name}' not found.",
            status_code=404,
        )
    return entries[0].get("content", {})

def run_saved_search(self, name: str, **dispatch_args) -> str:
    """
    Dispatch a saved search and return the resulting job SID.

    Parameters
    ----------
    name : str
        Saved search name.
    **dispatch_args
        Override dispatch parameters (e.g. ``earliest_time``).

    Returns
    -------
    str
        Search job SID.
    """
    import urllib.parse as _up
    safe_name = _up.quote(name, safe="")
    response = self._client.post(
        f"saved/searches/{safe_name}/dispatch",
        data=dispatch_args or {},
        namespaced=True,
    )
    sid = response.get("sid")
    if not sid:
        raise SplunkSearchError(
            f"Failed to dispatch saved search '{name}'.",
        )
    return sid

# ── Index operations ───────────────────────────────────────────────────

def list_indexes(self) -> list[dict]:
    """
    List all accessible Splunk indexes.

    Returns
    -------
    list[dict]
        Index metadata entries (name, totalEventCount, currentDBSizeMB, etc.)
    """
    results = []
    for entry in self._client.paginate(
        "data/indexes",
        namespaced=False,
        page_size=100,
    ):
        content = entry.get("content", {})
        results.append({
            "name": entry.get("name"),
            "total_event_count": content.get("totalEventCount"),
            "current_db_size_mb": content.get("currentDBSizeMB"),
            "disabled": content.get("disabled"),
            "data_type": content.get("datatype"),
        })
    return results

def get_index_stats(self, index: str | None = None) -> dict:
    """
    Return event count and size stats for a specific index.

    Parameters
    ----------
    index : str | None
        Index name. Defaults to config.default_index.

    Returns
    -------
    dict
        Index stats dict.
    """
    import urllib.parse as _up
    target = index or self._client.config.default_index
    safe = _up.quote(target, safe="")
    response = self._client.get(f"data/indexes/{safe}", namespaced=False)
    entries = response.get("entry", [])
    if not entries:
        from .exceptions import SplunkNotFoundError
        raise SplunkNotFoundError(
            f"Index '{target}' not found.",
            status_code=404,
        )
    return entries[0].get("content", {})
```