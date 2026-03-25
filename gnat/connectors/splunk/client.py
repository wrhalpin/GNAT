"""
ctm_sak.connectors.splunk.client
==================================

Splunk Enterprise / Splunk Cloud REST API connector.

Authentication
--------------
Two modes supported:

**Token-based** (recommended for automation)::

    [splunk]
    host      = https://splunk.example.com:8089
    api_token = <bearer-token>
    auth_type = token

**Username + password** (generates a session token on first use)::

    [splunk]
    host     = https://splunk.example.com:8089
    username = analyst
    password = s3cr3t
    auth_type = basic

Note: Splunk uses port 8089 (management port) for the REST API, not 8000
(the web UI port).

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | Splunk Resource                  |
+====================+==================================+
| indicator          | threat-intel lookup / notable    |
+--------------------+----------------------------------+
| malware            | threat-intel lookup              |
+--------------------+----------------------------------+
| vulnerability      | notable event (CVE)              |
+--------------------+----------------------------------+

Key Features
------------
* ``search(spl)`` — run any SPL search (blocking or async)
* ``get_notable_events()`` — fetch ES Notable Events
* ``post_threat_intel(ioc_type, value)`` — add to threat-intel lookup
* ``get_threat_intel(ioc_type)`` — read a threat-intel lookup table
* ``list_saved_searches()`` — enumerate saved searches
* ``get_kvstore(collection)`` — read a KV Store collection
* ``post_kvstore(collection, record)`` — write to KV Store

Output mode: all endpoints use ``output_mode=json``.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ctm_sak.clients.base import BaseClient, SAKClientError
from ctm_sak.connectors.base_connector import ConnectorMixin


class SplunkClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Splunk Enterprise / Splunk Cloud REST API.

    Parameters
    ----------
    host : str
        Base URL including port, e.g. ``"https://splunk.example.com:8089"``.
    api_token : str, optional
        Splunk bearer token.  Takes precedence over username/password.
    username : str, optional
        Splunk username (used if *api_token* is not set).
    password : str, optional
        Splunk password.
    app : str
        Splunk app context for searches.  Default ``"search"``.
    search_timeout : int
        Maximum seconds to wait for a blocking search job.  Default 120.
    """

    stix_type_map: Dict[str, str] = {
        "indicator":     "threat_activity",
        "malware":       "threat_activity",
        "vulnerability": "notable",
    }

    # IOC type → Splunk threat-intel lookup name
    _TI_LOOKUP: Dict[str, str] = {
        "ip":     "ip_intel",
        "domain": "http_intel",
        "url":    "http_intel",
        "email":  "email_intel",
        "md5":    "file_intel",
        "sha256": "file_intel",
        "sha1":   "file_intel",
    }

    def __init__(
        self,
        host: str,
        api_token: str = "",
        username: str = "",
        password: str = "",
        app: str = "search",
        search_timeout: int = 120,
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._api_token      = api_token
        self._username       = username
        self._password       = password
        self._app            = app
        self._search_timeout = search_timeout

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Authenticate to Splunk.

        If *api_token* is set, injects a Bearer header.
        Otherwise exchanges username+password for a session token via
        ``/services/auth/login``.

        Raises
        ------
        SAKClientError
            If neither token nor credentials are configured, or if
            username/password authentication fails.
        """
        if self._api_token:
            self._auth_headers["Authorization"] = f"Bearer {self._api_token}"
            return

        if self._username and self._password:
            resp = self.post(
                "/services/auth/login",
                data={
                    "username": self._username,
                    "password": self._password,
                    "output_mode": "json",
                },
            )
            session_key = (
                resp.get("sessionKey") if isinstance(resp, dict)
                else None
            )
            if not session_key:
                raise SAKClientError("Splunk: authentication failed — no session key")
            self._auth_headers["Authorization"] = f"Splunk {session_key}"
            return

        raise SAKClientError(
            "Splunk: no credentials configured. "
            "Set api_token or username+password in config."
        )

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping Splunk via the server-info endpoint."""
        self.get("/services/server/info", params={"output_mode": "json"})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """
        Fetch a single Splunk result.

        For indicators: looks up a value in the threat-intel lookup.
        For vulnerabilities / notables: fetches by event key.
        """
        if stix_type in ("indicator", "malware"):
            # Search threat-intel by id/value
            results = self.search(
                f'| inputlookup ip_intel | where id="{object_id}" | head 1'
            )
            return results[0] if results else {}

        if stix_type == "vulnerability":
            results = self.search(
                f'index=notable event_id="{object_id}" | head 1'
            )
            return results[0] if results else {}

        raise SAKClientError(f"Splunk: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List Splunk objects via SPL search.

        Parameters
        ----------
        filters : dict, optional
            Supported keys:
            * ``query`` — arbitrary SPL string appended after the base search
            * ``earliest`` — Splunk time modifier, e.g. ``"-24h"``
            * ``latest``   — end time, default ``"now"``
        """
        filters   = dict(filters or {})
        query     = filters.pop("query", "")
        earliest  = filters.pop("earliest", "-24h")
        latest    = filters.pop("latest", "now")

        if stix_type in ("indicator", "malware"):
            spl = f"| inputlookup ip_intel {query} | head {page_size}"
        elif stix_type == "vulnerability":
            spl = (
                f"index=notable earliest={earliest} latest={latest} "
                f"{query} | head {page_size}"
            )
        else:
            raise SAKClientError(f"Splunk: unsupported STIX type '{stix_type}'")

        return self.search(spl)

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Write a threat-intel entry to a Splunk lookup table.

        Parameters
        ----------
        payload : dict
            Must contain ``ioc_type`` (``"ip"``, ``"domain"``, etc.)
            and ``value``.  Additional keys are written as-is.
        """
        ioc_type = payload.get("ioc_type", "ip")
        value    = payload.get("value", "")
        if not value:
            raise SAKClientError("Splunk upsert: 'value' is required")
        return self.post_threat_intel(ioc_type, value, extra=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Remove an entry from the threat-intel lookup by id."""
        spl = f'| inputlookup ip_intel | where id!="{object_id}" | outputlookup ip_intel'
        self.search(spl)

    # ── Domain-specific operations ────────────────────────────────────────

    def search(
        self,
        spl: str,
        earliest: str = "-24h",
        latest: str   = "now",
        max_results: int = 10_000,
        blocking: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Execute a Splunk SPL search and return result rows.

        Parameters
        ----------
        spl : str
            SPL search string.  Do not include leading ``search`` keyword
            for transforming commands (``| inputlookup``, ``| stats``, etc.).
        earliest : str
            Splunk time modifier for earliest bound.  Default ``"-24h"``.
        latest : str
            Splunk time modifier for latest bound.  Default ``"now"``.
        max_results : int
            Maximum rows to return.  Default 10 000.
        blocking : bool
            If ``True`` (default), waits for the job to finish before returning.
            If ``False``, returns the job SID immediately.

        Returns
        -------
        list of dict
            Result rows.  Each dict maps field name → value.

        Raises
        ------
        SAKClientError
            If the search job fails or times out.
        """
        if not spl.startswith("|") and not spl.startswith("search"):
            spl = f"search {spl}"

        # Create search job
        job_resp = self.post(
            f"/services/search/jobs",
            data={
                "search":         spl,
                "earliest_time":  earliest,
                "latest_time":    latest,
                "output_mode":    "json",
                "exec_mode":      "normal" if not blocking else "blocking",
                "count":          str(max_results),
            },
        )
        sid = job_resp.get("sid") if isinstance(job_resp, dict) else None
        if not sid:
            raise SAKClientError("Splunk: failed to create search job")

        if not blocking:
            return [{"sid": sid}]

        # Poll until done
        deadline = time.time() + self._search_timeout
        while time.time() < deadline:
            status = self.get(
                f"/services/search/jobs/{sid}",
                params={"output_mode": "json"},
            )
            entry   = status.get("entry", [{}])[0] if isinstance(status, dict) else {}
            content = entry.get("content", {})
            disp    = content.get("dispatchState", "")
            if disp in ("DONE", "FAILED", "FINALIZED"):
                break
            time.sleep(1.0)
        else:
            raise SAKClientError(
                f"Splunk: search job {sid} timed out after {self._search_timeout}s"
            )

        if content.get("dispatchState") == "FAILED":
            raise SAKClientError(
                f"Splunk: search job {sid} failed: "
                f"{content.get('messages', '')}"
            )

        # Fetch results
        results_resp = self.get(
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": str(max_results)},
        )
        rows = results_resp.get("results", []) if isinstance(results_resp, dict) else []

        # Clean up the job
        try:
            self.delete(f"/services/search/jobs/{sid}")
        except Exception:  # noqa: BLE001
            pass

        return rows

    def get_notable_events(
        self,
        earliest: str = "-24h",
        latest: str   = "now",
        max_results: int = 500,
        filters: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch Splunk Enterprise Security Notable Events.

        Parameters
        ----------
        filters : dict, optional
            Key-value pairs appended as SPL WHERE conditions.
            e.g. ``{"severity": "critical", "status": "1"}``

        Returns
        -------
        list of dict
            Notable event rows with ``rule_name``, ``severity``,
            ``src``, ``dest``, ``event_id``, ``urgency`` etc.
        """
        where_clauses = ""
        if filters:
            where_clauses = " | where " + " AND ".join(
                f'{k}="{v}"' for k, v in filters.items()
            )
        spl = (
            f"index=notable earliest={earliest} latest={latest}"
            f"{where_clauses} | head {max_results}"
        )
        return self.search(spl, earliest=earliest, latest=latest)

    def post_threat_intel(
        self,
        ioc_type: str,
        value: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add an entry to a Splunk threat-intelligence lookup table.

        Parameters
        ----------
        ioc_type : str
            IOC type key: ``"ip"``, ``"domain"``, ``"url"``,
            ``"email"``, ``"md5"``, ``"sha256"``, ``"sha1"``.
        value : str
            The IOC value to add.
        extra : dict, optional
            Additional fields to write to the lookup row.

        Returns
        -------
        dict
            Result of the outputlookup search.
        """
        lookup = self._TI_LOOKUP.get(ioc_type, "http_intel")
        fields = {ioc_type: value, "source": "ctm-sak"}
        if extra:
            fields.update({k: str(v) for k, v in extra.items()
                           if k not in ("ioc_type", "value")})
        field_str = " ".join(f'{k}="{v}"' for k, v in fields.items())
        spl = (
            f'| makeresults | eval {field_str.replace("=", "=", 1)}'
            f' | inputlookup append=t {lookup}'
            f' | outputlookup {lookup}'
        )
        return {"lookup": lookup, "value": value, "result": self.search(spl)}

    def get_threat_intel(
        self,
        ioc_type: str,
        value_filter: Optional[str] = None,
        max_results: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Read entries from a Splunk threat-intel lookup table.

        Parameters
        ----------
        ioc_type : str
            IOC type key (see :meth:`post_threat_intel`).
        value_filter : str, optional
            Filter by value substring.
        """
        lookup = self._TI_LOOKUP.get(ioc_type, "http_intel")
        filter_clause = (
            f' | search {ioc_type}="*{value_filter}*"'
            if value_filter else ""
        )
        spl = f"| inputlookup {lookup}{filter_clause} | head {max_results}"
        return self.search(spl)

    def list_saved_searches(
        self, app: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List saved searches in the given app context.

        Parameters
        ----------
        app : str, optional
            Splunk app namespace.  Defaults to the instance ``app`` setting.

        Returns
        -------
        list of dict
            Saved search entries with ``name``, ``search``, ``cron_schedule``.
        """
        app = app or self._app
        resp = self.get(
            f"/servicesNS/-/{app}/saved/searches",
            params={"output_mode": "json", "count": 200},
        )
        return resp.get("entry", []) if isinstance(resp, dict) else []

    def get_kvstore(
        self, collection: str, query: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Read records from a Splunk KV Store collection.

        Parameters
        ----------
        collection : str
            KV Store collection name.
        query : dict, optional
            MongoDB-style query filter (JSON-encoded).

        Returns
        -------
        list of dict
            Collection records.
        """
        import json as _json
        params: Dict[str, Any] = {"output_mode": "json"}
        if query:
            params["query"] = _json.dumps(query)
        resp = self.get(
            f"/servicesNS/nobody/{self._app}/storage/collections/data/{collection}",
            params=params,
        )
        return resp if isinstance(resp, list) else []

    def post_kvstore(
        self, collection: str, record: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Write a record to a Splunk KV Store collection.

        Parameters
        ----------
        collection : str
            KV Store collection name.
        record : dict
            The record to write.

        Returns
        -------
        dict
            Response containing the ``_key`` of the stored record.
        """
        return self.post(
            f"/servicesNS/nobody/{self._app}/storage/collections/data/{collection}",
            json=record,
        )

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate a Splunk result row to STIX 2.1.

        Handles notable events (produces ``vulnerability`` or ``indicator``)
        and threat-intel lookup rows (produces ``indicator``).
        """
        # Notable event
        if "rule_name" in native or "event_id" in native:
            severity = native.get("severity", "unknown")
            conf_map = {
                "critical": 95, "high": 80,
                "medium": 60, "low": 40, "informational": 20,
            }
            return {
                "type":         "indicator",
                "id":           f"indicator--{native.get('event_id', '')}",
                "name":         native.get("rule_name", ""),
                "description":  native.get("search_name", ""),
                "pattern":      (
                    f"[ipv4-addr:value = '{native.get('src', '')}']"
                    if native.get("src") else "[unknown:value = '']"
                ),
                "pattern_type": "stix",
                "created":      native.get("_time", ""),
                "modified":     native.get("_time", ""),
                "confidence":   conf_map.get(severity, 50),
                "x_splunk_severity": severity,
                "x_splunk_urgency":  native.get("urgency", ""),
                "x_splunk_src":      native.get("src", ""),
                "x_splunk_dest":     native.get("dest", ""),
                "x_splunk_index":    native.get("index", ""),
            }

        # Threat-intel lookup row — try common field names
        value = (
            native.get("ip") or native.get("domain") or
            native.get("url") or native.get("md5") or
            native.get("sha256") or native.get("email") or
            native.get("value") or ""
        )
        ioc_type_map = {
            "ip":     "[ipv4-addr:value = '{v}']",
            "domain": "[domain-name:value = '{v}']",
            "url":    "[url:value = '{v}']",
            "md5":    "[file:hashes.MD5 = '{v}']",
            "sha256": "[file:hashes.SHA-256 = '{v}']",
            "email":  "[email-addr:value = '{v}']",
        }
        detected_key = next(
            (k for k in ("ip", "domain", "url", "md5", "sha256", "email")
             if native.get(k)), "ip"
        )
        pattern = ioc_type_map.get(
            detected_key, "[unknown:value = '{v}']"
        ).format(v=value.replace("'", "\\'"))

        return {
            "type":            "indicator",
            "id":              f"indicator--{native.get('_key', '')}",
            "name":            value,
            "pattern":         pattern,
            "pattern_type":    "stix",
            "created":         native.get("_time", ""),
            "modified":        native.get("_time", ""),
            "confidence":      70,
            "x_splunk_source": native.get("source", ""),
            "x_splunk_index":  native.get("index", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate a STIX Indicator to a Splunk threat-intel lookup row.
        """
        import re
        pattern = stix_dict.get("pattern", "")
        m = re.search(r"=\s*'([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")

        ioc_type = "ip"
        if "domain-name" in pattern:
            ioc_type = "domain"
        elif "url:" in pattern:
            ioc_type = "url"
        elif "MD5" in pattern:
            ioc_type = "md5"
        elif "SHA-256" in pattern:
            ioc_type = "sha256"
        elif "email-addr" in pattern:
            ioc_type = "email"

        return {
            "ioc_type": ioc_type,
            "value":    value,
            "source":   "ctm-sak",
        }
