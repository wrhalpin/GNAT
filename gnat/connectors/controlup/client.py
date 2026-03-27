"""
gnat.connectors.controlup.client
=================================

ControlUp DEX Platform REST API connector.

API overview
------------
- Base URL : ``https://api.controlup.io``
- Auth     : ``Authorization: Bearer <api_key>``
- Org scope: ``orgId`` path segment — every resource URL is prefixed with
  ``/dex/v1/organizations/{orgId}/`` (DEX) or
  ``/vdi/v1/organizations/{orgId}/`` (VDI & DaaS).
- Pagination: query params ``page`` (0-based) and ``pageSize`` (max 1000).
  Responses wrap items in ``{"data": [...], "totalCount": N}``.

STIX mapping
------------
+-------------------+-----------------------------------+
| ControlUp type    | STIX 2.1 type                     |
+===================+===================================+
| device/endpoint   | ``infrastructure``                |
+-------------------+-----------------------------------+
| session           | ``observed-data`` + user-account  |
+-------------------+-----------------------------------+
| alert / event     | ``indicator``                     |
+-------------------+-----------------------------------+
| vulnerability     | ``vulnerability``                 |
+-------------------+-----------------------------------+

References
----------
https://api.controlup.io/reference
https://support.controlup.com/docs/create-an-api-key
"""

import re
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, SAKClientError
from gnat.connectors.base_connector import ConnectorMixin


class ControlUpClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the ControlUp DEX / VDI REST APIs.

    Parameters
    ----------
    host : str
        API base URL. Defaults to ``https://api.controlup.io``.
    api_key : str
        Bearer token created at app.controlup.com.
    org_id : str
        ControlUp organisation ID.
    product : str
        ``"dex"`` (endpoint/desktops) or ``"vdi"`` (virtual desktops).
        Determines the URL prefix used for all requests.
    """

    stix_type_map: Dict[str, str] = {
        "infrastructure": "devices",
        "observed-data":  "sessions",
        "indicator":      "alerts",
        "vulnerability":  "vulnerabilities",
    }

    _SEVERITY_CONFIDENCE: Dict[str, int] = {
        "critical": 90,
        "high":     75,
        "medium":   55,
        "low":      35,
        "info":     20,
    }

    def __init__(
        self,
        host: str = "https://api.controlup.io",
        api_key: str = "",
        org_id: str = "",
        product: str = "dex",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._org_id = org_id
        self._product = product.lower()

    # ── URL helpers ───────────────────────────────────────────────────────

    @property
    def _prefix(self) -> str:
        """URL prefix for all resource paths."""
        if self._product == "vdi":
            return f"/vdi/v1/organizations/{self._org_id}"
        return f"/dex/v1/organizations/{self._org_id}"

    def _url(self, path: str) -> str:
        """Combine prefix with a resource path."""
        return f"{self._prefix}/{path.lstrip('/')}"

    # ── ConnectorMixin contract ───────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Bearer token header; ControlUp uses static API keys."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """Ping the devices endpoint with page size 1."""
        try:
            if self._product == "vdi":
                resp = self.get(self._url("sessions"), params={"pageSize": 1})
            else:
                resp = self.get(self._url("devices"), params={"pageSize": 1})
            return isinstance(resp, dict)
        except SAKClientError:
            return False

    # ── CRUD ─────────────────────────────────────────────────────────────

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """
        Fetch a single ControlUp object by STIX type and native ID.

        Parameters
        ----------
        stix_type : str
            One of ``infrastructure``, ``observed-data``, ``indicator``,
            ``vulnerability``.
        object_id : str
            Native ControlUp resource ID.

        Returns
        -------
        dict
            Raw API response for the resource.
        """
        route_map = {
            "infrastructure": f"devices/{object_id}",
            "observed-data":  f"sessions/{object_id}",
            "indicator":      f"alerts/{object_id}",
            "vulnerability":  f"vulnerabilities/{object_id}",
        }
        route = route_map.get(stix_type)
        if route is None:
            raise SAKClientError(
                f"ControlUp connector does not support stix_type={stix_type!r}"
            )
        resp = self.get(self._url(route))
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List ControlUp objects of a given STIX type.

        Parameters
        ----------
        stix_type : str
            One of ``infrastructure``, ``observed-data``, ``indicator``,
            ``vulnerability``.
        filters : dict, optional
            Additional query parameters forwarded to the API (e.g.
            ``{"status": "active"}`` for devices, ``{"severity": "high"}``
            for alerts).
        page : int
            1-based page number (converted internally to 0-based).
        page_size : int
            Number of records per page (max 1000).

        Returns
        -------
        list[dict]
            List of raw API objects.
        """
        route_map = {
            "infrastructure": "devices",
            "observed-data":  "sessions",
            "indicator":      "alerts",
            "vulnerability":  "vulnerabilities",
        }
        route = route_map.get(stix_type)
        if route is None:
            raise SAKClientError(
                f"ControlUp connector does not support stix_type={stix_type!r}"
            )
        params: Dict[str, Any] = {
            "page":     page - 1,   # API is 0-based
            "pageSize": min(page_size, 1000),
        }
        if filters:
            params.update(filters)
        resp = self.get(self._url(route), params=params)
        if isinstance(resp, dict):
            return resp.get("data", resp.get("items", []))
        return []

    def upsert_object(
        self, stix_type: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        ControlUp is primarily read-only from an external integration
        perspective. The only writable surface exposed by the API is device
        **tags** (infrastructure objects).

        Parameters
        ----------
        stix_type : str
            Must be ``"infrastructure"`` (tags on a device).
        payload : dict
            Must contain ``"device_id"`` and ``"tags"`` (list of str).

        Returns
        -------
        dict
            API response confirming the tag update.
        """
        if stix_type != "infrastructure":
            raise SAKClientError(
                f"ControlUp only supports upsert for 'infrastructure' (device tags), "
                f"not {stix_type!r}. The API is read-only for other resource types."
            )
        device_id = payload.get("device_id")
        if not device_id:
            raise SAKClientError("payload must include 'device_id' for tag upsert.")
        tags = payload.get("tags", [])
        return self.put(
            self._url(f"devices/{device_id}/tags"),
            json_body={"tags": tags},
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """
        Delete is not supported by the ControlUp REST API.

        Raises
        ------
        SAKClientError
            Always, as the API offers no delete endpoints.
        """
        raise SAKClientError(
            "ControlUp does not expose delete operations via the REST API. "
            "Use the ControlUp web console to remove objects."
        )

    # ── DEX-specific methods ──────────────────────────────────────────────

    def get_device(self, device_id: str) -> Dict[str, Any]:
        """
        Fetch a single device/endpoint by its ControlUp device ID.

        Parameters
        ----------
        device_id : str
            Unique ControlUp device identifier.

        Returns
        -------
        dict
            Device record including hostname, OS, health score, tags, and
            last-seen timestamp.
        """
        return self.get_object("infrastructure", device_id)

    def list_devices(
        self,
        status: Optional[str] = None,
        os_family: Optional[str] = None,
        tag: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List managed endpoints/devices.

        Parameters
        ----------
        status : str, optional
            Filter by device status: ``"active"``, ``"inactive"``,
            ``"offline"``.
        os_family : str, optional
            Filter by OS family: ``"windows"``, ``"macos"``, ``"linux"``.
        tag : str, optional
            Filter by device tag name.
        page : int
            1-based page number.
        page_size : int
            Records per page.

        Returns
        -------
        list[dict]
            Device records.
        """
        filters: Dict[str, Any] = {}
        if status:
            filters["status"] = status
        if os_family:
            filters["osFamily"] = os_family
        if tag:
            filters["tag"] = tag
        return self.list_objects("infrastructure", filters=filters,
                                 page=page, page_size=page_size)

    def list_sessions(
        self,
        username: Optional[str] = None,
        device_id: Optional[str] = None,
        state: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List active or recent user sessions.

        Parameters
        ----------
        username : str, optional
            Filter by username (partial match supported).
        device_id : str, optional
            Filter sessions to a specific device.
        state : str, optional
            Session state: ``"active"``, ``"disconnected"``, ``"idle"``.
        page : int
            1-based page number.
        page_size : int
            Records per page.

        Returns
        -------
        list[dict]
            Session records.
        """
        filters: Dict[str, Any] = {}
        if username:
            filters["username"] = username
        if device_id:
            filters["deviceId"] = device_id
        if state:
            filters["state"] = state
        return self.list_objects("observed-data", filters=filters,
                                 page=page, page_size=page_size)

    def list_alerts(
        self,
        severity: Optional[str] = None,
        resolved: Optional[bool] = None,
        device_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List security alerts and trigger events.

        Parameters
        ----------
        severity : str, optional
            ``"critical"``, ``"high"``, ``"medium"``, ``"low"``, ``"info"``.
        resolved : bool, optional
            ``True`` for closed/resolved alerts, ``False`` for open only.
        device_id : str, optional
            Scope alerts to a specific endpoint.
        page : int
            1-based page number.
        page_size : int
            Records per page.

        Returns
        -------
        list[dict]
            Alert records.
        """
        filters: Dict[str, Any] = {}
        if severity:
            filters["severity"] = severity
        if resolved is not None:
            filters["resolved"] = str(resolved).lower()
        if device_id:
            filters["deviceId"] = device_id
        return self.list_objects("indicator", filters=filters,
                                 page=page, page_size=page_size)

    def query_data_index(
        self,
        index: str,
        metrics: Optional[List[str]] = None,
        filters: Optional[Dict[str, Any]] = None,
        time_range: Optional[Dict[str, str]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        """
        Query the ControlUp Data Access Layer (DAL) for a named data index.

        The DAL exposes raw telemetry indices such as ``"devices"``,
        ``"sessions"``, ``"processes"``, ``"network"``, and
        ``"user-experience"``.  Queries are POST-based with a structured
        body rather than GET query parameters.

        Parameters
        ----------
        index : str
            Data index name (e.g. ``"devices"``, ``"sessions"``,
            ``"processes"``, ``"network"``).
        metrics : list[str], optional
            Specific metric columns to return. ``None`` returns all columns.
        filters : dict, optional
            Key/value filter conditions applied server-side.
        time_range : dict, optional
            ``{"from": "ISO8601", "to": "ISO8601"}`` window.
        page : int
            1-based page number.
        page_size : int
            Records per page.

        Returns
        -------
        dict
            Raw DAL response containing ``"data"`` list and ``"totalCount"``.

        Examples
        --------
        >>> cu = ControlUpClient(host=..., api_key=..., org_id=...)
        >>> cu.authenticate()
        >>> result = cu.query_data_index(
        ...     index="processes",
        ...     metrics=["processName", "cpuUsage", "memoryUsage"],
        ...     filters={"deviceId": "abc123"},
        ... )
        >>> result["data"]
        [{"processName": "chrome.exe", "cpuUsage": 12.4, ...}, ...]
        """
        body: Dict[str, Any] = {
            "index":    index,
            "page":     page - 1,
            "pageSize": min(page_size, 1000),
        }
        if metrics:
            body["metrics"] = metrics
        if filters:
            body["filters"] = filters
        if time_range:
            body["timeRange"] = time_range
        resp = self.post(self._url("data/query"), json_body=body)
        return resp if isinstance(resp, dict) else {"data": [], "totalCount": 0}

    def get_session_statistics(
        self, device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retrieve aggregated session statistics.

        Parameters
        ----------
        device_id : str, optional
            Scope statistics to a single endpoint.

        Returns
        -------
        dict
            Statistics payload including active/idle/disconnected counts
            and average logon duration.
        """
        params: Dict[str, Any] = {}
        if device_id:
            params["deviceId"] = device_id
        resp = self.get(self._url("sessions/statistics"), params=params)
        return resp if isinstance(resp, dict) else {}

    # ── STIX translation ──────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a ControlUp native object to STIX 2.1 format.

        The method auto-detects the object type from the presence of
        discriminator keys in the native dict.

        Parameters
        ----------
        native : dict
            Raw ControlUp API object.

        Returns
        -------
        dict
            STIX 2.1 representation.
        """
        if "cveId" in native or "cvssScore" in native:
            return self._vuln_to_stix(native)
        if "alertId" in native or ("alertType" in native and "severity" in native):
            return self._alert_to_stix(native)
        if "sessionId" in native or "sessionState" in native:
            return self._session_to_stix(native)
        if "hostname" in native or "osFamily" in native or "deviceId" in native:
            return self._device_to_stix(native)
        # Fallback: generic observed-data
        return self._generic_to_stix(native)

    def _device_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """ControlUp device/endpoint → STIX infrastructure SDO."""
        device_id  = native.get("deviceId", native.get("id", ""))
        hostname   = native.get("hostname", native.get("name", ""))
        os_name    = native.get("osName", "")
        os_version = native.get("osVersion", "")
        os_family  = native.get("osFamily", "").lower()
        last_seen  = native.get("lastSeen", native.get("lastContact", ""))
        tags       = native.get("tags", [])
        health     = native.get("healthScore", native.get("dexScore"))
        ip_addrs   = native.get("ipAddresses", [])
        status     = native.get("status", native.get("connectionStatus", ""))

        # Map OS family to STIX infrastructure type labels
        infra_type = "workstation"
        if os_family in ("windows-server", "linux", "unix"):
            infra_type = "server"

        stix: Dict[str, Any] = {
            "type":                "infrastructure",
            "id":                  f"infrastructure--cu-{device_id}",
            "name":                hostname,
            "infrastructure_types": [infra_type],
            "created":             last_seen,
            "modified":            last_seen,
            "x_cu_device_id":      device_id,
            "x_cu_os_name":        os_name,
            "x_cu_os_version":     os_version,
            "x_cu_os_family":      os_family,
            "x_cu_status":         status,
            "x_cu_health_score":   health,
            "x_cu_tags":           tags[:20],
            "x_cu_ip_addresses":   ip_addrs[:10],
            "x_source_platform":   "controlup",
        }
        return stix

    def _session_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """ControlUp session → STIX observed-data SDO."""
        session_id   = native.get("sessionId", native.get("id", ""))
        username     = native.get("username", "")
        device_id    = native.get("deviceId", "")
        hostname     = native.get("hostname", "")
        state        = native.get("sessionState", "")
        logon_time   = native.get("logonTime", "")
        last_active  = native.get("lastActivity", logon_time)
        logon_dur    = native.get("logonDuration")    # seconds
        protocol     = native.get("protocol", "")

        user_ref: Dict[str, Any] = {
            "type":        "user-account",
            "user_id":     username,
            "display_name": native.get("displayName", username),
            "x_domain":    native.get("domain", ""),
        }

        stix: Dict[str, Any] = {
            "type":              "observed-data",
            "id":                f"observed-data--cu-{session_id}",
            "first_observed":    logon_time,
            "last_observed":     last_active,
            "number_observed":   1,
            "object_refs":       [],   # populated by caller if bundling
            "x_cu_session_id":   session_id,
            "x_cu_username":     username,
            "x_cu_device_id":    device_id,
            "x_cu_hostname":     hostname,
            "x_cu_state":        state,
            "x_cu_protocol":     protocol,
            "x_cu_logon_duration_s": logon_dur,
            "x_cu_user_ref":     user_ref,
            "x_source_platform": "controlup",
        }
        return stix

    def _alert_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """ControlUp alert/trigger event → STIX indicator SDO."""
        alert_id   = native.get("alertId", native.get("id", ""))
        name       = native.get("name", native.get("alertType", "ControlUp Alert"))
        severity   = native.get("severity", "medium").lower()
        description = native.get("description", native.get("message", ""))
        created    = native.get("createdAt", native.get("triggeredAt", ""))
        resolved   = native.get("resolved", False)
        device_id  = native.get("deviceId", "")
        hostname   = native.get("hostname", "")
        alert_type = native.get("alertType", "")
        category   = native.get("category", "")

        # Build a generic pattern — ControlUp alerts are behavioural, not IOC-based
        pattern = f"[process:name = '{alert_type}']" if alert_type else "[domain-name:value = 'controlup.alert']"
        confidence = self._SEVERITY_CONFIDENCE.get(severity, 50)

        stix: Dict[str, Any] = {
            "type":             "indicator",
            "id":               f"indicator--cu-{alert_id}",
            "name":             name,
            "description":      description[:500],
            "pattern":          pattern,
            "pattern_type":     "stix",
            "created":          created,
            "modified":         created,
            "confidence":       confidence,
            "indicator_types":  ["anomalous-activity"],
            "x_cu_alert_id":    alert_id,
            "x_cu_severity":    severity,
            "x_cu_category":    category,
            "x_cu_alert_type":  alert_type,
            "x_cu_device_id":   device_id,
            "x_cu_hostname":    hostname,
            "x_cu_resolved":    resolved,
            "x_source_platform": "controlup",
        }
        return stix

    def _vuln_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """ControlUp vulnerability finding → STIX vulnerability SDO."""
        vuln_id   = native.get("id", native.get("cveId", ""))
        cve_id    = native.get("cveId", "")
        name      = cve_id or native.get("title", vuln_id)
        severity  = native.get("severity", "")
        cvss      = native.get("cvssScore")
        desc      = native.get("description", "")
        detected  = native.get("detectedAt", native.get("firstSeen", ""))
        device_id = native.get("deviceId", "")

        return {
            "type":               "vulnerability",
            "id":                 f"vulnerability--cu-{vuln_id}",
            "name":               name,
            "description":        desc[:500],
            "created":            detected,
            "modified":           detected,
            "x_cve_id":           cve_id,
            "x_cvss_score":       cvss,
            "x_severity":         severity,
            "x_cu_device_id":     device_id,
            "x_source_platform":  "controlup",
        }

    def _generic_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback: wrap an unknown ControlUp object as observed-data."""
        obj_id  = str(native.get("id", native.get("deviceId", "unknown")))
        created = native.get("createdAt", native.get("timestamp", ""))
        return {
            "type":              "observed-data",
            "id":                f"observed-data--cu-{obj_id}",
            "first_observed":    created,
            "last_observed":     created,
            "number_observed":   1,
            "object_refs":       [],
            "x_cu_raw":          native,
            "x_source_platform": "controlup",
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a STIX object back to a ControlUp-compatible payload.

        Currently only ``infrastructure`` (device tag update) is writable.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 object dict.

        Returns
        -------
        dict
            ControlUp API-compatible payload.
        """
        stix_type = stix_dict.get("type", "")
        if stix_type == "infrastructure":
            return {
                "device_id": stix_dict.get("x_cu_device_id", ""),
                "tags":      stix_dict.get("x_cu_tags", []),
            }
        if stix_type == "indicator":
            # Extract the raw value from a STIX pattern for reference only
            pattern = stix_dict.get("pattern", "")
            m = re.search(r"= '([^']+)'", pattern)
            return {
                "name":     stix_dict.get("name", ""),
                "value":    m.group(1) if m else "",
                "severity": stix_dict.get("x_cu_severity", "medium"),
            }
        return {"name": stix_dict.get("name", ""), "type": stix_type}
