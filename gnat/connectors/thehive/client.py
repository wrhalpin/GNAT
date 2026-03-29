"""
gnat.connectors.thehive.client
================================
TheHive 5.x SOAR / case-management connector.

TheHive uses a single API key for authentication passed in the
``Authorization: Bearer <api_key>`` header.  The API is STIX-native in the
sense that it deals with cases, alerts, observables, and tasks — all of which
map naturally to STIX objects.

INI config::

    [thehive]
    host    = https://thehive.example.com
    api_key = YOUR_THEHIVE_API_KEY
    auth_type = token

References
----------
https://docs.strangebee.com/thehive/api-docs/
"""

from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

_API = "/api/v1"

# TheHive severity: 1=Low, 2=Medium, 3=High, 4=Critical
_SEVERITY_MAP = {1: "low", 2: "medium", 3: "high", 4: "critical"}
_SEVERITY_REV = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# TheHive TLP: 0=White, 1=Green, 2=Amber, 3=Red
_TLP_MAP = {0: "white", 1: "green", 2: "amber", 3: "red"}


class TheHiveClient(BaseClient, ConnectorMixin):
    """
    HTTP client for TheHive 5.x REST API.

    Parameters
    ----------
    host : str
        TheHive base URL, e.g. ``https://thehive.example.com``.
    api_key : str
        TheHive API key (Profile → API Key).
    org : str, optional
        Organisation name for multi-tenant deployments (sets
        ``X-Organisation`` header when provided).
    """

    stix_type_map: Dict[str, str] = {
        "case":          "case",
        "alert":         "alert",
        "observed-data": "alert",
        "indicator":     "observable",
        "course-of-action": "case/task",
    }

    def __init__(
        self,
        host: str,
        api_key: str = "",
        org: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._org     = org

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Set Bearer token and optional organisation header."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Content-Type"]  = "application/json"
        if self._org:
            self._auth_headers["X-Organisation"] = self._org

    def health_check(self) -> bool:
        """Check API health via ``GET /api/v1/status``."""
        resp = self.get(f"{_API}/status")
        return isinstance(resp, dict)

    def get_object(
        self, stix_type: str, object_id: str
    ) -> Dict[str, Any]:
        """Retrieve a case, alert, or observable by ID."""
        resource = self._resolve_resource(stix_type)
        resp = self.get(f"{_API}/{resource}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search TheHive objects.

        Uses ``POST /api/v1/query`` with a JSON filter body.

        ``filters`` may include:

        * ``_field`` + ``_value``: simple field equality filter
        * ``severity``: 1–4
        * ``status``: ``"New"``, ``"InProgress"``, ``"Closed"``, etc.
        * ``tags``: list of tag strings to match
        """
        resource = self._resolve_resource(stix_type)
        query: Dict[str, Any] = {
            "query": [{"_name": "listCase" if resource == "case" else "listAlert"}],
        }
        if filters:
            criteria = []
            for key, value in filters.items():
                criteria.append({"_field": key, "_value": value})
            if criteria:
                query["query"].append({"_name": "filter", "_and": criteria})
        query["query"].append({"_name": "page",
                               "from": (page - 1) * page_size,
                               "to": page * page_size})

        resp = self.post(f"{_API}/query", json=query)
        if isinstance(resp, list):
            return resp
        return resp.get("items", []) if isinstance(resp, dict) else []

    def upsert_object(
        self, stix_type: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create or update a TheHive case/alert.

        If ``payload`` contains ``"id"`` the object is updated via
        ``PATCH``; otherwise created via ``POST``.
        """
        resource = self._resolve_resource(stix_type)
        obj_id = payload.pop("id", None)
        if obj_id:
            resp = self.patch(f"{_API}/{resource}/{obj_id}", json=payload)
        else:
            resp = self.post(f"{_API}/{resource}", json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a case or alert by ID."""
        resource = self._resolve_resource(stix_type)
        self.delete(f"{_API}/{resource}/{object_id}")

    # ------------------------------------------------------------------
    # Extra helpers
    # ------------------------------------------------------------------

    def add_observable(
        self, case_id: str, stix_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add an observable (IOC) to an existing TheHive case.

        Extracts the IOC value and type from the STIX pattern and posts
        to ``/api/v1/case/{case_id}/observable``.
        """
        data_type, value = self._stix_to_observable(stix_obj)
        payload = {
            "dataType": data_type,
            "data":     value,
            "tlp":      1,
            "ioc":      True,
            "tags":     ["gnat"],
            "message":  stix_obj.get("description", stix_obj.get("name", "")),
        }
        resp = self.post(f"{_API}/case/{case_id}/observable", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a TheHive case/alert/observable dict to a STIX dict."""
        obj_type = native.get("_type", native.get("type", ""))
        if obj_type in ("case", "Case"):
            return self._case_to_stix(native)
        if obj_type in ("alert", "Alert"):
            return self._alert_to_stix(native)
        return self._observable_to_stix(native)

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Build a TheHive case payload from a STIX object."""
        stix_type = stix_dict.get("type", "")
        title = stix_dict.get("name", stix_dict.get("title", "Imported from GNAT"))
        sev   = min(4, max(1, stix_dict.get("confidence", 50) // 25 + 1))
        payload: Dict[str, Any] = {
            "title":       title,
            "description": stix_dict.get("description", title),
            "severity":    sev,
            "tlp":         1,
            "tags":        ["gnat", stix_type],
        }
        if stix_type == "indicator":
            payload["type"]   = "indicator"
            payload["source"] = "gnat"
        return payload

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_resource(stix_type: str) -> str:
        mapping = {
            "case":          "case",
            "alert":         "alert",
            "observed-data": "alert",
            "indicator":     "case",  # indicators become observables in cases
            "course-of-action": "case",
        }
        return mapping.get(stix_type, "case")

    def _case_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type":              "observed-data",
            "id":                f"observed-data--hive-{native.get('_id', '')}",
            "name":              native.get("title", ""),
            "description":       native.get("description", "")[:500],
            "created":           native.get("_createdAt", ""),
            "modified":          native.get("_updatedAt", ""),
            "first_observed":    native.get("startDate", ""),
            "last_observed":     native.get("endDate", ""),
            "number_observed":   1,
            "confidence":        (native.get("severity", 2) - 1) * 25,
            "x_source_platform": "thehive",
            "x_hive_case_id":    native.get("_id", ""),
            "x_hive_status":     native.get("status", ""),
            "x_hive_tags":       native.get("tags", []),
        }

    def _alert_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type":              "indicator",
            "id":                f"indicator--hive-{native.get('_id', '')}",
            "name":              native.get("title", ""),
            "description":       native.get("description", "")[:500],
            "pattern":           f"[domain-name:value = '{native.get('sourceRef', '')}']",
            "pattern_type":      "stix",
            "created":           native.get("_createdAt", ""),
            "modified":          native.get("_updatedAt", ""),
            "confidence":        (native.get("severity", 2) - 1) * 25,
            "indicator_types":   [native.get("type", "unknown")],
            "x_source_platform": "thehive",
            "x_hive_alert_id":   native.get("_id", ""),
            "x_hive_status":     native.get("status", ""),
        }

    def _observable_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        data_type = native.get("dataType", "domain")
        value     = native.get("data", "")
        pattern   = self._observable_pattern(data_type, value)
        return {
            "type":              "indicator",
            "id":                f"indicator--hive-obs-{native.get('_id', '')}",
            "name":              value,
            "pattern":           pattern,
            "pattern_type":      "stix",
            "created":           native.get("_createdAt", ""),
            "modified":          native.get("_updatedAt", ""),
            "x_source_platform": "thehive",
            "x_hive_data_type":  data_type,
            "x_hive_ioc":        native.get("ioc", False),
            "x_hive_tags":       native.get("tags", []),
        }

    @staticmethod
    def _observable_pattern(data_type: str, value: str) -> str:
        mapping = {
            "ip":     f"[ipv4-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url":    f"[url:value = '{value}']",
            "hash":   f"[file:hashes.'SHA-256' = '{value}']",
            "mail":   f"[email-message:from_ref.value = '{value}']",
            "filename": f"[file:name = '{value}']",
        }
        return mapping.get(data_type, f"[domain-name:value = '{value}']")

    @staticmethod
    def _stix_to_observable(stix_obj: Dict[str, Any]) -> tuple:
        """Return (data_type, value) from a STIX Indicator pattern."""
        import re
        pattern = stix_obj.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_obj.get("name", "")
        if "ipv4-addr" in pattern or "ipv6-addr" in pattern:
            return "ip", value
        if "domain-name" in pattern:
            return "domain", value
        if "url:" in pattern:
            return "url", value
        if "file:hashes" in pattern:
            return "hash", value
        if "email" in pattern:
            return "mail", value
        return "domain", value
