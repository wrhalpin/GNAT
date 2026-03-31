"""
gnat.connectors.greymatter.client
=====================================

ReliaQuest GreyMatter (formerly EclecticIQ) connector.

Authentication
--------------
OAuth2 client-credentials flow::

    [greymatter]
    host          = https://api.greymatter.io
    client_id     = <client-id>
    client_secret = <client-secret>
    auth_type     = oauth2

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | GreyMatter Entity Type           |
+====================+==================================+
| indicator          | observable-value                 |
+--------------------+----------------------------------+
| threat-actor       | threat-actor                     |
+--------------------+----------------------------------+
| malware            | malware                          |
+--------------------+----------------------------------+
| vulnerability      | vulnerability                    |
+--------------------+----------------------------------+
| attack-pattern     | attack-pattern                   |
+--------------------+----------------------------------+

API Reference
-------------
GreyMatter exposes a REST API under ``/v1``.  Key resources:

* ``/v1/observables``       — observable values (IPs, domains, hashes, URLs)
* ``/v1/indicators``        — compound indicators with patterns
* ``/v1/incidents``         — security incidents
* ``/v1/threat-actors``     — threat actor entities
* ``/v1/malware``           — malware families / samples
* ``/v1/vulnerabilities``   — CVE / vulnerability records
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class GreyMatterClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the ReliaQuest GreyMatter REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://api.greymatter.io"``.
    client_id : str
        OAuth2 client ID.
    client_secret : str
        OAuth2 client secret.
    verify_ssl : bool
        Verify TLS.  Default ``True``.
    """

    stix_type_map: dict[str, str] = {
        "indicator":      "observables",
        "threat-actor":   "threat-actors",
        "malware":        "malware",
        "vulnerability":  "vulnerabilities",
        "attack-pattern": "attack-patterns",
    }

    # GreyMatter observable type → STIX pattern template
    _OBS_PATTERN: dict[str, str] = {
        "ipv4":   "[ipv4-addr:value = '{v}']",
        "ipv6":   "[ipv6-addr:value = '{v}']",
        "domain": "[domain-name:value = '{v}']",
        "url":    "[url:value = '{v}']",
        "md5":    "[file:hashes.MD5 = '{v}']",
        "sha1":   "[file:hashes.SHA-1 = '{v}']",
        "sha256": "[file:hashes.SHA-256 = '{v}']",
        "email":  "[email-addr:value = '{v}']",
    }

    def __init__(
        self,
        host: str,
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._client_id     = client_id
        self._client_secret = client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Obtain an OAuth2 Bearer token via client-credentials flow.

        Raises
        ------
        GNATClientError
            If the token request fails or the response has no access_token.
        """
        resp = self.post(
            "/v1/auth/token",
            data={
                "grant_type":    "client_credentials",
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
            },
        )
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("GreyMatter: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the GreyMatter health endpoint."""
        self.get("/v1/health")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single GreyMatter object by id.

        Parameters
        ----------
        stix_type : str
            STIX type string (resolves the API resource path).
        object_id : str
            GreyMatter entity UUID (or STIX id — the UUID portion is extracted).
        """
        resource = self._resolve(stix_type)
        gm_id    = self._to_gm_id(object_id)
        return self.get(f"/v1/{resource}/{gm_id}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List GreyMatter objects of a given STIX type.

        Parameters
        ----------
        filters : dict, optional
            GreyMatter query filters (e.g. ``{"type": "ipv4", "tag": "apt28"}``).
        """
        resource = self._resolve(stix_type)
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get(f"/v1/{resource}", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any],
                      linked_cases: list[str] | None = None,
                      **kwargs: Any) -> dict[str, Any]:
        """
        Create or update a GreyMatter object.

        Parameters
        ----------
        stix_type : str
            STIX type; resolves the API resource path.
        payload : dict
            Object fields.  An ``"id"`` key triggers an update (PUT).
        linked_cases : list of str, optional
            GreyMatter investigation / case IDs to link.  When provided,
            ``linked_cases`` is merged into *payload* before the request.
        """
        resource = self._resolve(stix_type)
        gm_id    = payload.pop("id", None)
        if linked_cases:
            payload["linked_cases"] = linked_cases
        if gm_id:
            return self.put(f"/v1/{resource}/{gm_id}", json=payload)
        return self.post(f"/v1/{resource}", json=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a GreyMatter object."""
        resource = self._resolve(stix_type)
        self.delete(f"/v1/{resource}/{self._to_gm_id(object_id)}")

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a GreyMatter observable/entity dict to STIX 2.1.

        Handles both observable-value records and full entity records.
        """
        data     = native.get("data", native)
        gm_type  = data.get("type", "")
        value    = data.get("value", data.get("name", ""))
        pattern  = self._OBS_PATTERN.get(
            gm_type, "[unknown:value = '{v}']"
        ).format(v=value.replace("'", "\\'"))

        return {
            "type":            "indicator",
            "id":              f"indicator--{data.get('id', '')}",
            "name":            value,
            "description":     data.get("description", ""),
            "pattern":         pattern,
            "pattern_type":    "stix",
            "created":         data.get("created_at", ""),
            "modified":        data.get("updated_at", ""),
            "indicator_types": [data.get("classification", "unknown")],
            "confidence":      data.get("confidence", 50),
            "x_gm_type":       gm_type,
            "x_gm_tags":       data.get("tags", []),
            "x_gm_severity":   data.get("severity", ""),
            "x_tlp":           data.get("tlp", "white"),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX Indicator dict to a GreyMatter observable payload.
        """
        pattern = stix_dict.get("pattern", "")
        gm_type = self._infer_gm_type(pattern)
        value   = self._extract_value(pattern)
        return {
            "type":        gm_type,
            "value":       value or stix_dict.get("name", ""),
            "description": stix_dict.get("description", ""),
            "confidence":  stix_dict.get("confidence", 50),
            "tlp":         stix_dict.get("x_tlp", "white"),
            "tags":        stix_dict.get("x_gm_tags", []),
        }

    # ── Investigation linking ─────────────────────────────────────────────

    def link_investigation(
        self,
        case_id: str,
        stix_obj: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Link a STIX object to an existing GreyMatter investigation (case).

        Calls ``POST /v1/incidents/{case_id}/linked_observables`` with the
        observable value derived from *stix_obj*, associating the threat
        intelligence with the investigation record.

        Parameters
        ----------
        case_id : str
            GreyMatter investigation / incident UUID.
        stix_obj : dict
            STIX 2.1 indicator SDO (or any dict with ``name``/``pattern``).

        Returns
        -------
        dict
            Raw GreyMatter API response.

        Raises
        ------
        GNATClientError
            If the link request fails.
        """
        gm_type  = self._infer_gm_type(stix_obj.get("pattern", ""))
        value    = self._extract_value(stix_obj.get("pattern", ""))
        if not value:
            value = stix_obj.get("name", "")
        payload = {
            "case_id":     case_id,
            "type":        gm_type,
            "value":       value,
            "stix_id":     stix_obj.get("id", ""),
            "description": stix_obj.get("description", ""),
        }
        return self.post(f"/v1/incidents/{case_id}/linked_observables", json=payload)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _resolve(self, stix_type: str) -> str:
        resource = self.stix_type_map.get(stix_type)
        if not resource:
            raise GNATClientError(
                f"GreyMatter: unsupported STIX type '{stix_type}'. "
                f"Supported: {sorted(self.stix_type_map.keys())}"
            )
        return resource

    @staticmethod
    def _to_gm_id(stix_or_plain_id: str) -> str:
        """Extract UUID from a STIX id or return as-is."""
        return stix_or_plain_id.split("--", 1)[-1]

    @staticmethod
    def _infer_gm_type(pattern: str) -> str:
        pattern = pattern.lower()
        if "ipv4-addr"   in pattern: return "ipv4"
        if "ipv6-addr"   in pattern: return "ipv6"
        if "domain-name" in pattern: return "domain"
        if "url:"        in pattern: return "url"
        if "sha-256"     in pattern: return "sha256"
        if "sha-1"       in pattern: return "sha1"
        if "md5"         in pattern: return "md5"
        if "email-addr"  in pattern: return "email"
        return "unknown"

    @staticmethod
    def _extract_value(pattern: str) -> str:
        """Pull the quoted value out of a simple STIX pattern."""
        import re
        m = re.search(r"=\s*'([^']+)'", pattern)
        return m.group(1) if m else ""
