"""
gnat.connectors.threatq.client
==================================

ThreatQ Threat Intelligence Platform connector.

Authentication
--------------
ThreatQ uses OAuth2 client-credentials flow.  Provide ``client_id`` and
``client_secret`` (and optionally ``username`` / ``password`` for password
grant) in the INI config::

    [threatq]
    host          = https://threatq.example.com
    client_id     = my-client-id
    client_secret = s3cr3t
    auth_type     = oauth2

STIX Type Mapping
-----------------
+--------------------+---------------------------+
| STIX Type          | ThreatQ Type              |
+====================+===========================+
| indicator          | indicator                 |
+--------------------+---------------------------+
| threat-actor       | adversary                 |
+--------------------+---------------------------+
| malware            | malware                   |
+--------------------+---------------------------+
| vulnerability      | vulnerability             |
+--------------------+---------------------------+
| attack-pattern     | attack-pattern            |
+--------------------+---------------------------+

Sector / Industry attributes
-----------------------------
ThreatQ stores sector and industry context as entries in a generic
``attributes`` array (not as top-level fields).  Attributes are only
returned when ``?with=attributes`` is included in the request.

The attribute ``name`` strings are configured per-deployment and are not
standardised across ThreatQ instances.  GNAT matches against the following
known variants (case-insensitive):

* ``"Targeted Industry"`` / ``"Target Industry"``
* ``"Targeted Sector"``  / ``"Target Sector"`` / ``"Sector"``
* ``"Targets"`` (used by the Adversary Reader CDF feed)
* ``"Victim Industry"``

Use :meth:`get_attribute_types` to discover the exact names used in a
specific deployment.  Matched values are written to ``x_target_sectors``
on the returned STIX dict.
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

# Attribute name variants recognised as sector/industry — case-insensitive.
_SECTOR_ATTR_NAMES: frozenset = frozenset({
    "targeted industry",
    "target industry",
    "targeted sector",
    "target sector",
    "sector",
    "targets",
    "victim industry",
})


class ThreatQClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the ThreatQ REST API.

    Parameters
    ----------
    host : str
        Base URL of the ThreatQ instance.
    client_id : str
        OAuth2 client ID.
    client_secret : str
        OAuth2 client secret.
    auth_type : str
        Authentication type.  Currently only ``"oauth2"`` is supported.
    verify_ssl : bool
        Verify TLS certificates.  Default ``True``.
    timeout : float
        Request timeout in seconds.  Default ``30``.
    **kwargs
        Forwarded to :class:`~gnat.clients.base.BaseClient`.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "indicator",
        "threat-actor": "adversary",
        "malware": "malware",
        "vulnerability": "vulnerability",
        "attack-pattern": "attack-pattern",
    }

    def __init__(
        self,
        host: str,
        client_id: str = "",
        client_secret: str = "",
        auth_type: str = "oauth2",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret
        self._auth_type = auth_type

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Obtain an OAuth2 access token and inject it as a Bearer header.

        Raises
        ------
        GNATClientError
            If the token request fails.
        """
        payload = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        resp = self.post("/api/token", data=payload)
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("ThreatQ: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    # ------------------------------------------------------------------
    # ConnectorMixin — CRUD
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Return True if the ThreatQ instance is reachable."""
        self.get("/api/ping")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a ThreatQ object by its numeric id.

        Parameters
        ----------
        stix_type : str
            STIX type string (used to resolve the API path).
        object_id : str
            STIX id or ThreatQ numeric id.

        Returns
        -------
        dict
            Raw ThreatQ API response (includes ``attributes`` array).
        """
        resource = self._resolve_resource(stix_type)
        tq_id = self._extract_numeric_id(object_id)
        return self.get(
            f"/api/{resource}/{tq_id}",
            params={"with": "tags,score,attributes"},
        )

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """Return a paginated list of ThreatQ objects (includes attributes)."""
        resource = self._resolve_resource(stix_type)
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
            "with": "attributes",
        }
        if filters:
            params.update(filters)
        resp = self.get(f"/api/{resource}", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update a ThreatQ object."""
        resource = self._resolve_resource(stix_type)
        tq_id = payload.pop("id", None)
        if tq_id:
            return self.put(f"/api/{resource}/{tq_id}", json=payload)
        return self.post(f"/api/{resource}", json=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a ThreatQ object."""
        resource = self._resolve_resource(stix_type)
        tq_id = self._extract_numeric_id(object_id)
        self.delete(f"/api/{resource}/{tq_id}")

    def get_attribute_types(self) -> list[str]:
        """
        Return all attribute type names configured in this ThreatQ deployment.

        Use this to discover the exact attribute name strings for sector/industry
        fields — they vary between deployments.  The names returned can be
        compared against :data:`_SECTOR_ATTR_NAMES` or used to extend it via
        the ``[sector_aliases]`` INI section.

        Returns
        -------
        list of str
            Attribute type names (e.g. ``["Targeted Industry", "Source", ...]``).
        """
        resp = self.get("/api/attribute_types")
        return [
            item.get("name", "")
            for item in (resp.get("data", []) if isinstance(resp, dict) else [])
            if item.get("name")
        ]

    # ------------------------------------------------------------------
    # ConnectorMixin — STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a ThreatQ indicator dict to STIX 2.1 format.

        Sector and industry context is extracted from the ``attributes`` array
        when present (requires ``?with=attributes`` on the originating request,
        which :meth:`get_object` and :meth:`list_objects` both include).
        Matched attribute values are written to ``x_target_sectors``.

        Parameters
        ----------
        native : dict
            Raw ThreatQ API indicator object.

        Returns
        -------
        dict
            Partial STIX Indicator dict.
        """
        data = native.get("data", native)
        stix: dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{data.get('id', '')}",
            "name": data.get("value", ""),
            "pattern": f"[{data.get('type', 'unknown')}:value = '{data.get('value', '')}']",
            "pattern_type": "stix",
            "created": data.get("created_at", ""),
            "modified": data.get("updated_at", ""),
            "indicator_types": [data.get("class", "unknown")],
        }
        sectors = self._extract_sectors(data.get("attributes", []))
        if sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX Indicator dict to a ThreatQ API payload.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 indicator dict.

        Returns
        -------
        dict
            ThreatQ-compatible request body.
        """
        return {
            "value": stix_dict.get("name", ""),
            "type": self._infer_tq_type(stix_dict.get("pattern", "")),
            "status": {"name": "Active"},
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_resource(self, stix_type: str) -> str:
        resource = self.stix_type_map.get(stix_type)
        if not resource:
            raise GNATClientError(f"ThreatQ: unsupported STIX type '{stix_type}'")
        return resource + "s"  # ThreatQ uses plural endpoints

    @staticmethod
    def _extract_sectors(attributes: list[dict[str, Any]]) -> list[str]:
        """
        Extract sector/industry values from a ThreatQ attributes array.

        Matches ``attributes[].name`` case-insensitively against the known
        sector attribute name variants (:data:`_SECTOR_ATTR_NAMES`).

        Parameters
        ----------
        attributes : list of dict
            The ``attributes`` array from a ThreatQ API response.

        Returns
        -------
        list of str
            Sector/industry string values (may be empty).
        """
        sectors = []
        for attr in attributes:
            name = str(attr.get("name", "")).lower().strip()
            if name in _SECTOR_ATTR_NAMES:
                val = str(attr.get("value", "")).strip()
                if val:
                    sectors.append(val)
        return sectors

    @staticmethod
    def _extract_numeric_id(stix_or_numeric_id: str) -> str:
        """Extract the numeric portion from a STIX id or return as-is."""
        if "--" in stix_or_numeric_id:
            return stix_or_numeric_id.split("--", 1)[1]
        return stix_or_numeric_id

    @staticmethod
    def _infer_tq_type(pattern: str) -> str:
        """Infer the ThreatQ indicator type from a STIX pattern string."""
        pattern = pattern.lower()
        if "ipv4-addr" in pattern:
            return "IP Address"
        if "domain-name" in pattern:
            return "FQDN"
        if "url" in pattern:
            return "URL"
        if "file:hashes" in pattern:
            return "MD5"
        if "email-addr" in pattern:
            return "Email Address"
        return "String"
