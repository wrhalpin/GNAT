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
| observed-data      | event                     |
+--------------------+---------------------------+

Investigation Linking
---------------------
ThreatQ *Events* are the investigation container.  Use :meth:`link_event`
to associate a STIX indicator with an existing event, or pass ``event_id``
to :meth:`upsert_object` to link automatically on write::

    client.link_event("42", stix_indicator)
    client.upsert_object("indicator", payload, event_id="42")

Pass ``stix_type="observed-data"`` to standard CRUD methods to interact
with ThreatQ Events directly::

    client.list_objects("observed-data")
    client.get_object("observed-data", "42")

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
_SECTOR_ATTR_NAMES: frozenset = frozenset(
    {
        "targeted industry",
        "target industry",
        "targeted sector",
        "target sector",
        "sector",
        "targets",
        "victim industry",
    }
)


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
        "indicator":     "indicator",
        "threat-actor":  "adversary",
        "malware":       "malware",
        "vulnerability": "vulnerability",
        "attack-pattern": "attack-pattern",
        "observed-data": "event",
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
        """
        Return a paginated list of ThreatQ objects.

        For indicator-like types, ``?with=attributes`` is automatically
        appended so sector/industry data is included.  Events (``observed-data``)
        do not use this parameter.
        """
        resource = self._resolve_resource(stix_type)
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if stix_type != "observed-data":
            params["with"] = "attributes"
        if filters:
            params.update(filters)
        resp = self.get(f"/api/{resource}", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(
        self,
        stix_type: str,
        payload: dict[str, Any],
        event_id: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Create or update a ThreatQ object.

        Parameters
        ----------
        stix_type : str
            STIX type (used to resolve the API resource path).
        payload : dict
            Object fields.  An ``"id"`` key triggers an update (PUT).
        event_id : str, optional
            For indicator writes only: if provided, the indicator is linked
            to this ThreatQ Event after upsert via :meth:`link_event`.
        """
        resource = self._resolve_resource(stix_type)
        tq_id = payload.pop("id", None)
        if tq_id:
            result = self.put(f"/api/{resource}/{tq_id}", json=payload)
        else:
            result = self.post(f"/api/{resource}", json=payload)
        if event_id and stix_type != "observed-data":
            self.link_event(event_id, payload)
        return result

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
        Translate a ThreatQ native object to STIX 2.1.

        Dispatches to :meth:`_event_to_stix` for ThreatQ Events (detected by
        ``happened_at`` or ``event_type`` fields) and to the indicator path
        for all other objects.  Sector/industry attributes are extracted from
        the ``attributes`` array when present.

        Parameters
        ----------
        native : dict
            Raw ThreatQ API response (indicator or event record).

        Returns
        -------
        dict
            STIX 2.1 SDO (``indicator`` or ``observed-data``).
        """
        data = native.get("data", native)
        # Events have happened_at or event_type; indicators have value+type
        if "happened_at" in data or "event_type" in data:
            return self._event_to_stix(data)
        stix: dict[str, Any] = {
            "type":            "indicator",
            "id":              f"indicator--{data.get('id', '')}",
            "name":            data.get("value", ""),
            "pattern":         f"[{data.get('type', 'unknown')}:value = '{data.get('value', '')}']",
            "pattern_type":    "stix",
            "created":         data.get("created_at", ""),
            "modified":        data.get("updated_at", ""),
            "indicator_types": [data.get("class", "unknown")],
        }
        sectors = self._extract_sectors(data.get("attributes", []))
        if sectors:
            stix["x_target_sectors"] = sectors
        return stix

    @staticmethod
    def _event_to_stix(data: dict[str, Any]) -> dict[str, Any]:
        """
        Map a ThreatQ Event record to a STIX ``observed-data`` SDO.

        Parameters
        ----------
        data : dict
            ThreatQ event record (with ``title``, ``happened_at``,
            ``event_type``, etc.).
        """
        created  = data.get("created_at", "")
        modified = data.get("updated_at", created)
        happened = data.get("happened_at", created)
        return {
            "type":            "observed-data",
            "id":              f"observed-data--{data.get('id', '')}",
            "created":         created,
            "modified":        modified,
            "first_observed":  happened,
            "last_observed":   happened,
            "number_observed": 1,
            "object_refs":     [],
            "name":            data.get("title", ""),
            "description":     data.get("description", ""),
            "x_tq_event_type": data.get("event_type", ""),
            "x_tq_event_id":   str(data.get("id", "")),
        }

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
    # Investigation linking
    # ------------------------------------------------------------------

    def link_event(
        self,
        event_id: str,
        stix_obj: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Link a STIX indicator to an existing ThreatQ Event.

        Calls ``POST /api/events/{event_id}/indicators`` with an indicator
        payload derived from *stix_obj*, associating the threat intelligence
        with the event (investigation) record.

        Parameters
        ----------
        event_id : str
            ThreatQ Event numeric ID (or STIX id — the numeric portion is
            extracted automatically).
        stix_obj : dict
            STIX 2.1 indicator SDO (or any dict with ``name``/``pattern``).

        Returns
        -------
        dict
            Raw ThreatQ API response.
        """
        tq_id   = self._extract_numeric_id(event_id)
        payload = {
            "value":  stix_obj.get("name", ""),
            "type":   self._infer_tq_type(stix_obj.get("pattern", "")),
            "status": {"name": "Active"},
        }
        return self.post(f"/api/events/{tq_id}/indicators", json=payload)

    # ------------------------------------------------------------------
    # Evidence expansion
    # ------------------------------------------------------------------

    def get_event_indicators(self, event_id: str) -> list[dict[str, Any]]:
        """
        Return all indicators linked to a ThreatQ Event.

        Calls ``GET /api/events/{event_id}/indicators``.

        Parameters
        ----------
        event_id : str
            ThreatQ Event numeric ID (or STIX id — the numeric portion is
            extracted automatically).

        Returns
        -------
        list of dict
            Raw ThreatQ indicator records.
        """
        tq_id = self._extract_numeric_id(event_id)
        resp  = self.get(f"/api/events/{tq_id}/indicators", params={"with": "attributes"})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_event_adversaries(self, event_id: str) -> list[dict[str, Any]]:
        """
        Return all adversaries (threat actors) linked to a ThreatQ Event.

        Calls ``GET /api/events/{event_id}/adversaries``.

        Parameters
        ----------
        event_id : str
            ThreatQ Event numeric ID (or STIX id).

        Returns
        -------
        list of dict
            Raw ThreatQ adversary records.
        """
        tq_id = self._extract_numeric_id(event_id)
        resp  = self.get(f"/api/events/{tq_id}/adversaries")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def search_indicators_by_value(self, value: str) -> list[dict[str, Any]]:
        """
        Search ThreatQ indicators by value.

        Calls ``GET /api/indicators?search={value}&with=attributes``.

        Parameters
        ----------
        value : str
            Indicator value to search for (IP, domain, hash, URL, …).

        Returns
        -------
        list of dict
            Raw ThreatQ indicator records (includes attributes array).
        """
        resp = self.get(
            "/api/indicators",
            params={"search": value, "with": "attributes", "limit": 50},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ------------------------------------------------------------------
    # Indicator relationship methods
    # ------------------------------------------------------------------

    def get_indicator_adversaries(self, indicator_id: str) -> list[dict[str, Any]]:
        """
        Return adversaries (threat actors) linked to a ThreatQ indicator.

        Calls ``GET /api/indicators/{id}/adversaries``.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(indicator_id)
        resp  = self.get(f"/api/indicators/{tq_id}/adversaries")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_indicator_events(self, indicator_id: str) -> list[dict[str, Any]]:
        """
        Return events (investigations) linked to a ThreatQ indicator.

        Calls ``GET /api/indicators/{id}/events``.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(indicator_id)
        resp  = self.get(f"/api/indicators/{tq_id}/events")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_indicator_malware(self, indicator_id: str) -> list[dict[str, Any]]:
        """
        Return malware families linked to a ThreatQ indicator.

        Calls ``GET /api/indicators/{id}/malware``.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(indicator_id)
        resp  = self.get(f"/api/indicators/{tq_id}/malware")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_indicator_vulnerabilities(self, indicator_id: str) -> list[dict[str, Any]]:
        """
        Return vulnerabilities linked to a ThreatQ indicator.

        Calls ``GET /api/indicators/{id}/vulnerabilities``.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(indicator_id)
        resp  = self.get(f"/api/indicators/{tq_id}/vulnerabilities")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_indicator_signatures(self, indicator_id: str) -> list[dict[str, Any]]:
        """
        Return detection signatures associated with a ThreatQ indicator.

        Calls ``GET /api/indicators/{id}/signatures``.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(indicator_id)
        resp  = self.get(f"/api/indicators/{tq_id}/signatures")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_indicator_comments(self, indicator_id: str) -> list[dict[str, Any]]:
        """
        Return analyst comments on a ThreatQ indicator.

        Calls ``GET /api/indicators/{id}/comments``.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(indicator_id)
        resp  = self.get(f"/api/indicators/{tq_id}/comments")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def add_indicator_comment(self, indicator_id: str, comment: str) -> dict[str, Any]:
        """
        Post an analyst comment on a ThreatQ indicator.

        Calls ``POST /api/indicators/{id}/comments``.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        comment : str
            Comment body text.
        """
        tq_id = self._extract_numeric_id(indicator_id)
        return self.post(f"/api/indicators/{tq_id}/comments", json={"value": comment})

    def score_indicator(
        self,
        indicator_id: str,
        generated_score: int | None = None,
        manual_score: int | None = None,
    ) -> dict[str, Any]:
        """
        Update the generated or manual score on a ThreatQ indicator.

        Calls ``PUT /api/indicators/{id}/score``.  Scores range 0–10.

        Parameters
        ----------
        indicator_id : str
            ThreatQ indicator numeric ID or STIX id.
        generated_score : int, optional
            System-generated score (0–10).
        manual_score : int, optional
            Analyst-assigned manual score (0–10).
        """
        tq_id = self._extract_numeric_id(indicator_id)
        payload: dict[str, Any] = {}
        if generated_score is not None:
            payload["generated_score"] = generated_score
        if manual_score is not None:
            payload["manual_score"] = manual_score
        return self.put(f"/api/indicators/{tq_id}/score", json=payload)

    # ------------------------------------------------------------------
    # Adversary relationship methods
    # ------------------------------------------------------------------

    def get_adversary_indicators(self, adversary_id: str) -> list[dict[str, Any]]:
        """
        Return indicators linked to a ThreatQ adversary.

        Calls ``GET /api/adversaries/{id}/indicators?with=attributes``.

        Parameters
        ----------
        adversary_id : str
            ThreatQ adversary numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(adversary_id)
        resp  = self.get(
            f"/api/adversaries/{tq_id}/indicators",
            params={"with": "attributes"},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_adversary_malware(self, adversary_id: str) -> list[dict[str, Any]]:
        """
        Return malware families associated with a ThreatQ adversary.

        Calls ``GET /api/adversaries/{id}/malware``.

        Parameters
        ----------
        adversary_id : str
            ThreatQ adversary numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(adversary_id)
        resp  = self.get(f"/api/adversaries/{tq_id}/malware")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_adversary_vulnerabilities(self, adversary_id: str) -> list[dict[str, Any]]:
        """
        Return vulnerabilities associated with a ThreatQ adversary.

        Calls ``GET /api/adversaries/{id}/vulnerabilities``.

        Parameters
        ----------
        adversary_id : str
            ThreatQ adversary numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(adversary_id)
        resp  = self.get(f"/api/adversaries/{tq_id}/vulnerabilities")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_adversary_attack_patterns(self, adversary_id: str) -> list[dict[str, Any]]:
        """
        Return MITRE ATT&CK patterns associated with a ThreatQ adversary.

        Calls ``GET /api/adversaries/{id}/attack-patterns``.

        Parameters
        ----------
        adversary_id : str
            ThreatQ adversary numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(adversary_id)
        resp  = self.get(f"/api/adversaries/{tq_id}/attack-patterns")
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ------------------------------------------------------------------
    # Event (investigation) extended methods
    # ------------------------------------------------------------------

    def get_event_malware(self, event_id: str) -> list[dict[str, Any]]:
        """
        Return malware families linked to a ThreatQ Event.

        Calls ``GET /api/events/{id}/malware``.

        Parameters
        ----------
        event_id : str
            ThreatQ Event numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(event_id)
        resp  = self.get(f"/api/events/{tq_id}/malware")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_event_vulnerabilities(self, event_id: str) -> list[dict[str, Any]]:
        """
        Return vulnerabilities linked to a ThreatQ Event.

        Calls ``GET /api/events/{id}/vulnerabilities``.

        Parameters
        ----------
        event_id : str
            ThreatQ Event numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(event_id)
        resp  = self.get(f"/api/events/{tq_id}/vulnerabilities")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_event_attack_patterns(self, event_id: str) -> list[dict[str, Any]]:
        """
        Return MITRE ATT&CK patterns linked to a ThreatQ Event.

        Calls ``GET /api/events/{id}/attack-patterns``.

        Parameters
        ----------
        event_id : str
            ThreatQ Event numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(event_id)
        resp  = self.get(f"/api/events/{tq_id}/attack-patterns")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def add_event_comment(self, event_id: str, comment: str) -> dict[str, Any]:
        """
        Post a comment on a ThreatQ Event (investigation).

        Calls ``POST /api/events/{id}/comments``.

        Parameters
        ----------
        event_id : str
            ThreatQ Event numeric ID or STIX id.
        comment : str
            Comment body text.
        """
        tq_id = self._extract_numeric_id(event_id)
        return self.post(f"/api/events/{tq_id}/comments", json={"value": comment})

    # ------------------------------------------------------------------
    # Signatures
    # ------------------------------------------------------------------

    def list_signatures(
        self,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List ThreatQ detection signatures (Snort, Yara, Sigma, etc.).

        Calls ``GET /api/signatures``.

        Parameters
        ----------
        filters : dict, optional
            Query filters (e.g. ``{"type": "Snort"}``).
        """
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/api/signatures", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_signature(self, signature_id: str) -> dict[str, Any]:
        """
        Retrieve a single ThreatQ signature by ID.

        Calls ``GET /api/signatures/{id}``.

        Parameters
        ----------
        signature_id : str
            ThreatQ signature numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(signature_id)
        resp  = self.get(f"/api/signatures/{tq_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def get_signature_indicators(self, signature_id: str) -> list[dict[str, Any]]:
        """
        Return indicators linked to a ThreatQ signature.

        Calls ``GET /api/signatures/{id}/indicators``.

        Parameters
        ----------
        signature_id : str
            ThreatQ signature numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(signature_id)
        resp  = self.get(f"/api/signatures/{tq_id}/indicators")
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ------------------------------------------------------------------
    # Attachments
    # ------------------------------------------------------------------

    def list_attachments(
        self,
        entity_type: str = "",
        entity_id: str = "",
    ) -> list[dict[str, Any]]:
        """
        List ThreatQ file attachments, optionally scoped to an entity.

        Calls ``GET /api/attachments`` (unscoped) or
        ``GET /api/{entity_type}/{entity_id}/attachments`` (scoped).

        Parameters
        ----------
        entity_type : str, optional
            ThreatQ entity type (e.g. ``"indicators"``, ``"events"``).
        entity_id : str, optional
            ThreatQ entity numeric ID.
        """
        if entity_type and entity_id:
            tq_id = self._extract_numeric_id(entity_id)
            path  = f"/api/{entity_type}/{tq_id}/attachments"
        else:
            path  = "/api/attachments"
        resp = self.get(path)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upload_attachment(
        self,
        entity_type: str,
        entity_id: str,
        filename: str,
        content: bytes,
        content_type: str = "application/octet-stream",
    ) -> dict[str, Any]:
        """
        Upload a file attachment and link it to a ThreatQ entity.

        Calls ``POST /api/{entity_type}/{entity_id}/attachments`` with a
        multipart form body.

        Parameters
        ----------
        entity_type : str
            ThreatQ entity type (e.g. ``"indicators"``, ``"events"``).
        entity_id : str
            ThreatQ entity numeric ID or STIX id.
        filename : str
            Attachment filename as stored in ThreatQ.
        content : bytes
            Raw file bytes.
        content_type : str
            MIME type of the attachment.  Default ``"application/octet-stream"``.
        """
        tq_id = self._extract_numeric_id(entity_id)
        resp  = self.post(
            f"/api/{entity_type}/{tq_id}/attachments",
            files={"file": (filename, content, content_type)},
        )
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def list_tasks(
        self,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List ThreatQ tasks.

        Calls ``GET /api/tasks``.

        Parameters
        ----------
        filters : dict, optional
            Query filters (e.g. ``{"status": "open"}``).
        """
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/api/tasks", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def create_task(
        self,
        title: str,
        event_id: str = "",
        assignee: str = "",
        due_date: str = "",
        description: str = "",
    ) -> dict[str, Any]:
        """
        Create a new ThreatQ task.

        Calls ``POST /api/tasks``.

        Parameters
        ----------
        title : str
            Task title / name.
        event_id : str, optional
            ThreatQ Event ID to link this task to.
        assignee : str, optional
            Username of the assignee.
        due_date : str, optional
            ISO-8601 due date string.
        description : str, optional
            Task description.
        """
        payload: dict[str, Any] = {"title": title, "description": description}
        if event_id:
            payload["event_id"] = self._extract_numeric_id(event_id)
        if assignee:
            payload["assignee"] = assignee
        if due_date:
            payload["due_date"] = due_date
        resp = self.post("/api/tasks", json=payload)
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def complete_task(self, task_id: str) -> dict[str, Any]:
        """
        Mark a ThreatQ task as completed.

        Calls ``PUT /api/tasks/{task_id}`` with ``status = "Completed"``.

        Parameters
        ----------
        task_id : str
            ThreatQ task numeric ID.
        """
        tq_id = self._extract_numeric_id(task_id)
        return self.put(f"/api/tasks/{tq_id}", json={"status": "Completed"})

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def list_sources(self) -> list[dict[str, Any]]:
        """
        Return all ThreatQ intelligence sources defined in the deployment.

        Calls ``GET /api/sources``.
        """
        resp = self.get("/api/sources")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_source(self, source_id: str) -> dict[str, Any]:
        """
        Retrieve a specific ThreatQ source by ID.

        Calls ``GET /api/sources/{source_id}``.

        Parameters
        ----------
        source_id : str
            ThreatQ source numeric ID.
        """
        tq_id = self._extract_numeric_id(source_id)
        resp  = self.get(f"/api/sources/{tq_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    # ------------------------------------------------------------------
    # Malware / vulnerability entity helpers
    # ------------------------------------------------------------------

    def get_malware_indicators(self, malware_id: str) -> list[dict[str, Any]]:
        """
        Return indicators linked to a ThreatQ malware family.

        Calls ``GET /api/malware/{id}/indicators?with=attributes``.

        Parameters
        ----------
        malware_id : str
            ThreatQ malware numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(malware_id)
        resp  = self.get(
            f"/api/malware/{tq_id}/indicators",
            params={"with": "attributes"},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_malware_adversaries(self, malware_id: str) -> list[dict[str, Any]]:
        """
        Return adversaries associated with a ThreatQ malware family.

        Calls ``GET /api/malware/{id}/adversaries``.

        Parameters
        ----------
        malware_id : str
            ThreatQ malware numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(malware_id)
        resp  = self.get(f"/api/malware/{tq_id}/adversaries")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_vulnerability_indicators(self, vuln_id: str) -> list[dict[str, Any]]:
        """
        Return indicators linked to a ThreatQ vulnerability.

        Calls ``GET /api/vulnerabilities/{id}/indicators?with=attributes``.

        Parameters
        ----------
        vuln_id : str
            ThreatQ vulnerability numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(vuln_id)
        resp  = self.get(
            f"/api/vulnerabilities/{tq_id}/indicators",
            params={"with": "attributes"},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_vulnerability_adversaries(self, vuln_id: str) -> list[dict[str, Any]]:
        """
        Return adversaries linked to a ThreatQ vulnerability.

        Calls ``GET /api/vulnerabilities/{id}/adversaries``.

        Parameters
        ----------
        vuln_id : str
            ThreatQ vulnerability numeric ID or STIX id.
        """
        tq_id = self._extract_numeric_id(vuln_id)
        resp  = self.get(f"/api/vulnerabilities/{tq_id}/adversaries")
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_resource(self, stix_type: str) -> str:
        resource = self.stix_type_map.get(stix_type)
        if not resource:
            raise GNATClientError(f"ThreatQ: unsupported STIX type '{stix_type}'")
        if stix_type == "observed-data":
            return "events"   # already the plural form used by the ThreatQ API
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
