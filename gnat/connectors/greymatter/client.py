# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
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
* ``/v1/incidents``         — security investigations / cases (``observed-data``)
* ``/v1/threat-actors``     — threat actor entities
* ``/v1/malware``           — malware families / samples
* ``/v1/vulnerabilities``   — CVE / vulnerability records

Investigation CRUD
------------------
Pass ``stix_type="observed-data"`` to the standard CRUD methods to interact
with GreyMatter investigations (cases)::

    client.list_objects("observed-data")
    client.get_object("observed-data", case_uuid)
    client.upsert_object("observed-data", {"title": "APT28 Campaign"})

Use :meth:`link_investigation` to link a STIX observable to an existing case.
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
        "observed-data":  "incidents",
    }

    # GreyMatter observable type → STIX pattern template
    _OBS_PATTERN: dict[str, str] = {
        "ipv4":   "[ipv4-addr:value = '{v}']",
        "ipv6":   "[ipv6-addr:value = '{v}']",
        "domain": "[domain-name:value = '{v}']",
        "url": "[url:value = '{v}']",
        "md5": "[file:hashes.MD5 = '{v}']",
        "sha1": "[file:hashes.SHA-1 = '{v}']",
        "sha256": "[file:hashes.SHA-256 = '{v}']",
        "email": "[email-addr:value = '{v}']",
    }

    def __init__(
        self,
        host: str,
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
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
                "grant_type": "client_credentials",
                "client_id": self._client_id,
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
        gm_id = self._to_gm_id(object_id)
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
        gm_id = payload.pop("id", None)
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
        Translate a GreyMatter observable/entity or incident dict to STIX 2.1.

        Dispatches to :meth:`_incident_to_stix` when the native record looks
        like an investigation/case (detected by ``case_number`` or
        ``assigned_to`` fields), otherwise maps to a STIX Indicator.

        Parameters
        ----------
        native : dict
            Raw GreyMatter API response.
        """
        data = native.get("data", native)
        # Investigations/cases have case_number or assigned_to; observables have type+value
        if "case_number" in data or "assigned_to" in data:
            return self._incident_to_stix(data)
        gm_type  = data.get("type", "")
        value    = data.get("value", data.get("name", ""))
        pattern  = self._OBS_PATTERN.get(
            gm_type, "[unknown:value = '{v}']"
        ).format(v=value.replace("'", "\\'"))

        return {
            "type": "indicator",
            "id": f"indicator--{data.get('id', '')}",
            "name": value,
            "description": data.get("description", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "created": data.get("created_at", ""),
            "modified": data.get("updated_at", ""),
            "indicator_types": [data.get("classification", "unknown")],
            "confidence": data.get("confidence", 50),
            "x_gm_type": gm_type,
            "x_gm_tags": data.get("tags", []),
            "x_gm_severity": data.get("severity", ""),
            "x_tlp": data.get("tlp", "white"),
        }

    @staticmethod
    def _incident_to_stix(data: dict[str, Any]) -> dict[str, Any]:
        """
        Map a GreyMatter investigation/case record to STIX ``observed-data``.

        Parameters
        ----------
        data : dict
            GreyMatter incident/case record (with ``case_number``,
            ``assigned_to``, ``status``, ``severity`` etc.).
        """
        created  = data.get("created_at", "")
        modified = data.get("updated_at", created)
        return {
            "type":              "observed-data",
            "id":                f"observed-data--{data.get('id', '')}",
            "created":           created,
            "modified":          modified,
            "first_observed":    created,
            "last_observed":     modified,
            "number_observed":   1,
            "object_refs":       [],
            "name":              data.get("title", data.get("name", "")),
            "description":       data.get("description", ""),
            "x_gm_case_number":  data.get("case_number", ""),
            "x_gm_status":       data.get("status", ""),
            "x_gm_severity":     data.get("severity", ""),
            "x_gm_assigned_to":  data.get("assigned_to", ""),
            "x_gm_tags":         data.get("tags", []),
            "x_tlp":             data.get("tlp", "white"),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX Indicator dict to a GreyMatter observable payload.
        """
        pattern = stix_dict.get("pattern", "")
        gm_type = self._infer_gm_type(pattern)
        value = self._extract_value(pattern)
        return {
            "type": gm_type,
            "value": value or stix_dict.get("name", ""),
            "description": stix_dict.get("description", ""),
            "confidence": stix_dict.get("confidence", 50),
            "tlp": stix_dict.get("x_tlp", "white"),
            "tags": stix_dict.get("x_gm_tags", []),
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
        gm_type = self._infer_gm_type(stix_obj.get("pattern", ""))
        value = self._extract_value(stix_obj.get("pattern", ""))
        if not value:
            value = stix_obj.get("name", "")
        payload = {
            "case_id": case_id,
            "type": gm_type,
            "value": value,
            "stix_id": stix_obj.get("id", ""),
            "description": stix_obj.get("description", ""),
        }
        return self.post(f"/v1/incidents/{case_id}/linked_observables", json=payload)

    # ── Evidence expansion ────────────────────────────────────────────────

    def get_investigation_observables(self, case_id: str) -> list[dict[str, Any]]:
        """
        Return all observables linked to a GreyMatter investigation/case.

        Calls ``GET /v1/incidents/{case_id}/linked_observables``.

        Parameters
        ----------
        case_id : str
            GreyMatter investigation / case UUID.

        Returns
        -------
        list of dict
            Raw GreyMatter observable records.
        """
        resp = self.get(f"/v1/incidents/{self._to_gm_id(case_id)}/linked_observables")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_investigation_tasks(self, case_id: str) -> list[dict[str, Any]]:
        """
        Return tasks associated with a GreyMatter investigation/case.

        Calls ``GET /v1/incidents/{case_id}/tasks``.

        Parameters
        ----------
        case_id : str
            GreyMatter investigation / case UUID.

        Returns
        -------
        list of dict
            Raw GreyMatter task records.
        """
        resp = self.get(f"/v1/incidents/{self._to_gm_id(case_id)}/tasks")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def search_observables_by_value(self, value: str) -> list[dict[str, Any]]:
        """
        Search GreyMatter observables by value (IP, domain, hash, email, …).

        Calls ``GET /v1/observables?value={value}``.

        Parameters
        ----------
        value : str
            Observable value to search for.

        Returns
        -------
        list of dict
            Raw GreyMatter observable records.
        """
        resp = self.get("/v1/observables", params={"value": value, "limit": 50})
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── Case / Investigation management ───────────────────────────────────

    def add_case_comment(self, case_id: str, text: str) -> dict[str, Any]:
        """
        Post a comment on an existing GreyMatter investigation case.

        Calls ``POST /v1/incidents/{case_id}/comments``.

        Parameters
        ----------
        case_id : str
            GreyMatter case UUID.
        text : str
            Comment body text.
        """
        return self.post(
            f"/v1/incidents/{self._to_gm_id(case_id)}/comments",
            json={"text": text},
        )

    def list_case_comments(self, case_id: str) -> list[dict[str, Any]]:
        """
        Return all comments on a GreyMatter investigation case.

        Calls ``GET /v1/incidents/{case_id}/comments``.

        Parameters
        ----------
        case_id : str
            GreyMatter case UUID.
        """
        resp = self.get(f"/v1/incidents/{self._to_gm_id(case_id)}/comments")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def update_case_status(self, case_id: str, status: str) -> dict[str, Any]:
        """
        Change the status of a GreyMatter investigation case.

        Calls ``PUT /v1/incidents/{case_id}/status``.

        Parameters
        ----------
        case_id : str
            GreyMatter case UUID.
        status : str
            New status value — e.g. ``"open"``, ``"in_progress"``,
            ``"resolved"``, ``"closed"``.
        """
        return self.put(
            f"/v1/incidents/{self._to_gm_id(case_id)}/status",
            json={"status": status},
        )

    def assign_case(self, case_id: str, assignee: str) -> dict[str, Any]:
        """
        Reassign a GreyMatter investigation case to a different analyst.

        Calls ``PUT /v1/incidents/{case_id}/assignee``.

        Parameters
        ----------
        case_id : str
            GreyMatter case UUID.
        assignee : str
            Username or user ID of the new assignee.
        """
        return self.put(
            f"/v1/incidents/{self._to_gm_id(case_id)}/assignee",
            json={"assignee": assignee},
        )

    def close_case(
        self,
        case_id: str,
        resolution: str = "",
        close_notes: str = "",
    ) -> dict[str, Any]:
        """
        Close a GreyMatter investigation case.

        Calls ``POST /v1/incidents/{case_id}/close``.

        Parameters
        ----------
        case_id : str
            GreyMatter case UUID.
        resolution : str
            Resolution label (e.g. ``"true_positive"``, ``"false_positive"``).
        close_notes : str
            Optional closure notes.
        """
        return self.post(
            f"/v1/incidents/{self._to_gm_id(case_id)}/close",
            json={"resolution": resolution, "close_notes": close_notes},
        )

    def add_case_observable(
        self,
        case_id: str,
        obs_type: str,
        value: str,
        confidence: int = 50,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new observable and immediately link it to a case.

        Calls ``POST /v1/incidents/{case_id}/observables``.

        Parameters
        ----------
        case_id : str
            GreyMatter case UUID.
        obs_type : str
            GreyMatter observable type: ``"ipv4"``, ``"domain"``,
            ``"url"``, ``"md5"``, ``"sha1"``, ``"sha256"``, ``"email"``.
        value : str
            Observable value.
        confidence : int
            Confidence score 0–100.  Default ``50``.
        tags : list of str, optional
            Tags to apply to the observable.
        """
        return self.post(
            f"/v1/incidents/{self._to_gm_id(case_id)}/observables",
            json={
                "type":       obs_type,
                "value":      value,
                "confidence": confidence,
                "tags":       tags or [],
            },
        )

    # ── Observable bulk operations ────────────────────────────────────────

    def bulk_create_observables(
        self,
        observables: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Create multiple observables in a single request.

        Calls ``POST /v1/observables/bulk``.  Each item in *observables*
        should contain at minimum ``type`` and ``value``.

        Parameters
        ----------
        observables : list of dict
            List of observable payloads, e.g.
            ``[{"type": "ipv4", "value": "1.2.3.4"}]``.
        """
        resp = self.post("/v1/observables/bulk", json={"observables": observables})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def tag_observable(
        self,
        observable_id: str,
        tags: list[str],
    ) -> dict[str, Any]:
        """
        Apply tags to an existing GreyMatter observable.

        Calls ``PUT /v1/observables/{observable_id}/tags``.

        Parameters
        ----------
        observable_id : str
            GreyMatter observable UUID.
        tags : list of str
            Tags to apply (replaces existing tag set).
        """
        return self.put(
            f"/v1/observables/{self._to_gm_id(observable_id)}/tags",
            json={"tags": tags},
        )

    # ── Threat actor / malware / vulnerability helpers ────────────────────

    def get_threat_actor(self, actor_id: str) -> dict[str, Any]:
        """
        Retrieve a GreyMatter threat-actor entity by ID.

        Calls ``GET /v1/threat-actors/{actor_id}``.

        Parameters
        ----------
        actor_id : str
            GreyMatter threat-actor UUID (or STIX id).
        """
        return self.get(f"/v1/threat-actors/{self._to_gm_id(actor_id)}")

    def list_threat_actors(
        self,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List GreyMatter threat-actor entities.

        Parameters
        ----------
        filters : dict, optional
            Query filters (e.g. ``{"tag": "apt28"}``).
        """
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/v1/threat-actors", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_malware_family(self, malware_id: str) -> dict[str, Any]:
        """
        Retrieve a GreyMatter malware-family entity by ID.

        Calls ``GET /v1/malware/{malware_id}``.

        Parameters
        ----------
        malware_id : str
            GreyMatter malware UUID (or STIX id).
        """
        return self.get(f"/v1/malware/{self._to_gm_id(malware_id)}")

    def list_malware(
        self,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List GreyMatter malware-family entities.

        Parameters
        ----------
        filters : dict, optional
            Query filters (e.g. ``{"tag": "ransomware"}``).
        """
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/v1/malware", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_vulnerability(self, vuln_id: str) -> dict[str, Any]:
        """
        Retrieve a GreyMatter vulnerability entity by ID or CVE number.

        Calls ``GET /v1/vulnerabilities/{vuln_id}``.

        Parameters
        ----------
        vuln_id : str
            GreyMatter vulnerability UUID, STIX id, or CVE-YYYY-NNNNN string.
        """
        return self.get(f"/v1/vulnerabilities/{self._to_gm_id(vuln_id)}")

    def list_vulnerabilities(
        self,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List GreyMatter vulnerability entities.

        Parameters
        ----------
        filters : dict, optional
            Query filters (e.g. ``{"cve": "CVE-2021-44228"}``).
        """
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/v1/vulnerabilities", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def list_attack_patterns(
        self,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List GreyMatter attack-pattern (MITRE ATT&CK technique) entities.

        Parameters
        ----------
        filters : dict, optional
            Query filters (e.g. ``{"technique_id": "T1059"}``).
        """
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/v1/attack-patterns", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── Analytics / metrics ────────────────────────────────────────────────

    def get_metrics(
        self,
        from_date: str = "",
        to_date: str = "",
    ) -> dict[str, Any]:
        """
        Return GreyMatter operational metrics for a date range.

        Calls ``GET /v1/metrics``.  Both *from_date* and *to_date* are
        ISO-8601 date strings (e.g. ``"2026-01-01"``); omit either to use
        the platform's default range.

        Parameters
        ----------
        from_date : str, optional
            Start of the reporting window (ISO-8601).
        to_date : str, optional
            End of the reporting window (ISO-8601).
        """
        params: dict[str, Any] = {}
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date
        resp = self.get("/v1/metrics", params=params)
        return resp if isinstance(resp, dict) else {}

    def get_observable_enrichments(self, observable_id: str) -> dict[str, Any]:
        """
        Fetch enrichment data (WHOIS, passive DNS, threat intel) for an observable.

        Calls ``GET /v1/observables/{observable_id}/enrichments``.

        Parameters
        ----------
        observable_id : str
            GreyMatter observable UUID.
        """
        resp = self.get(
            f"/v1/observables/{self._to_gm_id(observable_id)}/enrichments"
        )
        return resp if isinstance(resp, dict) else {}

    def get_case_timeline(self, case_id: str) -> list[dict[str, Any]]:
        """
        Retrieve the activity timeline for a GreyMatter investigation case.

        Calls ``GET /v1/incidents/{case_id}/timeline``.

        Parameters
        ----------
        case_id : str
            GreyMatter case UUID.
        """
        resp = self.get(f"/v1/incidents/{self._to_gm_id(case_id)}/timeline")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def list_users(self) -> list[dict[str, Any]]:
        """
        Return all GreyMatter platform users.

        Calls ``GET /v1/users``.
        """
        resp = self.get("/v1/users")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_playbook(self, playbook_id: str) -> dict[str, Any]:
        """
        Retrieve a GreyMatter playbook by ID.

        Calls ``GET /v1/playbooks/{playbook_id}``.

        Parameters
        ----------
        playbook_id : str
            GreyMatter playbook UUID.
        """
        return self.get(f"/v1/playbooks/{self._to_gm_id(playbook_id)}")

    def list_playbooks(
        self,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List available GreyMatter playbooks.

        Parameters
        ----------
        filters : dict, optional
            Query filters (e.g. ``{"status": "active"}``).
        """
        params: dict[str, Any] = {
            "limit":  page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/v1/playbooks", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def run_playbook(
        self,
        playbook_id: str,
        case_id: str,
        inputs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute a GreyMatter playbook against an investigation case.

        Calls ``POST /v1/playbooks/{playbook_id}/run``.

        Parameters
        ----------
        playbook_id : str
            GreyMatter playbook UUID.
        case_id : str
            GreyMatter case UUID to run the playbook against.
        inputs : dict, optional
            Additional playbook input parameters.
        """
        payload: dict[str, Any] = {
            "case_id": self._to_gm_id(case_id),
        }
        if inputs:
            payload["inputs"] = inputs
        return self.post(
            f"/v1/playbooks/{self._to_gm_id(playbook_id)}/run",
            json=payload,
        )

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
        if "ipv4-addr"   in pattern:
            return "ipv4"
        if "ipv6-addr"   in pattern:
            return "ipv6"
        if "domain-name" in pattern:
            return "domain"
        if "url:"        in pattern:
            return "url"
        if "sha-256"     in pattern:
            return "sha256"
        if "sha-1"       in pattern:
            return "sha1"
        if "md5"         in pattern:
            return "md5"
        if "email-addr"  in pattern:
            return "email"
        return "unknown"

    @staticmethod
    def _extract_value(pattern: str) -> str:
        """Pull the quoted value out of a simple STIX pattern."""
        import re

        m = re.search(r"=\s*'([^']+)'", pattern)
        return m.group(1) if m else ""
