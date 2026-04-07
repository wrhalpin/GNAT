# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.yeti.client
==============================
Yeti FOSS threat intelligence platform connector.

Yeti is a STIX-native open-source TI platform.  It exposes a REST API
that accepts and returns JSON objects aligned closely with STIX 2.1.
The API key is passed in the ``X-Yeti-API-Key`` header.

INI config::

    [yeti]
    host    = https://yeti.example.com
    api_key = YOUR_YETI_API_KEY
    auth_type = token

References
----------
https://yeti-platform.io/
https://yeti-platform.github.io/docs/api/
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

_API = "/api/v2"


class YetiClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Yeti Threat Intelligence Platform REST API v2.

    Yeti's data model maps closely to STIX 2.1:
    * **Observables** → STIX Indicators
    * **Entities** (ThreatActors, Malware, etc.) → STIX SDOs
    * **Relationships** → STIX SROs

    Parameters
    ----------
    host : str
        Yeti base URL, e.g. ``https://yeti.example.com``.
    api_key : str
        Yeti API key (generated under Account → API Keys).
    """

    stix_type_map: dict[str, str] = {
        "indicator": "observables",
        "threat-actor": "entities",
        "malware": "entities",
        "campaign": "entities",
        "relationship": "relationships",
    }

    def __init__(
        self,
        host: str,
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Set the Yeti API key header."""
        self._auth_headers["X-Yeti-API-Key"] = self._api_key
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """Check API health via a minimal observable query."""
        resp = self.post(f"{_API}/observables/search", json={"count": 1})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve a Yeti observable or entity by ID."""
        resource = self.stix_type_map.get(stix_type, "observables")
        resp = self.get(f"{_API}/{resource}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search Yeti observables or entities via ``POST /{resource}/search``.

        ``filters`` may include:

        * ``value``: observable value to search for
        * ``type``: observable type (``"ip"``, ``"domain"``, ``"url"``, etc.)
        * ``tags``: list of tag strings to filter by
        * ``query``: free-text search string for entities
        """
        resource = self.stix_type_map.get(stix_type, "observables")
        body: dict[str, Any] = {
            "count": min(page_size, 200),
            "page": page - 1,
        }
        if filters:
            body.update(filters)

        resp = self.post(f"{_API}/{resource}/search", json=body)
        if not isinstance(resp, dict):
            return []
        return resp.get("observables", resp.get("entities", resp.get("results", [])))

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create or update a Yeti observable or entity.

        If ``payload`` contains ``"id"`` the record is updated via ``PUT``;
        otherwise created via ``POST``.
        """
        resource = self.stix_type_map.get(stix_type, "observables")
        obj_id = payload.pop("id", None)
        if obj_id:
            resp = self.put(f"{_API}/{resource}/{obj_id}", json=payload)
        else:
            resp = self.post(f"{_API}/{resource}", json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a Yeti object by ID."""
        resource = self.stix_type_map.get(stix_type, "observables")
        self.delete(f"{_API}/{resource}/{object_id}")

    # ------------------------------------------------------------------
    # Extra helpers
    # ------------------------------------------------------------------

    def add_tag(self, object_id: str, stix_type: str, tag: str) -> dict[str, Any]:
        """
        Tag a Yeti observable or entity.

        Parameters
        ----------
        object_id : str
            Yeti object ID.
        stix_type : str
            STIX type string to resolve the resource path.
        tag : str
            Tag to apply.
        """
        resource = self.stix_type_map.get(stix_type, "observables")
        resp = self.post(
            f"{_API}/{resource}/{object_id}/tag",
            json={"tags": [tag]},
        )
        return resp if isinstance(resp, dict) else {}

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Yeti observable or entity dict to a STIX dict."""
        yeti_type = native.get("type", "")
        if yeti_type in ("ThreatActor", "threat-actor"):
            return self._entity_to_threat_actor(native)
        if yeti_type in ("Malware", "malware"):
            return self._entity_to_malware(native)
        if yeti_type in ("Campaign", "campaign"):
            return self._entity_to_campaign(native)
        return self._observable_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a Yeti observable payload from a STIX Indicator dict."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        obs_type = self._stix_to_yeti_type(pattern)
        return {
            "value": value,
            "type": obs_type,
            "tags": stix_dict.get("labels", []),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _observable_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        yeti_type = native.get("type", "ip")
        value = native.get("value", "")
        pattern = self._make_pattern(yeti_type, value)
        tags = [t.get("name", t) if isinstance(t, dict) else t for t in native.get("tags", [])]
        return {
            "type": "indicator",
            "id": f"indicator--yeti-{native.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("created", ""),
            "modified": native.get("modified", ""),
            "indicator_types": ["malicious-activity"],
            "labels": tags,
            "x_source_platform": "yeti",
            "x_yeti_id": native.get("id", ""),
            "x_yeti_type": yeti_type,
            "x_yeti_tags": tags,
        }

    def _entity_to_threat_actor(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "threat-actor",
            "id": f"threat-actor--yeti-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "aliases": native.get("aliases", []),
            "created": native.get("created", ""),
            "modified": native.get("modified", ""),
            "x_source_platform": "yeti",
            "x_yeti_id": native.get("id", ""),
        }

    def _entity_to_malware(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "malware",
            "id": f"malware--yeti-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "is_family": True,
            "created": native.get("created", ""),
            "modified": native.get("modified", ""),
            "x_source_platform": "yeti",
            "x_yeti_id": native.get("id", ""),
        }

    def _entity_to_campaign(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "campaign",
            "id": f"campaign--yeti-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "created": native.get("created", ""),
            "modified": native.get("modified", ""),
            "x_source_platform": "yeti",
        }

    @staticmethod
    def _make_pattern(yeti_type: str, value: str) -> str:
        t = (yeti_type or "").lower()
        if t in ("ip", "ipv4", "ipv4addr"):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("ipv6", "ipv6addr"):
            return f"[ipv6-addr:value = '{value}']"
        if t in ("hostname", "domain", "fqdn"):
            return f"[domain-name:value = '{value}']"
        if t in ("url",):
            return f"[url:value = '{value}']"
        if t in ("md5",):
            return f"[file:hashes.'MD5' = '{value}']"
        if t in ("sha1",):
            return f"[file:hashes.'SHA-1' = '{value}']"
        if t in ("sha256",):
            return f"[file:hashes.'SHA-256' = '{value}']"
        if t in ("email",):
            return f"[email-message:from_ref.value = '{value}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_to_yeti_type(pattern: str) -> str:
        if "ipv4-addr" in pattern:
            return "ip"
        if "ipv6-addr" in pattern:
            return "ipv6"
        if "domain-name" in pattern:
            return "hostname"
        if "url:" in pattern:
            return "url"
        if "MD5" in pattern:
            return "md5"
        if "SHA-1" in pattern:
            return "sha1"
        if "SHA-256" in pattern:
            return "sha256"
        if "email" in pattern:
            return "email"
        return "hostname"
