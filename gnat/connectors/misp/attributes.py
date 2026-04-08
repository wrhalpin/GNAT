# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.attributes
=====================================
Attribute management commands for the MISP connector.

Attributes are the individual IOC values within MISP events.
Each attribute has a type (ip-src, domain, md5, etc.) and a value.

Common attribute types
-----------------------
  ip-src, ip-dst         — source/destination IPv4/IPv6
  domain                 — domain name
  hostname               — hostname
  url                    — full URL
  md5, sha1, sha256      — file hashes
  filename               — file name
  email-src, email-dst   — email addresses
  email-subject          — email subject
  regkey                 — Windows registry key
  mutex                  — mutex name
  snort, yara            — detection signatures
  vulnerability          — CVE ID
  comment                — free-text annotation

Key attribute fields
--------------------
  id        — integer attribute ID
  uuid      — UUID (stable)
  event_id  — parent event ID
  type      — attribute type string
  category  — MISP category (Network activity, Payload delivery, etc.)
  value     — the IOC value
  to_ids    — bool: should be used for detection?
  comment   — optional analyst comment
  timestamp — Unix timestamp of creation/update
  Tag       — list of tag dicts

References
----------
- https://www.misp-project.org/openapi/#tag/Attributes
"""

from collections.abc import Iterator

from .client import MISPClient

# Attribute type → STIX SCO type hint
ATTR_TYPE_TO_STIX = {
    "ip-src": "ipv4-addr",
    "ip-dst": "ipv4-addr",
    "ip-src|port": "ipv4-addr",
    "ip-dst|port": "ipv4-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
    "sha512": "file",
    "filename": "file",
    "filename|md5": "file",
    "email-src": "email-addr",
    "email-dst": "email-addr",
    "email-subject": "email-message",
    "regkey": "windows-registry-key",
    "vulnerability": "vulnerability",
    "AS": "autonomous-system",
}


class MISPAttributeCommands:
    """Attribute management operations."""

    def __init__(self, client: MISPClient) -> None:
        """Initialize MISPAttributeCommands."""
        self._client = client

    # ── Search ─────────────────────────────────────────────────────────────

    def search_attributes(
        self,
        value: str | None = None,
        type_attr: str | None = None,
        category: str | None = None,
        event_id: int | str | None = None,
        tags: list[str] | None = None,
        to_ids: bool | None = None,
        limit: int | None = None,
        page: int = 1,
    ) -> list[dict]:
        """
        Search attributes with flexible filters.

        Parameters
        ----------
        value : str | None
            IOC value to search for.
        type_attr : str | None
            Attribute type (e.g. 'ip-src', 'domain', 'md5').
        category : str | None
            MISP category string.
        event_id : int | str | None
            Restrict to a specific event.
        tags : list[str] | None
            Tag filters.
        to_ids : bool | None
            Filter by to_ids flag.
        limit : int | None
            Max results.
        page : int
            Page number.

        Returns
        -------
        list[dict]
            Attribute dicts.
        """
        body: dict = {
            "returnFormat": "json",
            "limit": limit or self._client.config.max_results,
            "page": page,
        }
        if value:
            body["value"] = value
        if type_attr:
            body["type"] = type_attr
        if category:
            body["category"] = category
        if event_id:
            body["eventid"] = str(event_id)
        if tags:
            body["tags"] = tags
        if to_ids is not None:
            body["to_ids"] = 1 if to_ids else 0

        response = self._client.post_json("attributes/restSearch", body=body)
        return self._unwrap_attributes(response)

    def iter_all_attributes(
        self,
        type_attr: str | None = None,
        to_ids: bool | None = None,
        event_id: int | str | None = None,
    ) -> Iterator[dict]:
        """Generator yielding all matching attributes, paginating."""
        base: dict = {"returnFormat": "json"}
        if type_attr:
            base["type"] = type_attr
        if to_ids is not None:
            base["to_ids"] = 1 if to_ids else 0
        if event_id:
            base["eventid"] = str(event_id)
        yield from self._client.paginate(
            "attributes/restSearch", body=base, response_key="Attribute"
        )

    # ── CRUD ───────────────────────────────────────────────────────────────

    def get_attribute(self, attribute_id: int | str) -> dict:
        """Retrieve a single attribute by ID."""
        response = self._client.get_json(f"attributes/view/{attribute_id}")
        if isinstance(response, dict):
            return response.get("Attribute", response)
        return response

    def add_attribute(
        self,
        event_id: int | str,
        type_attr: str,
        value: str,
        category: str = "Network activity",
        to_ids: bool = True,
        comment: str = "",
        distribution: int | None = None,
    ) -> dict:
        """
        Add a single attribute to an event.

        Parameters
        ----------
        event_id : int | str
            Parent event ID.
        type_attr : str
            Attribute type (e.g. 'ip-src', 'domain', 'sha256').
        value : str
            IOC value.
        category : str
            MISP category.
        to_ids : bool
            Whether to use for IDS detection.
        comment : str
            Optional analyst comment.
        distribution : int | None
            Override event distribution.

        Returns
        -------
        dict
            Created attribute dict.
        """
        attr: dict = {
            "type": type_attr,
            "value": value,
            "category": category,
            "to_ids": to_ids,
            "comment": comment,
            "distribution": distribution
            if distribution is not None
            else self._client.config.default_distribution,
        }
        response = self._client.post_json(f"attributes/add/{event_id}", body={"Attribute": attr})
        if isinstance(response, dict):
            return response.get("Attribute", response)
        return response

    def add_attributes_bulk(
        self,
        event_id: int | str,
        attributes: list[dict],
    ) -> list[dict]:
        """
        Add multiple attributes to an event in one call.

        Parameters
        ----------
        event_id : int | str
        attributes : list[dict]
            List of attribute dicts, each with at minimum
            'type' and 'value' keys.

        Returns
        -------
        list[dict]
            Created attribute dicts.
        """
        response = self._client.post_json(
            f"attributes/add/{event_id}",
            body={"Attribute": attributes},
        )
        if isinstance(response, dict):
            saved = response.get("Attribute", [])
            return saved if isinstance(saved, list) else [saved]
        return response if isinstance(response, list) else []

    def update_attribute(
        self,
        attribute_id: int | str,
        updates: dict,
    ) -> dict:
        """
        Update an attribute.

        Parameters
        ----------
        attribute_id : int | str
        updates : dict
            Fields to update (type, value, comment, to_ids, etc.)

        Returns
        -------
        dict
        """
        response = self._client.post_json(
            f"attributes/edit/{attribute_id}",
            body={"Attribute": updates},
        )
        if isinstance(response, dict):
            return response.get("Attribute", response)
        return response

    def delete_attribute(self, attribute_id: int | str) -> dict:
        """Delete an attribute by ID."""
        return self._client.delete_json(f"attributes/delete/{attribute_id}")

    def add_tag_to_attribute(self, attribute_id: int | str, tag: str) -> dict:
        """Attach a tag to an attribute."""
        return self._client.post_json(
            "tags/attachTagToObject",
            body={"uuid": str(attribute_id), "tag": tag, "local": False},
        )

    # ── IOC push helpers ───────────────────────────────────────────────────

    def add_ip_attributes(
        self,
        event_id: int | str,
        ips: list[str],
        attr_type: str = "ip-src",
        to_ids: bool = True,
        comment: str = "",
    ) -> list[dict]:
        """
        Add multiple IP addresses to an event as attributes.

        Parameters
        ----------
        event_id : int | str
        ips : list[str]
        attr_type : str
            'ip-src' or 'ip-dst'.
        to_ids : bool
        comment : str

        Returns
        -------
        list[dict]
        """
        attrs = [
            {"type": attr_type, "value": ip, "to_ids": to_ids, "comment": comment} for ip in ips
        ]
        return self.add_attributes_bulk(event_id, attrs)

    def add_hash_attributes(
        self,
        event_id: int | str,
        hashes: dict[str, str],
        to_ids: bool = True,
        comment: str = "",
    ) -> list[dict]:
        """
        Add file hashes to an event.

        Parameters
        ----------
        event_id : int | str
        hashes : dict[str, str]
            {hash_type: hash_value} e.g. {'sha256': 'abc...', 'md5': 'def...'}
        to_ids : bool
        comment : str

        Returns
        -------
        list[dict]
        """
        type_map = {"sha256": "sha256", "sha1": "sha1", "md5": "md5", "sha512": "sha512"}
        attrs = []
        for hash_type, value in hashes.items():
            misp_type = type_map.get(hash_type.lower())
            if misp_type and value:
                attrs.append(
                    {
                        "type": misp_type,
                        "value": value,
                        "category": "Payload delivery",
                        "to_ids": to_ids,
                        "comment": comment,
                    }
                )
        return self.add_attributes_bulk(event_id, attrs) if attrs else []

    # ── Normalisation ──────────────────────────────────────────────────────

    @staticmethod
    def normalise_attribute(attr: dict) -> dict:
        """Flatten a MISP attribute to GNAT normalised format."""
        tags = [t.get("name", "") for t in attr.get("Tag", [])]
        return {
            "id": attr.get("id"),
            "uuid": attr.get("uuid"),
            "event_id": attr.get("event_id"),
            "type": attr.get("type"),
            "category": attr.get("category"),
            "value": attr.get("value"),
            "to_ids": attr.get("to_ids", False),
            "comment": attr.get("comment", ""),
            "distribution": attr.get("distribution"),
            "timestamp": attr.get("timestamp"),
            "tags": tags,
            "stix_type": ATTR_TYPE_TO_STIX.get(attr.get("type", ""), ""),
            "_raw": attr,
        }

    @staticmethod
    def _unwrap_attributes(response) -> list[dict]:
        """Normalise MISP attribute response envelope to plain list."""
        if isinstance(response, list):
            return [item.get("Attribute", item) for item in response]
        if isinstance(response, dict):
            # restSearch returns {"response": {"Attribute": [...]}}
            inner = response.get("response", {})
            if isinstance(inner, dict):
                attrs = inner.get("Attribute", [])
            else:
                attrs = inner if isinstance(inner, list) else []
            return attrs
        return []
