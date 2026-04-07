# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.tags
===============================
Tag management commands for the MISP connector.

Tags are labels applied to events and attributes. MISP supports:
  - Free-form tags (e.g. 'phishing', 'ransomware')
  - TLP tags: tlp:white, tlp:green, tlp:amber, tlp:red
  - PAP tags: PAP:WHITE, PAP:GREEN, PAP:AMBER, PAP:RED
  - Galaxy tags: misp-galaxy:threat-actor="APT28"
  - Taxonomy tags: circl:incident-classification="malware"

References
----------
- https://www.misp-project.org/openapi/#tag/Tags
"""

from .client import MISPClient


class MISPTagCommands:
    """Tag management operations."""

    def __init__(self, client: MISPClient) -> None:
        self._client = client

    def list_tags(self) -> list[dict]:
        """List all available tags on this MISP instance."""
        response = self._client.get_json("tags/index")
        if isinstance(response, dict):
            return response.get("Tag", [])
        return response if isinstance(response, list) else []

    def get_tag(self, tag_id: int) -> dict:
        """Retrieve a single tag by ID."""
        response = self._client.get_json(f"tags/view/{tag_id}")
        if isinstance(response, dict):
            return response.get("Tag", response)
        return response

    def create_tag(
        self,
        name: str,
        colour: str = "#ffffff",
        exportable: bool = True,
        hide_tag: bool = False,
    ) -> dict:
        """
        Create a new tag.

        Parameters
        ----------
        name : str
            Tag label string.
        colour : str
            Hex colour for the tag badge.
        exportable : bool
            Whether the tag is shared with the community.
        hide_tag : bool
            If True, tag is only used internally.

        Returns
        -------
        dict
        """
        tag: dict = {
            "name": name,
            "colour": colour,
            "exportable": exportable,
            "hide_tag": hide_tag,
        }
        response = self._client.post_json("tags/add", body={"Tag": tag})
        if isinstance(response, dict):
            return response.get("Tag", response)
        return response

    def attach_tag_to_event(self, event_uuid: str, tag: str) -> dict:
        """Attach a tag to an event by UUID."""
        return self._client.post_json(
            "tags/attachTagToObject",
            body={"uuid": event_uuid, "tag": tag},
        )

    def attach_tag_to_attribute(self, attribute_uuid: str, tag: str) -> dict:
        """Attach a tag to an attribute by UUID."""
        return self._client.post_json(
            "tags/attachTagToObject",
            body={"uuid": attribute_uuid, "tag": tag, "local": False},
        )

    def remove_tag_from_event(self, event_uuid: str, tag: str) -> dict:
        """Remove a tag from an event."""
        return self._client.post_json(
            "tags/removeTagFromObject",
            body={"uuid": event_uuid, "tag": tag},
        )

    # TLP convenience helpers

    def set_tlp_white(self, event_uuid: str) -> dict:
        """Apply TLP:WHITE to an event."""
        return self.attach_tag_to_event(event_uuid, "tlp:white")

    def set_tlp_green(self, event_uuid: str) -> dict:
        """Apply TLP:GREEN to an event."""
        return self.attach_tag_to_event(event_uuid, "tlp:green")

    def set_tlp_amber(self, event_uuid: str) -> dict:
        """Apply TLP:AMBER to an event."""
        return self.attach_tag_to_event(event_uuid, "tlp:amber")

    def set_tlp_red(self, event_uuid: str) -> dict:
        """Apply TLP:RED to an event."""
        return self.attach_tag_to_event(event_uuid, "tlp:red")
