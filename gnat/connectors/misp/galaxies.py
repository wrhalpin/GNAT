# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.galaxies
===================================
Galaxy and cluster management commands for the MISP connector.

MISP Galaxies are structured knowledge bases expressed as clusters:
  - misp-galaxy:threat-actor    — threat actor profiles
  - mitre-attack-pattern        — MITRE ATT&CK techniques
  - misp-galaxy:malware         — malware families
  - misp-galaxy:tool            — adversary tools
  - misp-galaxy:ransomware      — ransomware families
  - misp-galaxy:sector          — targeted sectors
  - misp-galaxy:country         — country attribution

Galaxy clusters map naturally to STIX SDOs:
  threat-actor     → STIX threat-actor SDO
  attack-pattern   → STIX attack-pattern SDO
  malware          → STIX malware SDO
  tool             → STIX tool SDO

References
----------
- https://www.misp-project.org/openapi/#tag/Galaxies
"""

from .client import MISPClient


class MISPGalaxyCommands:
    """Galaxy and cluster inspection operations."""

    def __init__(self, client: MISPClient) -> None:
        """Initialize MISPGalaxyCommands."""
        self._client = client

    def list_galaxies(self) -> list[dict]:
        """List all galaxies available on this MISP instance."""
        response = self._client.get_json("galaxies/index")
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            return response.get("Galaxy", [])
        return []

    def get_galaxy(self, galaxy_id: int | str) -> dict:
        """Retrieve a galaxy with its clusters by ID."""
        response = self._client.get_json(f"galaxies/view/{galaxy_id}")
        if isinstance(response, dict):
            return response.get("Galaxy", response)
        return response

    def search_clusters(self, value: str) -> list[dict]:
        """
        Search galaxy clusters by name or description.

        Parameters
        ----------
        value : str
            Search string.

        Returns
        -------
        list[dict]
            Matching cluster dicts.
        """
        response = self._client.post_json(
            "galaxy_clusters/restSearch",
            body={"returnFormat": "json", "searchall": value},
        )
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            inner = response.get("response", [])
            return [item.get("GalaxyCluster", item) for item in inner]
        return []

    def get_mitre_techniques(self) -> list[dict]:
        """
        Return all MITRE ATT&CK technique clusters.

        Returns
        -------
        list[dict]
            ATT&CK technique cluster dicts with uuid, value (technique ID),
            description, and meta fields.
        """
        return self.search_clusters("T")

    def attach_cluster_to_event(self, event_uuid: str, cluster_tag: str) -> dict:
        """
        Attach a galaxy cluster to an event via its tag.

        Parameters
        ----------
        event_uuid : str
            Event UUID.
        cluster_tag : str
            Galaxy cluster tag, e.g.
            'misp-galaxy:threat-actor="APT28"'.

        Returns
        -------
        dict
        """
        return self._client.post_json(
            "tags/attachTagToObject",
            body={"uuid": event_uuid, "tag": cluster_tag},
        )
