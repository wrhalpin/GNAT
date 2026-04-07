# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.qradar.reference_data
==========================================
Reference data commands for the QRadar connector.

QRadar's reference data system is a key-value store used primarily
to feed threat intelligence (IOCs) into correlation rules. Rules can
test whether an observed IP/domain/hash exists in a reference set,
enabling dynamic IOC-driven detection without rule redeployment.

Reference data types
---------------------
  Reference Set       — ordered list of values (e.g. malicious IPs)
                        POST /api/reference_data/sets
                        Bulk add: POST /api/reference_data/sets/bulk_load/<name>

  Reference Map       — key → single value
                        POST /api/reference_data/maps
                        Bulk add: POST /api/reference_data/maps/bulk_load/<name>

  Reference Map of Sets — key → set of values
                        POST /api/reference_data/map_of_sets

  Reference Table     — key → row (multi-column)
                        POST /api/reference_data/tables

GNAT IOC workflow
---------------------
  1. Ensure the reference set exists (create_set if not)
  2. Bulk-add STIX indicator values via add_set_values_bulk()
  3. QRadar correlation rules reference the set automatically

Element types supported by reference sets
-------------------------------------------
  ALN   — alphanumeric (strings, hostnames, domains, URLs)
  NUM   — numeric (integers)
  IP    — IP address (parsed and stored as IP, supports CIDR)
  PORT  — port number
  ALNIC — alphanumeric, case-insensitive

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-reference-data
"""

from .client import QRadarClient
from .exceptions import QRadarNotFoundError


class QRadarReferenceDataCommands:
    """
    Reference data (sets, maps, tables) management operations.

    Parameters
    ----------
    client : QRadarClient
        Authenticated HTTP client.
    """

    def __init__(self, client: QRadarClient) -> None:
        """Initialize QRadarReferenceDataCommands."""
        self._client = client

    # ── Reference Sets ─────────────────────────────────────────────────────

    def list_sets(self) -> list[dict]:
        """
        List all reference sets.

        Returns
        -------
        list[dict]
            Reference set metadata records.
        """
        return list(self._client.paginate("reference_data/sets"))

    def get_set(self, name: str, page_size: int | None = None) -> dict:
        """
        Retrieve a reference set and its contents.

        Parameters
        ----------
        name : str
            Reference set name.
        page_size : int | None
            Items per page for set data.

        Returns
        -------
        dict
            Reference set record including data array.

        Raises
        ------
        QRadarNotFoundError
            If no set with this name exists.
        """
        return self._client.get(
            f"reference_data/sets/{name}",
            range_header=f"items=0-{(page_size or self._client.config.max_results) - 1}",
        )

    def create_set(
        self,
        name: str,
        element_type: str = "IP",
        timeout_type: str = "UNKNOWN",
        time_to_live: str | None = None,
    ) -> dict:
        """
        Create a new reference set.

        Parameters
        ----------
        name : str
            Unique name for the reference set.
        element_type : str
            Value type: 'IP', 'ALN', 'ALNIC', 'NUM', or 'PORT'.
        timeout_type : str
            Expiry mode: 'UNKNOWN' (never), 'FIRST_SEEN', or 'LAST_SEEN'.
        time_to_live : str | None
            TTL string e.g. '7 days', '24 hours' (requires timeout_type set).

        Returns
        -------
        dict
            Created reference set metadata.
        """
        params: dict = {
            "name": name,
            "element_type": element_type,
            "timeout_type": timeout_type,
        }
        if time_to_live:
            params["time_to_live"] = time_to_live
        return self._client.post("reference_data/sets", params=params)

    def delete_set(self, name: str, purge_only: bool = False) -> dict:
        """
        Delete a reference set.

        Parameters
        ----------
        name : str
            Set name to delete.
        purge_only : bool
            If True, clear contents but keep the set definition.

        Returns
        -------
        dict
            Deletion task info.
        """
        params = {"purge_only": str(purge_only).lower()}
        return self._client.delete(f"reference_data/sets/{name}", params=params)

    def add_set_value(self, name: str, value: str, source: str = "gnat") -> dict:
        """
        Add a single value to a reference set.

        Parameters
        ----------
        name : str
            Reference set name.
        value : str
            Value to add.
        source : str
            Source tag for provenance tracking.

        Returns
        -------
        dict
            Updated reference set metadata.
        """
        return self._client.post(
            f"reference_data/sets/{name}",
            params={"value": value, "source": source},
        )

    def add_set_values_bulk(
        self,
        name: str,
        values: list[str],
        source: str = "gnat",
    ) -> dict:
        """
        Bulk-add multiple values to a reference set.

        This is the recommended method for IOC ingestion — much more
        efficient than individual add_set_value() calls.

        Parameters
        ----------
        name : str
            Reference set name.
        values : list[str]
            Values to add.
        source : str
            Source tag.

        Returns
        -------
        dict
            Bulk load result metadata.
        """
        return self._client.post(
            f"reference_data/sets/bulk_load/{name}",
            body=values,
        )

    def remove_set_value(self, name: str, value: str) -> dict:
        """
        Remove a single value from a reference set.

        Parameters
        ----------
        name : str
            Set name.
        value : str
            Value to remove.

        Returns
        -------
        dict
            Updated reference set metadata.
        """
        return self._client.delete(f"reference_data/sets/{name}/{value}")

    def ensure_set_exists(
        self,
        name: str,
        element_type: str = "IP",
        timeout_type: str = "UNKNOWN",
        time_to_live: str | None = None,
    ) -> dict:
        """
        Return an existing reference set or create it if it does not exist.

        Parameters
        ----------
        name : str
            Reference set name.
        element_type : str
            Element type (used only when creating).
        timeout_type : str
            TTL mode (used only when creating).
        time_to_live : str | None
            TTL value (used only when creating).

        Returns
        -------
        dict
            Reference set metadata.
        """
        try:
            return self._client.get(f"reference_data/sets/{name}")
        except QRadarNotFoundError:
            return self.create_set(
                name,
                element_type=element_type,
                timeout_type=timeout_type,
                time_to_live=time_to_live,
            )

    # ── Reference Maps ─────────────────────────────────────────────────────

    def list_maps(self) -> list[dict]:
        """List all reference maps."""
        return list(self._client.paginate("reference_data/maps"))

    def get_map(self, name: str) -> dict:
        """Get a reference map and its contents."""
        return self._client.get(f"reference_data/maps/{name}")

    def create_map(
        self,
        name: str,
        key_label: str = "key",
        value_label: str = "value",
        element_type: str = "ALN",
        key_name_types: dict | None = None,
        timeout_type: str = "UNKNOWN",
    ) -> dict:
        """
        Create a reference map (key → single value).

        Parameters
        ----------
        name : str
            Map name.
        key_label : str
            Human-readable label for the key column.
        value_label : str
            Human-readable label for the value column.
        element_type : str
            Value element type ('ALN', 'IP', 'NUM', 'PORT', 'ALNIC').
        key_name_types : dict | None
            Column type definitions for the key.
        timeout_type : str
            TTL mode.

        Returns
        -------
        dict
            Created map metadata.
        """
        params: dict = {
            "name": name,
            "key_label": key_label,
            "value_label": value_label,
            "element_type": element_type,
            "timeout_type": timeout_type,
        }
        return self._client.post("reference_data/maps", params=params)

    def add_map_entry(
        self,
        name: str,
        key: str,
        value: str,
        source: str = "gnat",
    ) -> dict:
        """
        Add or update a key/value pair in a reference map.

        Parameters
        ----------
        name : str
            Map name.
        key : str
            Key string.
        value : str
            Value string.
        source : str
            Source tag.

        Returns
        -------
        dict
            Updated map metadata.
        """
        return self._client.post(
            f"reference_data/maps/{name}",
            params={"key": key, "value": value, "source": source},
        )

    def add_map_entries_bulk(
        self,
        name: str,
        entries: dict[str, str],
        source: str = "gnat",
    ) -> dict:
        """
        Bulk-add key/value entries to a reference map.

        Parameters
        ----------
        name : str
            Map name.
        entries : dict[str, str]
            {key: value} pairs to add.
        source : str
            Source tag.

        Returns
        -------
        dict
            Bulk load result.
        """
        return self._client.post(
            f"reference_data/maps/bulk_load/{name}",
            body=entries,
        )

    # ── Reference Map of Sets ──────────────────────────────────────────────

    def list_map_of_sets(self) -> list[dict]:
        """List all reference map-of-sets."""
        return list(self._client.paginate("reference_data/map_of_sets"))

    def create_map_of_sets(
        self,
        name: str,
        element_type: str = "ALN",
        timeout_type: str = "UNKNOWN",
    ) -> dict:
        """Create a reference map-of-sets (key → set of values)."""
        return self._client.post(
            "reference_data/map_of_sets",
            params={"name": name, "element_type": element_type, "timeout_type": timeout_type},
        )

    def add_map_of_sets_value(
        self,
        name: str,
        key: str,
        value: str,
        source: str = "gnat",
    ) -> dict:
        """Add a value to a key's set in a map-of-sets."""
        return self._client.post(
            f"reference_data/map_of_sets/{name}",
            params={"key": key, "value": value, "source": source},
        )

    def add_map_of_sets_bulk(
        self,
        name: str,
        entries: dict[str, list[str]],
    ) -> dict:
        """
        Bulk-add entries to a map-of-sets.

        Parameters
        ----------
        name : str
            Map-of-sets name.
        entries : dict[str, list[str]]
            {key: [value1, value2, ...]} mapping.

        Returns
        -------
        dict
            Bulk load result.
        """
        return self._client.post(
            f"reference_data/map_of_sets/bulk_load/{name}",
            body=entries,
        )

    # ── IOC ingestion workflow helpers ─────────────────────────────────────

    def push_ip_iocs(
        self,
        set_name: str,
        ips: list[str],
        create_if_missing: bool = True,
    ) -> dict:
        """
        Push a list of malicious IPs into a QRadar reference set.

        Parameters
        ----------
        set_name : str
            Reference set name (e.g. 'gnat_malicious_ips').
        ips : list[str]
            IPv4/IPv6 addresses to add.
        create_if_missing : bool
            Create the set if it does not already exist.

        Returns
        -------
        dict
            Bulk load result.
        """
        if create_if_missing:
            self.ensure_set_exists(set_name, element_type="IP")
        return self.add_set_values_bulk(set_name, ips)

    def push_domain_iocs(
        self,
        set_name: str,
        domains: list[str],
        create_if_missing: bool = True,
    ) -> dict:
        """
        Push malicious domain names into a QRadar reference set.

        Parameters
        ----------
        set_name : str
            Reference set name (e.g. 'gnat_malicious_domains').
        domains : list[str]
            Domain strings to add.
        create_if_missing : bool
            Create the set if it does not already exist.

        Returns
        -------
        dict
            Bulk load result.
        """
        if create_if_missing:
            self.ensure_set_exists(set_name, element_type="ALN")
        return self.add_set_values_bulk(set_name, domains)

    def push_hash_iocs(
        self,
        set_name: str,
        hashes: list[str],
        create_if_missing: bool = True,
    ) -> dict:
        """
        Push file hashes into a QRadar reference set.

        Parameters
        ----------
        set_name : str
            Reference set name (e.g. 'gnat_malicious_hashes').
        hashes : list[str]
            Hash strings (MD5, SHA-1, SHA-256) to add.
        create_if_missing : bool
            Create the set if it does not exist.

        Returns
        -------
        dict
            Bulk load result.
        """
        if create_if_missing:
            self.ensure_set_exists(set_name, element_type="ALN")
        return self.add_set_values_bulk(set_name, hashes)
