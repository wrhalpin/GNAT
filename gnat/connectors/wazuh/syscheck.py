# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.wazuh.syscheck

File Integrity Monitoring (FIM / syscheck) commands.

Wazuh syscheck monitors file and directory changes:

- New files detected
- Modified files (size, permissions, owner, content hash)
- Deleted files
- Registry key changes (Windows agents)

Syscheck database is maintained per-agent on the Wazuh manager.

## Event types

added     -- new file/directory detected
modified  -- existing file changed
deleted   -- file/directory removed

## Fields of interest

file, date, mtime, size, perm, uid, gid, uname, gname,
md5, sha1, sha256, inode, type (file/registry)

These map naturally to STIX 2.1 file SCOs.

## References

- https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Syscheck
"""

from .client import WazuhClient


class WazuhSyscheckCommands:
    """
    File Integrity Monitoring (syscheck) operations.

    Parameters
    ----------
    client : WazuhClient
        Authenticated HTTP client.
    """

    def __init__(self, client: WazuhClient) -> None:
        self._client = client

    # ── FIM event queries ──────────────────────────────────────────────────

    def get_fim_events(
        self,
        agent_id: str,
        event_type: str | None = None,
        file_path: str | None = None,
        hash_md5: str | None = None,
        hash_sha256: str | None = None,
        date_after: str | None = None,
        date_before: str | None = None,
        limit: int | None = None,
        sort: str | None = None,
    ) -> list[dict]:
        """
        Query syscheck FIM events for a specific agent.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.
        event_type : str | None
            'added', 'modified', or 'deleted'.
        file_path : str | None
            Filter by exact file path.
        hash_md5 : str | None
            Filter by MD5 hash.
        hash_sha256 : str | None
            Filter by SHA-256 hash.
        date_after : str | None
            ISO 8601 timestamp lower bound (e.g. '2024-01-01T00:00:00').
        date_before : str | None
            ISO 8601 timestamp upper bound.
        limit : int | None
            Max results (Wazuh hard cap: 500).
        sort : str | None
            Sort expression, e.g. '-date'.

        Returns
        -------
        list[dict]
            Syscheck event records.
        """
        params: dict = {"limit": min(limit or self._client.config.max_results, 500)}
        q_parts: list[str] = []

        if event_type:
            q_parts.append(f"type={event_type}")
        if file_path:
            params["file"] = file_path
        if hash_md5:
            params["md5"] = hash_md5
        if hash_sha256:
            params["sha256"] = hash_sha256
        if date_after:
            q_parts.append(f"date>{date_after}")
        if date_before:
            q_parts.append(f"date<{date_before}")
        if q_parts:
            params["q"] = ";".join(q_parts)
        if sort:
            params["sort"] = sort

        response = self._client.get(f"syscheck/{agent_id}", params=params)
        return self._client.extract_items(response)

    def iter_fim_events(
        self,
        agent_id: str,
        event_type: str | None = None,
        date_after: str | None = None,
    ):
        """
        Generator that yields all FIM events for an agent, paginating.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.
        event_type : str | None
            'added', 'modified', or 'deleted'.
        date_after : str | None
            Only return events after this timestamp.

        Yields
        ------
        dict
            FIM event record.
        """
        params: dict = {}
        q_parts: list[str] = []
        if event_type:
            q_parts.append(f"type={event_type}")
        if date_after:
            q_parts.append(f"date>{date_after}")
        if q_parts:
            params["q"] = ";".join(q_parts)

        yield from self._client.paginate(f"syscheck/{agent_id}", params=params)

    def get_last_scan_time(self, agent_id: str) -> dict:
        """
        Retrieve the timestamp of the last syscheck scan for an agent.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.

        Returns
        -------
        dict
            Contains 'start' and 'end' timestamps of the last scan.
        """
        response = self._client.get(f"syscheck/{agent_id}/last_scan")
        return response.get("data", {})

    def run_syscheck_scan(self, agent_id: str) -> dict:
        """
        Trigger an on-demand syscheck scan on an agent.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.

        Returns
        -------
        dict
            API response confirming the scan was queued.
        """
        return self._client.put(f"syscheck/{agent_id}")

    def run_syscheck_all_agents(self) -> dict:
        """
        Trigger on-demand syscheck scan on all active agents.

        Returns
        -------
        dict
            API response including any failed agent IDs.
        """
        return self._client.put("syscheck")

    def clear_syscheck_database(self, agent_id: str) -> dict:
        """
        Clear the syscheck database for a specific agent.

        Caution: This removes all FIM baseline data for the agent.
        On the next scan, all files will appear as 'added'.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.

        Returns
        -------
        dict
            API response.
        """
        return self._client.delete(f"syscheck/{agent_id}")

    # ── Normalisation helper ───────────────────────────────────────────────

    @staticmethod
    def normalise_fim_event(event: dict) -> dict:
        """
        Flatten a Wazuh syscheck event to GNAT normalised format.

        Designed to map cleanly to a STIX 2.1 file SCO via WazuhSTIXMapper.

        Parameters
        ----------
        event : dict
            Raw syscheck event record from the API.

        Returns
        -------
        dict
            Normalised FIM event dict.
        """
        return {
            "file": event.get("file"),
            "event_type": event.get("type"),
            "date": event.get("date"),
            "mtime": event.get("mtime"),
            "size": event.get("size"),
            "permissions": event.get("perm"),
            "uid": event.get("uid"),
            "gid": event.get("gid"),
            "owner": event.get("uname"),
            "group_owner": event.get("gname"),
            "inode": event.get("inode"),
            "md5": event.get("md5"),
            "sha1": event.get("sha1"),
            "sha256": event.get("sha256"),
            "file_type": event.get("type"),  # 'file' or 'registry'
            "attributes": event.get("attrs"),
            "_raw": event,
        }
