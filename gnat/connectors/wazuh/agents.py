"""
gnat.connectors.wazuh.agents

Agent management commands for the Wazuh connector.

Covers the full agent lifecycle and metadata operations:

- List/get agents with rich filtering
- Agent status and connectivity monitoring
- Restart / upgrade agents
- Group assignment
- Agent configuration summary

## Wazuh agent status values

active       -- agent is connected and reporting
disconnected -- agent was connected but has stopped reporting
never_connected -- agent was enrolled but never connected
pending      -- agent enrolled but awaiting first connection

## Agent info fields of interest for GNAT

id, name, ip, status, os.platform, os.version, version,
lastKeepAlive, registerIP, dateAdd, group, manager, node_name

## References

- https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Agents
  """

from collections.abc import Iterator

from .client import WazuhClient
from .exceptions import WazuhNotFoundError

# Valid agent status filter values

AGENT_STATUSES = {"active", "disconnected", "never_connected", "pending"}

class WazuhAgentCommands:
    """
    Agent management operations.

    Parameters
    ----------
    client : WazuhClient
        Authenticated HTTP client.
    """

    def __init__(self, client: WazuhClient) -> None:
        self._client = client

    # ── Listing and retrieval ──────────────────────────────────────────────

    def list_agents(
        self,
        status: str | list[str] | None = None,
        os_platform: str | None = None,
        group: str | None = None,
        name: str | None = None,
        ip: str | None = None,
        select: list[str] | None = None,
        sort: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List Wazuh agents with optional filters.

        Parameters
        ----------
        status : str | list[str] | None
            Filter by agent status. One or more of:
            'active', 'disconnected', 'never_connected', 'pending'.
        os_platform : str | None
            Filter by OS platform (e.g. 'windows', 'ubuntu', 'centos').
        group : str | None
            Filter by group name.
        name : str | None
            Filter by agent name (supports wildcards).
        ip : str | None
            Filter by agent IP address.
        select : list[str] | None
            Fields to return (reduces response size).
        sort : str | None
            Sort field, e.g. '+name' or '-lastKeepAlive'.
        limit : int | None
            Max results. Defaults to config.max_results.

        Returns
        -------
        list[dict]
            Agent records.
        """
        params: dict = {
            "limit": min(
                limit or self._client.config.max_results,
                500
            )
        }
        if status:
            params["status"] = (
                ",".join(status) if isinstance(status, list) else status
            )
        if os_platform:
            params["os.platform"] = os_platform
        if group:
            params["group"] = group
        if name:
            params["name"] = name
        if ip:
            params["ip"] = ip
        if select:
            params["select"] = ",".join(select)
        if sort:
            params["sort"] = sort

        response = self._client.get("agents", params=params)
        return self._client.extract_items(response)

    def iter_all_agents(
        self,
        status: str | list[str] | None = None,
        os_platform: str | None = None,
        group: str | None = None,
        select: list[str] | None = None,
    ) -> Iterator[dict]:
        """
        Generator that yields ALL agents, paginating automatically.

        Parameters
        ----------
        status : str | list[str] | None
            Status filter.
        os_platform : str | None
            OS platform filter.
        group : str | None
            Group filter.
        select : list[str] | None
            Fields to return.

        Yields
        ------
        dict
            Agent record.
        """
        params: dict = {}
        if status:
            params["status"] = (
                ",".join(status) if isinstance(status, list) else status
            )
        if os_platform:
            params["os.platform"] = os_platform
        if group:
            params["group"] = group
        if select:
            params["select"] = ",".join(select)

        yield from self._client.paginate("agents", params=params)

    def get_agent(self, agent_id: str) -> dict:
        """
        Retrieve a single agent by ID.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID (e.g. '001').

        Returns
        -------
        dict
            Agent record.

        Raises
        ------
        WazuhNotFoundError
            If the agent ID does not exist.
        """
        response = self._client.get(f"agents/{agent_id}")
        items = self._client.extract_items(response)
        if not items:
            raise WazuhNotFoundError(
                f"Agent '{agent_id}' not found.",
                status_code=404,
            )
        return items[0]

    def get_agent_by_name(self, name: str) -> dict | None:
        """
        Find a single agent by name.

        Parameters
        ----------
        name : str
            Exact agent name to find.

        Returns
        -------
        dict | None
            Agent record, or None if not found.
        """
        agents = self.list_agents(name=name, select=["id", "name", "status", "ip"])
        for agent in agents:
            if agent.get("name") == name:
                return agent
        return None

    def get_agent_summary(self) -> dict:
        """
        Return a summary of agent counts by status.

        Returns
        -------
        dict
            Keys: active, disconnected, never_connected, pending, total.
        """
        response = self._client.get("agents/summary/status")
        data = response.get("data", {})
        return {
            "active": data.get("active", 0),
            "disconnected": data.get("disconnected", 0),
            "never_connected": data.get("never_connected", 0),
            "pending": data.get("pending", 0),
            "total": data.get("total_affected_items", 0),
        }

    def get_agent_config(
        self,
        agent_id: str,
        component: str = "syscheck",
        configuration: str = "syscheck",
    ) -> dict:
        """
        Retrieve the active configuration for a specific agent component.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.
        component : str
            Component name: 'syscheck', 'agent', 'logcollector',
            'analysis', 'com', 'wmodules', etc.
        configuration : str
            Configuration section within the component.

        Returns
        -------
        dict
            Component configuration dict.
        """
        response = self._client.get(
            f"agents/{agent_id}/config/{component}/{configuration}"
        )
        return response.get("data", {})

    def get_agent_stats(self, agent_id: str, component: str = "logcollector") -> dict:
        """
        Retrieve component statistics for an agent.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.
        component : str
            'logcollector', 'agent', or 'analysis'.

        Returns
        -------
        dict
            Statistics dict.
        """
        response = self._client.get(f"agents/{agent_id}/stats/{component}")
        return response.get("data", {})

    # ── Lifecycle operations ───────────────────────────────────────────────

    def restart_agent(self, agent_id: str) -> dict:
        """
        Restart a single Wazuh agent.

        Parameters
        ----------
        agent_id : str
            Agent ID to restart.

        Returns
        -------
        dict
            API response.
        """
        return self._client.put(f"agents/{agent_id}/restart")

    def restart_agents(self, agent_ids: list[str]) -> dict:
        """
        Restart multiple agents by ID list.

        Parameters
        ----------
        agent_ids : list[str]
            List of agent IDs to restart.

        Returns
        -------
        dict
            API response including failed_items for any that could not restart.
        """
        params = {"agents_list": ",".join(agent_ids)}
        return self._client.put("agents/restart", params=params)

    def restart_agents_in_group(self, group_id: str) -> dict:
        """
        Restart all agents belonging to a group.

        Parameters
        ----------
        group_id : str
            Wazuh group name.

        Returns
        -------
        dict
            API response.
        """
        return self._client.put(f"agents/group/{group_id}/restart")

    def delete_agent(
        self,
        agent_id: str,
        purge: bool = False,
    ) -> dict:
        """
        Remove a Wazuh agent from the manager.

        Parameters
        ----------
        agent_id : str
            Agent ID to delete.
        purge : bool
            If True, permanently remove agent data from the manager.

        Returns
        -------
        dict
            API response.
        """
        params: dict = {"agents_list": agent_id}
        if purge:
            params["purge"] = "true"
        return self._client.delete("agents", params=params)

    # ── Group management ───────────────────────────────────────────────────

    def list_groups(self) -> list[dict]:
        """
        List all agent groups.

        Returns
        -------
        list[dict]
            Group records (name, count, configSum).
        """
        response = self._client.get("groups")
        return self._client.extract_items(response)

    def get_group_agents(self, group_id: str) -> list[dict]:
        """
        List agents belonging to a group.

        Parameters
        ----------
        group_id : str
            Group name.

        Returns
        -------
        list[dict]
            Agent records.
        """
        results = []
        for item in self._client.paginate(f"groups/{group_id}/agents"):
            results.append(item)
        return results

    def assign_agent_to_group(
        self,
        agent_id: str,
        group_id: str,
        force_single_group: bool = False,
    ) -> dict:
        """
        Assign an agent to a group.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        group_id : str
            Target group name.
        force_single_group : bool
            If True, remove agent from all other groups first.

        Returns
        -------
        dict
            API response.
        """
        params: dict = {}
        if force_single_group:
            params["force_single_group"] = "true"
        return self._client.put(
            f"agents/{agent_id}/group/{group_id}",
            params=params,
        )

    def remove_agent_from_group(self, agent_id: str, group_id: str) -> dict:
        """
        Remove an agent from a specific group.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        group_id : str
            Group to remove from.

        Returns
        -------
        dict
            API response.
        """
        return self._client.delete(f"agents/{agent_id}/group/{group_id}")

    # ── Normalisation helper ───────────────────────────────────────────────

    @staticmethod
    def normalise_agent(agent: dict) -> dict:
        """
        Flatten a Wazuh agent record for GNAT normalised format.

        Parameters
        ----------
        agent : dict
            Raw Wazuh agent record.

        Returns
        -------
        dict
            Normalised agent dict with consistent field names.
        """
        os_info = agent.get("os", {})
        return {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip"),
            "status": agent.get("status"),
            "os_platform": os_info.get("platform"),
            "os_name": os_info.get("name"),
            "os_version": os_info.get("version"),
            "agent_version": agent.get("version"),
            "last_keep_alive": agent.get("lastKeepAlive"),
            "date_added": agent.get("dateAdd"),
            "groups": agent.get("group", []),
            "manager": agent.get("manager"),
            "node_name": agent.get("node_name"),
            "register_ip": agent.get("registerIP"),
            "_raw": agent,
        }
