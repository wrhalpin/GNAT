# “””
gnat.connectors.wazuh.active_response

Active Response command execution for the Wazuh connector.

Wazuh Active Response (AR) allows remote execution of predefined
scripts on agents in response to security events.

## Common built-in AR scripts

firewall-drop     — Block an IP via iptables (Linux) or Windows Firewall
disable-account   — Disable a user account
restart-wazuh     — Restart the Wazuh agent
host-deny         — Add entry to /etc/hosts.deny
win_route-null    — Add null route (Windows)
netsh.exe         — Windows firewall management

AR response is fire-and-forget by default. Use the `alert` parameter
to pass contextual data to the AR script.

Security note: AR commands require the `active-response:command` RBAC
permission. Restrict this to dedicated service accounts.

## References

- https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Active-response
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/
  “””

from .client import WazuhClient
from .exceptions import WazuhPermissionError

class WazuhActiveResponseCommands:
“””
Active Response command execution.

```
Parameters
----------
client : WazuhClient
    Authenticated HTTP client.
"""

def __init__(self, client: WazuhClient) -> None:
    self._client = client

def run_command(
    self,
    command: str,
    agent_ids: list[str],
    arguments: list[str] | None = None,
    alert: dict | None = None,
    custom: bool = False,
) -> dict:
    """
    Execute an Active Response command on one or more agents.

    Parameters
    ----------
    command : str
        AR script name (e.g. 'firewall-drop', 'disable-account').
    agent_ids : list[str]
        Target agent IDs. Pass ['000'] to run on the manager itself.
    arguments : list[str] | None
        Optional arguments passed to the AR script.
        For firewall-drop: ['-', 'null', '0', '0', '1.2.3.4']
    alert : dict | None
        Alert context dict to pass to the AR script.
        Keys: id, rule.id, data.srcip, etc.
    custom : bool
        Set True for custom AR scripts (not built-in Wazuh scripts).

    Returns
    -------
    dict
        API response with affected_items and failed_items.

    Raises
    ------
    WazuhPermissionError
        If the authenticated user lacks active-response RBAC permission.
    """
    body: dict = {
        "command": command,
        "arguments": arguments or [],
        "custom": custom,
    }
    if alert:
        body["alert"] = alert

    params = {"agents_list": ",".join(agent_ids)}
    return self._client.put("active-response", body=body, params=params)

def block_ip(
    self,
    ip_address: str,
    agent_ids: list[str],
    alert_context: dict | None = None,
) -> dict:
    """
    Block an IP address on specified agents via the firewall-drop script.

    Uses the standard Wazuh firewall-drop AR script which calls
    iptables (Linux) or Windows Firewall rules.

    Parameters
    ----------
    ip_address : str
        IP address to block.
    agent_ids : list[str]
        Agents on which to apply the block.
    alert_context : dict | None
        Optional alert dict to pass as context.

    Returns
    -------
    dict
        API response.
    """
    return self.run_command(
        command="firewall-drop",
        agent_ids=agent_ids,
        arguments=["-", "null", "0", "0", ip_address],
        alert=alert_context,
    )

def unblock_ip(
    self,
    ip_address: str,
    agent_ids: list[str],
) -> dict:
    """
    Remove an IP block on specified agents (firewall-drop undo).

    Parameters
    ----------
    ip_address : str
        IP address to unblock.
    agent_ids : list[str]
        Target agents.

    Returns
    -------
    dict
        API response.
    """
    return self.run_command(
        command="firewall-drop",
        agent_ids=agent_ids,
        arguments=["-", "null", "0", "0", ip_address],
        alert={"action": "delete"},
    )

def disable_user_account(
    self,
    username: str,
    agent_ids: list[str],
) -> dict:
    """
    Disable a user account on specified agents.

    Uses the disable-account AR script. Works on Linux agents.

    Parameters
    ----------
    username : str
        Username to disable.
    agent_ids : list[str]
        Target agents.

    Returns
    -------
    dict
        API response.
    """
    return self.run_command(
        command="disable-account",
        agent_ids=agent_ids,
        arguments=[username],
    )

def restart_agent_process(self, agent_ids: list[str]) -> dict:
    """
    Restart the Wazuh agent process via Active Response.

    This is distinct from ``WazuhAgentCommands.restart_agent()``
    which uses the Manager API restart endpoint.

    Parameters
    ----------
    agent_ids : list[str]
        Target agents.

    Returns
    -------
    dict
        API response.
    """
    return self.run_command(
        command="restart-wazuh",
        agent_ids=agent_ids,
    )
```