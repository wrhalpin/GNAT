# “””
ctm_sak.connectors.wazuh.rules

Rule and decoder management commands for the Wazuh connector.

## References

- https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Rules
  “””

from .client import WazuhClient

class WazuhRulesCommands:
“””
Ruleset inspection and management operations.

```
Parameters
----------
client : WazuhClient
    Authenticated HTTP client.
"""

def __init__(self, client: WazuhClient) -> None:
    self._client = client

def list_rules(
    self,
    rule_ids: list[str] | None = None,
    group: str | None = None,
    level: int | None = None,
    filename: str | None = None,
    status: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """
    List Wazuh detection rules with optional filters.

    Parameters
    ----------
    rule_ids : list[str] | None
        Filter by specific rule IDs.
    group : str | None
        Filter by rule group (e.g. 'authentication_failed').
    level : int | None
        Filter by exact severity level (0-15).
    filename : str | None
        Filter by rule file name.
    status : str | None
        'enabled' or 'disabled'.
    limit : int | None
        Max results.

    Returns
    -------
    list[dict]
        Rule records.
    """
    params: dict = {
        "limit": min(limit or self._client.config.max_results, 500)
    }
    if rule_ids:
        params["rule_ids"] = ",".join(rule_ids)
    if group:
        params["group"] = group
    if level is not None:
        params["level"] = level
    if filename:
        params["filename"] = filename
    if status:
        params["status"] = status

    response = self._client.get("rules", params=params)
    return self._client.extract_items(response)

def get_rule(self, rule_id: str) -> dict | None:
    """
    Retrieve a single rule by ID.

    Parameters
    ----------
    rule_id : str
        Rule ID string (e.g. '100200').

    Returns
    -------
    dict | None
        Rule record or None if not found.
    """
    response = self._client.get("rules", params={"rule_ids": rule_id})
    items = self._client.extract_items(response)
    return items[0] if items else None

def list_rule_groups(self) -> list[str]:
    """
    List all defined rule group names.

    Returns
    -------
    list[str]
        Rule group name strings.
    """
    response = self._client.get("rules/groups")
    return self._client.extract_items(response)

def list_rule_files(self, status: str | None = None) -> list[dict]:
    """
    List rule XML files on the Wazuh manager.

    Parameters
    ----------
    status : str | None
        'enabled' or 'disabled'.

    Returns
    -------
    list[dict]
        Rule file records.
    """
    params: dict = {}
    if status:
        params["status"] = status
    response = self._client.get("rules/files", params=params)
    return self._client.extract_items(response)

def list_decoders(
    self,
    filename: str | None = None,
    status: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """
    List Wazuh log decoders.

    Parameters
    ----------
    filename : str | None
        Filter by decoder file name.
    status : str | None
        'enabled' or 'disabled'.
    limit : int | None
        Max results.

    Returns
    -------
    list[dict]
        Decoder records.
    """
    params: dict = {
        "limit": min(limit or self._client.config.max_results, 500)
    }
    if filename:
        params["filename"] = filename
    if status:
        params["status"] = status
    response = self._client.get("decoders", params=params)
    return self._client.extract_items(response)

def get_mitre_techniques(self, rule_id: str | None = None) -> list[dict]:
    """
    Get MITRE ATT&CK technique mappings for rules.

    Parameters
    ----------
    rule_id : str | None
        Optionally filter to a specific rule.

    Returns
    -------
    list[dict]
        MITRE technique mapping records.
    """
    params: dict = {}
    if rule_id:
        params["rule_ids"] = rule_id
    response = self._client.get("rules/requirement/mitre", params=params)
    return self._client.extract_items(response)
```