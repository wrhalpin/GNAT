# “””
gnat.connectors.wazuh.alerts

Alert and security event commands for the Wazuh connector.

Wazuh stores alerts in the Wazuh Indexer (OpenSearch) index
`wazuh-alerts-*`. The Manager API provides limited alert querying
via the `/alerts` endpoint (available in Wazuh 4.6+).

For richer queries (time ranges, field filters, aggregations),
WazuhIndexerCommands provides direct Indexer API access.

## Alert severity mapping (Wazuh → GNAT)

Wazuh uses integer rule levels (0–15):
0–3   → informational (GNAT severity 0)
4–7   → low          (GNAT severity 1)
8–11  → medium       (GNAT severity 2)
12–14 → high         (GNAT severity 3)
15    → critical      (GNAT severity 4)

## References

- https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Events
- https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
  “””

from .client import WazuhClient

# ── Severity mapping ──────────────────────────────────────────────────────────

def _level_to_severity(level: int) -> int:
if level >= 15:
return 4
if level >= 12:
return 3
if level >= 8:
return 2
if level >= 4:
return 1
return 0

_SEVERITY_LABELS = {0: “informational”, 1: “low”, 2: “medium”, 3: “high”, 4: “critical”}

class WazuhAlertCommands:
“””
Alert and security event query operations.

```
Parameters
----------
client : WazuhClient
    Authenticated HTTP client.
"""

def __init__(self, client: WazuhClient) -> None:
    self._client = client

# ── Alert queries ──────────────────────────────────────────────────────

def get_alerts(
    self,
    agent_id: str | None = None,
    rule_id: str | None = None,
    rule_level: int | None = None,
    min_rule_level: int | None = None,
    limit: int | None = None,
    select: list[str] | None = None,
    sort: str | None = None,
    query: str | None = None,
) -> list[dict]:
    """
    Query alerts from the Wazuh Manager API.

    Note: The /events endpoint is available in Wazuh 4.6+.
    For earlier versions, use WazuhIndexerCommands.search_alerts().

    Parameters
    ----------
    agent_id : str | None
        Filter by originating agent ID.
    rule_id : str | None
        Filter by specific rule ID.
    rule_level : int | None
        Filter by exact rule level.
    min_rule_level : int | None
        Filter to return only alerts at or above this level.
    limit : int | None
        Max alerts to return (Wazuh hard cap: 500).
    select : list[str] | None
        Fields to include in response.
    sort : str | None
        Sort expression, e.g. '-rule.level'.
    query : str | None
        Wazuh API q-syntax filter string.
        e.g. ``"rule.groups=authentication_failed;agent.id=001"``

    Returns
    -------
    list[dict]
        Alert records.
    """
    params: dict = {
        "limit": min(limit or self._client.config.max_results, 500)
    }
    if agent_id:
        params["agents_list"] = agent_id
    if rule_id:
        params["rule_ids"] = rule_id
    if rule_level is not None:
        params["rule.level"] = rule_level
    if min_rule_level is not None:
        params["q"] = f"rule.level>={min_rule_level}"
        if query:
            params["q"] += f";{query}"
    elif query:
        params["q"] = query
    if select:
        params["select"] = ",".join(select)
    if sort:
        params["sort"] = sort

    response = self._client.get("events", params=params)
    return self._client.extract_items(response)

def get_alerts_by_severity(
    self,
    severity: str | int,
    agent_id: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """
    Get alerts filtered by GNAT severity label or integer.

    Parameters
    ----------
    severity : str | int
        GNAT severity: 'informational'|'low'|'medium'|'high'|'critical'
        or integer 0–4.
    agent_id : str | None
        Optionally filter to a specific agent.
    limit : int | None
        Max results.

    Returns
    -------
    list[dict]
        Normalised alert records.
    """
    level_range = self._severity_to_level_range(severity)
    if level_range is None:
        raise ValueError(
            f"Invalid severity '{severity}'. "
            "Use 0-4 or 'informational'/'low'/'medium'/'high'/'critical'."
        )
    min_level, max_level = level_range
    query = f"rule.level>={min_level};rule.level<={max_level}"
    alerts = self.get_alerts(
        agent_id=agent_id,
        query=query,
        limit=limit,
    )
    return [self.normalise_alert(a) for a in alerts]

def get_top_rules_triggered(
    self,
    agent_id: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """
    Return the most frequently triggered rules.

    Queries the /rules/check endpoint to retrieve firing counts.
    Useful for prioritising rule tuning.

    Parameters
    ----------
    agent_id : str | None
        Limit to a specific agent's alerts.
    limit : int
        Number of top rules to return.

    Returns
    -------
    list[dict]
        Rule hit count records, sorted by count descending.
    """
    params: dict = {"limit": min(limit, 500)}
    if agent_id:
        params["agents_list"] = agent_id
    response = self._client.get("events", params=params)
    alerts = self._client.extract_items(response)

    counts: dict[str, dict] = {}
    for alert in alerts:
        rule = alert.get("rule", {})
        rid = str(rule.get("id", "unknown"))
        if rid not in counts:
            counts[rid] = {
                "rule_id": rid,
                "rule_description": rule.get("description", ""),
                "rule_level": rule.get("level", 0),
                "count": 0,
            }
        counts[rid]["count"] += 1

    return sorted(counts.values(), key=lambda x: x["count"], reverse=True)[:limit]

# ── Stats ──────────────────────────────────────────────────────────────

def get_event_stats(self) -> dict:
    """
    Get global event/alert statistics from the Wazuh manager.

    Returns
    -------
    dict
        Event counts, hourly/weekly stats.
    """
    response = self._client.get("manager/stats")
    return response.get("data", {})

def get_event_stats_by_hour(self) -> list[dict]:
    """
    Get per-hour event counts for the current day.

    Returns
    -------
    list[dict]
        24 hourly event count records.
    """
    response = self._client.get("manager/stats/hourly")
    return self._client.extract_items(response)

def get_event_stats_by_week(self) -> list[dict]:
    """
    Get per-weekday event counts.

    Returns
    -------
    list[dict]
        7 weekday event count records.
    """
    response = self._client.get("manager/stats/weekly")
    return self._client.extract_items(response)

# ── Normalisation helper ───────────────────────────────────────────────

@staticmethod
def normalise_alert(alert: dict) -> dict:
    """
    Flatten a Wazuh alert record to GNAT normalised format.

    Parameters
    ----------
    alert : dict
        Raw Wazuh alert from the API response.

    Returns
    -------
    dict
        Normalised alert dict.
    """
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = int(rule.get("level", 0))
    severity = _level_to_severity(level)
    return {
        "id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "rule_id": str(rule.get("id", "")),
        "rule_description": rule.get("description", ""),
        "rule_level": level,
        "rule_groups": rule.get("groups", []),
        "rule_mitre": rule.get("mitre", {}),
        "severity": severity,
        "severity_label": _SEVERITY_LABELS.get(severity, "unknown"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "src_ip": alert.get("data", {}).get("srcip"),
        "dst_ip": alert.get("data", {}).get("dstip"),
        "src_user": alert.get("data", {}).get("srcuser"),
        "dst_user": alert.get("data", {}).get("dstuser"),
        "full_log": alert.get("full_log"),
        "decoder": alert.get("decoder", {}).get("name"),
        "location": alert.get("location"),
        "_raw": alert,
    }

@staticmethod
def _severity_to_level_range(
    severity: str | int,
) -> tuple[int, int] | None:
    """Map a severity label or integer to a (min_level, max_level) tuple."""
    _map = {
        "informational": (0, 3), 0: (0, 3),
        "low": (4, 7),           1: (4, 7),
        "medium": (8, 11),       2: (8, 11),
        "high": (12, 14),        3: (12, 14),
        "critical": (15, 15),    4: (15, 15),
    }
    return _map.get(severity)
```