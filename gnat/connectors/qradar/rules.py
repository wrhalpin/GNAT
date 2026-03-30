"""
gnat.connectors.qradar.rules
==================================
Correlation rule inspection commands for the QRadar connector.

Rules are the detection logic in QRadar. When event/flow data matches
a rule's conditions, the rule fires and contributes to (or creates) an
offense. Rules are read-only via the API — modification requires the
QRadar UI or the custom rule wizard.

Rule fields of interest
------------------------
  id          — unique integer rule ID
  name        — display name
  type        — 'COMMON', 'LOG', 'NETWORK', 'OFFLINE', 'ANOMALY'
  enabled     — bool
  owner       — owning username
  notes       — analyst notes
  origin      — 'SYSTEM', 'USER', 'MODIFICATION'
  base_host_id — the rule's host context
  average_capacity — average capacity usage %
  capacity_timestamp — last capacity measurement

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-analytics-rules
"""

from .client import QRadarClient


class QRadarRulesCommands:
    """
    Correlation rule inspection operations.

    Parameters
    ----------
    client : QRadarClient
        Authenticated HTTP client.
    """

    def __init__(self, client: QRadarClient) -> None:
        self._client = client

    def list_rules(
        self,
        filter_val: str | None = None,
        fields: str | None = None,
        enabled_only: bool = False,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List correlation rules.

        Parameters
        ----------
        filter_val : str | None
            QRadar filter expression, e.g. ``"type=COMMON and enabled=true"``.
        fields : str | None
            Comma-separated fields to return.
        enabled_only : bool
            If True, only return enabled rules.
        limit : int | None
            Max rules to return.

        Returns
        -------
        list[dict]
            Rule records.
        """
        params: dict = {}
        if enabled_only:
            params["filter"] = "enabled=true"
        if filter_val:
            if "filter" in params:
                params["filter"] = f"({params['filter']}) and ({filter_val})"
            else:
                params["filter"] = filter_val
        if fields:
            params["fields"] = fields

        items = []
        for item in self._client.paginate("analytics/rules", params=params):
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def get_rule(self, rule_id: int) -> dict:
        """
        Retrieve a single rule by ID.

        Parameters
        ----------
        rule_id : int
            Rule integer ID.

        Returns
        -------
        dict
            Rule record.
        """
        return self._client.get(f"analytics/rules/{rule_id}")

    def search_rules(self, name_fragment: str) -> list[dict]:
        """
        Find rules by name substring.

        Parameters
        ----------
        name_fragment : str
            Substring to search for in rule names.

        Returns
        -------
        list[dict]
            Matching rule records.
        """
        return self.list_rules(filter=f"name ilike '%{name_fragment}%'")

    def list_rule_groups(self) -> list[dict]:
        """
        List rule groups / categories.

        Returns
        -------
        list[dict]
            Rule group records.
        """
        return list(self._client.paginate("analytics/rule_groups"))
