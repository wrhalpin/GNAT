"""
gnat.connectors.elastic.kibana_rules

Kibana Security Detection Engine rule commands.

The Detection Engine (formerly SIEM Detection Engine) manages
detection rules that generate alerts when matched.

## Rule types supported by Kibana

query          -- KQL or Lucene query match
saved_query    -- pre-saved KQL query
eql            -- Event Query Language (sequence detection)
machine_learning -- ML anomaly job
threshold      -- field count threshold
threat_match   -- threat intelligence indicator match
new_terms      -- new field values detection

## Key rule fields

rule_id        -- stable user-defined UUID (not the Kibana internal id)
name           -- human-readable rule name
description    -- rule description
enabled        -- bool
severity       -- 'low' | 'medium' | 'high' | 'critical'
risk_score     -- integer 1-100
type           -- rule type string (see above)
query          -- the detection query (for 'query' type)
language       -- 'kuery' | 'lucene' | 'eql'
index          -- index patterns to search
tags           -- list of tag strings
threat         -- MITRE ATT&CK mapping list
interval       -- schedule interval (e.g. '5m')
from           -- search window lookback (e.g. 'now-6m')
to             -- search window end (e.g. 'now')
version        -- rule schema version (incremented on update)

Kibana Detection Engine API base path:
/api/detection_engine/rules/

## References

- https://www.elastic.co/guide/en/security/current/rule-api-overview.html
"""

import urllib.parse
from collections.abc import Iterator

from .client import ElasticClient

_RULES_BASE = "api/detection_engine/rules"


class KibanaRulesCommands:
    """
    Detection Engine rule management operations.

    Parameters
    ----------
    client : ElasticClient
        Authenticated HTTP client.
    """

    def __init__(self, client: ElasticClient) -> None:
        self._client = client

    # ── List and search ────────────────────────────────────────────────────

    def list_rules(
        self,
        page: int = 1,
        per_page: int = 20,
        sort_field: str = "enabled",
        sort_order: str = "desc",
        filter_val: str | None = None,
        tags: list[str] | None = None,
    ) -> dict:
        """
        List detection rules with pagination.

        Parameters
        ----------
        page : int
            Page number (1-based).
        per_page : int
            Rules per page (max 100).
        sort_field : str
            Field to sort by: 'enabled', 'created_at', 'updated_at', 'name'.
        sort_order : str
            'asc' or 'desc'.
        filter_val : str | None
            KQL filter string (e.g. ``'alert.attributes.name: "Malware*"'``).
        tags : list[str] | None
            Filter by rule tags (AND logic).

        Returns
        -------
        dict
            ``{"data": [...], "total": N, "page": N, "perPage": N}``
        """
        params: dict = {
            "page": page,
            "per_page": min(per_page, 100),
            "sort_field": sort_field,
            "sort_order": sort_order,
        }
        if filter_val:
            params["filter"] = filter_val
        if tags:
            params["tags"] = tags

        return self._client.kibana_get(f"{_RULES_BASE}/_find", params=params)

    def iter_all_rules(
        self,
        filter_val: str | None = None,
        tags: list[str] | None = None,
    ) -> Iterator[dict]:
        """
        Generator yielding all detection rules, paginating automatically.

        Parameters
        ----------
        filter_val : str | None
            KQL filter.
        tags : list[str] | None
            Tag filter.

        Yields
        ------
        dict
            Rule dicts.
        """
        yield from self._client.kibana_paginate(
            f"{_RULES_BASE}/_find",
            params={"sort_field": "created_at", "sort_order": "asc"},
            page_size=100,
            data_key="data",
        )

    def get_rule(self, rule_id: str) -> dict:
        """
        Retrieve a rule by its stable ``rule_id``.

        Parameters
        ----------
        rule_id : str
            The rule's ``rule_id`` field (user-defined UUID, not Kibana internal id).

        Returns
        -------
        dict
            Rule dict.

        Raises
        ------
        ElasticKibanaNotFoundError
            If no rule with this rule_id exists.
        """
        return self._client.kibana_get(_RULES_BASE, params={"rule_id": rule_id})

    def get_rule_by_id(self, rule_id: str) -> dict:
        """
        Retrieve a rule by Kibana internal ``id``.

        Parameters
        ----------
        rule_id : str
            Kibana internal rule UUID.

        Returns
        -------
        dict
            Rule dict.
        """
        return self._client.kibana_get(_RULES_BASE, params={"id": rule_id})

    # ── CRUD ───────────────────────────────────────────────────────────────

    def create_rule(self, rule: dict) -> dict:
        """
        Create a new detection rule.

        Parameters
        ----------
        rule : dict
            Rule definition. Required fields vary by rule type.
            Minimum for a 'query' type rule:
              name, description, risk_score, severity, type,
              query, language, index.

        Returns
        -------
        dict
            Created rule with Kibana-assigned id and timestamps.
        """
        return self._client.kibana_post(_RULES_BASE, body=rule)

    def update_rule(self, rule: dict) -> dict:
        """
        Update an existing rule (full update, not patch).

        The rule dict must include either ``id`` or ``rule_id`` to identify
        which rule to update. All other required fields must be present.

        Parameters
        ----------
        rule : dict
            Updated rule definition.

        Returns
        -------
        dict
            Updated rule.
        """
        return self._client.kibana_put(_RULES_BASE, body=rule)

    def patch_rule(self, rule_id: str, updates: dict) -> dict:
        """
        Partially update a rule (patch specific fields only).

        Parameters
        ----------
        rule_id : str
            Stable rule_id of the rule to patch.
        updates : dict
            Fields to update (e.g. ``{"enabled": False, "risk_score": 75}``).

        Returns
        -------
        dict
            Updated rule.
        """
        updates["rule_id"] = rule_id
        return self._client.kibana_patch(_RULES_BASE, body=updates)

    def delete_rule(self, rule_id: str) -> dict:
        """
        Delete a rule by rule_id.

        Parameters
        ----------
        rule_id : str
            Stable rule_id.

        Returns
        -------
        dict
            Deleted rule info.
        """
        return self._client.kibana_delete(_RULES_BASE, params={"rule_id": rule_id})

    # ── Enable / disable ───────────────────────────────────────────────────

    def enable_rule(self, rule_id: str) -> dict:
        """
        Enable a detection rule.

        Parameters
        ----------
        rule_id : str
            Stable rule_id.

        Returns
        -------
        dict
            Updated rule.
        """
        return self.patch_rule(rule_id, {"enabled": True})

    def disable_rule(self, rule_id: str) -> dict:
        """
        Disable a detection rule.

        Parameters
        ----------
        rule_id : str
            Stable rule_id.

        Returns
        -------
        dict
            Updated rule.
        """
        return self.patch_rule(rule_id, {"enabled": False})

    def bulk_enable(self, rule_ids: list[str]) -> dict:
        """
        Enable multiple rules in one request.

        Parameters
        ----------
        rule_ids : list[str]
            List of stable rule_id values.

        Returns
        -------
        dict
            Bulk action response.
        """
        _actions = [{"type": "enable", "id": rid} for rid in rule_ids]
        return self._client.kibana_patch(
            f"{_RULES_BASE}/_bulk_action",
            body={"action": "enable", "rule_ids": rule_ids},
        )

    def bulk_disable(self, rule_ids: list[str]) -> dict:
        """
        Disable multiple rules in one request.

        Parameters
        ----------
        rule_ids : list[str]
            List of stable rule_id values.

        Returns
        -------
        dict
            Bulk action response.
        """
        return self._client.kibana_patch(
            f"{_RULES_BASE}/_bulk_action",
            body={"action": "disable", "rule_ids": rule_ids},
        )

    def bulk_delete(self, rule_ids: list[str]) -> dict:
        """
        Delete multiple rules in one request.

        Parameters
        ----------
        rule_ids : list[str]
            List of stable rule_id values.

        Returns
        -------
        dict
            Bulk delete response.
        """
        return self._client.kibana_post(
            f"{_RULES_BASE}/_bulk_delete",
            body=[{"rule_id": rid} for rid in rule_ids],
        )

    # ── Import / export ────────────────────────────────────────────────────

    def export_rules(
        self,
        rule_ids: list[str] | None = None,
    ) -> bytes:
        """
        Export detection rules as NDJSON.

        Parameters
        ----------
        rule_ids : list[str] | None
            Specific rule_ids to export. If None, exports all rules.

        Returns
        -------
        bytes
            NDJSON-encoded rule definitions.
        """
        url = self._client.config.kibana_url(f"{_RULES_BASE}/_export")
        body = None
        if rule_ids:
            body = {"objects": [{"rule_id": rid} for rid in rule_ids]}

        headers = self._client.auth.get_kibana_headers("POST")
        import json

        encoded = json.dumps(body).encode() if body else b""
        response = self._client._http.request("POST", url, body=encoded, headers=headers)
        return response.data

    def import_rules(
        self,
        ndjson_data: bytes,
        overwrite: bool = False,
    ) -> dict:
        """
        Import detection rules from NDJSON data.

        Parameters
        ----------
        ndjson_data : bytes
            NDJSON-encoded rule definitions (from export or manual creation).
        overwrite : bool
            If True, overwrite existing rules with matching rule_id.

        Returns
        -------
        dict
            Import summary with success_count, errors_count, rules_count.
        """
        params = {"overwrite": str(overwrite).lower()}
        url = self._client.config.kibana_url(f"{_RULES_BASE}/_import")
        if params:
            url += f"?{urllib.parse.urlencode(params)}"

        # Import requires multipart/form-data with file field
        headers = {
            **self._client.auth.get_kibana_headers("POST"),
            "Content-Type": "application/ndjson",
        }
        response = self._client._http.request(
            "POST",
            url,
            body=ndjson_data,
            headers=headers,
        )
        return self._client._safe_parse(response.data)

    # ── Normalisation helper ───────────────────────────────────────────────

    @staticmethod
    def normalise_rule(rule: dict) -> dict:
        """
        Flatten a Kibana detection rule for GNAT normalised format.

        Parameters
        ----------
        rule : dict
            Raw Kibana rule dict.

        Returns
        -------
        dict
            Normalised rule dict.
        """
        threat = rule.get("threat", [])
        mitre_techniques: list[str] = []
        mitre_tactics: list[str] = []
        for t in threat:
            tactic = t.get("tactic", {})
            if tactic.get("id"):
                mitre_tactics.append(tactic["id"])
            for tech in t.get("technique", []):
                if tech.get("id"):
                    mitre_techniques.append(tech["id"])
            # Sub-techniques
            for tech in t.get("technique", []):
                for sub in tech.get("subtechnique", []):
                    if sub.get("id"):
                        mitre_techniques.append(sub["id"])

        return {
            "id": rule.get("id"),
            "rule_id": rule.get("rule_id"),
            "name": rule.get("name"),
            "description": rule.get("description"),
            "enabled": rule.get("enabled"),
            "type": rule.get("type"),
            "severity": rule.get("severity"),
            "risk_score": rule.get("risk_score"),
            "tags": rule.get("tags", []),
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "query": rule.get("query"),
            "language": rule.get("language"),
            "index": rule.get("index", []),
            "interval": rule.get("interval"),
            "from": rule.get("from"),
            "version": rule.get("version"),
            "created_at": rule.get("created_at"),
            "updated_at": rule.get("updated_at"),
            "_raw": rule,
        }
