# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.sentinel.analytic_rules
============================================
Analytic rule management commands for Microsoft Sentinel.

Analytic rules are KQL-based detection rules that generate alerts.
Rule types: Scheduled, MicrosoftSecurityIncidentCreation, Fusion,
MLBehaviorAnalytics, ThreatIntelligence, NRT (Near Real Time).

References
----------
- https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules
"""

from collections.abc import Iterator

from .client import SentinelClient


class SentinelAnalyticRuleCommands:
    """Analytic rule inspection and management."""

    def __init__(self, client: SentinelClient) -> None:
        """Initialize SentinelAnalyticRuleCommands."""
        self._client = client

    def list_rules(
        self,
        kind: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List analytic rules.

        Parameters
        ----------
        kind : str | None
            Filter by rule kind: 'Scheduled', 'Fusion', 'NRT',
            'MicrosoftSecurityIncidentCreation', 'MLBehaviorAnalytics'.
        limit : int | None
            Max results.

        Returns
        -------
        list[dict]
        """
        items = []
        for item in self._client.paginate("alertRules"):
            if kind and item.get("kind") != kind:
                continue
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def iter_all_rules(self, kind: str | None = None) -> Iterator[dict]:
        """Generator yielding all analytic rules."""
        for item in self._client.paginate("alertRules"):
            if kind and item.get("kind") != kind:
                continue
            yield item

    def get_rule(self, rule_id: str) -> dict:
        """Retrieve a single analytic rule by ID."""
        return self._client.get(f"alertRules/{rule_id}")

    def enable_rule(self, rule_id: str) -> dict:
        """Enable a scheduled analytic rule."""
        current = self.get_rule(rule_id)
        props = current.get("properties", {})
        props["enabled"] = True
        return self._client.put(f"alertRules/{rule_id}", body=current)

    def disable_rule(self, rule_id: str) -> dict:
        """Disable a scheduled analytic rule."""
        current = self.get_rule(rule_id)
        props = current.get("properties", {})
        props["enabled"] = False
        return self._client.put(f"alertRules/{rule_id}", body=current)

    def delete_rule(self, rule_id: str) -> dict:
        """Delete an analytic rule."""
        return self._client.delete(f"alertRules/{rule_id}")

    def list_rule_templates(self, kind: str | None = None) -> list[dict]:
        """
        List available rule templates (Microsoft-provided detection templates).

        Parameters
        ----------
        kind : str | None
            Filter by template kind.
        """
        items = []
        for item in self._client.paginate("alertRuleTemplates"):
            if kind and item.get("kind") != kind:
                continue
            items.append(item)
        return items

    @staticmethod
    def normalise_rule(rule: dict) -> dict:
        """Flatten a Sentinel analytic rule to GNAT normalised format."""
        props = rule.get("properties", {})
        return {
            "id": rule.get("name"),
            "kind": rule.get("kind"),
            "display_name": props.get("displayName"),
            "description": props.get("description", ""),
            "enabled": props.get("enabled", False),
            "severity": props.get("severity"),
            "query": props.get("query"),
            "query_frequency": props.get("queryFrequency"),
            "query_period": props.get("queryPeriod"),
            "trigger_operator": props.get("triggerOperator"),
            "trigger_threshold": props.get("triggerThreshold"),
            "tactics": props.get("tactics", []),
            "techniques": props.get("techniques", []),
            "last_modified": props.get("lastModifiedUtc"),
            "_raw": rule,
        }
