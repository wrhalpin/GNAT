# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.investigations.model
============================

Core data model for the evidence graph built by :class:`InvestigationBuilder`.

The graph has two primitive types:

* :class:`EvidenceNode` — a normalised record from any connected platform
  (incident, observable, asset, identity, finding, task, artifact, …).
* :class:`EvidenceEdge` — a directed relationship between two nodes
  (source attribution, cross-platform correlation, parent–child containment).

:class:`EvidenceGraph` is the container that holds nodes + edges plus
pre-built correlation indexes (by IOC value, hostname, username, campaign
label, and ticket reference) so the correlator can run in O(n) time.

Seeds
-----
An investigation starts from one or more :class:`Seed` values supplied by
the analyst.  Each seed has a :class:`SeedType` that controls which platform
APIs are queried::

    seeds = [
        Seed("185.220.101.0", SeedType.IP),
        Seed("INC-4892",      SeedType.CASE_ID, hint_platform="xsoar"),
    ]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SeedType(str, Enum):
    """Classification of an investigation seed value."""

    IOC_VALUE = "ioc_value"  # Generic indicator (IP, domain, URL, hash)
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    EMAIL = "email"
    URL = "url"
    HOSTNAME = "hostname"
    USERNAME = "username"
    ALERT_ID = "alert_id"
    CASE_ID = "case_id"
    TICKET_REF = "ticket_ref"
    EMAIL_SUBJ = "email_subject"


class NodeType(str, Enum):
    """Normalised record category regardless of source platform."""

    INCIDENT = "incident"
    OBSERVABLE = "observable"
    ASSET = "asset"
    IDENTITY = "identity"
    FINDING = "finding"
    TASK = "task"
    DECISION = "decision"
    ARTIFACT = "artifact"
    TIMELINE_EVENT = "timeline_event"


@dataclass
class Seed:
    """
    A single investigation seed value.

    Parameters
    ----------
    value : str
        The seed string (IP address, case ID, hostname, hash, …).
    seed_type : SeedType
        Tells the builder how to query each connector.
    hint_platform : str or None
        Restrict expansion to a single platform name (e.g. ``"xsoar"``).
        When ``None``, all connected platforms are queried.
    """

    value: str
    seed_type: SeedType
    hint_platform: str | None = None


@dataclass
class EvidenceNode:
    """
    A normalised record from any connected platform.

    Parameters
    ----------
    node_id : str
        Stable deduplication key: ``"{platform}::{node_type}::{source_id}"``.
    node_type : NodeType
        Normalised category.
    platform : str
        Source connector name (``"xsoar"``, ``"greymatter"``, ``"threatq"``).
    source_id : str
        Native platform identifier (incident id, case UUID, event id, …).
    stix : dict
        Normalised STIX 2.1 SDO built from the native record.
    raw : dict
        Unmodified platform API response — preserved for traceability.
    ioc_values : list of str
        Extracted indicator values (IPs, domains, hashes, URLs).
    hostnames : list of str
        Extracted hostnames / asset names.
    usernames : list of str
        Extracted usernames / identity references.
    campaign_labels : list of str
        Campaign or actor labels found in tags, names, or custom fields.
    ticket_refs : list of str
        External ticket references (Jira, ServiceNow, …).
    time_window : (str, str) or None
        Earliest and latest timestamps found in the record.
    origin : str
        Which tool produced this node (``"gnat"``, ``"sandgnat"``,
        ``"sensegnat"``, ``"redgnat"``, ``"external"``).  Default ``"gnat"``.
    investigation_id : str or None
        ``x_gnat_investigation_id`` from the source STIX object, if present.
    investigation_origin : str or None
        ``x_gnat_investigation_origin`` from the source STIX object.
    investigation_link_type : str or None
        ``x_gnat_investigation_link_type`` (``"confirmed"``,
        ``"inferred"``, or ``"suggested"``).
    """

    node_id: str
    node_type: NodeType
    platform: str
    source_id: str
    stix: dict[str, Any]
    raw: dict[str, Any]
    ioc_values: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    campaign_labels: list[str] = field(default_factory=list)
    ticket_refs: list[str] = field(default_factory=list)
    infrastructure_roles: list[str] = field(default_factory=list)
    time_window: tuple[str, str] | None = None
    origin: str = "gnat"
    investigation_id: str | None = None
    investigation_origin: str | None = None
    investigation_link_type: str | None = None


@dataclass
class EvidenceEdge:
    """
    A directed relationship between two :class:`EvidenceNode` objects.

    Parameters
    ----------
    source_id : str
        ``node_id`` of the source node.
    target_id : str
        ``node_id`` of the target node.
    relationship_type : str
        Relationship verb: ``"part-of"``, ``"same-ioc"``, ``"same-host"``,
        ``"same-user"``, ``"same-campaign"``, ``"same-ticket"``,
        ``"indicates"``, ``"related-to"``.
    confidence : float
        0–1 confidence score.  Auto-correlation edges default to 0.9.
        Structural (part-of) edges are 1.0.
    source_platform : str
        Which platform produced this edge (empty for inferred edges).
    reasoning : str
        Human-readable justification (e.g. ``"Shared IOC: 185.220.101.5"``).
    link_type : str
        Cross-tool link type: ``"confirmed"``, ``"inferred"``, or
        ``"suggested"``.  Default ``"inferred"``.
    """

    source_id: str
    target_id: str
    relationship_type: str
    confidence: float = 1.0
    source_platform: str = ""
    reasoning: str = ""
    link_type: str = "inferred"


@dataclass
class EvidenceGraph:
    """
    Container for the full evidence graph produced by :class:`InvestigationBuilder`.

    Attributes
    ----------
    title : str
        Human-readable investigation title.
    seeds : list of Seed
        The seeds that started this investigation.
    nodes : dict
        ``{node_id: EvidenceNode}`` — all collected evidence.
    edges : list of EvidenceEdge
        All structural and correlation edges.
    by_ioc : dict
        ``{ioc_value_lower: [node_id, …]}`` — correlation index.
    by_hostname : dict
        ``{hostname_lower: [node_id, …]}`` — correlation index.
    by_username : dict
        ``{username_lower: [node_id, …]}`` — correlation index.
    by_campaign : dict
        ``{label_lower: [node_id, …]}`` — correlation index.
    by_ticket : dict
        ``{ticket_ref: [node_id, …]}`` — correlation index.
    """

    title: str
    seeds: list[Seed]
    nodes: dict[str, EvidenceNode] = field(default_factory=dict)
    edges: list[EvidenceEdge] = field(default_factory=list)
    # Correlation indexes populated by correlator
    by_ioc: dict[str, list[str]] = field(default_factory=dict)
    by_hostname: dict[str, list[str]] = field(default_factory=dict)
    by_username: dict[str, list[str]] = field(default_factory=dict)
    by_campaign: dict[str, list[str]] = field(default_factory=dict)
    by_ticket: dict[str, list[str]] = field(default_factory=dict)
    by_infra_role: dict[str, list[str]] = field(default_factory=dict)

    # ── Convenience helpers ───────────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        """Return a compact summary dict suitable for logging or display."""
        platform_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for node in self.nodes.values():
            platform_counts[node.platform] = platform_counts.get(node.platform, 0) + 1
            type_counts[node.node_type] = type_counts.get(node.node_type, 0) + 1
        cross = sum(
            1
            for e in self.edges
            if e.relationship_type.startswith("same-")
            and self.nodes.get(
                e.source_id, EvidenceNode("", NodeType.OBSERVABLE, "", "", {}, {})
            ).platform
            != self.nodes.get(
                e.target_id, EvidenceNode("", NodeType.OBSERVABLE, "", "", {}, {})
            ).platform
        )
        return {
            "title": self.title,
            "seeds": len(self.seeds),
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "cross_platform_hits": cross,
            "by_platform": platform_counts,
            "by_type": type_counts,
            "shared_iocs": sum(1 for v in self.by_ioc.values() if len(v) > 1),
            "shared_hosts": sum(1 for v in self.by_hostname.values() if len(v) > 1),
            "shared_campaigns": sum(1 for v in self.by_campaign.values() if len(v) > 1),
            "infrastructure_roles": {role: len(nids) for role, nids in self.by_infra_role.items()},
        }
