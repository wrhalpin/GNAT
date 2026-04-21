# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.investigations.workspace
================================

Materialise a completed :class:`~.model.EvidenceGraph` into a GNAT
:class:`~gnat.context.workspace.Workspace`.

Each :class:`~.model.EvidenceNode` becomes a STIX object in the workspace.
Each :class:`~.model.EvidenceEdge` becomes a STIX Relationship with
confidence and reasoning stored in ``x_*`` extension fields.

The workspace ``metadata`` dict stores the full investigation summary,
seed list, and correlation indexes so the graph can be reconstructed
or reviewed without re-querying the connected platforms.

Usage::

    from gnat.investigations.workspace import materialize

    ws = materialize(
        graph,
        workspace_manager,
        name="ransomware-apr-2026",
    )
    print(f"Workspace '{ws.name}' — {len(ws.objects)} objects")
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.investigations.model import EvidenceGraph, EvidenceNode
from gnat.orm.base import STIXBase
from gnat.orm.relationship import Relationship

logger = logging.getLogger(__name__)

# STIX types that the ORM can represent as proper Relationship SROs
_RELATIONSHIP_TYPES = frozenset(
    {
        "part-of",
        "same-ioc",
        "same-host",
        "same-user",
        "same-campaign",
        "same-ticket",
        "indicates",
        "related-to",
    }
)


def materialize(
    graph: EvidenceGraph,
    workspace_manager: Any,
    name: str | None = None,
    description: str = "",
) -> Any:
    """
    Persist an :class:`~.model.EvidenceGraph` into a GNAT workspace.

    Parameters
    ----------
    graph : EvidenceGraph
        The completed evidence graph produced by
        :class:`~.builder.InvestigationBuilder`.
    workspace_manager : WorkspaceManager
        A :class:`~gnat.context.workspace.WorkspaceManager` instance used to
        create the workspace.
    name : str, optional
        Workspace name.  Defaults to a slug derived from *graph.title*.
    description : str, optional
        Human-readable workspace description.

    Returns
    -------
    Workspace
        The newly created (or updated) workspace containing all graph nodes
        and edges.
    """
    ws_name = name or _title_to_slug(graph.title)
    ws_desc = description or f"Evidence graph: {graph.title}"

    ws = workspace_manager.create(ws_name, description=ws_desc)

    # ── Add nodes ──────────────────────────────────────────────────────────
    added = 0
    for node in graph.nodes.values():
        try:
            stix_obj = _node_to_stix_base(node)
            ws.add(stix_obj)
            added += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not add node %s to workspace: %s", node.node_id, exc)

    # ── Add edges as Relationship SROs ─────────────────────────────────────
    for edge in graph.edges:
        src_node = graph.nodes.get(edge.source_id)
        tgt_node = graph.nodes.get(edge.target_id)
        if not src_node or not tgt_node:
            continue
        src_stix_id = src_node.stix.get("id", "")
        tgt_stix_id = tgt_node.stix.get("id", "")
        if not src_stix_id or not tgt_stix_id:
            continue
        try:
            rel = Relationship(
                relationship_type=edge.relationship_type,
                source_ref=src_stix_id,
                target_ref=tgt_stix_id,
            )
            rel.x_confidence = edge.confidence
            rel.x_reasoning = edge.reasoning
            rel.x_source_platform = edge.source_platform
            ws.add(rel)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not add edge %s→%s: %s", edge.source_id, edge.target_id, exc)

    # ── Store investigation metadata in workspace ──────────────────────────
    summary = graph.summary()
    ws.metadata = {
        "investigation_title": graph.title,
        "seeds": [
            {"value": s.value, "type": s.seed_type, "platform": s.hint_platform}
            for s in graph.seeds
        ],
        "summary": summary,
        "correlation": {
            "shared_iocs": {k: v for k, v in graph.by_ioc.items() if len(v) > 1},
            "shared_hosts": {k: v for k, v in graph.by_hostname.items() if len(v) > 1},
            "shared_users": {k: v for k, v in graph.by_username.items() if len(v) > 1},
            "shared_campaigns": {k: v for k, v in graph.by_campaign.items() if len(v) > 1},
            "shared_tickets": {k: v for k, v in graph.by_ticket.items() if len(v) > 1},
        },
    }
    ws.save()

    logger.info(
        "Materialised %d nodes, %d edges into workspace %r",
        added,
        len(graph.edges),
        ws_name,
    )
    return ws


# ── Helpers ────────────────────────────────────────────────────────────────


def _node_to_stix_base(node: EvidenceNode) -> STIXBase:
    """Wrap a normalised node's STIX dict as a :class:`~gnat.orm.base.STIXBase`."""
    stix_type = node.stix.get("type", "x-evidence-node")
    obj = STIXBase(stix_type=stix_type, **{k: v for k, v in node.stix.items() if k != "type"})
    # Tag with investigation metadata not already in the STIX dict
    obj.x_evidence_node_id = node.node_id
    obj.x_evidence_node_type = node.node_type
    obj.x_source_platform = node.platform
    obj.x_source_id = node.source_id
    if node.time_window:
        obj.x_time_window_start = node.time_window[0]
        obj.x_time_window_end = node.time_window[1]
    return obj


def _title_to_slug(title: str) -> str:
    """Convert an investigation title to a valid workspace name slug."""
    slug = title.lower()
    for ch in (" ", "/", "\\", ":", ";", ",", ".", "!", "?", '"', "'"):
        slug = slug.replace(ch, "-")
    # Collapse repeated hyphens and strip leading/trailing
    while "--" in slug:
        slug = slug.replace("--", "-")
    slug = slug.strip("-")
    return f"investigation-{slug}"[:80]
