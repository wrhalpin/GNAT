"""
gnat.analysis.graph
====================

:class:`GraphQuery` API for interactive investigative graph exploration.

Analysts can pivot from a known entity, expand multi-hop neighbourhoods,
and filter by confidence threshold, date range, or platform — all without
a separate graph database.  The graph is assembled at query time from an
in-memory :class:`~gnat.investigations.model.EvidenceGraph`.

Operations
----------
- **pivot** — given entity X, return all entities related to X within N hops
- **expand** — add a set of nodes and their immediate edges to a
  :class:`GraphContext`
- **filter** — apply confidence threshold, date range, or platform filter to a
  :class:`GraphContext`

Usage::

    from gnat.analysis.graph import GraphQuery

    gq      = GraphQuery(evidence_graph)
    context = gq.pivot("xsoar::incident::INC-4892", hops=2)
    context = gq.filter(context, min_confidence=0.6, platforms=["xsoar", "threatq"])

    print(f"Nodes: {len(context.nodes)}, Edges: {len(context.edges)}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GraphContext:
    """
    A mutable sub-graph assembled by :class:`GraphQuery` operations.

    Parameters
    ----------
    nodes : dict
        Mapping of node_id → EvidenceNode.
    edges : list
        EvidenceEdge objects connecting nodes in this context.
    seed_ids : list of str
        Node IDs that seeded this context.
    """

    nodes: dict[str, Any] = field(default_factory=dict)
    edges: list[Any] = field(default_factory=list)
    seed_ids: list[str] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def platforms(self) -> set[str]:
        """Distinct platforms in this context."""
        result: set[str] = set()
        for node in self.nodes.values():
            # Support both node.platform (str) and node.platforms (set/list)
            ps = getattr(node, "platforms", None)
            if ps:
                result.update(ps)
            else:
                p = getattr(node, "platform", None)
                if p:
                    result.add(p)
        return result

    def to_dict(self) -> dict[str, Any]:
        """Serialise context to a plain dict (for API responses)."""
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "seed_ids": self.seed_ids,
            "platforms": self.platforms(),
            "nodes": {
                nid: {
                    **(n.stix if isinstance(n.stix, dict) else {"id": nid}),
                    **(
                        {"infrastructure_roles": n.infrastructure_roles}
                        if getattr(n, "infrastructure_roles", None)
                        else {}
                    ),
                }
                for nid, n in self.nodes.items()
            },
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.relationship_type,
                    "confidence": e.confidence,
                }
                for e in self.edges
            ],
        }


class GraphQuery:
    """
    Interactive graph exploration over an :class:`~gnat.investigations.model.EvidenceGraph`.

    Parameters
    ----------
    graph : EvidenceGraph
        The evidence graph to query.  Must have ``nodes`` (dict) and
        ``edges`` (list) attributes.

    Examples
    --------
    >>> gq = GraphQuery(evidence_graph)
    >>> ctx = gq.pivot("xsoar::incident::INC-4892", hops=1)
    >>> ctx.node_count
    5
    """

    def __init__(self, graph: Any) -> None:
        self._graph = graph
        # Build adjacency index once
        self._adjacency = self._build_adjacency()

    # ── Public API ────────────────────────────────────────────────────────────

    def pivot(self, node_id: str, hops: int = 1) -> GraphContext:
        """
        Return all nodes within *hops* edges of *node_id*.

        Parameters
        ----------
        node_id : str
            Starting node identifier.
        hops : int
            Number of edge traversals (default 1).

        Returns
        -------
        GraphContext

        Raises
        ------
        KeyError
            If *node_id* is not in the graph.
        """
        if node_id not in self._graph.nodes:
            raise KeyError(f"Node not found in graph: {node_id!r}")

        visited: set[str] = {node_id}
        frontier = {node_id}

        for _ in range(hops):
            next_frontier: set[str] = set()
            for nid in frontier:
                for neighbor in self._adjacency.get(nid, set()):
                    if neighbor not in visited:
                        next_frontier.add(neighbor)
                        visited.add(neighbor)
            frontier = next_frontier

        return self._build_context(visited, seed_ids=[node_id])

    def expand(self, context: GraphContext, node_ids: list[str]) -> GraphContext:
        """
        Add *node_ids* and their immediate neighbours to *context*.

        Parameters
        ----------
        context : GraphContext
            Existing context to expand.
        node_ids : list of str
            Node IDs to add.

        Returns
        -------
        GraphContext
            New context containing the union of existing and new nodes.
        """
        all_ids = set(context.nodes.keys())
        for nid in node_ids:
            all_ids.add(nid)
            all_ids |= self._adjacency.get(nid, set())

        new_ctx = self._build_context(all_ids, seed_ids=context.seed_ids + node_ids)
        return new_ctx

    def filter(
        self,
        context: GraphContext,
        min_confidence: float | None = None,
        platforms: list[str] | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        node_types: list[str] | None = None,
        infra_roles: list[str] | None = None,
    ) -> GraphContext:
        """
        Apply filters to a :class:`GraphContext`, returning a narrowed context.

        Parameters
        ----------
        context : GraphContext
        min_confidence : float, optional
            Retain edges with ``confidence >= min_confidence`` (0.0–1.0).
        platforms : list of str, optional
            Retain nodes from these platforms only.
        date_from : datetime, optional
            Retain nodes first observed on or after this date.
        date_to : datetime, optional
            Retain nodes first observed on or before this date.
        node_types : list of str, optional
            Retain nodes with these ``node_type`` values (e.g. ``["incident",
            "observable"]``).

        Returns
        -------
        GraphContext
        """
        filtered_nodes: dict[str, Any] = {}

        for nid, node in context.nodes.items():
            # Platform filter — support both node.platform and node.platforms
            if platforms is not None:
                node_platforms = getattr(node, "platforms", None) or (
                    {getattr(node, "platform", None)} if getattr(node, "platform", None) else set()
                )
                if not set(platforms) & set(node_platforms):
                    continue
            # Node type filter — accept string or enum value
            if node_types is not None:
                raw_type = getattr(node, "node_type", None)
                nt = raw_type.value if hasattr(raw_type, "value") else str(raw_type)
                if nt not in node_types:
                    continue
            # Confidence filter on nodes
            if min_confidence is not None:
                node_conf = getattr(node, "confidence", None)
                if node_conf is not None and node_conf < min_confidence:
                    continue
            # Date filter
            if date_from or date_to:
                ts = self._node_timestamp(node)
                if ts:
                    if date_from and ts < date_from:
                        continue
                    if date_to and ts > date_to:
                        continue
            # Infrastructure role filter
            if infra_roles is not None:
                node_roles = getattr(node, "infrastructure_roles", [])
                if not set(infra_roles) & set(node_roles):
                    continue
            filtered_nodes[nid] = node

        filtered_edges = [
            e
            for e in context.edges
            if e.source_id in filtered_nodes and e.target_id in filtered_nodes
        ]

        return GraphContext(
            nodes=filtered_nodes,
            edges=filtered_edges,
            seed_ids=context.seed_ids,
        )

    def neighbours(self, node_id: str) -> list[str]:
        """Return the immediate neighbour node IDs of *node_id*."""
        return list(self._adjacency.get(node_id, set()))

    def shortest_path(self, source_id: str, target_id: str) -> list[str] | None:
        """
        Find the shortest path between two nodes using BFS.

        Returns
        -------
        list of str
            Ordered node IDs from source to target, or ``None`` if unreachable.
        """
        if source_id not in self._graph.nodes or target_id not in self._graph.nodes:
            return None
        if source_id == target_id:
            return [source_id]

        visited = {source_id}
        queue: list[list[str]] = [[source_id]]

        while queue:
            path = queue.pop(0)
            node = path[-1]
            for neighbor in self._adjacency.get(node, set()):
                if neighbor == target_id:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
        return None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _build_adjacency(self) -> dict[str, set[str]]:
        adj: dict[str, set[str]] = {}
        for edge in self._graph.edges:
            adj.setdefault(edge.source_id, set()).add(edge.target_id)
            adj.setdefault(edge.target_id, set()).add(edge.source_id)
        return adj

    def _build_context(self, node_ids: set[str], seed_ids: list[str]) -> GraphContext:
        nodes = {nid: self._graph.nodes[nid] for nid in node_ids if nid in self._graph.nodes}
        edges = [e for e in self._graph.edges if e.source_id in nodes and e.target_id in nodes]
        return GraphContext(nodes=nodes, edges=edges, seed_ids=seed_ids)

    @staticmethod
    def _node_timestamp(node: Any) -> datetime | None:
        """Extract a comparable datetime from a node's time_window or stix."""
        if node.time_window and node.time_window[0]:
            try:
                return datetime.fromisoformat(node.time_window[0].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        if node.stix:
            ts = node.stix.get("first_observed") or node.stix.get("created")
            if ts:
                try:
                    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass
        return None
