# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.federation.topology
=========================

Topology helpers for federated GNAT deployments.

Provides hierarchy traversal (ancestors, descendants), topology graph
construction for REST API responses, and effective TLP computation for
directed peer edges.

Default TLP rules for hierarchical edges
-----------------------------------------
* **Child → Parent** (``direction`` from child's perspective): up to AMBER.
  Subsidiaries share operational intel up the hierarchy.
* **Parent → Child**: up to GREEN.
  The parent distributes sector-level threat intel downward.

These defaults can be overridden by setting explicit ``max_tlp`` values
on each peer record in the registry.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.federation.peer import FederationPeer, PeerRegistry

logger = logging.getLogger(__name__)

# Default TLP for hierarchy edges (as strings matching TLPLevel values)
DEFAULT_CHILD_TO_PARENT_TLP = "amber"  # subsidiary → parent
DEFAULT_PARENT_TO_CHILD_TLP = "green"  # parent → subsidiary


class FederationTopology:
    """
    Topology graph analysis for a set of registered federation peers.

    Parameters
    ----------
    registry : PeerRegistry
        Source of peer configuration.

    Examples
    --------
    ::

        topo = FederationTopology(registry)
        print(topo.ancestors("hospital-a"))    # ["health-system-parent"]
        print(topo.descendants("parent"))      # ["hospital-a", "hospital-b"]
        print(topo.is_leaf("hospital-a"))      # True
        print(topo.effective_max_tlp("hospital-a", "health-system-parent"))  # "amber"
    """

    def __init__(self, registry: PeerRegistry) -> None:
        """Initialize FederationTopology."""
        self._registry = registry

    # ------------------------------------------------------------------
    # Hierarchy traversal
    # ------------------------------------------------------------------

    def ancestors(self, peer_id: str) -> list[str]:
        """
        Return the ancestor chain for *peer_id* from immediate parent to root.

        Parameters
        ----------
        peer_id : str
            Starting peer.

        Returns
        -------
        list[str]
            Peer IDs from nearest ancestor to root.  Empty for root nodes.

        Raises
        ------
        ValueError
            If a cycle is detected in the parent chain.
        """
        result: list[str] = []
        visited: set[str] = {peer_id}
        current_id = peer_id

        while True:
            peer = self._registry.get(current_id)
            if peer is None or peer.parent_peer_id is None:
                break
            parent_id = peer.parent_peer_id
            if parent_id in visited:
                raise ValueError(f"Cycle detected in federation hierarchy at peer {parent_id!r}.")
            visited.add(parent_id)
            result.append(parent_id)
            current_id = parent_id

        return result

    def descendants(self, peer_id: str) -> list[str]:
        """
        Return all descendants of *peer_id* (children, grandchildren, …).

        Parameters
        ----------
        peer_id : str
            Root of the subtree.

        Returns
        -------
        list[str]
            All descendant peer IDs in breadth-first order.
        """
        result: list[str] = []
        queue: list[str] = [peer_id]
        visited: set[str] = {peer_id}

        while queue:
            current = queue.pop(0)
            children = [
                p.peer_id
                for p in self._registry.list()
                if p.parent_peer_id == current and p.peer_id not in visited
            ]
            for child_id in children:
                visited.add(child_id)
                result.append(child_id)
                queue.append(child_id)

        return result

    def parent(self, peer_id: str) -> FederationPeer | None:
        """Return the parent peer of *peer_id*, or ``None``."""
        peer = self._registry.get(peer_id)
        if peer is None or peer.parent_peer_id is None:
            return None
        return self._registry.get(peer.parent_peer_id)

    def children(self, peer_id: str) -> list[FederationPeer]:
        """Return direct children of *peer_id*."""
        return [p for p in self._registry.list() if p.parent_peer_id == peer_id]

    def is_leaf(self, peer_id: str) -> bool:
        """Return ``True`` if *peer_id* has no registered children."""
        return not any(p.parent_peer_id == peer_id for p in self._registry.list())

    def is_root(self, peer_id: str) -> bool:
        """Return ``True`` if *peer_id* has no parent declared."""
        peer = self._registry.get(peer_id)
        return peer is not None and peer.parent_peer_id is None

    # ------------------------------------------------------------------
    # TLP computation
    # ------------------------------------------------------------------

    def effective_max_tlp(self, from_peer_id: str, to_peer_id: str) -> str:
        """
        Compute the effective TLP ceiling for sharing from *from_peer_id*
        to *to_peer_id*.

        Logic
        -----
        1. Use the explicit ``max_tlp`` configured on the sending peer's record.
        2. If both peers are in a parent-child relationship, apply hierarchy
           defaults when the sender's ``max_tlp`` is still the default ``"green"``:
           - Child → Parent: ``"amber"``
           - Parent → Child: ``"green"``

        Parameters
        ----------
        from_peer_id : str
            The peer sending data.
        to_peer_id : str
            The peer receiving data.

        Returns
        -------
        str
            TLP level string (e.g. ``"green"``, ``"amber"``).
        """
        sender = self._registry.get(from_peer_id)
        if sender is None:
            return DEFAULT_PARENT_TO_CHILD_TLP

        # Explicit max_tlp always wins unless it's the generic default
        if sender.max_tlp != "green":
            return sender.max_tlp

        # Check hierarchy relationship
        if sender.parent_peer_id == to_peer_id:
            # from_peer_id is a child sending up to its parent
            return DEFAULT_CHILD_TO_PARENT_TLP

        receiver = self._registry.get(to_peer_id)
        if receiver is not None and receiver.parent_peer_id == from_peer_id:
            # from_peer_id is a parent sending down to a child
            return DEFAULT_PARENT_TO_CHILD_TLP

        return sender.max_tlp

    # ------------------------------------------------------------------
    # Graph representation
    # ------------------------------------------------------------------

    def hierarchy_graph(self) -> dict[str, Any]:
        """
        Return a JSON-serialisable graph of the federation topology.

        The graph contains:

        * ``nodes`` — list of peer summary dicts
        * ``edges`` — list of ``{from, to, direction, max_tlp}`` dicts
        * ``hierarchy_edges`` — subset of edges that cross a parent-child boundary

        Returns
        -------
        dict
            Topology graph suitable for the ``/api/federation/topology`` endpoint.
        """
        all_peers = self._registry.list()

        nodes = [
            {
                "peer_id": p.peer_id,
                "display_name": p.display_name,
                "taxii_url": p.taxii_url,
                "direction": p.direction,
                "max_tlp": p.max_tlp,
                "parent_peer_id": p.parent_peer_id,
                "enabled": p.enabled,
                "is_leaf": self.is_leaf(p.peer_id),
                "is_root": self.is_root(p.peer_id),
                "last_sync_at": p.last_sync_at,
                "last_sync_status": p.last_sync_status,
            }
            for p in all_peers
        ]

        edges: list[dict[str, Any]] = []
        hierarchy_edges: list[dict[str, Any]] = []

        for peer in all_peers:
            if peer.parent_peer_id:
                edge = {
                    "from": peer.peer_id,
                    "to": peer.parent_peer_id,
                    "direction": peer.direction,
                    "max_tlp": self.effective_max_tlp(peer.peer_id, peer.parent_peer_id),
                    "type": "hierarchical",
                }
                edges.append(edge)
                hierarchy_edges.append(edge)
            else:
                # Mesh peers — represent as undirected edge if both registered
                for other in all_peers:
                    if (
                        other.peer_id != peer.peer_id
                        and other.parent_peer_id is None
                        and peer.peer_id < other.peer_id  # deduplicate symmetric edges
                    ):
                        edges.append(
                            {
                                "from": peer.peer_id,
                                "to": other.peer_id,
                                "direction": "mesh",
                                "max_tlp": min(
                                    peer.max_tlp,
                                    other.max_tlp,
                                    key=lambda t: {
                                        "white": 0,
                                        "clear": 0,
                                        "green": 1,
                                        "amber": 2,
                                        "amber+strict": 3,
                                        "red": 4,
                                    }.get(t, 1),
                                ),
                                "type": "mesh",
                            }
                        )

        return {
            "nodes": nodes,
            "edges": edges,
            "hierarchy_edges": hierarchy_edges,
            "total_peers": len(all_peers),
            "enabled_peers": sum(1 for p in all_peers if p.enabled),
        }
