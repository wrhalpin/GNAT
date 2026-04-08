# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.investigations.correlator
=================================

Builds cross-system correlation edges in an :class:`~.model.EvidenceGraph`.

After the :class:`~.builder.InvestigationBuilder` has collected and
normalised all evidence nodes, the correlator:

1. Indexes each node by its extracted correlation attributes (IOC values,
   hostnames, usernames, campaign labels, ticket references).
2. Adds :class:`~.model.EvidenceEdge` objects between any two nodes from
   **different platforms** that share one or more attributes.

Only cross-platform matches generate edges — same-platform links are
uninteresting for correlation purposes because a single platform already
knows its own relationships.

Usage::

    from gnat.investigations.correlator import correlate

    correlate(graph)   # mutates graph in-place
"""

from __future__ import annotations

from gnat.investigations.model import EvidenceEdge, EvidenceGraph


def correlate(graph: EvidenceGraph) -> None:
    """
    Add cross-system correlation edges to *graph* in-place.

    Builds five index maps (by IOC value, hostname, username, campaign label,
    ticket reference) and then emits ``same-*`` edges for any cross-platform
    matches found in those maps.

    Parameters
    ----------
    graph : EvidenceGraph
        The graph to correlate.  Modified in-place.
    """
    # ── Build indexes ──────────────────────────────────────────────────────
    for node in graph.nodes.values():
        for val in node.ioc_values:
            key = val.lower().strip()
            if key:
                graph.by_ioc.setdefault(key, [])
                if node.node_id not in graph.by_ioc[key]:
                    graph.by_ioc[key].append(node.node_id)

        for h in node.hostnames:
            key = h.lower().strip()
            if key:
                graph.by_hostname.setdefault(key, [])
                if node.node_id not in graph.by_hostname[key]:
                    graph.by_hostname[key].append(node.node_id)

        for u in node.usernames:
            key = u.lower().strip()
            if key:
                graph.by_username.setdefault(key, [])
                if node.node_id not in graph.by_username[key]:
                    graph.by_username[key].append(node.node_id)

        for c in node.campaign_labels:
            key = c.lower().strip()
            if key:
                graph.by_campaign.setdefault(key, [])
                if node.node_id not in graph.by_campaign[key]:
                    graph.by_campaign[key].append(node.node_id)

        for t in node.ticket_refs:
            key = t.strip()
            if key:
                graph.by_ticket.setdefault(key, [])
                if node.node_id not in graph.by_ticket[key]:
                    graph.by_ticket[key].append(node.node_id)

    # ── Emit cross-platform edges ──────────────────────────────────────────
    _add_edges(graph, graph.by_ioc,      "same-ioc",      "IOC")
    _add_edges(graph, graph.by_hostname, "same-host",     "hostname")
    _add_edges(graph, graph.by_username, "same-user",     "username")
    _add_edges(graph, graph.by_campaign, "same-campaign", "campaign label")
    _add_edges(graph, graph.by_ticket,   "same-ticket",   "ticket")


def _add_edges(
    graph: EvidenceGraph,
    index: dict[str, list[str]],
    relationship_type: str,
    label: str,
) -> None:
    """Emit cross-platform edges for every multi-node entry in *index*."""
    existing: set[tuple[str, str, str]] = {
        (e.source_id, e.target_id, e.relationship_type)
        for e in graph.edges
    }

    for key, node_ids in index.items():
        if len(node_ids) < 2:
            continue

        # Only create edges when at least two different platforms are involved
        platforms = {graph.nodes[nid].platform for nid in node_ids if nid in graph.nodes}
        if len(platforms) < 2:
            continue

        for i, a in enumerate(node_ids):
            for b in node_ids[i + 1:]:
                if a not in graph.nodes or b not in graph.nodes:
                    continue
                if graph.nodes[a].platform == graph.nodes[b].platform:
                    continue  # same-platform pair — skip
                # Canonical order to avoid duplicate reverse-direction edges
                src, tgt = (a, b) if a < b else (b, a)
                sig = (src, tgt, relationship_type)
                if sig in existing:
                    continue
                existing.add(sig)
                graph.edges.append(EvidenceEdge(
                    source_id         = src,
                    target_id         = tgt,
                    relationship_type = relationship_type,
                    confidence        = 0.9,
                    reasoning         = f"Shared {label}: {key}",
                ))
