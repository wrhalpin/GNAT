"""
gnat.investigations.builder
==============================

:class:`InvestigationBuilder` orchestrates the five-step evidence graph
pipeline:

1. **Seed expansion** — translate each seed into platform queries and collect
   the initial node set (indicators, incidents, cases, events).
2. **Incident expansion** — for each collected incident/case/event, fetch its
   constituent evidence (alerts, tasks, linked observables, timeline entries,
   adversaries).
3. **Normalisation** — every raw platform record is translated into a common
   :class:`~.model.EvidenceNode` via :mod:`.normalizer`.
4. **Correlation** — cross-system edges are added for any two nodes from
   different platforms that share an IOC value, hostname, username, campaign
   label, or ticket reference.
5. **Materialisation** — the completed graph can be persisted into a GNAT
   workspace via :func:`.workspace.materialize`.

Usage::

    from gnat.investigations.builder import InvestigationBuilder
    from gnat.investigations.model import Seed, SeedType
    from gnat.investigations.workspace import materialize

    builder = InvestigationBuilder({
        "xsoar":       xsoar_client,
        "greymatter":  gm_client,
        "threatq":     tq_client,
    })

    graph = builder.build(
        seeds=[
            Seed("185.220.101.5", SeedType.IP),
            Seed("INC-4892",      SeedType.CASE_ID, hint_platform="xsoar"),
        ],
        title="Ransomware triage – 2026-04-05",
    )

    print(graph.summary())
    ws = materialize(graph, workspace_manager, "ransomware-apr-2026")
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.investigations.correlator import correlate
from gnat.investigations.model import (
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Seed,
    SeedType,
)
from gnat.investigations.normalizer import normalize

logger = logging.getLogger(__name__)

# Seed types that should trigger a value-search on indicators/observables
_IOC_SEED_TYPES = frozenset({
    SeedType.IOC_VALUE,
    SeedType.IP,
    SeedType.DOMAIN,
    SeedType.HASH,
    SeedType.EMAIL,
    SeedType.URL,
})

# Seed types that should also search incidents by free-text query
_INCIDENT_SEARCH_TYPES = frozenset({
    SeedType.IOC_VALUE,
    SeedType.IP,
    SeedType.DOMAIN,
    SeedType.HOSTNAME,
    SeedType.HASH,
    SeedType.USERNAME,
})


class InvestigationBuilder:
    """
    Build an :class:`~.model.EvidenceGraph` by querying multiple connectors.

    Parameters
    ----------
    connectors : dict
        Mapping of platform name → connector instance.  Any connector that
        implements the :class:`~gnat.connectors.base_connector.ConnectorMixin`
        interface (or a subset of it) is accepted.  Platform names should
        match those expected by the normaliser: ``"xsoar"``, ``"greymatter"``,
        ``"threatq"``.
    """

    def __init__(self, connectors: dict[str, Any]) -> None:
        self._connectors = connectors

    # ── Public API ────────────────────────────────────────────────────────

    def build(
        self,
        seeds: list[Seed],
        title: str = "Investigation",
        expand_depth: int = 1,
    ) -> EvidenceGraph:
        """
        Run the full five-step evidence graph pipeline.

        Parameters
        ----------
        seeds : list of Seed
            Starting points for evidence collection.
        title : str
            Human-readable investigation title stored in the graph.
        expand_depth : int
            Number of expansion rounds.  ``1`` (default) collects direct
            children of each seed-identified incident.  Higher values would
            continue expanding newly discovered incidents (reserved for future
            use; currently only ``1`` is applied).

        Returns
        -------
        EvidenceGraph
        """
        graph = EvidenceGraph(title=title, seeds=seeds)

        # Step 1: Expand seeds → initial nodes
        logger.debug("InvestigationBuilder: expanding %d seeds", len(seeds))
        for seed in seeds:
            self._expand_seed(graph, seed)

        # Step 2: Expand each incident → constituent evidence
        incident_nodes = [
            n for n in list(graph.nodes.values())
            if n.node_type == NodeType.INCIDENT
        ]
        logger.debug(
            "InvestigationBuilder: expanding %d incident nodes", len(incident_nodes)
        )
        for node in incident_nodes:
            self._expand_incident(graph, node)

        # Step 3-4: Correlate (builds indexes + cross-platform edges)
        correlate(graph)

        logger.info(
            "InvestigationBuilder: finished — %s",
            graph.summary(),
        )
        return graph

    # ── Step 1: seed expansion ────────────────────────────────────────────

    def _expand_seed(self, graph: EvidenceGraph, seed: Seed) -> None:
        for platform, connector in self._connectors.items():
            if seed.hint_platform and seed.hint_platform != platform:
                continue
            self._query_seed_on_platform(graph, seed, platform, connector)

    def _query_seed_on_platform(
        self,
        graph: EvidenceGraph,
        seed: Seed,
        platform: str,
        connector: Any,
    ) -> None:
        # ── IOC / indicator value search ──────────────────────────────────
        if seed.seed_type in _IOC_SEED_TYPES:
            # Prefer platform-specific value-search methods
            if hasattr(connector, "search_indicators_by_value"):
                self._collect(graph, platform, "indicator",
                              _safe_call(connector.search_indicators_by_value, seed.value))
            elif hasattr(connector, "search_observables_by_value"):
                self._collect(graph, platform, "observable",
                              _safe_call(connector.search_observables_by_value, seed.value))
            # Also fall back to generic list_objects with query filter
            else:
                results = _safe_call(
                    connector.list_objects, "indicator",
                    filters={"query": seed.value},
                )
                self._collect(graph, platform, "indicator", results)

        # ── Direct case / alert / ticket lookup ───────────────────────────
        if seed.seed_type in (SeedType.CASE_ID, SeedType.ALERT_ID, SeedType.TICKET_REF):
            result = _safe_call(connector.get_object, "observed-data", seed.value)
            if result:
                node = normalize(platform, "incident", result)
                if node:
                    _add_node(graph, node)

        # ── Incident text search for IOC / hostname / username seeds ──────
        if seed.seed_type in _INCIDENT_SEARCH_TYPES:
            results = _safe_call(
                connector.list_objects, "observed-data",
                filters={"query": seed.value},
            )
            self._collect(graph, platform, "incident", results)

        # ── Hostname / username: search indicators too ────────────────────
        if seed.seed_type in (SeedType.HOSTNAME, SeedType.USERNAME):
            results = _safe_call(
                connector.list_objects, "indicator",
                filters={"query": seed.value},
            )
            self._collect(graph, platform, "indicator", results)

    # ── Step 2: incident expansion ────────────────────────────────────────

    def _expand_incident(self, graph: EvidenceGraph, node: EvidenceNode) -> None:
        connector = self._connectors.get(node.platform)
        if connector is None:
            return

        platform = node.platform
        inc_id   = node.source_id

        if platform == "xsoar":
            self._expand_xsoar_incident(graph, node, connector, inc_id)
        elif platform == "greymatter":
            self._expand_gm_incident(graph, node, connector, inc_id)
        elif platform == "threatq":
            self._expand_tq_event(graph, node, connector, inc_id)

    def _expand_xsoar_incident(
        self,
        graph: EvidenceGraph,
        parent: EvidenceNode,
        connector: Any,
        inc_id: str,
    ) -> None:
        if hasattr(connector, "get_incident_alerts"):
            for r in _safe_call(connector.get_incident_alerts, inc_id):
                child = normalize(parent.platform, "alert", r)
                if child:
                    _add_node(graph, child)
                    _add_part_of(graph, child, parent)

        if hasattr(connector, "get_incident_tasks"):
            for r in _safe_call(connector.get_incident_tasks, inc_id):
                child = normalize(parent.platform, "task", r)
                if child:
                    _add_node(graph, child)
                    _add_part_of(graph, child, parent)

        if hasattr(connector, "get_incident_timeline"):
            for r in _safe_call(connector.get_incident_timeline, inc_id):
                child = normalize(parent.platform, "timeline", r)
                if child:
                    _add_node(graph, child)
                    _add_part_of(graph, child, parent)

    def _expand_gm_incident(
        self,
        graph: EvidenceGraph,
        parent: EvidenceNode,
        connector: Any,
        case_id: str,
    ) -> None:
        if hasattr(connector, "get_investigation_observables"):
            for r in _safe_call(connector.get_investigation_observables, case_id):
                child = normalize(parent.platform, "observable", r)
                if child:
                    _add_node(graph, child)
                    _add_part_of(graph, child, parent)

        if hasattr(connector, "get_investigation_tasks"):
            for r in _safe_call(connector.get_investigation_tasks, case_id):
                child = normalize(parent.platform, "task", r)
                if child:
                    _add_node(graph, child)
                    _add_part_of(graph, child, parent)

    def _expand_tq_event(
        self,
        graph: EvidenceGraph,
        parent: EvidenceNode,
        connector: Any,
        event_id: str,
    ) -> None:
        if hasattr(connector, "get_event_indicators"):
            for r in _safe_call(connector.get_event_indicators, event_id):
                child = normalize(parent.platform, "indicator", r)
                if child:
                    _add_node(graph, child)
                    _add_part_of(graph, child, parent)

        if hasattr(connector, "get_event_adversaries"):
            for r in _safe_call(connector.get_event_adversaries, event_id):
                child = normalize(parent.platform, "adversary", r)
                if child:
                    _add_node(graph, child)
                    _add_part_of(graph, child, parent)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _collect(
        self,
        graph: EvidenceGraph,
        platform: str,
        record_type: str,
        results: list[dict[str, Any]] | None,
    ) -> None:
        if not results:
            return
        for raw in results:
            node = normalize(platform, record_type, raw)
            if node:
                _add_node(graph, node)


# ── Module-level helpers ───────────────────────────────────────────────────

def _add_node(graph: EvidenceGraph, node: EvidenceNode) -> None:
    """Add *node* to *graph*, skipping duplicates (by node_id)."""
    if node.node_id not in graph.nodes:
        graph.nodes[node.node_id] = node


def _add_part_of(
    graph: EvidenceGraph,
    child: EvidenceNode,
    parent: EvidenceNode,
) -> None:
    """Add a structural ``part-of`` edge from *child* to *parent*."""
    graph.edges.append(EvidenceEdge(
        source_id         = child.node_id,
        target_id         = parent.node_id,
        relationship_type = "part-of",
        confidence        = 1.0,
        source_platform   = child.platform,
    ))


def _safe_call(fn: Any, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    """
    Call *fn* with *args* / *kwargs*, returning an empty list on any exception.

    Connectors may not support every method or a platform may be unreachable.
    Evidence collection should be best-effort — a single failure must not stop
    the whole graph build.
    """
    try:
        result = fn(*args, **kwargs)
        if result is None:
            return []
        if isinstance(result, dict):
            return [result]
        return list(result)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Evidence expansion skipped (%s): %s", fn, exc)
        return []
