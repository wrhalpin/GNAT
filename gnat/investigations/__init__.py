"""
gnat.investigations
====================

Incident-centric evidence graph builder.

Collects evidence from connected platforms (XSOAR, GreyMatter, ThreatQ, …),
normalises it into a common model, correlates cross-system matches, and
materialises the result into a GNAT workspace.

Five-step pipeline
------------------
1. **Seed expansion** — query each connected system for incidents, alerts,
   observables, and indicators matching the seed values.
2. **Incident expansion** — for each discovered incident/case/event, fetch
   its constituent evidence (alerts, tasks, linked observables, timeline).
3. **Normalisation** — translate every raw record into a common
   :class:`~.model.EvidenceNode`.
4. **Correlation** — add ``same-ioc``, ``same-host``, ``same-user``,
   ``same-campaign``, and ``same-ticket`` edges between nodes from
   different platforms that share correlation attributes.
5. **Materialisation** — write nodes and edges to a GNAT workspace as
   STIX objects and Relationship SROs.

Quick start::

    from gnat.investigations import InvestigationBuilder, Seed, SeedType, materialize

    builder = InvestigationBuilder({
        "xsoar":      xsoar_client,
        "greymatter": gm_client,
        "threatq":    tq_client,
    })

    graph = builder.build(
        seeds=[
            Seed("185.220.101.5", SeedType.IP),
            Seed("INC-4892",      SeedType.CASE_ID, hint_platform="xsoar"),
        ],
        title="Ransomware triage – 2026-04-05",
    )

    print(graph.summary())
    ws = materialize(graph, workspace_manager)
"""

from gnat.investigations.builder import InvestigationBuilder
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
from gnat.investigations.workspace import materialize

__all__ = [
    "InvestigationBuilder",
    "EvidenceGraph",
    "EvidenceNode",
    "EvidenceEdge",
    "NodeType",
    "Seed",
    "SeedType",
    "normalize",
    "correlate",
    "materialize",
]
