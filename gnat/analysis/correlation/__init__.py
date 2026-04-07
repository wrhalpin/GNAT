"""
gnat.analysis.correlation
==========================

Correlation engine components for the analyst layer.

Modules
-------
entity_resolver
    :class:`~.entity_resolver.EntityResolver` — deduplicates indicators
    across platforms via canonical key normalisation.
relationship_scorer
    :class:`~.relationship_scorer.RelationshipScorer` — scores relationships
    between entities based on co-occurrence, source reliability, and recency.
cluster_detector
    :class:`~.cluster_detector.ClusterDetector` — groups related indicators
    into candidate clusters using rule-based heuristics.
enrichment
    :class:`~.enrichment.EnrichmentDispatcher` — fans out enrichment queries
    to multiple connectors best-effort.

Quick start::

    from gnat.analysis.correlation import (
        EntityResolver,
        IndicatorRecord,
        RelationshipScorer,
        ClusterDetector,
        EnrichmentDispatcher,
    )

    records = [
        IndicatorRecord("threatq",    "185.220.101.5", "ipv4-addr", "501"),
        IndicatorRecord("greymatter", "185.220.101.5", "ipv4-addr", "obs-301"),
    ]
    resolver = EntityResolver()
    groups   = resolver.resolve(records)

    detector  = ClusterDetector()
    clusters  = detector.detect(list(groups.values()))
"""

from gnat.analysis.correlation.cluster_detector import Cluster, ClusterDetector
from gnat.analysis.correlation.enrichment import EnrichmentDispatcher, EnrichmentResult
from gnat.analysis.correlation.entity_resolver import (
    EntityGroup,
    EntityResolver,
    IndicatorRecord,
)
from gnat.analysis.correlation.relationship_scorer import RelationshipScorer

__all__ = [
    # Entity resolution
    "EntityResolver",
    "IndicatorRecord",
    "EntityGroup",
    # Relationship scoring
    "RelationshipScorer",
    # Clustering
    "ClusterDetector",
    "Cluster",
    # Enrichment
    "EnrichmentDispatcher",
    "EnrichmentResult",
]
