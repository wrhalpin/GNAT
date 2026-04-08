"""
gnat.analysis.correlation.cluster_detector
==========================================

:class:`ClusterDetector` groups related indicators into candidate clusters
based on shared attributes — surfacing potential threat-actor or campaign
linkages without requiring ML models.

Clustering strategy (rule-based, Phase 3)
-----------------------------------------
A cluster is formed when two or more :class:`~.entity_resolver.EntityGroup`
objects share at least one of:

- **Network infrastructure overlap** — same /24 subnet (IPv4), same ASN,
  or same registrar/hosting pattern in domain TLDs
- **Co-occurrence** — both entities appeared in the same incident, event,
  or observable on at least one platform
- **Tag overlap** — both share one or more analyst tags (e.g. "blackcat",
  "cobalt-strike")
- **Timing pattern** — both were first seen within a 72-hour window

Clusters are scored with a :class:`~gnat.analysis.confidence.ConfidenceScore`
that reflects how many independent signals support the grouping.

Usage::

    from gnat.analysis.correlation.cluster_detector import ClusterDetector
    from gnat.analysis.correlation.entity_resolver import EntityResolver, IndicatorRecord

    records = [...]  # list of IndicatorRecord
    resolver = EntityResolver()
    groups   = resolver.resolve(records)

    detector = ClusterDetector()
    clusters = detector.detect(list(groups.values()))
    for c in clusters:
        print(c.label, c.confidence.label, c.member_ids)
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

from gnat.analysis.confidence import (
    ConfidenceScore,
    InformationCredibility,
    SourceReliability,
)
from gnat.analysis.correlation.entity_resolver import EntityGroup

logger = logging.getLogger(__name__)


@dataclass
class Cluster:
    """
    A candidate cluster of related indicators.

    Parameters
    ----------
    id : str
        Unique cluster identifier (derived from member IDs).
    label : str
        Auto-generated descriptive label.
    member_ids : list of str
        Canonical IDs of :class:`~.entity_resolver.EntityGroup` objects in
        this cluster.
    signals : list of str
        Human-readable descriptions of signals supporting the cluster.
    confidence : ConfidenceScore
        Cluster confidence based on number of independent signals.
    suggested_actor : str, optional
        Suggested threat-actor label if tag overlap implies attribution.
    suggested_campaign : str, optional
        Suggested campaign label if temporal + infrastructure patterns match.
    """

    id:                 str
    label:              str
    member_ids:         list[str]
    signals:            list[str]         = field(default_factory=list)
    confidence:         ConfidenceScore   = field(
                            default_factory=ConfidenceScore.low
                        )
    suggested_actor:    str | None        = None
    suggested_campaign: str | None        = None

    @property
    def size(self) -> int:
        return len(self.member_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":                 self.id,
            "label":              self.label,
            "member_ids":         self.member_ids,
            "signals":            self.signals,
            "confidence":         self.confidence.to_dict(),
            "suggested_actor":    self.suggested_actor,
            "suggested_campaign": self.suggested_campaign,
            "size":               self.size,
        }


class ClusterDetector:
    """
    Detect candidate indicator clusters using rule-based heuristics.

    Parameters
    ----------
    subnet_bits : int
        IPv4 prefix length for subnet clustering (default 24 = /24).
    tag_min_overlap : int
        Minimum shared tags to count as a tag-overlap signal (default 1).
    timing_window_hours : int
        Maximum hours between first-seen timestamps to count as a timing
        signal (default 72).
    min_signals : int
        Minimum signals required to form a cluster (default 1).
    """

    def __init__(
        self,
        subnet_bits:         int = 24,
        tag_min_overlap:     int = 1,
        timing_window_hours: int = 72,
        min_signals:         int = 1,
    ) -> None:
        self._subnet_bits         = subnet_bits
        self._tag_min_overlap     = tag_min_overlap
        self._timing_window_hours = timing_window_hours
        self._min_signals         = min_signals

    def detect(self, groups: list[EntityGroup]) -> list[Cluster]:
        """
        Detect candidate clusters in a resolved entity group set.

        Parameters
        ----------
        groups : list of EntityGroup

        Returns
        -------
        list of Cluster
            Clusters with at least ``min_signals`` supporting signals, sorted
            by descending confidence.
        """
        # Build a signal adjacency: canonical_id -> canonical_id -> list[signal]
        adjacency: dict[str, dict[str, list[str]]] = {}

        for i, g in enumerate(groups):
            for j, h in enumerate(groups):
                if j <= i:
                    continue
                signals = self._compute_signals(g, h)
                if signals:
                    adjacency.setdefault(g.canonical_id, {})[h.canonical_id] = signals
                    adjacency.setdefault(h.canonical_id, {})[g.canonical_id] = signals

        # Connected-component clustering: union-find
        clusters = self._connected_components(groups, adjacency)

        result = [c for c in clusters if len(c.signals) >= self._min_signals]
        result.sort(key=lambda c: c.confidence.stix_confidence, reverse=True)
        logger.debug("ClusterDetector: found %d clusters from %d entity groups",
                     len(result), len(groups))
        return result

    # ── Signal computation ────────────────────────────────────────────────────

    def _compute_signals(self, g: EntityGroup, h: EntityGroup) -> list[str]:
        signals: list[str] = []

        # Subnet overlap (IPv4)
        subnet_g = self._subnet(g)
        subnet_h = self._subnet(h)
        if subnet_g and subnet_h and subnet_g == subnet_h:
            signals.append(f"shared_subnet:{subnet_g}")

        # Tag overlap
        tags_g = set(g.all_tags)
        tags_h = set(h.all_tags)
        shared = tags_g & tags_h
        if len(shared) >= self._tag_min_overlap:
            signals.append(f"shared_tags:{sorted(shared)}")

        # Platform co-occurrence (both seen on same platform)
        shared_platforms = set(g.platforms) & set(h.platforms)
        if shared_platforms:
            signals.append(f"co_platform:{sorted(shared_platforms)}")

        # Timing proximity
        if self._timing_overlap(g, h):
            signals.append("timing_proximity")

        return signals

    def _subnet(self, g: EntityGroup) -> str | None:
        """Return the /<subnet_bits> network string for IPv4 groups."""
        if g.ioc_type != "ipv4-addr":
            return None
        try:
            net = ipaddress.IPv4Network(
                f"{g.canonical_value}/{self._subnet_bits}", strict=False
            )
            return str(net)
        except ValueError:
            return None

    def _timing_overlap(self, g: EntityGroup, h: EntityGroup) -> bool:
        """True if any first_seen timestamps are within timing_window_hours."""
        from datetime import datetime, timezone as _tz
        window_s = self._timing_window_hours * 3600
        g_times = [r.first_seen for r in g.records if r.first_seen]
        h_times = [r.first_seen for r in h.records if r.first_seen]
        for ts_g in g_times:
            for ts_h in h_times:
                try:
                    dt_g = datetime.fromisoformat(ts_g.replace("Z", "+00:00"))
                    dt_h = datetime.fromisoformat(ts_h.replace("Z", "+00:00"))
                    if abs((dt_g - dt_h).total_seconds()) <= window_s:
                        return True
                except (ValueError, TypeError):
                    continue
        return False

    # ── Connected components ──────────────────────────────────────────────────

    def _connected_components(
        self,
        groups: list[EntityGroup],
        adjacency: dict[str, dict[str, list[str]]],
    ) -> list[Cluster]:
        visited: set[str] = set()
        clusters: list[Cluster] = []
        id_map = {g.canonical_id: g for g in groups}

        for g in groups:
            if g.canonical_id in visited:
                continue
            # BFS
            component: list[str] = []
            all_signals: list[str] = []
            queue = [g.canonical_id]
            while queue:
                cur = queue.pop()
                if cur in visited:
                    continue
                visited.add(cur)
                component.append(cur)
                for neighbor, sigs in adjacency.get(cur, {}).items():
                    if neighbor not in visited:
                        queue.append(neighbor)
                        all_signals.extend(sigs)

            if len(component) < 2:
                continue

            # Build cluster
            unique_signals = list(dict.fromkeys(all_signals))  # preserve order, dedup
            n_signals = len(unique_signals)
            stix_conf = min(100, 20 + n_signals * 20)
            if n_signals >= 3:
                src_rel  = SourceReliability.B_USUALLY_RELIABLE
                credibility = InformationCredibility.PROBABLY_TRUE
            elif n_signals == 2:
                src_rel  = SourceReliability.C_FAIRLY_RELIABLE
                credibility = InformationCredibility.POSSIBLY_TRUE
            else:
                src_rel  = SourceReliability.D_NOT_USUALLY_RELIABLE
                credibility = InformationCredibility.DOUBTFUL

            conf = ConfidenceScore(
                source_reliability      = src_rel,
                information_credibility = credibility,
                stix_confidence         = stix_conf,
                rationale               = f"{n_signals} clustering signal(s)",
            )

            # Derive a label from dominant IOC type and tag hints
            ioc_types = [id_map[cid].ioc_type for cid in component if cid in id_map]
            dominant  = max(set(ioc_types), key=ioc_types.count) if ioc_types else "indicator"
            all_tags: set[str] = set()
            for cid in component:
                if cid in id_map:
                    all_tags.update(id_map[cid].all_tags)
            label = f"cluster:{dominant}:{'+'.join(sorted(all_tags)[:3])}" if all_tags else f"cluster:{dominant}:{len(component)}-members"

            suggested_actor = next(
                (t for t in sorted(all_tags) if not t.startswith("tlp:")), None
            )

            cluster_id = "-".join(sorted(component[:3]))
            clusters.append(Cluster(
                id               = cluster_id,
                label            = label,
                member_ids       = component,
                signals          = unique_signals,
                confidence       = conf,
                suggested_actor  = suggested_actor,
            ))

        return clusters
