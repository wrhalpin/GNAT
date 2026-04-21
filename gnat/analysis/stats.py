# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.stats
===================

Workspace-level statistical summaries.

Provides:

* :class:`WorkspaceStats` — aggregate metrics across STIX objects
  stored in a workspace (confidence distributions, source reliability
  matrix, MITRE ATT&CK coverage).

Requires the Solr sidecar for type/platform breakdowns; falls back to
zero counts when Solr is unavailable.

Usage::

    from gnat.search import SolrSearchIndex
    from gnat.analysis.stats import WorkspaceStats

    idx   = SolrSearchIndex.from_config(cfg)
    stats = WorkspaceStats(idx)

    dist = stats.confidence_distribution()
    # {"high": 1203, "medium": 4510, "low": 892, "unknown": 340}

    matrix = stats.source_reliability_matrix()
    # {"crowdstrike": {"indicator": 12040, "malware": 300, ...}, ...}

    coverage = stats.attack_coverage_report()
    # {"TA0001 - Initial Access": {"technique_count": 12, "confidence_avg": 67.5}, ...}
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.search.index import SolrSearchIndex

logger = logging.getLogger(__name__)

# ATT&CK tactics with their standard IDs.  Kill-chain phase names in Solr
# are checked against this mapping for coverage reporting.
_ATTACK_TACTICS: dict[str, str] = {
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
}

# Confidence score bands (GNAT scale 0-100)
_CONFIDENCE_BANDS: list[tuple[str, int, int]] = [
    ("high", 75, 100),
    ("medium", 40, 74),
    ("low", 1, 39),
    ("unknown", 0, 0),
]


@dataclass
class AttackTacticCoverage:
    """Coverage summary for a single ATT&CK tactic."""

    tactic_id: str
    tactic_name: str
    object_count: int = 0
    technique_count: int = 0
    confidence_avg: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict."""
        return {
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "object_count": self.object_count,
            "technique_count": self.technique_count,
            "confidence_avg": round(self.confidence_avg, 1),
        }


class WorkspaceStats:
    """
    Aggregate statistics computed from the Solr search index.

    Parameters
    ----------
    index : SolrSearchIndex
        Index with faceting support.

    Notes
    -----
    All methods degrade gracefully — they return empty structures if Solr
    is unreachable rather than raising.
    """

    def __init__(self, index: SolrSearchIndex) -> None:
        """Initialize WorkspaceStats."""
        self._index = index

    def type_counts(self) -> dict[str, int]:
        """
        Return document counts by STIX type.

        Returns
        -------
        dict[str, int]
            ``{"indicator": 12043, "malware": 3201, ...}``
        """
        return self._index.facet("stix_type", limit=50)

    def platform_counts(self) -> dict[str, int]:
        """
        Return document counts by source platform.

        Returns
        -------
        dict[str, int]
            ``{"crowdstrike": 8012, "threatq": 4300, ...}``
        """
        return self._index.facet("source_platform", limit=100)

    def source_reliability_matrix(
        self,
        platforms: list[str] | None = None,
    ) -> dict[str, dict[str, int]]:
        """
        Build a platform × STIX-type count matrix.

        Parameters
        ----------
        platforms : list[str], optional
            Restrict to these platforms.  Defaults to all.

        Returns
        -------
        dict[str, dict[str, int]]
            ``{platform: {stix_type: count, ...}, ...}``
        """
        all_platforms = platforms or list(self.platform_counts().keys())
        matrix: dict[str, dict[str, int]] = {}
        for platform in all_platforms:
            try:
                type_counts = self._index.facet(
                    "stix_type",
                    query=f'source_platform:"{platform}"',
                    limit=50,
                )
                if type_counts:
                    matrix[platform] = type_counts
            except Exception as exc:
                logger.warning(
                    "WorkspaceStats.source_reliability_matrix: platform %r failed — %s",
                    platform,
                    exc,
                )
        return matrix

    def confidence_distribution(self) -> dict[str, int]:
        """
        Return counts of objects per confidence band.

        Uses Solr facet.query to count objects in each range because
        confidence is numeric (not a string facet field).

        Returns
        -------
        dict[str, int]
            ``{"high": N, "medium": N, "low": N, "unknown": N}``

        Note
        ----
        Requires the ``confidence`` field to be indexed in Solr schema.
        Returns zeros if the field is absent.
        """
        result: dict[str, int] = {}
        for band_name, low, high in _CONFIDENCE_BANDS:
            if low == 0 and high == 0:
                # "unknown" = confidence not set (value = 0 or missing)
                query_filter = "confidence:[0 TO 0] OR (*:* AND -confidence:[* TO *])"
            else:
                query_filter = f"confidence:[{low} TO {high}]"
            params_str = f"?q=*:*&fq={query_filter}&rows=0&wt=json"
            url = f"{self._index.base_url}/select{params_str}"
            try:
                resp = self._index._http.request("GET", url)
                if resp.status == 200:
                    import json

                    data = json.loads(resp.data.decode("utf-8"))
                    result[band_name] = data.get("response", {}).get("numFound", 0)
                else:
                    result[band_name] = 0
            except Exception as exc:
                logger.warning(
                    "WorkspaceStats.confidence_distribution: band %r failed — %s",
                    band_name,
                    exc,
                )
                result[band_name] = 0
        return result

    def attack_coverage_report(
        self,
        stix_types: list[str] | None = None,
    ) -> list[AttackTacticCoverage]:
        """
        Summarise ATT&CK tactic coverage from indexed attack-pattern objects.

        Queries Solr for attack-pattern objects grouped by kill-chain tactic.

        Parameters
        ----------
        stix_types : list[str], optional
            Object types to include.  Defaults to ``["attack-pattern"]``.

        Returns
        -------
        list[AttackTacticCoverage]
            One entry per tactic, sorted by object_count descending.
        """
        types = stix_types or ["attack-pattern"]

        # Get total attack-pattern count per tactic via Solr facet
        tactic_facet = self._index.facet(
            "kill_chain_phase_name",
            stix_types=types,
            limit=200,
        )

        coverages: list[AttackTacticCoverage] = []
        for tactic_name, count in tactic_facet.items():
            # Normalise: "initial access" → "initial-access"
            normalised = tactic_name.lower().replace(" ", "-")
            tactic_id = _ATTACK_TACTICS.get(normalised, "")
            coverages.append(
                AttackTacticCoverage(
                    tactic_id=tactic_id or normalised,
                    tactic_name=tactic_name,
                    object_count=count,
                )
            )

        # For tactics with no match, add zeros for all known tactics
        covered_names = {c.tactic_name.lower().replace(" ", "-") for c in coverages}
        for norm_name, tactic_id in _ATTACK_TACTICS.items():
            if norm_name not in covered_names:
                coverages.append(
                    AttackTacticCoverage(
                        tactic_id=tactic_id,
                        tactic_name=norm_name,
                        object_count=0,
                    )
                )

        coverages.sort(key=lambda c: c.object_count, reverse=True)
        return coverages

    def summary(self) -> dict[str, Any]:
        """
        Return a combined summary dict suitable for dashboard display.

        Returns
        -------
        dict
            ``{"type_counts": ..., "platform_counts": ..., "confidence": ...}``
        """
        return {
            "type_counts": self.type_counts(),
            "platform_counts": self.platform_counts(),
            "confidence_distribution": self.confidence_distribution(),
            "attack_tactic_count": len(
                [c for c in self.attack_coverage_report() if c.object_count > 0]
            ),
        }
