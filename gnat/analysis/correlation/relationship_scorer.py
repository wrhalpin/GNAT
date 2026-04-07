"""
gnat.analysis.correlation.relationship_scorer
==============================================

:class:`RelationshipScorer` scores relationships between entities (indicator
groups, observable nodes, investigation artifacts) based on co-occurrence,
source reliability, and recency.

The resulting :class:`~gnat.analysis.confidence.ConfidenceScore` can be
attached to :class:`~gnat.investigations.model.EvidenceEdge` objects or used
directly in report :class:`~gnat.reporting.models.Finding` confidence fields.

Scoring model
-------------
Three inputs combine into a final STIX 0–100 numeric confidence:

1. **Co-occurrence score** — how many platforms independently observed both
   entities together.  Each additional corroborating platform adds +15 points
   (capped at 45).

2. **Recency score** — how recently was the relationship last observed.
   Observations within 7 days score 25; within 30 days score 15; within 90
   days score 5; older than 90 days score 0.

3. **Source reliability bonus** — if all contributing platforms have
   Admiralty reliability ≥ B (``USUALLY_RELIABLE``), add a +10 bonus.

Sum of the three scores gives the raw STIX confidence (capped at 100).
The Admiralty pair is set conservatively to the *worst* source in the set.

Usage::

    from gnat.analysis.correlation.relationship_scorer import RelationshipScorer

    scorer = RelationshipScorer()
    score = scorer.score(
        platforms         = ["threatq", "greymatter", "xsoar"],
        last_observed_iso = "2026-04-06T14:00:00Z",
        source_reliabilities = {
            "threatq":    SourceReliability.B_USUALLY_RELIABLE,
            "greymatter": SourceReliability.A_COMPLETELY_RELIABLE,
            "xsoar":      SourceReliability.B_USUALLY_RELIABLE,
        },
    )
    print(score.label)  # e.g. "B2 (HIGH)"
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from gnat.analysis.confidence import (
    ConfidenceScore,
    InformationCredibility,
    SourceReliability,
)

logger = logging.getLogger(__name__)

# Points for each additional corroborating platform (1 = no corroboration)
_CO_OCCURRENCE_POINTS = [0, 0, 15, 30, 45]   # index = number of platforms

# Recency buckets: (max_days, score)
_RECENCY_BUCKETS = [
    (7,   25),
    (30,  15),
    (90,   5),
    (None, 0),
]

# Reliability bonus: all platforms ≥ B_USUALLY_RELIABLE
_RELIABILITY_BONUS = 10

# Minimum base score when at least one platform reports the relationship
_BASE_SCORE = 20


class RelationshipScorer:
    """
    Score relationships between entities based on corroboration and recency.

    This is intentionally rule-based, not ML-based.  The rules are
    transparent, auditable, and do not require training data.

    Parameters
    ----------
    base_score : int
        Minimum confidence when at least one platform reports the relationship
        (default 20).
    """

    def __init__(self, base_score: int = _BASE_SCORE) -> None:
        self._base = base_score

    def score(
        self,
        platforms:             list[str],
        last_observed_iso:     str | None = None,
        source_reliabilities:  dict[str, SourceReliability] | None = None,
        rationale:             str | None = None,
    ) -> ConfidenceScore:
        """
        Score a relationship observed across one or more platforms.

        Parameters
        ----------
        platforms : list of str
            Platform names that observed this relationship.  Must be non-empty.
        last_observed_iso : str, optional
            ISO 8601 timestamp of the most recent observation.  Used to
            compute the recency bonus.
        source_reliabilities : dict, optional
            Mapping of platform name → :class:`~gnat.analysis.confidence.SourceReliability`.
            Platforms not in the dict default to ``C_FAIRLY_RELIABLE``.
        rationale : str, optional
            Human-readable explanation appended to the score.

        Returns
        -------
        ConfidenceScore
        """
        if not platforms:
            raise ValueError("platforms must be non-empty")

        reliabilities = source_reliabilities or {}

        # 1. Co-occurrence score
        n = min(len(set(platforms)), len(_CO_OCCURRENCE_POINTS) - 1)
        co_score = _CO_OCCURRENCE_POINTS[n]

        # 2. Recency score
        recency_score = self._recency_score(last_observed_iso)

        # 3. Reliability bonus
        worst_reliability = self._worst_reliability(platforms, reliabilities)
        bonus = _RELIABILITY_BONUS if self._all_reliable(platforms, reliabilities) else 0

        raw = min(100, self._base + co_score + recency_score + bonus)

        # Admiralty credibility: co-occurrence → credibility level
        credibility = self._credibility_from_platforms(len(set(platforms)))

        parts = [
            f"platforms={sorted(set(platforms))}",
            f"co_occurrence_score={co_score}",
            f"recency_score={recency_score}",
            f"reliability_bonus={bonus}",
            f"stix_confidence={raw}",
        ]
        auto_rationale = "; ".join(parts)
        full_rationale = f"{rationale}  [{auto_rationale}]" if rationale else auto_rationale

        return ConfidenceScore(
            source_reliability      = worst_reliability,
            information_credibility = credibility,
            stix_confidence         = raw,
            rationale               = full_rationale,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _recency_score(last_observed_iso: str | None) -> int:
        if not last_observed_iso:
            return 0
        try:
            ts = datetime.fromisoformat(last_observed_iso.replace("Z", "+00:00"))
            age_days = (datetime.now(tz=timezone.utc) - ts).days
            for max_days, pts in _RECENCY_BUCKETS:
                if max_days is None or age_days <= max_days:
                    return pts
        except (ValueError, TypeError):
            pass
        return 0

    @staticmethod
    def _worst_reliability(
        platforms: list[str],
        reliabilities: dict[str, SourceReliability],
    ) -> SourceReliability:
        """Return the lowest (most pessimistic) reliability grade."""
        grades = [
            reliabilities.get(p, SourceReliability.C_FAIRLY_RELIABLE)
            for p in platforms
        ]
        # Sort by Admiralty value (A best → F worst); return worst
        order = {r: i for i, r in enumerate(SourceReliability)}
        return max(grades, key=lambda r: order[r])

    @staticmethod
    def _all_reliable(
        platforms: list[str],
        reliabilities: dict[str, SourceReliability],
    ) -> bool:
        """True if all platforms are A or B reliability."""
        reliable = {SourceReliability.A_COMPLETELY_RELIABLE, SourceReliability.B_USUALLY_RELIABLE}
        for p in platforms:
            r = reliabilities.get(p, SourceReliability.C_FAIRLY_RELIABLE)
            if r not in reliable:
                return False
        return True

    @staticmethod
    def _credibility_from_platforms(n_platforms: int) -> InformationCredibility:
        if n_platforms >= 3:
            return InformationCredibility.CONFIRMED
        if n_platforms == 2:
            return InformationCredibility.PROBABLY_TRUE
        return InformationCredibility.POSSIBLY_TRUE
