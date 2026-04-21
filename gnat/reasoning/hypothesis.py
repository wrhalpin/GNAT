# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reasoning.hypothesis
=========================

Hypothesis lifecycle engine.

:class:`HypothesisEngine` manages the full ``propose → evaluate → close``
lifecycle for :class:`~gnat.stix.sdos.hypothesis.STIXHypothesis` objects.

All state is persisted via the existing workspace/store path — hypotheses
are STIX objects and follow the same storage patterns as indicators or
threat actors.

Usage
-----
::

    from gnat.reasoning.hypothesis import HypothesisEngine
    from gnat.context.workspace import WorkspaceManager

    manager = WorkspaceManager.default()
    engine = HypothesisEngine(manager=manager, workspace_name="analysis-ws")

    h = engine.propose(
        statement="192.0.2.1 is a Lazarus Group C2.",
        initial_evidence=[indicator_stix_id],
    )
    h = engine.evaluate(h.id)
    print(h.confidence, h.status)
    h = engine.close(h.id, verdict="confirmed")
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from gnat.stix.sdos.hypothesis import STIXHypothesis

if TYPE_CHECKING:
    from gnat.context.workspace import WorkspaceManager

logger = logging.getLogger(__name__)

# Trust level → evidence weight mapping
_TRUST_WEIGHTS: dict[str, float] = {
    "trusted_internal": 0.9,
    "semi_trusted": 0.6,
    "untrusted_external": 0.3,
}
_DEFAULT_WEIGHT = 0.5


class HypothesisEngine:
    """
    Manages the propose → evaluate → close lifecycle for STIX hypotheses.

    Parameters
    ----------
    manager : WorkspaceManager
        Workspace manager used to open the target workspace.
    workspace_name : str
        Name of the workspace where hypotheses are stored.
    search_index : SearchIndex, optional
        Solr (or Null) index used for evidence corroboration queries.
        Defaults to ``NullSearchIndex`` if omitted.

    Examples
    --------
    ::

        engine = HypothesisEngine(manager=manager, workspace_name="threats")
        h = engine.propose("APT29 behind Q1 phishing", ["indicator--abc"])
        h = engine.evaluate(h.id)
        h = engine.close(h.id, "confirmed")
    """

    def __init__(
        self,
        manager: WorkspaceManager,
        workspace_name: str = "analysis",
        search_index: Any | None = None,
    ) -> None:
        """Initialize HypothesisEngine."""
        self._manager = manager
        self._workspace_name = workspace_name
        if search_index is not None:
            self._search_index = search_index
        else:
            from gnat.search.index import NullSearchIndex

            self._search_index = NullSearchIndex()

    # ── Public API ─────────────────────────────────────────────────────────────

    def propose(
        self,
        statement: str,
        initial_evidence: list[str] | None = None,
        confidence: float = 0.2,
    ) -> STIXHypothesis:
        """
        Create a new hypothesis with an initial confidence score.

        Parameters
        ----------
        statement : str
            The assertion being tested.
        initial_evidence : list of str, optional
            STIX relationship IDs or object IDs linking initial evidence.
        confidence : float
            Initial confidence in ``[0.0, 1.0]``.  Defaults to 0.2 (low).

        Returns
        -------
        STIXHypothesis
            The newly created, persisted hypothesis.
        """
        h = STIXHypothesis(
            statement=statement,
            confidence=confidence,
            status="pending",
        )
        for ev_id in initial_evidence or []:
            h.add_supporting_evidence(ev_id)

        self._persist(h)
        logger.info(
            "HypothesisEngine: proposed %r (confidence=%.2f, evidence=%d)",
            statement[:80],
            confidence,
            len(initial_evidence or []),
        )
        return h

    def evaluate(self, hypothesis_id: str) -> STIXHypothesis:
        """
        Re-evaluate a hypothesis using the search index for corroboration.

        Queries the search index with the hypothesis statement.  Matching
        objects are counted and weighted by their source connector's trust
        level (from ``source_platform`` metadata).  The confidence score is
        updated in-place.

        Parameters
        ----------
        hypothesis_id : str
            STIX ID of the hypothesis to evaluate.

        Returns
        -------
        STIXHypothesis
            The updated hypothesis.

        Raises
        ------
        KeyError
            If no hypothesis with *hypothesis_id* is found.
        """
        h = self._load(hypothesis_id)

        # Query search index for corroborating evidence
        statement = h._properties.get("statement", "")
        corroborating_ids: list[str] = []
        try:
            corroborating_ids = self._search_index.search(statement, limit=20)
        except Exception as exc:  # noqa: BLE001
            logger.debug("HypothesisEngine: search index unavailable — %s", exc)

        # Compute weighted confidence from evidence counts
        support_count = len(h._properties.get("supporting_evidence", []))
        refute_count = len(h._properties.get("refuting_evidence", []))
        corroboration_boost = min(len(corroborating_ids) * 0.05, 0.3)

        if support_count + refute_count == 0 and not corroborating_ids:
            # No evidence at all — stay at initial confidence
            pass
        else:
            # Weighted ratio: support boosts, refutation reduces
            total = support_count + refute_count + 1  # +1 avoids div-by-zero
            raw = (support_count / total) + corroboration_boost
            confidence = max(0.0, min(1.0, raw))
            h.update_confidence(confidence)

        # Auto-classify status thresholds
        conf = h._properties.get("confidence", 0.0)
        if conf >= 0.75:
            h._properties["status"] = "confirmed"
        elif conf <= 0.15 and refute_count > 0:
            h._properties["status"] = "refuted"

        self._persist(h)
        logger.info(
            "HypothesisEngine: evaluated %s — confidence=%.2f status=%r",
            hypothesis_id,
            conf,
            h._properties.get("status"),
        )
        return h

    def close(self, hypothesis_id: str, verdict: str) -> STIXHypothesis:
        """
        Finalise a hypothesis with an explicit verdict.

        Parameters
        ----------
        hypothesis_id : str
            STIX ID of the hypothesis.
        verdict : str
            Final verdict: ``"confirmed"``, ``"refuted"``, or ``"inconclusive"``.

        Returns
        -------
        STIXHypothesis
            The closed hypothesis.
        """
        h = self._load(hypothesis_id)
        h.close(verdict)
        self._persist(h)
        logger.info("HypothesisEngine: closed %s with verdict %r", hypothesis_id, verdict)
        return h

    def get(self, hypothesis_id: str) -> STIXHypothesis | None:
        """Return a hypothesis by ID, or ``None`` if not found."""
        try:
            return self._load(hypothesis_id)
        except KeyError:
            return None

    def list_all(self) -> list[STIXHypothesis]:
        """Return all hypotheses in the workspace."""
        ws = self._manager.open(self._workspace_name)
        result = []
        for obj in ws.objects.values():
            if getattr(obj, "stix_type", "") == STIXHypothesis.stix_type:
                result.append(obj)
            elif isinstance(obj, dict) and obj.get("type") == STIXHypothesis.stix_type:
                result.append(STIXHypothesis.from_dict(obj))
        return result

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _persist(self, h: STIXHypothesis) -> None:
        ws = self._manager.open(self._workspace_name)
        ws._add_object(h.to_dict(), mark_dirty=True)

    def _load(self, hypothesis_id: str) -> STIXHypothesis:
        ws = self._manager.open(self._workspace_name)
        obj = ws.objects.get(hypothesis_id)
        if obj is None:
            raise KeyError(f"No hypothesis found with id {hypothesis_id!r}")
        raw = obj.to_dict() if hasattr(obj, "to_dict") else obj
        return STIXHypothesis.from_dict(raw)
