# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reasoning.engine
=====================

Evidence-weighted reasoning engine for observable prioritisation.

:class:`ReasoningEngine` takes a set of STIX observables and scores them
based on connector trust level, hypothesis confidence, negative evidence
TTL, object age, and cross-connector corroboration.  Outputs are stored
as STIX ``note`` objects linked to the scored observables.

Usage
-----
::

    from gnat.reasoning.engine import ReasoningEngine
    from gnat.core.context import ExecutionContext

    engine = ReasoningEngine(manager=manager, workspace_name="analysis-ws")
    ctx = ExecutionContext.create(
        initiated_by="manual", domain="analysis", workspace_id="analysis-ws"
    )
    results = engine.prioritize(observables, context=ctx)
    for observable, score, explanation in results:
        print(f"{score:.2f}  {explanation['summary']}")
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

if TYPE_CHECKING:
    from gnat.context.workspace import WorkspaceManager
    from gnat.core.context import ExecutionContext
    from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)

# Trust level → scoring weight
_TRUST_WEIGHTS: dict[str, float] = {
    "trusted_internal": 0.9,
    "semi_trusted": 0.6,
    "untrusted_external": 0.3,
}

# Object age scoring: confidence decays by this fraction per 24-hour period
_AGE_DECAY_PER_DAY = 0.05

# Maximum corroboration bonus
_MAX_CORROBORATION_BONUS = 0.25


class ReasoningEngine:
    """
    Evidence-weighted observable prioritisation engine.

    Scores STIX observables using multiple signal sources:

    * **Connector trust level** — objects from trusted internal platforms
      receive higher base weight.
    * **Hypothesis confidence** — observables linked to high-confidence
      hypotheses receive a boost.
    * **Negative evidence** — recent negative evidence records suppress
      the score (connector returned nothing for this observable).
    * **Object age** — older objects decay gradually.
    * **Cross-connector corroboration** — corroboration count from Solr
      search provides a bounded bonus.

    Outputs are structured dicts (not free text) for machine readability.
    Results are stored as STIX ``note`` objects in the workspace.

    Parameters
    ----------
    manager : WorkspaceManager
        Workspace manager.
    workspace_name : str
        Name of the target workspace.
    search_index : SearchIndex, optional
        Solr (or Null) search index for corroboration queries.
    """

    def __init__(
        self,
        manager: WorkspaceManager,
        workspace_name: str = "analysis",
        search_index: Any | None = None,
    ) -> None:
        """Initialize ReasoningEngine."""
        self._manager = manager
        self._workspace_name = workspace_name
        if search_index is not None:
            self._search_index = search_index
        else:
            from gnat.search.index import NullSearchIndex

            self._search_index = NullSearchIndex()

    # ── Public API ─────────────────────────────────────────────────────────────

    def prioritize(
        self,
        observable_set: list[STIXBase],
        context: ExecutionContext | None = None,
        store_notes: bool = True,
    ) -> list[tuple[STIXBase, float, dict[str, Any]]]:
        """
        Score and rank a set of observables.

        Parameters
        ----------
        observable_set : list of STIXBase
            Observables to evaluate.
        context : ExecutionContext, optional
            Active execution context.  Provides trust level and workspace info.
        store_notes : bool
            If ``True``, write scoring results as STIX ``note`` objects.
            Default ``True``.

        Returns
        -------
        list of (STIXBase, float, dict)
            Tuples of ``(observable, score, explanation)`` sorted by score
            descending.  Score is in ``[0.0, 1.0]``.  Explanation dict is
            machine-readable (not free text).
        """
        results: list[tuple[STIXBase, float, dict[str, Any]]] = []
        ws = self._manager.open(self._workspace_name)

        # Gather negative evidence records for fast lookup
        neg_evidence_by_target: dict[str, list[NegativeEvidenceRecord]] = {}
        for obj in ws.objects.values():
            raw = obj.to_dict() if hasattr(obj, "to_dict") else {}
            if raw.get("type") == NegativeEvidenceRecord.stix_type:
                rec = NegativeEvidenceRecord.from_dict(raw)
                target = rec._properties.get("target_ref", "")
                neg_evidence_by_target.setdefault(target, []).append(rec)

        for observable in observable_set:
            score, explanation = self._score_observable(
                observable=observable,
                context=context,
                neg_evidence=neg_evidence_by_target.get(observable.id, []),
            )
            results.append((observable, score, explanation))

            if store_notes:
                self._store_note(observable, score, explanation)

        results.sort(key=lambda t: t[1], reverse=True)
        logger.info(
            "ReasoningEngine.prioritize: scored %d observables in workspace %r",
            len(results),
            self._workspace_name,
        )
        return results

    # ── Scoring ────────────────────────────────────────────────────────────────

    def _score_observable(
        self,
        observable: STIXBase,
        context: ExecutionContext | None,
        neg_evidence: list[NegativeEvidenceRecord],
    ) -> tuple[float, dict[str, Any]]:
        """Compute a composite score for one observable."""
        explanation: dict[str, Any] = {
            "observable_id": observable.id,
            "observable_type": getattr(observable, "stix_type", "unknown"),
            "components": {},
        }

        # 1. Connector trust weight
        trust = "semi_trusted"
        if context is not None:
            trust = context.trust_level
        trust_weight = _TRUST_WEIGHTS.get(trust, 0.5)
        explanation["components"]["trust_weight"] = {
            "trust_level": trust,
            "weight": trust_weight,
        }

        # 2. Object age decay
        age_factor = self._age_factor(observable)
        explanation["components"]["age_factor"] = age_factor

        # 3. Negative evidence penalty
        neg_penalty = 0.0
        fresh_neg = [r for r in neg_evidence if not r.is_expired()]
        if fresh_neg:
            neg_penalty = min(0.3 * len(fresh_neg), 0.6)
        explanation["components"]["negative_evidence"] = {
            "count": len(fresh_neg),
            "penalty": neg_penalty,
        }

        # 4. Corroboration bonus from search index
        corroboration_bonus = 0.0
        try:
            obj_id = observable.id
            hits = self._search_index.search(obj_id, limit=10)
            corroboration_bonus = min(len(hits) * 0.05, _MAX_CORROBORATION_BONUS)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ReasoningEngine: search index unavailable — %s", exc)
        explanation["components"]["corroboration"] = {
            "hits": int(corroboration_bonus / 0.05) if corroboration_bonus else 0,
            "bonus": corroboration_bonus,
        }

        # 5. Composite score
        raw_score = (
            trust_weight * 0.4 + age_factor * 0.3 + corroboration_bonus * 0.3 - neg_penalty * 0.5
        )
        score = max(0.0, min(1.0, raw_score))
        explanation["score"] = round(score, 4)
        explanation["summary"] = (
            f"score={score:.2f} trust={trust} age_factor={age_factor:.2f} "
            f"neg_penalty={neg_penalty:.2f} corroboration_bonus={corroboration_bonus:.2f}"
        )
        return score, explanation

    @staticmethod
    def _age_factor(observable: STIXBase) -> float:
        """Return a 0–1 factor where 1.0 = fresh, decaying with object age."""
        modified_str = getattr(observable, "modified", "")
        if not modified_str:
            return 0.5
        try:
            ts = datetime.fromisoformat(modified_str.rstrip("Z"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0
            factor = max(0.0, 1.0 - _AGE_DECAY_PER_DAY * age_days)
            return round(factor, 4)
        except (ValueError, TypeError):
            return 0.5

    # ── Note storage ───────────────────────────────────────────────────────────

    def _store_note(
        self,
        observable: STIXBase,
        score: float,
        explanation: dict[str, Any],
    ) -> None:
        """Persist a STIX note object recording the scoring rationale."""
        import json

        from gnat.orm.base import _utcnow

        note_dict = {
            "type": "note",
            "id": f"note--{__import__('uuid').uuid4()}",
            "spec_version": "2.1",
            "created": _utcnow(),
            "modified": _utcnow(),
            "abstract": f"Reasoning score: {score:.4f}",
            "content": json.dumps(explanation, indent=2),
            "object_refs": [observable.id],
            "x_gnat_reasoning_score": score,
        }
        try:
            ws = self._manager.open(self._workspace_name)
            ws._add_object(note_dict, mark_dirty=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ReasoningEngine: could not store note — %s", exc)
