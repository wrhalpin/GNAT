# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.hypothesis_refinement
====================================

Hypothesis confidence scoring and refinement based on analyst feedback.
Updates scores dynamically as investigation progresses.
"""

from dataclasses import dataclass
from typing import Dict, List, Any
from enum import Enum


class FeedbackType(str, Enum):
    """Analyst feedback classification."""
    CONFIRMS = "confirms"  # "I'm confident in this" → increase score
    CONTRADICTS = "contradicts"  # "This seems unlikely" → decrease score
    NEUTRAL = "neutral"  # "Interesting but not sure" → no change
    REFINES = "refines"  # "This is partially right" → adjust focus


@dataclass
class HypothesisScore:
    """Hypothesis with confidence tracking."""
    text: str
    initial_confidence: float
    current_confidence: float
    feedback_history: List[Dict[str, Any]] = None
    connector_trust_scores: Dict[str, float] = None
    supporting_evidence_count: int = 0
    contradicting_evidence_count: int = 0

    def __post_init__(self):
        if self.feedback_history is None:
            self.feedback_history = []
        if self.connector_trust_scores is None:
            self.connector_trust_scores = {}


class HypothesisRefinement:
    """
    Refine hypothesis confidence scores based on analyst feedback and evidence.
    Applies connector trust weighting + feedback analysis.
    """

    # Connector trust tiers (from Phase 4 safety slides)
    CONNECTOR_TRUST = {
        "trusted_internal": 0.9,  # 31 connectors (GNAT, ThreatQ, internal DBs)
        "semi_trusted": 0.6,  # 61 connectors (ThreatStream, URLhaus, public APIs)
        "untrusted_external": 0.3,  # 7 connectors (unvetted OSINT, user-provided)
    }

    # Feedback scoring deltas
    FEEDBACK_DELTA = {
        FeedbackType.CONFIRMS: 0.15,  # +15% confidence
        FeedbackType.CONTRADICTS: -0.20,  # -20% confidence
        FeedbackType.NEUTRAL: 0.0,  # No change
        FeedbackType.REFINES: 0.08,  # +8% (partial support)
    }

    @classmethod
    def score_hypothesis(
        cls,
        hypothesis: HypothesisScore,
        analyst_feedback: str,
        connector_trust: str = "semi_trusted",
    ) -> HypothesisScore:
        """
        Update hypothesis confidence based on analyst feedback.

        Args:
            hypothesis: Hypothesis to score
            analyst_feedback: Analyst's response ("I'm confident", "This seems wrong", etc.)
            connector_trust: Trust level of source connectors (for weighting)

        Returns:
            Updated HypothesisScore
        """
        feedback_type = cls._classify_feedback(analyst_feedback)
        trust_weight = cls.CONNECTOR_TRUST.get(connector_trust, 0.6)
        delta = cls.FEEDBACK_DELTA.get(feedback_type, 0.0)

        # Apply trust weighting to feedback delta
        weighted_delta = delta * trust_weight

        # Update confidence (clamp to [0, 1])
        new_confidence = max(0.0, min(1.0, hypothesis.current_confidence + weighted_delta))

        # Log feedback
        hypothesis.feedback_history.append({
            "feedback": analyst_feedback,
            "type": feedback_type.value,
            "delta": delta,
            "weighted_delta": weighted_delta,
            "old_confidence": hypothesis.current_confidence,
            "new_confidence": new_confidence,
            "connector_trust": connector_trust,
        })

        hypothesis.current_confidence = new_confidence
        hypothesis.connector_trust_scores[feedback_type.value] = trust_weight

        return hypothesis

    @classmethod
    def _classify_feedback(cls, feedback: str) -> FeedbackType:
        """
        Classify analyst feedback into a type.

        Args:
            feedback: Analyst's natural language response

        Returns:
            FeedbackType classification
        """
        feedback_lower = feedback.lower()

        # Confirmation keywords
        if any(w in feedback_lower for w in ["confident", "agree", "correct", "valid", "likely", "probable"]):
            return FeedbackType.CONFIRMS

        # Contradiction keywords
        if any(w in feedback_lower for w in ["unlikely", "wrong", "incorrect", "disagree", "doubt", "suspicious"]):
            return FeedbackType.CONTRADICTS

        # Refinement keywords
        if any(w in feedback_lower for w in ["partially", "maybe", "sort of", "partial", "partly", "mixed"]):
            return FeedbackType.REFINES

        # Default: neutral
        return FeedbackType.NEUTRAL

    @classmethod
    def combine_scores(
        cls,
        hypotheses: List[HypothesisScore],
        method: str = "weighted_avg",
    ) -> float:
        """
        Combine multiple hypothesis scores into investigation confidence.

        Args:
            hypotheses: List of hypotheses
            method: "weighted_avg" | "max" | "min"

        Returns:
            Combined confidence score
        """
        if not hypotheses:
            return 0.0

        if method == "weighted_avg":
            # Weight by confidence (higher confidence = more weight)
            total_weight = sum(h.current_confidence for h in hypotheses)
            if total_weight == 0:
                return sum(h.current_confidence for h in hypotheses) / len(hypotheses)

            return sum(
                h.current_confidence ** 2 for h in hypotheses
            ) / total_weight

        elif method == "max":
            return max(h.current_confidence for h in hypotheses)

        elif method == "min":
            return min(h.current_confidence for h in hypotheses)

        return sum(h.current_confidence for h in hypotheses) / len(hypotheses)

    @classmethod
    def evaluate_evidence(
        cls,
        hypothesis: HypothesisScore,
        evidence_items: List[Dict[str, Any]],
    ) -> HypothesisScore:
        """
        Update hypothesis based on evidence (enrichment results, correlations, etc.).

        Args:
            hypothesis: Hypothesis to update
            evidence_items: List of supporting/contradicting evidence
                - {"type": "supporting", "connector": "ThreatQ", "text": "..."}
                - {"type": "contradicting", "connector": "URLhaus", "text": "..."}

        Returns:
            Updated HypothesisScore
        """
        for evidence in evidence_items:
            evidence_type = evidence.get("type")
            connector = evidence.get("connector", "unknown")
            connector_trust = evidence.get("trust", "semi_trusted")

            if evidence_type == "supporting":
                hypothesis.supporting_evidence_count += 1
                hypothesis = cls.score_hypothesis(
                    hypothesis,
                    feedback="Supporting evidence found",
                    connector_trust=connector_trust,
                )
            elif evidence_type == "contradicting":
                hypothesis.contradicting_evidence_count += 1
                hypothesis = cls.score_hypothesis(
                    hypothesis,
                    feedback="Contradicting evidence found",
                    connector_trust=connector_trust,
                )

        return hypothesis

    @classmethod
    def get_refinement_report(cls, hypothesis: HypothesisScore) -> Dict[str, Any]:
        """
        Generate a report of how a hypothesis score has evolved.

        Args:
            hypothesis: Hypothesis with feedback history

        Returns:
            Report dict with timeline and justification
        """
        return {
            "hypothesis": hypothesis.text,
            "initial_confidence": hypothesis.initial_confidence,
            "current_confidence": hypothesis.current_confidence,
            "change": hypothesis.current_confidence - hypothesis.initial_confidence,
            "feedback_count": len(hypothesis.feedback_history),
            "supporting_evidence": hypothesis.supporting_evidence_count,
            "contradicting_evidence": hypothesis.contradicting_evidence_count,
            "feedback_timeline": hypothesis.feedback_history,
        }
