# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.copilot_review
============================

Human-in-the-loop (HITL) review integration for Investigation Copilot.
High-confidence copilot suggestions are submitted to ReviewService for analyst approval.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

from gnat.agents.governor import ReviewService, ReviewItem, ReviewStatus


@dataclass
class CopilotReviewRequest:
    """Request to review a copilot suggestion."""
    copilot_suggestion: str
    investigation_id: str
    analyst_id: str
    confidence: float
    action_type: str  # "hypothesis_refinement", "escalate_to_ir", etc.
    supporting_evidence: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class CopilotReviewManager:
    """
    Manage HITL review of copilot suggestions.
    Submits high-confidence suggestions to ReviewService for analyst gate.
    """

    def __init__(self, review_service: Optional[ReviewService] = None):
        """
        Initialize review manager.

        Args:
            review_service: Optional ReviewService instance (creates default if None)
        """
        self.review_service = review_service

    async def submit_hypothesis_for_review(
        self,
        hypothesis_text: str,
        investigation_id: str,
        analyst_id: str,
        confidence: float,
        supporting_evidence: Optional[str] = None,
    ) -> Optional[str]:
        """
        Submit a high-confidence hypothesis to ReviewService for analyst approval.

        Args:
            hypothesis_text: The hypothesis being proposed
            investigation_id: Investigation ID
            analyst_id: Analyst ID
            confidence: Confidence score (0-1)
            supporting_evidence: Optional evidence text

        Returns:
            Review item ID if submitted, None if auto-approved
        """
        # Only submit if high confidence
        if confidence < 0.80:
            return None

        request = CopilotReviewRequest(
            copilot_suggestion=hypothesis_text,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            confidence=confidence,
            action_type="hypothesis_refinement",
            supporting_evidence=supporting_evidence,
        )

        return await self._submit_review(request)

    async def submit_escalation_for_approval(
        self,
        reason: str,
        investigation_id: str,
        analyst_id: str,
        target_team: str = "incident_response",
    ) -> str:
        """
        Submit an escalation recommendation for approval.

        Args:
            reason: Why escalation is recommended
            investigation_id: Investigation ID
            analyst_id: Analyst ID
            target_team: Team to escalate to ("incident_response", "management", etc.)

        Returns:
            Review item ID
        """
        request = CopilotReviewRequest(
            copilot_suggestion=f"Escalate to {target_team}",
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            confidence=1.0,
            action_type="escalate_to_ir",
            supporting_evidence=reason,
            metadata={"target_team": target_team},
        )

        return await self._submit_review(request, is_critical=True)

    async def _submit_review(
        self,
        request: CopilotReviewRequest,
        is_critical: bool = False,
    ) -> str:
        """
        Submit review request to ReviewService.

        Args:
            request: Review request
            is_critical: If True, sets high priority

        Returns:
            Review item ID
        """
        # Convert to ReviewItem format
        # TODO: Integrate with actual ReviewService from gnat.analysis.review
        # For now, mock implementation
        review_id = f"copilot_review_{datetime.utcnow().timestamp()}"

        return review_id

    async def check_review_status(self, review_id: str) -> Dict[str, Any]:
        """
        Check status of a submitted review.

        Args:
            review_id: Review item ID

        Returns:
            Review status dict with decision, notes, timestamp
        """
        # TODO: Query ReviewService for status
        return {
            "review_id": review_id,
            "status": "pending",  # PENDING, APPROVED, REJECTED, MODIFIED
            "decision": None,
            "reviewer_notes": None,
            "modified_properties": None,
        }

    async def await_review_decision(
        self,
        review_id: str,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        """
        Wait for a review decision (blocking).

        Args:
            review_id: Review item ID
            timeout_seconds: Max wait time

        Returns:
            Review decision with analyst feedback
        """
        import asyncio

        start = datetime.utcnow()
        while True:
            status = await self.check_review_status(review_id)

            if status["status"] != "pending":
                return status

            # Check timeout
            elapsed = (datetime.utcnow() - start).total_seconds()
            if elapsed > timeout_seconds:
                raise TimeoutError(f"Review decision timeout after {timeout_seconds}s")

            # Poll every 5 seconds
            await asyncio.sleep(5)

    async def get_pending_reviews(
        self,
        investigation_id: str,
    ) -> list:
        """
        Fetch all pending reviews for an investigation.

        Args:
            investigation_id: Investigation ID

        Returns:
            List of pending review items
        """
        # TODO: Query ReviewService for pending items
        return []

    async def get_review_history(
        self,
        investigation_id: str,
    ) -> list:
        """
        Fetch review history for an investigation.

        Args:
            investigation_id: Investigation ID

        Returns:
            List of all reviews (pending + completed)
        """
        # TODO: Query ReviewService
        return []
