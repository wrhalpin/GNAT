# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.hitl
================

Human-in-the-Loop (HITL) gateway for agent actions.

:class:`HITLGateway` is a thin bridge between :class:`AgentGovernor` and the
existing :class:`~gnat.review.service.ReviewService`.  It implements a
four-tier impact model:

* **low / medium** — auto-approved per policy; action is logged but not queued.
* **high** — submitted to :class:`~gnat.review.service.ReviewService` as a
  ``PENDING`` :class:`~gnat.review.models.ReviewItem`; blocks the action until
  approved or rejected.
* **critical** — same as ``high``, plus an XSOAR playbook is triggered via the
  existing :class:`~gnat.connectors.xsoar.client.XSOARClient`.

Usage
-----
::

    from gnat.agents.hitl import HITLGateway
    from gnat.agents.governor import AgentAction
    from gnat.policy.models import AgentActionType

    gateway = HITLGateway(review_service=svc)
    action = AgentAction(
        agent_id="threat-hunter-1",
        action_type=AgentActionType.TRIGGER_PLAYBOOK,
        target_ref="indicator--abc",
        impact_level="high",
    )
    review_item = gateway.submit_for_approval(action)
    status = gateway.check_approval_status(review_item.id)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from gnat.agents.governor import IMPACT_LEVELS, AgentAction
from gnat.stix.version import CURRENT_SPEC_VERSION

if TYPE_CHECKING:
    from gnat.review.models import ReviewItem, ReviewStatus
    from gnat.review.service import ReviewService

logger = logging.getLogger(__name__)

# Impact levels that require human review
_REVIEW_REQUIRED = frozenset({"high", "critical"})

# Timeout for pending approvals (seconds); actions auto-rejected after this
DEFAULT_APPROVAL_TIMEOUT_SECONDS = 3600


class HITLGateway:
    """
    Human-in-the-Loop gateway bridging :class:`AgentGovernor` to
    :class:`~gnat.review.service.ReviewService`.

    Parameters
    ----------
    review_service : ReviewService
        The existing GNAT review queue service.
    approval_timeout_seconds : int
        Seconds before a pending approval is auto-rejected.
        Defaults to 3600 (1 hour).
    xsoar_client : object, optional
        Pre-configured :class:`~gnat.connectors.xsoar.client.XSOARClient`
        instance.  When provided, critical actions trigger a SOAR playbook.
    source_workspace : str
        Workspace label used when submitting review items.
    """

    def __init__(
        self,
        review_service: "ReviewService",
        approval_timeout_seconds: int = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
        xsoar_client: Any | None = None,
        source_workspace: str = "agent-actions",
    ) -> None:
        """Initialize HITLGateway."""
        self._review_service = review_service
        self._approval_timeout = approval_timeout_seconds
        self._xsoar_client = xsoar_client
        self._source_workspace = source_workspace

        # Track review_item_id → AgentAction for status polling
        self._pending: dict[str, AgentAction] = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def evaluate(self, action: AgentAction) -> tuple[bool, "ReviewItem | None"]:
        """
        Evaluate an agent action against the impact-tier policy.

        Returns ``(auto_approved, review_item)``.

        * ``(True, None)`` — low/medium impact; auto-approved, no review item.
        * ``(False, ReviewItem)`` — high/critical; submitted for human review.

        Parameters
        ----------
        action : AgentAction
            The action to evaluate.

        Returns
        -------
        tuple of (bool, ReviewItem or None)
            ``(auto_approved, review_item)``
        """
        if action.impact_level not in _REVIEW_REQUIRED:
            # Auto-approve low / medium
            action.approved_by = "auto-policy"
            action.status = "approved"
            logger.info(
                "HITLGateway: auto-approved %s action by agent %r (impact=%r)",
                action.action_type.value,
                action.agent_id,
                action.impact_level,
            )
            return True, None

        # High / critical → submit for human review
        review_item = self.submit_for_approval(action)
        return False, review_item

    def submit_for_approval(self, action: AgentAction) -> "ReviewItem":
        """
        Submit *action* to the review queue and return the created
        :class:`~gnat.review.models.ReviewItem`.

        For ``"critical"`` impact actions, an XSOAR playbook notification is
        also triggered if an XSOAR client was provided.

        Parameters
        ----------
        action : AgentAction
            Action requiring human approval.

        Returns
        -------
        ReviewItem
            The newly created pending review item.
        """
        stix_data = self._action_to_stix(action)
        review_item = self._review_service.submit(
            stix_data=stix_data,
            source_workspace=self._source_workspace,
            submitted_by=action.agent_id,
        )
        action.status = "pending"
        self._pending[review_item.id] = action
        logger.info(
            "HITLGateway: submitted review item %r for agent %r action %s (impact=%r)",
            review_item.id,
            action.agent_id,
            action.action_type.value,
            action.impact_level,
        )

        if action.impact_level == "critical":
            self._notify_xsoar(action, review_item)

        return review_item

    def check_approval_status(self, review_id: str) -> "ReviewStatus":
        """
        Return the current :class:`~gnat.review.models.ReviewStatus` for *review_id*.

        If the item has been pending longer than ``approval_timeout_seconds``, it
        is automatically rejected.

        Parameters
        ----------
        review_id : str
            The ID of the review item to check.

        Returns
        -------
        ReviewStatus
        """
        from gnat.review.models import ReviewStatus

        review_item = self._review_service.get(review_id)

        # Check timeout for pending items
        if review_item.status == ReviewStatus.PENDING:
            submitted = review_item.submitted_at
            if submitted.tzinfo is None:
                submitted = submitted.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - submitted).total_seconds()
            if elapsed > self._approval_timeout:
                logger.warning(
                    "HITLGateway: review %r timed out after %.0fs — auto-rejecting",
                    review_id,
                    elapsed,
                )
                self._review_service.reject(
                    review_id,
                    reviewed_by="system-timeout",
                    reason=f"Approval timeout ({self._approval_timeout}s)",
                )
                review_item = self._review_service.get(review_id)

                # Update tracked action
                if review_id in self._pending:
                    self._pending[review_id].status = "rejected"

        return review_item.status

    def auto_approve_pending(self, review_id: str, reviewer: str = "auto-policy") -> None:
        """
        Programmatically approve a pending review item (used in tests and
        auto-escalation scenarios).

        Parameters
        ----------
        review_id : str
            ID of the item to approve.
        reviewer : str
            Name recorded as the approver.
        """
        self._review_service.approve(review_id, reviewed_by=reviewer)
        if review_id in self._pending:
            self._pending[review_id].status = "approved"
            self._pending[review_id].approved_by = reviewer

    # ── Internals ──────────────────────────────────────────────────────────────

    @staticmethod
    def _action_to_stix(action: AgentAction) -> dict[str, Any]:
        """Convert an :class:`AgentAction` to a minimal STIX-compatible dict."""
        import uuid as _uuid

        return {
            "type": "x-gnat-agent-action",
            "id": f"x-gnat-agent-action--{_uuid.uuid4()}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": action.submitted_at.isoformat(),
            "modified": action.submitted_at.isoformat(),
            "agent_id": action.agent_id,
            "action_type": action.action_type.value,
            "target_ref": action.target_ref,
            "impact_level": action.impact_level,
            "session_id": action.session_id,
            "context_id": action.context_id,
            "action_id": action.action_id,
        }

    def _notify_xsoar(self, action: AgentAction, review_item: Any) -> None:
        """Fire an XSOAR playbook notification for critical actions."""
        if self._xsoar_client is None:
            logger.debug(
                "HITLGateway: no XSOAR client configured; skipping critical notification"
            )
            return
        try:
            payload = {
                "type": "note",
                "id": f"note--{__import__('uuid').uuid4()}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "abstract": f"CRITICAL agent action pending approval: {action.action_type.value}",
                "content": (
                    f"Agent: {action.agent_id}\n"
                    f"Action: {action.action_type.value}\n"
                    f"Target: {action.target_ref}\n"
                    f"Review ID: {review_item.id}\n"
                    f"Impact: {action.impact_level}"
                ),
                "object_refs": [action.target_ref] if action.target_ref else [],
            }
            self._xsoar_client.upsert_object(payload)
            logger.info(
                "HITLGateway: XSOAR notified for critical action by agent %r",
                action.agent_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("HITLGateway: XSOAR notification failed — %s", exc)
