"""
gnat.review.service
====================
Business logic for the AI-extracted intel review queue.

Typical usage
-------------

::

    from gnat.review.store import ReviewQueueStore
    from gnat.review.service import ReviewService

    store = ReviewQueueStore("sqlite:///gnat.db")
    store.create_all()
    svc = ReviewService(store)

    # AI agent submits an object for review
    item = svc.submit(stix_obj_dict, source_workspace="analyst-ws",
                      submitted_by="research-agent")

    # Analyst approves with a note and bumps confidence to 80
    item = svc.approve(item.id, reviewed_by="alice",
                       notes="Confirmed via CTI feed cross-reference",
                       confidence_override=80)

    # Promote the approved object to staging
    promoted_obj = svc.promote(item.id, workspace_manager=mgr)
"""

from __future__ import annotations

import copy
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger("gnat.review.service")

_STAGING_DEFAULT = "_ctmsak_staging"


class ReviewError(Exception):
    """Raised for invalid review operations (wrong state, not found, etc.)."""


class ReviewService:
    """
    Manages the AI-extracted intel review queue.

    Parameters
    ----------
    store : ReviewQueueStore
        Persistent storage backend.
    """

    def __init__(self, store: Any) -> None:
        self._store = store

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def submit(
        self,
        stix_data: dict[str, Any],
        source_workspace: str,
        submitted_by: str,
        target_workspace: str = _STAGING_DEFAULT,
    ) -> Any:
        """
        Submit an AI-extracted STIX object for analyst review.

        Parameters
        ----------
        stix_data : dict
            The full STIX object dict (must have ``"id"`` and ``"type"``).
        source_workspace : str
            Name of the personal workspace the object lives in.
        submitted_by : str
            Name of the agent or analyst submitting this item.
        target_workspace : str
            Staging workspace to promote into on approval.

        Returns
        -------
        ReviewItem
        """
        from gnat.review.models import ReviewItem

        stix_id = stix_data.get("id", "")
        stix_type = stix_data.get("type", "")
        if not stix_id or not stix_type:
            raise ReviewError("stix_data must have non-empty 'id' and 'type' fields")

        item = ReviewItem(
            stix_id=stix_id,
            stix_type=stix_type,
            stix_data=copy.deepcopy(stix_data),
            source_workspace=source_workspace,
            target_workspace=target_workspace,
            submitted_by=submitted_by,
        )
        self._store.save(item)
        logger.info(
            "ReviewService: submitted %s %s from workspace %r",
            stix_type, stix_id, source_workspace,
        )
        return item

    # ------------------------------------------------------------------
    # Review actions
    # ------------------------------------------------------------------

    def approve(
        self,
        item_id: str,
        reviewed_by: str,
        notes: str | None = None,
        confidence_override: int | None = None,
    ) -> Any:
        """
        Approve a pending review item.

        Parameters
        ----------
        item_id : str
            Review item UUID.
        reviewed_by : str
            Analyst performing the approval.
        notes : str, optional
            Free-text notes to attach to the review.
        confidence_override : int, optional
            Override the AI confidence score (0–100).  If omitted, the
            original object confidence is used.

        Returns
        -------
        ReviewItem
            Updated item with status=APPROVED.
        """
        from gnat.review.models import ReviewStatus

        item = self._get_or_raise(item_id)
        if item.status not in (ReviewStatus.PENDING, ReviewStatus.MODIFIED):
            raise ReviewError(
                f"Cannot approve item in status {item.status.value!r}; "
                "item must be PENDING or MODIFIED"
            )
        if confidence_override is not None and not (0 <= confidence_override <= 100):
            raise ReviewError(
                f"confidence_override must be in [0, 100], got {confidence_override}"
            )

        item.status = ReviewStatus.APPROVED
        item.reviewed_by = reviewed_by
        item.reviewed_at = datetime.now(tz=timezone.utc)
        item.reviewer_notes = notes
        item.confidence_override = confidence_override
        self._store.save(item)
        logger.info(
            "ReviewService: approved %s by %s", item.stix_id, reviewed_by
        )
        return item

    def reject(
        self,
        item_id: str,
        reviewed_by: str,
        reason: str | None = None,
    ) -> Any:
        """
        Reject a pending review item.

        Parameters
        ----------
        item_id : str
            Review item UUID.
        reviewed_by : str
            Analyst performing the rejection.
        reason : str, optional
            Reason for rejection (stored in ``reviewer_notes``).

        Returns
        -------
        ReviewItem
            Updated item with status=REJECTED.
        """
        from gnat.review.models import ReviewStatus

        item = self._get_or_raise(item_id)
        if item.status not in (ReviewStatus.PENDING, ReviewStatus.MODIFIED):
            raise ReviewError(
                f"Cannot reject item in status {item.status.value!r}"
            )

        item.status = ReviewStatus.REJECTED
        item.reviewed_by = reviewed_by
        item.reviewed_at = datetime.now(tz=timezone.utc)
        item.reviewer_notes = reason
        self._store.save(item)
        logger.info(
            "ReviewService: rejected %s by %s", item.stix_id, reviewed_by
        )
        return item

    def modify(
        self,
        item_id: str,
        modified_by: str,
        modified_properties: dict[str, Any],
        notes: str | None = None,
        confidence_override: int | None = None,
    ) -> Any:
        """
        Record analyst modifications to a pending item without promoting yet.

        The item transitions to MODIFIED status.  Call :meth:`approve` next
        to complete the workflow, or :meth:`approve` with ``modified_properties``
        pre-loaded.

        Parameters
        ----------
        item_id : str
        modified_by : str
        modified_properties : dict
            Properties to overlay on the STIX object before promotion.
        notes : str, optional
        confidence_override : int, optional

        Returns
        -------
        ReviewItem
            Updated item with status=MODIFIED.
        """
        from gnat.review.models import ReviewStatus

        item = self._get_or_raise(item_id)
        if item.status == ReviewStatus.REJECTED:
            raise ReviewError("Cannot modify a rejected item")
        if item.status == ReviewStatus.APPROVED:
            raise ReviewError("Item is already approved; reject and resubmit to modify")
        if confidence_override is not None and not (0 <= confidence_override <= 100):
            raise ReviewError(
                f"confidence_override must be in [0, 100], got {confidence_override}"
            )

        item.status = ReviewStatus.MODIFIED
        item.reviewed_by = modified_by
        item.reviewed_at = datetime.now(tz=timezone.utc)
        item.reviewer_notes = notes
        item.confidence_override = confidence_override
        item.modified_properties.update(modified_properties)
        self._store.save(item)
        logger.info(
            "ReviewService: modified %s by %s", item.stix_id, modified_by
        )
        return item

    # ------------------------------------------------------------------
    # Promotion
    # ------------------------------------------------------------------

    def promote(
        self,
        item_id: str,
        workspace_manager: Any | None = None,
    ) -> dict[str, Any]:
        """
        Promote an approved item to its target (staging) workspace.

        Takes the original STIX object, applies any ``modified_properties``
        and ``confidence_override``, sets ``x_source_type="analyst_verified"``,
        clears the AI ceiling markers, then adds it to the target workspace.

        Parameters
        ----------
        item_id : str
            Review item UUID.
        workspace_manager : WorkspaceManager, optional
            Used to open/create the target workspace.  If None, a no-op
            promotion is performed (useful in tests).

        Returns
        -------
        dict
            The promoted STIX object dict (as it was written to the workspace).
        """
        from gnat.review.models import ReviewStatus

        item = self._get_or_raise(item_id)
        if item.status != ReviewStatus.APPROVED:
            raise ReviewError(
                f"Cannot promote item in status {item.status.value!r}; "
                "item must be APPROVED first"
            )
        if item.promoted_at is not None:
            raise ReviewError(
                f"Item {item_id} has already been promoted at {item.promoted_at}"
            )

        # Build the promoted object
        promoted = copy.deepcopy(item.stix_data)

        # Apply analyst modifications
        promoted.update(item.modified_properties)

        # Mark as analyst-verified
        promoted["x_source_type"] = "analyst_verified"

        # Apply confidence override or promote existing confidence
        if item.confidence_override is not None:
            promoted["confidence"] = item.confidence_override
        # Remove AI ceiling marker if present
        promoted.pop("x_ai_ceiling", None)

        # Add reviewer attribution
        promoted["x_reviewed_by"] = item.reviewed_by
        if item.reviewer_notes:
            promoted["x_review_notes"] = item.reviewer_notes

        # Write to target workspace if a manager is supplied
        if workspace_manager is not None:
            try:
                from gnat.orm.base import STIXBase
                target_ws = workspace_manager.get_or_create(item.target_workspace)
                stix_obj = STIXBase.from_dict(promoted)
                target_ws.add(stix_obj)
                logger.info(
                    "ReviewService: promoted %s → workspace %r",
                    item.stix_id, item.target_workspace,
                )
            except Exception as exc:
                raise ReviewError(
                    f"Failed to write object to workspace {item.target_workspace!r}: {exc}"
                ) from exc

        # Mark promotion complete
        item.promoted_at = datetime.now(tz=timezone.utc)
        self._store.save(item)
        return promoted

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def bulk_approve(
        self,
        item_ids: list[str],
        reviewed_by: str,
        notes: str | None = None,
    ) -> list[Any]:
        """Approve multiple items at once. Errors on individual items are collected."""
        results = []
        errors = []
        for item_id in item_ids:
            try:
                results.append(self.approve(item_id, reviewed_by=reviewed_by, notes=notes))
            except ReviewError as exc:
                errors.append(f"{item_id}: {exc}")
        if errors:
            logger.warning("ReviewService.bulk_approve: %d errors: %s", len(errors), errors)
        return results

    def bulk_reject(
        self,
        item_ids: list[str],
        reviewed_by: str,
        reason: str | None = None,
    ) -> list[Any]:
        """Reject multiple items at once."""
        results = []
        for item_id in item_ids:
            try:
                results.append(self.reject(item_id, reviewed_by=reviewed_by, reason=reason))
            except ReviewError:
                pass
        return results

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, item_id: str) -> Any:
        """Return a ReviewItem or raise ReviewError if not found."""
        return self._get_or_raise(item_id)

    def list(
        self,
        status: str | None = None,
        stix_type: str | None = None,
        submitted_by: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[Any]:
        """List review items with optional filters."""
        return self._store.list(
            status=status,
            stix_type=stix_type,
            submitted_by=submitted_by,
            page=page,
            page_size=page_size,
        )

    def stats(self) -> dict[str, Any]:
        """
        Return queue statistics.

        Returns
        -------
        dict with keys: ``pending``, ``approved``, ``rejected``, ``modified``,
        ``total``.
        """
        counts = self._store.stats()
        counts["total"] = sum(counts.values())
        return counts

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_or_raise(self, item_id: str) -> Any:
        item = self._store.get(item_id)
        if item is None:
            raise ReviewError(f"Review item {item_id!r} not found")
        return item
