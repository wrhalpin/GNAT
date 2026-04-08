"""
gnat.review
============
AI-extracted intel review and promotion queue.

Provides a structured analyst workflow for reviewing objects produced by GNAT
AI agents before they are promoted from personal workspaces to the shared
staging workspace (and ultimately the curated library).

Usage::

    from gnat.review.store import ReviewQueueStore
    from gnat.review.service import ReviewService

    store = ReviewQueueStore("sqlite:///gnat.db")
    store.create_all()
    svc = ReviewService(store)

    # AI agent submits an object
    item = svc.submit(stix_obj_dict, source_workspace="my-ws",
                      submitted_by="research-agent")

    # Analyst approves it
    item = svc.approve(item.id, reviewed_by="alice", confidence_override=80)

    # Promote to staging workspace
    promoted = svc.promote(item.id, workspace_manager=mgr)
"""

from gnat.review.models import ReviewItem, ReviewStatus
from gnat.review.service import ReviewError, ReviewService
from gnat.review.store import ReviewQueueStore

__all__ = [
    "ReviewItem",
    "ReviewStatus",
    "ReviewService",
    "ReviewError",
    "ReviewQueueStore",
]
