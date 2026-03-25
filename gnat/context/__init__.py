"""
ctm_sak.context
===============

Global/local context system for CTM-SAK analyst workspaces.

Quick start::

    from ctm_sak import SAKClient
    from ctm_sak.context import WorkspaceManager, GlobalContextRegistry

    # Build registry from connected clients
    tq = SAKClient().connect("threatq")
    rf = SAKClient().connect("recordedfuture")
    cs = SAKClient().connect("crowdstrike")

    manager = WorkspaceManager.from_clients(
        {"threatq": tq, "recorded_future": rf, "crowdstrike": cs},
        default="threatq",
        read_only=["recorded_future"],
    )

    # Create a workspace and start investigating
    ws = manager.create("apt28-q1-2025", description="APT28 campaign analysis")
    ws.load("indicator", filters={"tags": "apt28"})
    ws.enrich(sources=["recorded_future", "crowdstrike"])

    print(ws.diff())         # see what enrichment added
    result = ws.commit()     # write back to ThreatQ
    print(result)
"""

from ctm_sak.context.global_context import GlobalContext, GlobalContextRegistry
from ctm_sak.context.workspace import (
    Workspace,
    WorkspaceManager,
    CommitResult,
)
from ctm_sak.context.store import FlatFileStore

try:
    from ctm_sak.context.store import WorkspaceStore
    _HAS_SQLALCHEMY = True
except Exception:
    _HAS_SQLALCHEMY = False

__all__ = [
    "GlobalContext",
    "GlobalContextRegistry",
    "Workspace",
    "WorkspaceManager",
    "CommitResult",
    "FlatFileStore",
    "WorkspaceStore",
]
