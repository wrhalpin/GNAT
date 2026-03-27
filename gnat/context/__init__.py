"""
gnat.context
===============

Global/local context system for GNAT analyst workspaces.

Quick start::

    from gnat import SAKClient
    from gnat.context import WorkspaceManager, GlobalContextRegistry

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

from gnat.context.global_context import GlobalContext, GlobalContextRegistry
from gnat.context.workspace import (
    Workspace,
    WorkspaceManager,
    CommitResult,
)
from gnat.context.store import FlatFileStore

try:
    from gnat.context.store import WorkspaceStore
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
