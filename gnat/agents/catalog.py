# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.catalog
====================

Registry of available pre-built workflows.

:class:`WorkflowCatalog` provides a central registry that maps workflow names
to factory functions.  It also stores human-readable descriptions and
dependency requirements for each workflow, enabling the TUI and API to
display the catalog without importing all workflow modules.

Usage::

    from gnat.agents.catalog import WorkflowCatalog

    # List available workflows
    for entry in WorkflowCatalog.list():
        print(entry.name, "—", entry.description)

    # Build a workflow by name
    wf = WorkflowCatalog.build("phishing-triage", dispatcher=..., ...)
    result = wf.run(ctx)

    # Register a custom workflow
    WorkflowCatalog.register(
        name        = "my-triage",
        factory     = lambda **kw: build_my_triage(**kw),
        description = "Custom triage workflow for my environment",
        tags        = ["custom", "triage"],
    )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class CatalogEntry:
    """
    A single entry in the :class:`WorkflowCatalog`.

    Parameters
    ----------
    name : str
        Unique workflow name.
    factory : Callable
        ``(**kwargs) -> Workflow`` — called with kwargs when building a workflow.
    description : str
        Human-readable description.
    tags : list[str]
        Optional labels for filtering (e.g. ``["triage", "phishing"]``).
    required_deps : list[str]
        Dependency names required by this workflow (informational).
    """

    name:          str
    factory:       Callable[..., Any]
    description:   str                   = ""
    tags:          list[str]             = field(default_factory=list)
    required_deps: list[str]             = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise metadata to a JSON-friendly dict (no factory function)."""
        return {
            "name":          self.name,
            "description":   self.description,
            "tags":          self.tags,
            "required_deps": self.required_deps,
        }


class WorkflowCatalog:
    """
    Class-level registry of named workflow factories.

    All built-in workflows are pre-registered.  Third-party plugins can call
    :meth:`register` to add their own workflows.
    """

    _registry: dict[str, CatalogEntry] = {}

    @classmethod
    def register(
        cls,
        name:          str,
        factory:       Callable[..., Any],
        description:   str = "",
        tags:          list[str] | None = None,
        required_deps: list[str] | None = None,
    ) -> None:
        """
        Register a workflow factory.

        Parameters
        ----------
        name : str
            Unique workflow name.
        factory : Callable
            ``(**kwargs) -> Workflow``.
        description : str
            Human-readable description.
        tags : list[str], optional
        required_deps : list[str], optional
        """
        cls._registry[name] = CatalogEntry(
            name          = name,
            factory       = factory,
            description   = description,
            tags          = tags or [],
            required_deps = required_deps or [],
        )
        logger.debug("WorkflowCatalog.register: %r", name)

    @classmethod
    def get(cls, name: str) -> CatalogEntry | None:
        """Return the :class:`CatalogEntry` for *name*, or ``None``."""
        return cls._registry.get(name)

    @classmethod
    def build(cls, name: str, **kwargs: Any) -> Any:
        """
        Build a workflow by name, passing *kwargs* to its factory.

        Parameters
        ----------
        name : str
            Registered workflow name.
        **kwargs
            Forwarded to the factory function.

        Returns
        -------
        Workflow

        Raises
        ------
        KeyError
            If *name* is not registered.
        """
        entry = cls._registry.get(name)
        if entry is None:
            raise KeyError(
                f"Workflow {name!r} not found in catalog. "
                f"Available: {list(cls._registry.keys())}"
            )
        return entry.factory(**kwargs)

    @classmethod
    def list(
        cls,
        tags: list[str] | None = None,
    ) -> list[CatalogEntry]:
        """
        Return catalog entries, optionally filtered by tags.

        Parameters
        ----------
        tags : list[str], optional
            Return only entries that have ALL of these tags.

        Returns
        -------
        list[CatalogEntry]
            Sorted by name.
        """
        entries = list(cls._registry.values())
        if tags:
            entries = [
                e for e in entries
                if all(t in e.tags for t in tags)
            ]
        return sorted(entries, key=lambda e: e.name)

    @classmethod
    def to_dict(cls) -> list[dict[str, Any]]:
        """Return the full catalog as a list of dicts (no factory functions)."""
        return [e.to_dict() for e in cls.list()]


# ── Register built-in workflows ───────────────────────────────────────────────

def _phishing_factory(**kwargs: Any) -> Any:
    from gnat.agents.workflows.phishing_triage import build_phishing_triage_workflow
    return build_phishing_triage_workflow(**kwargs)


def _incident_factory(**kwargs: Any) -> Any:
    from gnat.agents.workflows.incident_response import build_incident_response_workflow
    return build_incident_response_workflow(**kwargs)


def _auto_investigation_factory(**kwargs: Any) -> Any:
    from gnat.agents.workflows.auto_investigation import build_auto_investigation_workflow
    return build_auto_investigation_workflow(**kwargs)


WorkflowCatalog.register(
    name          = "phishing-triage",
    factory       = _phishing_factory,
    description   = "Enrich IOCs from a phishing sample, detect gaps, draft report, transition investigation.",
    tags          = ["triage", "phishing", "automated"],
    required_deps = ["dispatcher", "resolver", "scorer", "detector", "assistant", "service"],
)

WorkflowCatalog.register(
    name          = "incident-response",
    factory       = _incident_factory,
    description   = "Incident response: enrich, correlate, hypothesise, escalate, contain.",
    tags          = ["incident", "response", "automated"],
    required_deps = ["dispatcher", "resolver", "scorer", "detector", "assistant", "service"],
)

WorkflowCatalog.register(
    name          = "auto-investigation",
    factory       = _auto_investigation_factory,
    description   = "Autonomous investigation pipeline: alert → enrich → score → route → open or review.",
    tags          = ["autonomous", "investigation", "triage"],
    required_deps = ["dispatcher", "resolver", "scorer", "detector", "llm_client", "inv_service"],
)
