# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.core.context
=================

Unified execution context that every GNAT operation carries.

Every pipeline run, enrichment call, connector request, and agent action
is tagged with an :class:`ExecutionContext`.  This gives GNAT end-to-end
traceability: you can reconstruct exactly which connector, in which domain,
under which trust level, produced any stored object.

Usage
-----
::

    from gnat.core.context import ExecutionContext

    ctx = ExecutionContext.create(
        initiated_by="splunk",
        domain="ingestion",
        workspace_id="ws-threats-2026",
    )
    # Pass ctx to pipeline entry points; it propagates automatically.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Query Budget (4E-2)
# ---------------------------------------------------------------------------

@dataclass
class QueryBudget:
    """
    Finite query budget carried by an :class:`ExecutionContext`.

    Each :class:`~gnat.clients.base.BaseClient` call deducts
    :attr:`~gnat.clients.base.BaseClient.COST_UNIT` units from the budget.
    When the budget reaches zero a
    :class:`~gnat.clients.base.BudgetExceeded` exception is raised.

    Parameters
    ----------
    max_units : int
        Maximum total cost units for this execution.  Default ``1000``.
    """

    max_units: int = 1000
    _consumed: int = field(default=0, init=False, repr=False)

    @property
    def remaining(self) -> int:
        """Remaining budget units."""
        return max(0, self.max_units - self._consumed)

    @property
    def is_exhausted(self) -> bool:
        """True when budget is fully consumed."""
        return self._consumed >= self.max_units

    def consume(self, units: int, connector: str = "") -> None:
        """
        Deduct *units* from the budget.

        Parameters
        ----------
        units : int
            Cost units to consume.
        connector : str
            Name of the consuming connector (for the error message).

        Raises
        ------
        gnat.clients.base.BudgetExceeded
            If the budget would be exceeded.
        """
        if self._consumed + units > self.max_units:
            from gnat.clients.base import BudgetExceeded
            raise BudgetExceeded(
                connector=connector,
                cost=units,
                remaining=self.remaining,
            )
        self._consumed += units
        logger.debug(
            "QueryBudget: consumed %d units by %r; remaining=%d/%d",
            units, connector, self.remaining, self.max_units,
        )

# Valid trust levels (mirrors BaseClient.TRUST_LEVEL values)
TRUST_LEVELS = frozenset({"trusted_internal", "semi_trusted", "untrusted_external"})

# Valid domain names (mirrors gnat.core.domains.Domain)
VALID_DOMAINS = frozenset({"ingestion", "analysis", "investigation", "reporting", "execution"})


@dataclass
class ExecutionContext:
    """
    Unified execution context propagated through all GNAT operations.

    Parameters
    ----------
    context_id : str
        UUID identifying this specific execution trace.
    initiated_by : str
        Connector name, agent ID, or ``"manual"`` for human-triggered runs.
    domain : str
        Operational domain: ``"ingestion"``, ``"analysis"``, ``"investigation"``,
        ``"reporting"``, or ``"execution"``.
    trust_level : str
        Trust classification inherited from the initiating connector:
        ``"trusted_internal"``, ``"semi_trusted"``, or ``"untrusted_external"``.
    policy_set : str
        Name of the active policy set (from ``[agent_policy]`` INI section).
    workspace_id : str
        Workspace isolation boundary for this operation.
    created_at : datetime
        UTC timestamp when this context was created.
    parent_context_id : str, optional
        UUID of the parent context for sub-operations; enables trace trees.
    is_replay : bool
        ``True`` if this execution is replaying a previously recorded run.
        Pipeline runners suppress side-effects (SOAR triggers, etc.) when set.
    """

    context_id: str
    initiated_by: str
    domain: str
    trust_level: str
    policy_set: str
    workspace_id: str
    created_at: datetime
    parent_context_id: str | None = None
    is_replay: bool = False
    budget: QueryBudget | None = None

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        initiated_by: str,
        domain: str,
        workspace_id: str,
        trust_level: str = "semi_trusted",
        policy_set: str = "default",
        parent_context_id: str | None = None,
        is_replay: bool = False,
        max_budget_units: int | None = None,
    ) -> ExecutionContext:
        """
        Create a new :class:`ExecutionContext` with a fresh UUID and UTC timestamp.

        Parameters
        ----------
        initiated_by : str
            Connector name, agent ID, or ``"manual"``.
        domain : str
            One of: ``"ingestion"``, ``"analysis"``, ``"investigation"``,
            ``"reporting"``, ``"execution"``.
        workspace_id : str
            Target workspace identifier.
        trust_level : str
            Trust classification.  Defaults to ``"semi_trusted"``.
        policy_set : str
            Active policy set name.  Defaults to ``"default"``.
        parent_context_id : str, optional
            UUID of the parent context for nested operations.
        is_replay : bool
            Mark this as a replay run.

        Returns
        -------
        ExecutionContext
        """
        budget = QueryBudget(max_units=max_budget_units) if max_budget_units is not None else None
        return cls(
            context_id=str(uuid.uuid4()),
            initiated_by=initiated_by,
            domain=domain,
            trust_level=trust_level,
            policy_set=policy_set,
            workspace_id=workspace_id,
            created_at=datetime.now(timezone.utc),
            parent_context_id=parent_context_id,
            is_replay=is_replay,
            budget=budget,
        )

    @classmethod
    def from_connector(
        cls,
        connector: Any,
        domain: str,
        workspace_id: str,
        policy_set: str = "default",
        parent_context_id: str | None = None,
        is_replay: bool = False,
    ) -> ExecutionContext:
        """
        Create an :class:`ExecutionContext` inheriting trust from a connector.

        The connector's ``TRUST_LEVEL`` class variable is read automatically.
        Falls back to ``"semi_trusted"`` if the connector has no ``TRUST_LEVEL``.

        Parameters
        ----------
        connector : object
            Any :class:`~gnat.clients.base.BaseClient` subclass instance.
        domain : str
            Operational domain for this execution.
        workspace_id : str
            Target workspace.
        """
        trust_level = getattr(type(connector), "TRUST_LEVEL", "semi_trusted")
        initiated_by = type(connector).__name__
        return cls.create(
            initiated_by=initiated_by,
            domain=domain,
            workspace_id=workspace_id,
            trust_level=trust_level,
            policy_set=policy_set,
            parent_context_id=parent_context_id,
            is_replay=is_replay,
        )

    # ── Serialization ──────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for Postgres insertion."""
        return {
            "context_id": self.context_id,
            "initiated_by": self.initiated_by,
            "domain": self.domain,
            "trust_level": self.trust_level,
            "policy_set": self.policy_set,
            "workspace_id": self.workspace_id,
            "created_at": self.created_at.isoformat(),
            "parent_context_id": self.parent_context_id,
            "is_replay": self.is_replay,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionContext:
        """Deserialize from a plain dict (e.g. from a DB row)."""
        created_at = data["created_at"]
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        return cls(
            context_id=data["context_id"],
            initiated_by=data["initiated_by"],
            domain=data["domain"],
            trust_level=data["trust_level"],
            policy_set=data.get("policy_set", "default"),
            workspace_id=data["workspace_id"],
            created_at=created_at,
            parent_context_id=data.get("parent_context_id"),
            is_replay=bool(data.get("is_replay", False)),
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def child(self, initiated_by: str, domain: str | None = None) -> ExecutionContext:
        """
        Create a child context for a sub-operation.

        Inherits ``workspace_id``, ``trust_level``, and ``policy_set`` from the
        parent.  ``parent_context_id`` is set to this context's ``context_id``.
        """
        return ExecutionContext.create(
            initiated_by=initiated_by,
            domain=domain or self.domain,
            workspace_id=self.workspace_id,
            trust_level=self.trust_level,
            policy_set=self.policy_set,
            parent_context_id=self.context_id,
            is_replay=self.is_replay,
        )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"ExecutionContext(id={self.context_id[:8]}…, "
            f"by={self.initiated_by!r}, domain={self.domain!r}, "
            f"trust={self.trust_level!r})"
        )
