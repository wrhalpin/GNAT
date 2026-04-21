# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.governor
====================

Agent governance layer — permission checks, action logging, and rate limiting.

:class:`AgentGovernor` is the single choke-point for all agent actions.  Every
action an agent wishes to perform must pass through :meth:`AgentGovernor.can_act`
before execution and be recorded via :meth:`AgentGovernor.record_action`.

Usage
-----
::

    from gnat.agents.governor import AgentGovernor, AgentAction
    from gnat.policy.models import AgentActionType

    governor = AgentGovernor()

    if governor.can_act("research-agent-1", AgentActionType.ENRICH, "semi_trusted"):
        governor.rate_limit_check("research-agent-1", window_seconds=60)
        action = AgentAction(
            agent_id="research-agent-1",
            action_type=AgentActionType.ENRICH,
            target_ref="indicator--abc123",
            impact_level="low",
        )
        governor.record_action(action)
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from gnat.policy.models import AgentActionType, agent_can_act

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when an agent exceeds its configured request rate."""

    def __init__(self, agent_id: str, window_seconds: int, current_count: int) -> None:
        """Initialize RateLimitExceeded."""
        super().__init__(
            f"Agent {agent_id!r} exceeded rate limit: "
            f"{current_count} calls within {window_seconds}s window"
        )
        self.agent_id = agent_id
        self.window_seconds = window_seconds
        self.current_count = current_count


class AgentPermissionDenied(Exception):
    """Raised when an agent action is denied by the governor."""

    def __init__(self, agent_id: str, action_type: AgentActionType, trust_level: str) -> None:
        """Initialize AgentPermissionDenied."""
        super().__init__(
            f"Agent {agent_id!r} (trust={trust_level!r}) denied "
            f"permission for action {action_type.value!r}"
        )
        self.agent_id = agent_id
        self.action_type = action_type
        self.trust_level = trust_level


# Valid impact levels (ordered low → high)
IMPACT_LEVELS = ("low", "medium", "high", "critical")


@dataclass
class AgentAction:
    """
    Record of a single agent action, stored in the ``agent_actions`` table.

    Parameters
    ----------
    agent_id : str
        Identifier of the agent requesting the action.
    action_type : AgentActionType
        Category of the action being performed.
    target_ref : str
        STIX ID or other reference to the object being acted upon.
    impact_level : str
        Severity classification: ``"low"``, ``"medium"``, ``"high"``, or ``"critical"``.
    session_id : str, optional
        UUID of the parent agent session.
    context_id : str, optional
        UUID of the active :class:`~gnat.core.context.ExecutionContext`.
    result_json : dict, optional
        Action outcome (populated after execution).
    approved_by : str, optional
        Human reviewer or auto-approve policy that authorised this action.
    """

    agent_id: str
    action_type: AgentActionType
    target_ref: str = ""
    impact_level: str = "low"
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    context_id: str | None = None
    result_json: dict[str, Any] = field(default_factory=dict)
    approved_by: str | None = None
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    executed_at: datetime | None = None
    status: str = "pending"  # pending | approved | rejected | executed

    def __post_init__(self) -> None:
        """Validate impact_level."""
        if self.impact_level not in IMPACT_LEVELS:
            raise ValueError(
                f"impact_level must be one of {IMPACT_LEVELS}, got {self.impact_level!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for DB insertion."""
        return {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "action_type": self.action_type.value,
            "target_ref": self.target_ref,
            "impact_level": self.impact_level,
            "context_id": self.context_id,
            "result_json": self.result_json,
            "approved_by": self.approved_by,
            "submitted_at": self.submitted_at.isoformat(),
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "status": self.status,
        }


class AgentGovernor:
    """
    Central governance authority for all GNAT agent actions.

    Responsibilities:

    * **Permission checks** — delegates to
      :func:`~gnat.policy.models.agent_can_act` and optional per-agent
      override policies loaded from config.
    * **Action recording** — persists :class:`AgentAction` records to the
      in-memory audit log (and optionally to the ``agent_actions`` DB table).
    * **Rate limiting** — sliding-window counter per agent; raises
      :exc:`RateLimitExceeded` when the configured limit is exceeded.

    Parameters
    ----------
    max_calls_per_window : int
        Maximum number of calls allowed per agent within *window_seconds*.
        Default is 100.
    window_seconds : int
        Sliding window size for rate limiting in seconds.  Default is 60.
    policy_overrides : dict, optional
        Per-agent permission overrides: ``{"agent-id": {"action_type": bool}}``.
        Overrides take precedence over the trust-level default matrix.
    """

    def __init__(
        self,
        max_calls_per_window: int = 100,
        window_seconds: int = 60,
        policy_overrides: dict[str, dict[str, bool]] | None = None,
    ) -> None:
        """Initialize AgentGovernor."""
        self._max_calls = max_calls_per_window
        self._window_seconds = window_seconds
        self._policy_overrides: dict[str, dict[str, bool]] = policy_overrides or {}

        # Sliding-window rate-limit state: agent_id → list of epoch timestamps
        self._call_timestamps: dict[str, list[float]] = {}

        # In-memory audit log
        self._action_log: list[AgentAction] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def can_act(
        self,
        agent_id: str,
        action_type: AgentActionType,
        trust_level: str = "semi_trusted",
    ) -> bool:
        """
        Return ``True`` if *agent_id* with *trust_level* may perform *action_type*.

        Checks per-agent policy overrides first; falls back to the default
        trust-level permission matrix from
        :func:`~gnat.policy.models.agent_can_act`.

        Parameters
        ----------
        agent_id : str
            Identifier of the requesting agent.
        action_type : AgentActionType
            The action being requested.
        trust_level : str
            Trust classification of the agent's connector or context.
        """
        # 1. Per-agent override (explicit allow/deny)
        agent_overrides = self._policy_overrides.get(agent_id, {})
        action_key = action_type.value
        if action_key in agent_overrides:
            result = bool(agent_overrides[action_key])
            self._emit_decision(agent_id, action_type, trust_level, result, source="override")
            return result

        # 2. Trust-level default matrix
        result = agent_can_act(trust_level, action_type)
        self._emit_decision(agent_id, action_type, trust_level, result, source="policy")
        return result

    def require_can_act(
        self,
        agent_id: str,
        action_type: AgentActionType,
        trust_level: str = "semi_trusted",
    ) -> None:
        """
        Assert *agent_id* may perform *action_type*, raising if not.

        Parameters
        ----------
        agent_id : str
        action_type : AgentActionType
        trust_level : str

        Raises
        ------
        AgentPermissionDenied
            If the action is not permitted.
        """
        if not self.can_act(agent_id, action_type, trust_level):
            raise AgentPermissionDenied(agent_id, action_type, trust_level)

    def record_action(self, action: AgentAction) -> None:
        """
        Persist an :class:`AgentAction` to the audit log.

        The action is appended to the in-memory log and emitted via the
        :class:`~gnat.plugins.hooks.HookBus` when available.

        Parameters
        ----------
        action : AgentAction
            The action to record.
        """
        self._action_log.append(action)
        logger.info(
            "AgentGovernor: recorded action agent=%r type=%r impact=%r target=%r status=%r",
            action.agent_id,
            action.action_type.value,
            action.impact_level,
            action.target_ref,
            action.status,
        )
        try:
            from gnat.plugins.hooks import HookBus

            HookBus.instance().emit(
                "agent_action",
                agent_id=action.agent_id,
                action_type=action.action_type.value,
                impact_level=action.impact_level,
                target_ref=action.target_ref,
                status=action.status,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("HookBus emit for agent_action failed: %s", exc)

    def rate_limit_check(
        self,
        agent_id: str,
        window_seconds: int | None = None,
        max_calls: int | None = None,
    ) -> None:
        """
        Check if *agent_id* is within its rate limit; raise if exceeded.

        Uses a sliding-window counter.  Expired timestamps outside the window
        are pruned on each call.

        Parameters
        ----------
        agent_id : str
            The agent being checked.
        window_seconds : int, optional
            Override the governor's default window.
        max_calls : int, optional
            Override the governor's default call limit.

        Raises
        ------
        RateLimitExceeded
            If the agent has exceeded the configured limit.
        """
        window = window_seconds or self._window_seconds
        limit = max_calls or self._max_calls
        now = time.monotonic()
        cutoff = now - window

        timestamps = self._call_timestamps.setdefault(agent_id, [])
        # Prune old entries
        timestamps[:] = [t for t in timestamps if t > cutoff]

        if len(timestamps) >= limit:
            raise RateLimitExceeded(agent_id, window, len(timestamps))

        timestamps.append(now)

    def get_action_log(self, agent_id: str | None = None) -> list[AgentAction]:
        """
        Return recorded actions, optionally filtered by *agent_id*.

        Parameters
        ----------
        agent_id : str, optional
            Filter to a specific agent; ``None`` returns all.
        """
        if agent_id is None:
            return list(self._action_log)
        return [a for a in self._action_log if a.agent_id == agent_id]

    def set_policy_override(
        self, agent_id: str, action_type: AgentActionType, allowed: bool
    ) -> None:
        """
        Set a per-agent permission override.

        Parameters
        ----------
        agent_id : str
            The agent to configure.
        action_type : AgentActionType
            The action type to override.
        allowed : bool
            Whether to allow (``True``) or deny (``False``) the action.
        """
        self._policy_overrides.setdefault(agent_id, {})[action_type.value] = allowed

    # ── Internals ──────────────────────────────────────────────────────────────

    def _emit_decision(
        self,
        agent_id: str,
        action_type: AgentActionType,
        trust_level: str,
        granted: bool,
        source: str,
    ) -> None:
        logger.debug(
            "AgentGovernor: agent=%r action=%r trust=%r → %s (source=%s)",
            agent_id,
            action_type.value,
            trust_level,
            "ALLOW" if granted else "DENY",
            source,
        )
