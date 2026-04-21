# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.testing.simulation
========================

Simulation primitives for GNAT pipeline tests.

:class:`SimulationConnector`
    A :class:`~gnat.clients.base.BaseClient` subclass that returns canned
    STIX fixtures without making any network calls.  Useful for unit and
    integration tests that must exercise the full pipeline without live
    credentials.

:class:`ReplayRunner`
    Replays a sequence of ``execution_log`` rows through the current
    pipeline, asserting that the output matches expected state.

:class:`AgentTestHarness`
    Wraps :class:`~gnat.agents.governor.AgentGovernor` and
    :class:`~gnat.agents.hitl.HITLGateway` with mock approval responses
    so agent action tests are deterministic.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

from gnat.agents.governor import AgentAction, AgentGovernor
from gnat.clients.base import BaseClient, GNATClientError
from gnat.policy.models import AgentActionType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SimulationConnector
# ---------------------------------------------------------------------------


class SimulationConnector(BaseClient):
    """
    A no-network :class:`~gnat.clients.base.BaseClient` that serves canned
    STIX fixtures for any query.

    All HTTP methods return data from the fixture list rather than making
    real HTTP calls.  Useful for unit and integration tests.

    Parameters
    ----------
    fixtures : list of dict
        STIX objects (or any JSON-serialisable dicts) to return from
        ``list_objects()`` / ``get()`` calls.
    host : str
        Nominal host URL (not actually used for connections).
    trust_level : str
        Trust classification for this simulation connector.
        Defaults to ``"semi_trusted"``.
    raise_on_request : bool
        If ``True``, any call to the underlying ``_request`` helper raises
        ``GNATClientError``.  Useful for testing error-handling paths.

    Examples
    --------
    ::

        sim = SimulationConnector(fixtures=[indicator_dict, malware_dict])
        objects = sim.list_objects()    # returns all fixtures
        obj = sim.get_object("indicator--abc")  # returns matching fixture
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "sim-v1"
    API_PREFIX: str = "/sim"
    COST_UNIT: int = 1

    def __init__(
        self,
        fixtures: list[dict[str, Any]] | None = None,
        host: str = "http://simulation.local",
        trust_level: str = "semi_trusted",
        raise_on_request: bool = False,
    ) -> None:
        """Initialize SimulationConnector."""
        # Bypass real connection pool setup with a dummy host
        self.host = host.rstrip("/")
        self.verify_ssl = False
        self.timeout = 30.0
        self.config: dict[str, Any] = {}
        self._auth_headers: dict[str, str] = {}
        self._authenticated = True  # pre-authenticated
        self._context: Any = None

        self._fixtures: list[dict[str, Any]] = list(fixtures or [])
        self.TRUST_LEVEL = trust_level  # type: ignore[assignment]
        self._raise_on_request = raise_on_request

        # Build a simple STIX-id index for fast lookup
        self._index: dict[str, dict[str, Any]] = {
            obj.get("id", ""): obj for obj in self._fixtures if obj.get("id")
        }
        logger.debug("SimulationConnector: loaded %d fixtures", len(self._fixtures))

    # ── ConnectorMixin-compatible interface ────────────────────────────────────

    def authenticate(self) -> None:
        """No-op — simulation connector is always authenticated."""

    def health_check(self) -> bool:
        """Always healthy."""
        return True

    def list_objects(
        self,
        stix_type: str | None = None,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Return fixture objects, optionally filtered by ``stix_type``.

        Parameters
        ----------
        stix_type : str, optional
            If provided, only fixtures with ``type == stix_type`` are returned.
        filters : dict, optional
            Currently ignored (no filter logic in simulation).
        page : int
            1-indexed page number (pagination supported).
        page_size : int
            Objects per page.
        """
        results = self._fixtures
        if stix_type:
            results = [f for f in results if f.get("type") == stix_type]
        # Simple pagination
        start = (page - 1) * page_size
        return results[start : start + page_size]

    def get_object(self, stix_id: str) -> dict[str, Any] | None:
        """Return the fixture with matching STIX id, or ``None``."""
        return self._index.get(stix_id)

    def upsert_object(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Add or replace a fixture by STIX id."""
        stix_id = stix_dict.get("id", "")
        self._index[stix_id] = stix_dict
        existing = next((i for i, f in enumerate(self._fixtures) if f.get("id") == stix_id), None)
        if existing is not None:
            self._fixtures[existing] = stix_dict
        else:
            self._fixtures.append(stix_dict)
        return stix_dict

    def delete_object(self, stix_id: str) -> None:
        """Remove a fixture by STIX id (no-op if not found)."""
        self._fixtures = [f for f in self._fixtures if f.get("id") != stix_id]
        self._index.pop(stix_id, None)

    def to_stix(self, obj: Any) -> dict[str, Any]:
        """Pass-through — fixtures are already STIX dicts."""
        return obj if isinstance(obj, dict) else {}

    def from_stix(self, stix_obj: dict[str, Any]) -> Any:
        """Pass-through — return the dict as-is."""
        return stix_obj

    def add_fixture(self, stix_dict: dict[str, Any]) -> None:
        """Dynamically add a fixture at runtime."""
        self.upsert_object(stix_dict)

    def iter_fixtures(self) -> Iterator[dict[str, Any]]:
        """Iterate over all fixtures."""
        yield from self._fixtures

    # ── Override _request to avoid real HTTP ──────────────────────────────────

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        if self._raise_on_request:
            raise GNATClientError(
                f"SimulationConnector: _request blocked (raise_on_request=True) — {method} {path}"
            )
        # Budget deduction still applies
        if self._context is not None:
            budget = getattr(self._context, "budget", None)
            if budget is not None:
                budget.consume(self.COST_UNIT, type(self).__name__)
        logger.debug("SimulationConnector: simulated %s %s", method, path)
        return {}


# ---------------------------------------------------------------------------
# ReplayRunner
# ---------------------------------------------------------------------------


class ReplayRunner:
    """
    Replays a recorded ``execution_log`` sequence through the current pipeline.

    Reads :class:`~gnat.core.context.ExecutionContext` records from a log
    (list of dicts) and re-executes them with ``is_replay=True``, asserting
    that the output objects match ``expected_stix_ids``.

    Parameters
    ----------
    pipeline_fn : callable
        Function ``(context) → list[dict]`` representing the pipeline to replay.
        Must accept an :class:`~gnat.core.context.ExecutionContext` and return
        a list of STIX dicts produced by the run.
    """

    def __init__(self, pipeline_fn: Any) -> None:
        """Initialize ReplayRunner."""
        self._pipeline_fn = pipeline_fn

    def replay(
        self,
        execution_log: list[dict[str, Any]],
        expected_stix_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Replay log entries through the pipeline.

        Parameters
        ----------
        execution_log : list of dict
            Rows from ``execution_log`` table (as plain dicts).
        expected_stix_ids : list of str, optional
            If provided, asserts that every ID appears in the pipeline output.

        Returns
        -------
        list of dict
            All STIX objects produced across all replayed contexts.

        Raises
        ------
        AssertionError
            If *expected_stix_ids* are not all present in the output.
        """
        from gnat.core.context import ExecutionContext

        all_output: list[dict[str, Any]] = []
        for row in execution_log:
            ctx = ExecutionContext.from_dict({**row, "is_replay": True})
            output = self._pipeline_fn(ctx)
            all_output.extend(output or [])

        if expected_stix_ids:
            produced_ids = {o.get("id") for o in all_output}
            missing = [sid for sid in expected_stix_ids if sid not in produced_ids]
            assert not missing, f"ReplayRunner: expected STIX IDs not produced: {missing}"

        logger.info(
            "ReplayRunner: replayed %d contexts, produced %d objects",
            len(execution_log),
            len(all_output),
        )
        return all_output


# ---------------------------------------------------------------------------
# AgentTestHarness
# ---------------------------------------------------------------------------


class _MockReviewService:
    """Minimal ReviewService stub that auto-approves everything."""

    class _MockItem:
        def __init__(self, agent_id: str) -> None:
            """Initialize _MockItem."""
            import uuid
            from datetime import datetime, timezone

            self.id = str(uuid.uuid4())
            self.submitted_by = agent_id
            self.submitted_at = datetime.now(timezone.utc)

            class _Status:
                value = "approved"

            # Use simple string-compatible status
            self.status = "approved"

    def submit(self, stix_data: Any, source_workspace: str, submitted_by: str, **_: Any) -> Any:
        """Submit."""
        return self._MockItem(submitted_by)

    def approve(self, item_id: str, reviewed_by: str = "auto", **_: Any) -> Any:
        """Approve."""
        return self._MockItem("")

    def reject(self, item_id: str, reviewed_by: str = "auto", **_: Any) -> Any:
        """Reject."""
        item = self._MockItem("")
        item.status = "rejected"
        return item

    def get(self, item_id: str) -> Any:
        """Get."""
        item = self._MockItem("")
        from gnat.review.models import ReviewStatus

        item.status = ReviewStatus.APPROVED
        return item


class AgentTestHarness:
    """
    Wraps :class:`~gnat.agents.governor.AgentGovernor` and
    :class:`~gnat.agents.hitl.HITLGateway` with mock approval responses.

    All HITL submissions are auto-approved.  Recorded actions are accessible
    via :attr:`recorded_actions` for post-test assertion.

    Parameters
    ----------
    max_calls_per_window : int
        Rate limit ceiling.  Defaults to ``10_000`` (effectively unlimited
        for tests).
    policy_overrides : dict, optional
        Per-agent permission overrides forwarded to :class:`AgentGovernor`.

    Examples
    --------
    ::

        harness = AgentTestHarness()
        action = AgentAction(
            agent_id="test-agent",
            action_type=AgentActionType.ENRICH,
            target_ref="indicator--abc",
            impact_level="low",
        )
        approved, review_item = harness.hitl.evaluate(action)
        assert approved is True
        harness.governor.record_action(action)
        assert len(harness.recorded_actions) == 1
    """

    def __init__(
        self,
        max_calls_per_window: int = 10_000,
        policy_overrides: dict[str, dict[str, bool]] | None = None,
    ) -> None:
        """Initialize AgentTestHarness."""
        self.governor = AgentGovernor(
            max_calls_per_window=max_calls_per_window,
            policy_overrides=policy_overrides,
        )

        from gnat.agents.hitl import HITLGateway

        self.hitl = HITLGateway(
            review_service=_MockReviewService(),  # type: ignore[arg-type]
            approval_timeout_seconds=86400,  # 24h — tests won't time out
        )

    @property
    def recorded_actions(self) -> list[AgentAction]:
        """Return all actions recorded by the governor."""
        return self.governor.get_action_log()

    def run_action(
        self,
        agent_id: str,
        action_type: AgentActionType,
        target_ref: str = "",
        impact_level: str = "low",
        trust_level: str = "semi_trusted",
    ) -> tuple[bool, AgentAction]:
        """
        Convenience method: check permission, rate-limit, evaluate HITL, record.

        Returns ``(approved, action)`` where *approved* reflects the HITL
        decision.

        Parameters
        ----------
        agent_id : str
        action_type : AgentActionType
        target_ref : str
        impact_level : str
        trust_level : str
        """
        self.governor.require_can_act(agent_id, action_type, trust_level)
        self.governor.rate_limit_check(agent_id)

        action = AgentAction(
            agent_id=agent_id,
            action_type=action_type,
            target_ref=target_ref,
            impact_level=impact_level,
        )
        approved, _ = self.hitl.evaluate(action)
        self.governor.record_action(action)
        return approved, action
