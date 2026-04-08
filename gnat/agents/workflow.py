"""
gnat.agents.workflow
=====================

Composable DAG workflow engine for GNAT investigation automation.

A :class:`Workflow` is a named sequence of :class:`WorkflowStep` objects.
Each step is an arbitrary callable that receives a :class:`WorkflowContext`
and returns any value.  Steps can be chained with ``on_success`` / ``on_failure``
step names, forming a directed acyclic graph.

The engine executes steps sequentially by default (``Workflow.run()``) but
respects ``on_success`` / ``on_failure`` routing to implement branching logic.

Usage::

    from gnat.agents.workflow import Workflow, WorkflowContext, WorkflowStep
    from gnat.agents.steps import enrich_step, gap_detect_step

    ctx = WorkflowContext(investigation_id="inv-123", shared={}, results={})

    result = (
        Workflow("phishing-triage")
        .add_step(enrich_step(dispatcher, ["8.8.8.8", "evil.example.com"]))
        .add_step(gap_detect_step(detector))
        .run(ctx)
    )

    print(result.success, result.steps_completed)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class WorkflowContext:
    """
    Mutable context passed through every step in a :class:`Workflow`.

    Parameters
    ----------
    investigation_id : str | None
        ID of the investigation being processed.
    shared : dict
        Cross-step data bag.  Steps write outputs here for later steps.
    results : dict
        Per-step return values keyed by step name.
    """

    investigation_id: str | None     = None
    shared:           dict[str, Any] = field(default_factory=dict)
    results:          dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowStep:
    """
    A single step in a :class:`Workflow`.

    Parameters
    ----------
    name : str
        Unique step name within the workflow.
    action : Callable[[WorkflowContext], Any]
        The callable to invoke.  Receives the mutable *context* object.
    on_success : str | None
        Name of the next step to run if this step succeeds.
        ``None`` means proceed to the next step in definition order.
    on_failure : str | None
        Name of a fallback step to jump to if this step raises.
        ``None`` means abort the workflow on failure.
    timeout_seconds : int
        Wall-clock timeout (informational; not enforced by the engine —
        use thread/process pools for hard timeouts).
    """

    name:            str
    action:          Callable[[WorkflowContext], Any]
    on_success:      str | None = None
    on_failure:      str | None = None
    timeout_seconds: int        = 60


@dataclass
class WorkflowResult:
    """
    Result of a completed :class:`Workflow` run.

    Parameters
    ----------
    success : bool
        True if all executed steps completed without unhandled exceptions.
    steps_completed : list[str]
        Names of steps that ran to completion.
    steps_failed : list[str]
        Names of steps that raised an exception.
    context : WorkflowContext
        The final context (may contain partial results on failure).
    errors : list[str]
        Human-readable error messages for each failed step.
    elapsed_seconds : float
        Total wall-clock time for the run.
    """

    success:         bool
    steps_completed: list[str]
    steps_failed:    list[str]
    context:         WorkflowContext
    errors:          list[str]
    elapsed_seconds: float = 0.0


class Workflow:
    """
    Named, composable DAG workflow.

    Parameters
    ----------
    name : str
        Human-readable workflow name (for logging).

    Examples
    --------
    >>> from gnat.agents.workflow import Workflow, WorkflowContext
    >>> wf = Workflow("demo")
    >>> wf.add_step(WorkflowStep("hello", lambda ctx: ctx.shared.update({"msg": "hi"})))
    Workflow(demo, 1 steps)
    >>> result = wf.run(WorkflowContext())
    >>> result.success
    True
    """

    def __init__(self, name: str) -> None:
        self.name  = name
        self._steps: list[WorkflowStep] = []
        self._step_map: dict[str, WorkflowStep] = {}

    def __repr__(self) -> str:
        return f"Workflow({self.name}, {len(self._steps)} steps)"

    def add_step(self, step: WorkflowStep) -> "Workflow":
        """
        Append a step to the workflow.  Returns self for fluent chaining.

        Raises
        ------
        ValueError
            If a step with the same name already exists.
        """
        if step.name in self._step_map:
            raise ValueError(f"Duplicate step name: {step.name!r}")
        self._steps.append(step)
        self._step_map[step.name] = step
        return self

    # ── Execution ─────────────────────────────────────────────────────────────

    def run(self, ctx: WorkflowContext) -> WorkflowResult:
        """
        Execute the workflow against *ctx*.

        Iterates steps in definition order (default) or follows
        ``on_success`` / ``on_failure`` routing when set.

        Exceptions raised by a step are caught; execution continues to the
        ``on_failure`` step if configured, otherwise the workflow is aborted.

        Parameters
        ----------
        ctx : WorkflowContext
            Mutable context object shared across all steps.

        Returns
        -------
        WorkflowResult
        """
        start_time      = time.monotonic()
        completed:list[str] = []
        failed:   list[str] = []
        errors:   list[str] = []

        # Use a pointer-based traversal to support routing
        _remaining = list(self._steps)  # default order
        visited   : set[str] = set()

        step_idx = 0
        while step_idx < len(self._steps):
            step = self._steps[step_idx]

            if step.name in visited:
                # Guard against cycles (shouldn't happen in a DAG)
                logger.warning("Workflow %r: step %r already visited — skipping", self.name, step.name)
                step_idx += 1
                continue

            visited.add(step.name)
            logger.debug("Workflow %r: running step %r", self.name, step.name)

            try:
                result = step.action(ctx)
                ctx.results[step.name] = result
                completed.append(step.name)
                logger.debug("Workflow %r: step %r completed", self.name, step.name)

                # Routing: jump to on_success step if specified
                if step.on_success and step.on_success in self._step_map:
                    next_name = step.on_success
                    # Find index of next_name
                    try:
                        step_idx = next(
                            i for i, s in enumerate(self._steps)
                            if s.name == next_name
                        )
                    except StopIteration:
                        step_idx += 1
                else:
                    step_idx += 1

            except Exception as exc:
                failed.append(step.name)
                msg = f"Step {step.name!r} failed: {exc}"
                errors.append(msg)
                logger.error("Workflow %r: %s", self.name, msg, exc_info=True)

                if step.on_failure and step.on_failure in self._step_map:
                    # Jump to fallback step
                    try:
                        step_idx = next(
                            i for i, s in enumerate(self._steps)
                            if s.name == step.on_failure
                        )
                    except StopIteration:
                        break
                else:
                    # Abort
                    break

        elapsed = time.monotonic() - start_time
        success = len(failed) == 0

        logger.info(
            "Workflow %r finished in %.2fs: %d completed, %d failed",
            self.name, elapsed, len(completed), len(failed),
        )

        return WorkflowResult(
            success         = success,
            steps_completed = completed,
            steps_failed    = failed,
            context         = ctx,
            errors          = errors,
            elapsed_seconds = elapsed,
        )
