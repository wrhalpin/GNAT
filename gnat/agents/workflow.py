"""
gnat.agents.workflow
=====================

Composable DAG workflow engine for GNAT investigation automation.

A :class:`Workflow` is a named sequence of :class:`WorkflowStep` objects.
Each step is an arbitrary callable that receives a :class:`WorkflowContext`
and returns any value.  Steps can be chained with ``on_success`` / ``on_failure``
step names, forming a directed acyclic graph.

The engine supports:

* **Sequential execution** — default; steps run in definition order
* **Conditional routing** — ``on_success`` / ``on_failure`` pointer routing
* **Branching** — ``branch_on(ctx) → step_name`` evaluator for data-driven routing
* **Parallel fan-out** — ``parallel_steps`` list runs multiple steps concurrently;
  fan-in waits for all to complete before continuing
* **Retry with backoff** — ``retry`` :class:`RetryPolicy` on any step

Usage::

    from gnat.agents.workflow import Workflow, WorkflowContext, WorkflowStep, RetryPolicy
    from gnat.agents.steps import enrich_step, gap_detect_step

    ctx = WorkflowContext(investigation_id="inv-123", shared={}, results={})

    result = (
        Workflow("phishing-triage")
        .add_step(WorkflowStep(
            "enrich",
            enrich_step(dispatcher, ["8.8.8.8"]),
            retry=RetryPolicy(max_attempts=3, backoff_seconds=2),
        ))
        .add_step(WorkflowStep(
            "route",
            lambda ctx: None,
            branch_on=lambda ctx: "high-confidence" if ctx.shared.get("score", 0) > 0.7 else "low-confidence",
        ))
        .run(ctx)
    )

    print(result.success, result.steps_completed)
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

    investigation_id: str | None = None
    shared: dict[str, Any] = field(default_factory=dict)
    results: dict[str, Any] = field(default_factory=dict)


@dataclass
class RetryPolicy:
    """
    Retry configuration for a :class:`WorkflowStep`.

    Parameters
    ----------
    max_attempts : int
        Total number of attempts (including the first try).  Must be ≥ 1.
    backoff_seconds : float
        Base sleep between retries.  Doubles on each attempt (exponential
        backoff).  E.g. ``backoff_seconds=2`` → sleeps of 2s, 4s, 8s, …
    retryable_exceptions : tuple[type[Exception], ...]
        Exception types that trigger a retry.  Default: any ``Exception``.
    """

    max_attempts: int = 3
    backoff_seconds: float = 2.0
    retryable_exceptions: tuple[type[Exception], ...] = field(default_factory=lambda: (Exception,))


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
    branch_on : Callable[[WorkflowContext], str] | None
        Data-driven router called *after* ``action`` succeeds.
        Returns the name of the next step to jump to.  Takes priority
        over ``on_success`` when present.
    parallel_steps : list[WorkflowStep] | None
        Fan-out: a list of steps to run concurrently.  The engine collects
        all results before advancing.  ``action`` is still run first (as a
        setup step); parallel steps run after it.
    retry : RetryPolicy | None
        Retry policy for this step.  When set, the step is retried on
        failure up to ``RetryPolicy.max_attempts`` times.
    timeout_seconds : int
        Wall-clock timeout (informational; not enforced by the engine —
        use thread/process pools for hard timeouts).
    """

    name: str
    action: Callable[[WorkflowContext], Any]
    on_success: str | None = None
    on_failure: str | None = None
    branch_on: Callable[[WorkflowContext], str] | None = None
    parallel_steps: list[WorkflowStep] | None = None
    retry: RetryPolicy | None = None
    timeout_seconds: int = 60


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

    success: bool
    steps_completed: list[str]
    steps_failed: list[str]
    context: WorkflowContext
    errors: list[str]
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
        self.name = name
        self._steps: list[WorkflowStep] = []
        self._step_map: dict[str, WorkflowStep] = {}

    def __repr__(self) -> str:
        return f"Workflow({self.name}, {len(self._steps)} steps)"

    def add_step(self, step: WorkflowStep) -> Workflow:
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
        ``on_success`` / ``branch_on`` / ``on_failure`` routing.

        Supports retry with exponential backoff (``WorkflowStep.retry``),
        data-driven branching (``WorkflowStep.branch_on``), and parallel
        fan-out (``WorkflowStep.parallel_steps``).

        Parameters
        ----------
        ctx : WorkflowContext
            Mutable context object shared across all steps.

        Returns
        -------
        WorkflowResult
        """
        start_time = time.monotonic()
        completed: list[str] = []
        failed: list[str] = []
        errors: list[str] = []
        visited: set[str] = set()

        step_idx = 0
        while step_idx < len(self._steps):
            step = self._steps[step_idx]

            if step.name in visited:
                logger.warning(
                    "Workflow %r: step %r already visited — skipping (cycle guard)",
                    self.name,
                    step.name,
                )
                step_idx += 1
                continue

            visited.add(step.name)
            logger.debug("Workflow %r: running step %r", self.name, step.name)

            try:
                # ── Retry logic ──────────────────────────────────────────
                result = self._run_step_with_retry(step, ctx)
                ctx.results[step.name] = result
                completed.append(step.name)
                logger.debug("Workflow %r: step %r completed", self.name, step.name)

                # ── Parallel fan-out ─────────────────────────────────────
                if step.parallel_steps:
                    par_completed, par_failed, par_errors = self._run_parallel(
                        step.parallel_steps, ctx
                    )
                    completed.extend(par_completed)
                    failed.extend(par_failed)
                    errors.extend(par_errors)
                    if par_failed:
                        break

                # ── Routing: branch_on > on_success > sequential ─────────
                next_idx = self._resolve_next(step, ctx, step_idx)
                step_idx = next_idx

            except Exception as exc:
                failed.append(step.name)
                msg = f"Step {step.name!r} failed: {exc}"
                errors.append(msg)
                logger.error("Workflow %r: %s", self.name, msg, exc_info=True)

                if step.on_failure and step.on_failure in self._step_map:
                    try:
                        step_idx = next(
                            i for i, s in enumerate(self._steps) if s.name == step.on_failure
                        )
                    except StopIteration:
                        break
                else:
                    break

        elapsed = time.monotonic() - start_time
        success = len(failed) == 0

        logger.info(
            "Workflow %r finished in %.2fs: %d completed, %d failed",
            self.name,
            elapsed,
            len(completed),
            len(failed),
        )

        return WorkflowResult(
            success=success,
            steps_completed=completed,
            steps_failed=failed,
            context=ctx,
            errors=errors,
            elapsed_seconds=elapsed,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _run_step_with_retry(self, step: WorkflowStep, ctx: WorkflowContext) -> Any:
        """
        Execute ``step.action`` with retry/backoff if ``step.retry`` is set.

        Raises the final exception if all attempts are exhausted.
        """
        policy = step.retry
        if policy is None:
            return step.action(ctx)

        last_exc: Exception | None = None
        for attempt in range(1, policy.max_attempts + 1):
            try:
                return step.action(ctx)
            except policy.retryable_exceptions as exc:
                last_exc = exc
                if attempt < policy.max_attempts:
                    sleep_time = policy.backoff_seconds * (2 ** (attempt - 1))
                    logger.warning(
                        "Workflow %r: step %r attempt %d/%d failed (%s) — retrying in %.1fs",
                        self.name,
                        step.name,
                        attempt,
                        policy.max_attempts,
                        exc,
                        sleep_time,
                    )
                    time.sleep(sleep_time)
                else:
                    logger.error(
                        "Workflow %r: step %r exhausted %d attempts",
                        self.name,
                        step.name,
                        policy.max_attempts,
                    )
        raise last_exc  # type: ignore[misc]

    def _run_parallel(
        self,
        steps: list[WorkflowStep],
        ctx: WorkflowContext,
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Run *steps* concurrently using a ThreadPoolExecutor (fan-out).

        All steps receive the same *ctx* reference.  Returns after all
        futures complete (fan-in).

        Returns
        -------
        tuple[completed, failed, errors]
        """
        completed: list[str] = []
        failed: list[str] = []
        errors: list[str] = []

        with ThreadPoolExecutor(max_workers=min(len(steps), 8)) as pool:
            future_to_step = {pool.submit(self._run_step_with_retry, s, ctx): s for s in steps}
            for future in as_completed(future_to_step):
                step = future_to_step[future]
                try:
                    result = future.result()
                    ctx.results[step.name] = result
                    completed.append(step.name)
                    logger.debug("Workflow %r: parallel step %r completed", self.name, step.name)
                except Exception as exc:
                    failed.append(step.name)
                    msg = f"Parallel step {step.name!r} failed: {exc}"
                    errors.append(msg)
                    logger.error("Workflow %r: %s", self.name, msg, exc_info=True)

        return completed, failed, errors

    def _resolve_next(
        self,
        step: WorkflowStep,
        ctx: WorkflowContext,
        current_idx: int,
    ) -> int:
        """
        Determine the index of the next step after *step* succeeds.

        Priority: ``branch_on`` > ``on_success`` > sequential.
        """
        # 1. branch_on (data-driven routing)
        if step.branch_on is not None:
            try:
                next_name = step.branch_on(ctx)
                if next_name and next_name in self._step_map:
                    try:
                        return next(i for i, s in enumerate(self._steps) if s.name == next_name)
                    except StopIteration:
                        pass
            except Exception as exc:
                logger.warning(
                    "Workflow %r: branch_on for step %r raised %s — falling through",
                    self.name,
                    step.name,
                    exc,
                )

        # 2. on_success routing
        if step.on_success and step.on_success in self._step_map:
            try:
                return next(i for i, s in enumerate(self._steps) if s.name == step.on_success)
            except StopIteration:
                pass

        # 3. Sequential advance
        return current_idx + 1
