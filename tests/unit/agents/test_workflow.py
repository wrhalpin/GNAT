"""Unit tests for gnat.agents.workflow and gnat.agents.steps."""

from __future__ import annotations

import pytest

from gnat.agents.workflow import Workflow, WorkflowContext, WorkflowStep

# ── WorkflowContext ────────────────────────────────────────────────────────────


def test_context_defaults():
    ctx = WorkflowContext()
    assert ctx.investigation_id is None
    assert ctx.shared == {}
    assert ctx.results == {}


def test_context_custom_values():
    ctx = WorkflowContext(investigation_id="inv-1", shared={"x": 1})
    assert ctx.investigation_id == "inv-1"
    assert ctx.shared["x"] == 1


# ── WorkflowStep ──────────────────────────────────────────────────────────────


def test_step_runs_action():
    log = []
    step = WorkflowStep(name="s1", action=lambda ctx: log.append("ran"))
    ctx = WorkflowContext()
    step.action(ctx)
    assert log == ["ran"]


# ── Workflow construction ─────────────────────────────────────────────────────


def test_workflow_add_and_repr():
    wf = Workflow("test")
    assert len(wf._steps) == 0
    wf.add_step(WorkflowStep("s1", lambda ctx: None))
    assert len(wf._steps) == 1
    assert "test" in repr(wf)


def test_workflow_duplicate_step_raises():
    wf = Workflow("dup")
    wf.add_step(WorkflowStep("s", lambda ctx: None))
    with pytest.raises(ValueError, match="Duplicate step name"):
        wf.add_step(WorkflowStep("s", lambda ctx: None))


def test_workflow_fluent_chaining():
    wf = (
        Workflow("chain")
        .add_step(WorkflowStep("a", lambda ctx: None))
        .add_step(WorkflowStep("b", lambda ctx: None))
    )
    assert len(wf._steps) == 2


# ── Successful run ────────────────────────────────────────────────────────────


def test_workflow_run_success():
    log = []

    def step1(ctx):
        log.append("s1")
        ctx.shared["flag"] = True

    def step2(ctx):
        log.append("s2")
        return 42

    wf = Workflow("success")
    wf.add_step(WorkflowStep("s1", step1))
    wf.add_step(WorkflowStep("s2", step2))

    ctx = WorkflowContext()
    result = wf.run(ctx)

    assert result.success is True
    assert result.steps_completed == ["s1", "s2"]
    assert result.steps_failed == []
    assert result.context.shared["flag"] is True
    assert result.context.results["s2"] == 42
    assert log == ["s1", "s2"]


def test_workflow_run_stores_elapsed():
    wf = Workflow("timing")
    wf.add_step(WorkflowStep("s", lambda ctx: None))
    result = wf.run(WorkflowContext())
    assert result.elapsed_seconds >= 0.0


# ── Failure handling ──────────────────────────────────────────────────────────


def test_workflow_step_failure_aborts():
    log = []

    def bad_step(ctx):
        raise ValueError("boom")

    def after(ctx):
        log.append("after")

    wf = Workflow("fail")
    wf.add_step(WorkflowStep("bad", bad_step))
    wf.add_step(WorkflowStep("after", after))

    result = wf.run(WorkflowContext())

    assert result.success is False
    assert "bad" in result.steps_failed
    assert "after" not in result.steps_completed
    assert log == []


def test_workflow_on_failure_routing():
    log = []

    def bad(ctx):
        raise RuntimeError("oops")

    def fallback(ctx):
        log.append("fallback")

    wf = Workflow("fallback-test")
    wf.add_step(WorkflowStep("bad", bad, on_failure="fallback"))
    wf.add_step(WorkflowStep("skipped", lambda ctx: log.append("skipped")))
    wf.add_step(WorkflowStep("fallback", fallback))

    result = wf.run(WorkflowContext())

    assert "fallback" in result.steps_completed
    assert log == ["fallback"]


def test_workflow_on_success_routing():
    log = []

    def s1(ctx):
        log.append("s1")

    def s2(ctx):
        log.append("s2")

    def skip(ctx):
        log.append("skip")

    wf = Workflow("success-route")
    wf.add_step(WorkflowStep("s1", s1, on_success="s2"))
    wf.add_step(WorkflowStep("skip", skip))
    wf.add_step(WorkflowStep("s2", s2))

    wf.run(WorkflowContext())
    # s1 routes to s2; "skip" is not visited
    assert "s1" in log
    assert "s2" in log


# ── Steps ─────────────────────────────────────────────────────────────────────


def test_enrich_step_calls_dispatcher():
    from gnat.agents.steps import enrich_step

    class Dispatcher:
        def enrich_batch(self, values):
            return {v: {"score": 1} for v in values}

    ctx = WorkflowContext()
    step = enrich_step(Dispatcher(), ["1.2.3.4"], name="enrich_test")
    step.action(ctx)

    assert "1.2.3.4" in ctx.shared["enrichment_results"]


def test_enrich_step_none_dispatcher_noop():
    from gnat.agents.steps import enrich_step

    ctx = WorkflowContext()
    step = enrich_step(None, ["1.2.3.4"])
    step.action(ctx)
    assert ctx.shared["enrichment_results"] == {}


def test_gap_detect_step_calls_detector():
    from gnat.agents.steps import gap_detect_step

    class Detector:
        def detect_all(self, inv_id):
            return ["gap1", "gap2"]

    ctx = WorkflowContext(investigation_id="inv-1")
    step = gap_detect_step(Detector())
    step.action(ctx)
    assert ctx.shared["gaps"] == ["gap1", "gap2"]


def test_gap_detect_step_none_detector():
    from gnat.agents.steps import gap_detect_step

    ctx = WorkflowContext()
    step = gap_detect_step(None)
    step.action(ctx)
    assert ctx.shared["gaps"] == []


def test_draft_report_step():
    from gnat.agents.steps import draft_report_step

    class Assistant:
        def draft_full(self, inv_id):
            return "**Draft report**"

    ctx = WorkflowContext(investigation_id="inv-1")
    step = draft_report_step(Assistant())
    step.action(ctx)
    assert "Draft" in ctx.shared["report_draft"]


def test_transition_step_calls_service():
    from gnat.agents.steps import transition_step

    transitions = []

    class FakeService:
        def transition(self, inv_id, status, note=None, author=None):
            transitions.append((inv_id, status))

    ctx = WorkflowContext(investigation_id="inv-1")
    step = transition_step(FakeService(), "in_progress")
    step.action(ctx)
    assert transitions == [("inv-1", "in_progress")]


def test_fn_step_wraps_callable():
    from gnat.agents.steps import fn_step

    def my_fn(ctx):
        ctx.shared["x"] = 99

    ctx = WorkflowContext()
    step = fn_step(my_fn, "my_fn")
    step.action(ctx)
    assert ctx.shared["x"] == 99


# ── Pre-built workflows ────────────────────────────────────────────────────────


def test_phishing_triage_workflow_runs():
    from gnat.agents.workflows.phishing_triage import build_phishing_triage_workflow

    wf = build_phishing_triage_workflow(iocs=["evil.com"])
    ctx = WorkflowContext(investigation_id="inv-1")
    result = wf.run(ctx)
    # All components are None → no-ops → should succeed
    assert result.success is True
    assert len(result.steps_completed) == 5


def test_incident_response_workflow_runs():
    from gnat.agents.workflows.incident_response import build_incident_response_workflow

    wf = build_incident_response_workflow(iocs=["1.2.3.4"])
    ctx = WorkflowContext(investigation_id="inv-2")
    result = wf.run(ctx)
    assert result.success is True
    assert len(result.steps_completed) == 5
