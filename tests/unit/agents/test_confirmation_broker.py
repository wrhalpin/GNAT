# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for ConfirmationBroker and related components."""

import asyncio
import threading

import pytest

from gnat.agents.confirmation import (
    ConfirmationAuditLog,
    ConfirmationBroker,
    ConfirmationDenied,
    ConfirmationOutcome,
    ConfirmationRequest,
    PolicyEngine,
    PromptResult,
    requires_confirmation,
)
from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.backends.dashboard import DashboardBackend
from gnat.agents.confirmation.backends.null import NullBackend
from gnat.agents.confirmation.backends.recording import RecordingBackend
from gnat.agents.confirmation.models import ConfirmationTimeout


def make_request(scope="library.promote", **overrides):
    defaults = {
        "scope": scope,
        "action": "promote",
        "agent": "ResearchAgent",
        "workspace": "test-ws",
        "subject": {"topic": "APT29"},
        "reason": "Testing",
    }
    defaults.update(overrides)
    return ConfirmationRequest(**defaults)


def make_broker(backend, policies=None, tmp_path=None, **kwargs):
    audit = (
        ConfirmationAuditLog(str(tmp_path / "audit.jsonl"))
        if tmp_path is not None
        else ConfirmationAuditLog.null()
    )
    return ConfirmationBroker(PolicyEngine(policies or {}), backend, audit, **kwargs)


class TimeoutBackend(ConfirmationBackend):
    """Backend that always times out."""

    def prompt(self, request):
        raise ConfirmationTimeout(request)


class TestConfirmationRequest:
    def test_create_request_defaults(self):
        req = make_request()
        assert req.scope == "library.promote"
        assert req.risk == "medium"
        assert req.timeout_seconds == 300
        assert req.principal == "analyst"
        assert req.principal_type == "analyst"

    def test_request_to_dict_serializes_uuid_and_datetime(self):
        data = make_request().to_dict()
        assert isinstance(data["request_id"], str)
        assert isinstance(data["created_at"], str)


class TestPolicyEngine:
    def test_auto_approve(self):
        engine = PolicyEngine({"library.promote": "auto_approve"})
        assert engine.decide(make_request()) == ConfirmationOutcome.AUTO_APPROVED

    def test_auto_deny(self):
        engine = PolicyEngine({"connector.delete.*": "auto_deny"})
        req = make_request(scope="connector.delete.aws")
        assert engine.decide(req) == ConfirmationOutcome.AUTO_DENIED

    def test_prompt_defers_to_backend(self):
        engine = PolicyEngine({"report.publish": "prompt"})
        assert engine.decide(make_request(scope="report.publish")) is None

    def test_unknown_scope_uses_default_action(self):
        engine = PolicyEngine({}, default_action="prompt_timeout_deny")
        assert engine.decide(make_request(scope="unknown.scope")) is None
        assert engine.matched_action("unknown.scope") == "prompt_timeout_deny"

    def test_prefix_wildcard_matches(self):
        engine = PolicyEngine({"connector.write.*": "prompt"})
        assert engine.matched_action("connector.write.threatq") == "prompt"
        assert engine.decide(make_request(scope="connector.write.threatq")) is None

    def test_prefix_wildcard_does_not_match_sibling_names(self):
        engine = PolicyEngine({"connector.write.*": "auto_deny"}, default_action="auto_approve")
        # "connector.writeable" must NOT match "connector.write.*"
        req = make_request(scope="connector.writeable")
        assert engine.decide(req) == ConfirmationOutcome.AUTO_APPROVED

    def test_first_match_wins(self):
        engine = PolicyEngine(
            {
                "connector.delete.gnat_remote": "auto_deny",
                "connector.delete.*": "auto_approve",
            }
        )
        denied = make_request(scope="connector.delete.gnat_remote")
        approved = make_request(scope="connector.delete.other")
        assert engine.decide(denied) == ConfirmationOutcome.AUTO_DENIED
        assert engine.decide(approved) == ConfirmationOutcome.AUTO_APPROVED

    def test_invalid_action_rejected(self):
        with pytest.raises(ValueError):
            PolicyEngine({"x.y": "definitely_not_an_action"})


class TestConfirmationBroker:
    def test_backend_approval_flow_and_audit(self, tmp_path):
        backend = RecordingBackend(ConfirmationOutcome.APPROVED)
        broker = make_broker(backend, tmp_path=tmp_path)
        req = make_request()

        decision = broker.request(req)

        assert decision.outcome == ConfirmationOutcome.APPROVED
        events = broker.audit_log.get_request_history(str(req.request_id))
        assert [e["event"] for e in events] == ["requested", "decided"]

    def test_request_or_raise_returns_decision_on_approval(self, tmp_path):
        broker = make_broker(RecordingBackend(ConfirmationOutcome.APPROVED), tmp_path=tmp_path)
        decision = broker.request_or_raise(make_request())
        assert decision.outcome == ConfirmationOutcome.APPROVED

    def test_request_or_raise_raises_on_denial(self, tmp_path):
        broker = make_broker(RecordingBackend(ConfirmationOutcome.DENIED), tmp_path=tmp_path)
        with pytest.raises(ConfirmationDenied):
            broker.request_or_raise(make_request())

    def test_policy_auto_approve_skips_backend(self, tmp_path):
        backend = RecordingBackend()
        broker = make_broker(
            backend, policies={"library.promote": "auto_approve"}, tmp_path=tmp_path
        )
        decision = broker.request(make_request())
        assert decision.outcome == ConfirmationOutcome.AUTO_APPROVED
        assert decision.decided_by == "policy:auto_approve"
        backend.assert_not_requested("library.promote")

    def test_timeout_with_prompt_timeout_approve_approves(self, tmp_path):
        """Regression: timeout under prompt_timeout_approve must approve."""
        broker = make_broker(
            TimeoutBackend(),
            policies={"deploy.thing": "prompt_timeout_approve"},
            tmp_path=tmp_path,
        )
        req = make_request(scope="deploy.thing")
        decision = broker.request_or_raise(req)  # must not raise
        assert decision.outcome == ConfirmationOutcome.APPROVED
        assert decision.decided_by == "system:timeout"

    def test_timeout_with_prompt_timeout_deny_denies(self, tmp_path):
        broker = make_broker(
            TimeoutBackend(),
            policies={"deploy.thing": "prompt_timeout_deny"},
            tmp_path=tmp_path,
        )
        with pytest.raises(ConfirmationDenied) as excinfo:
            broker.request_or_raise(make_request(scope="deploy.thing"))
        assert excinfo.value.decision.outcome == ConfirmationOutcome.TIMEOUT

    def test_disabled_broker_approves_without_audit(self):
        broker = make_broker(NullBackend(), enabled=False)
        decision = broker.request_or_raise(make_request())
        assert decision.outcome == ConfirmationOutcome.AUTO_APPROVED
        assert decision.decided_by == "policy:disabled"

    def test_configured_principal_recorded(self, tmp_path):
        broker = make_broker(RecordingBackend(), tmp_path=tmp_path, principal="wrhalpin")
        req = make_request()
        decision = broker.request(req)
        assert decision.decided_by == "wrhalpin"

    def test_backend_note_carried_into_decision(self, tmp_path):
        class NotingBackend(ConfirmationBackend):
            def prompt(self, request):
                return PromptResult(ConfirmationOutcome.APPROVED, note="looks fine")

        broker = make_broker(NotingBackend(), tmp_path=tmp_path)
        decision = broker.request(make_request())
        assert decision.note == "looks fine"


class TestAuditLog:
    def test_decided_events_carry_workspace_and_scope(self, tmp_path):
        """Regression: decided events must be visible to workspace filters."""
        broker = make_broker(RecordingBackend(), tmp_path=tmp_path)
        broker.request(make_request(workspace="ws-a"))
        broker.request(make_request(workspace="ws-b"))

        events = broker.audit_log.get_workspace_history("ws-a")
        assert [e["event"] for e in events] == ["requested", "decided"]

    def test_audit_summary_counts_outcomes(self, tmp_path):
        """Regression: summary must not report zero for decided requests."""
        broker = make_broker(RecordingBackend(ConfirmationOutcome.APPROVED), tmp_path=tmp_path)
        broker.request(make_request(workspace="ws-a"))
        broker.request(make_request(workspace="ws-a"))

        summary = broker.audit_log.get_audit_summary("ws-a")
        assert summary["total_requests"] == 2
        assert summary["approved"] == 2

    def test_null_audit_log_is_silent(self):
        log = ConfirmationAuditLog.null()
        log.record_requested(make_request())
        assert log.read_events() == []


class TestDashboardBackend:
    def test_decide_unblocks_prompt(self):
        backend = DashboardBackend()
        req = make_request(timeout_seconds=5)
        result_box = {}

        def worker():
            result_box["result"] = backend.prompt(req)

        thread = threading.Thread(target=worker)
        thread.start()

        # Wait for the request to appear in pending
        for _ in range(100):
            if backend.get_pending():
                break
            threading.Event().wait(0.01)
        assert backend.get_pending()[0].request_id == req.request_id

        backend.decide(req.request_id, ConfirmationOutcome.APPROVED, note="ok")
        thread.join(timeout=5)

        assert result_box["result"].outcome == ConfirmationOutcome.APPROVED
        assert result_box["result"].note == "ok"
        assert backend.get_pending() == []

    def test_prompt_times_out_when_nobody_decides(self):
        backend = DashboardBackend()
        req = make_request(timeout_seconds=0)  # immediate timeout
        with pytest.raises(ConfirmationTimeout):
            backend.prompt(req)
        assert backend.get_pending() == []

    def test_decide_unknown_request_raises(self):
        backend = DashboardBackend()
        with pytest.raises(KeyError):
            backend.decide(make_request().request_id, ConfirmationOutcome.APPROVED)

    def test_decide_rejects_non_terminal_outcomes(self):
        backend = DashboardBackend()
        with pytest.raises(ValueError):
            backend.decide(make_request().request_id, ConfirmationOutcome.TIMEOUT)


@pytest.fixture
def patched_default_broker(monkeypatch):
    """Point ConfirmationBroker.default() at a recording broker."""
    backend = RecordingBackend(ConfirmationOutcome.APPROVED)
    broker = make_broker(backend)
    monkeypatch.setattr(ConfirmationBroker, "default", classmethod(lambda cls: broker))
    yield backend, broker


class TestDecorator:
    def test_sync_function_gated_and_called(self, patched_default_broker):
        backend, _ = patched_default_broker

        @requires_confirmation(scope="test.action", risk="low", workspace="test-ws")
        def double(x):
            return x * 2

        assert double(5) == 10
        backend.assert_requested("test.action", action="double")

    def test_sync_function_denied(self, patched_default_broker):
        backend, _ = patched_default_broker
        backend.outcome = ConfirmationOutcome.DENIED

        @requires_confirmation(scope="test.action", risk="low")
        def double(x):
            return x * 2

        with pytest.raises(ConfirmationDenied):
            double(5)

    def test_async_function_gated_and_called(self, patched_default_broker):
        backend, _ = patched_default_broker

        @requires_confirmation(scope="test.async", risk="low")
        async def double(x):
            return x * 2

        assert asyncio.run(double(5)) == 10
        backend.assert_requested("test.async")

    def test_disabled_broker_skips_gating(self, monkeypatch):
        broker = make_broker(NullBackend(), enabled=False)
        monkeypatch.setattr(ConfirmationBroker, "default", classmethod(lambda cls: broker))

        @requires_confirmation(scope="test.action")
        def double(x):
            return x * 2

        assert double(5) == 10  # NullBackend would deny if gating ran

    def test_secrets_redacted_in_default_subject(self, patched_default_broker):
        backend, _ = patched_default_broker

        @requires_confirmation(scope="test.action")
        def connect(host, api_key=None):
            return host

        connect("example.com", api_key="s3cr3t")
        req = backend.find_by_scope("test.action")[0]
        assert req.subject["kwargs"]["api_key"] == "***REDACTED***"
        assert "s3cr3t" not in str(req.subject)

    def test_invalid_risk_rejected_at_decoration_time(self):
        with pytest.raises(ValueError):

            @requires_confirmation(scope="x", risk="catastrophic")
            def f():
                pass


class TestCallSiteIntegration:
    def test_promote_keyword_call_extracts_workspace_name(self, patched_default_broker):
        """Regression: promote(workspace=ws, ...) must not record 'unknown'."""
        backend, _ = patched_default_broker

        from gnat.research.library import ResearchLibrary

        class FakeWorkspace:
            name = "apt29-q2"
            objects = {}

        lib = ResearchLibrary.__new__(ResearchLibrary)  # skip heavy __init__
        with pytest.raises(ValueError):
            # Empty workspace raises ValueError *after* the gate passes
            lib.promote(workspace=FakeWorkspace(), topic="APT29", researcher="a1")

        req = backend.find_by_scope("library.promote")[0]
        assert req.workspace == "apt29-q2"
        assert req.subject["topic"] == "APT29"
