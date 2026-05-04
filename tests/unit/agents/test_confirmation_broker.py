# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Tests for ConfirmationBroker and related components.
"""

import pytest
from uuid import uuid4

from gnat.agents.confirmation import (
    ConfirmationBroker,
    ConfirmationRequest,
    ConfirmationOutcome,
    ConfirmationDenied,
    requires_confirmation,
)
from gnat.agents.confirmation.backends.recording import RecordingBackend
from gnat.agents.confirmation.policy import PolicyEngine


class TestConfirmationRequest:
    """Test ConfirmationRequest creation and serialization."""

    def test_create_request(self):
        """Test creating a request."""
        req = ConfirmationRequest(
            scope="library.promote",
            action="promote",
            agent="ResearchAgent",
            workspace="test-ws",
            subject={"topic": "APT29"},
            reason="Testing",
        )

        assert req.scope == "library.promote"
        assert req.action == "promote"
        assert req.risk == "medium"
        assert req.timeout_seconds == 300

    def test_request_to_dict(self):
        """Test request serialization."""
        req = ConfirmationRequest(
            scope="library.promote",
            action="promote",
            agent="ResearchAgent",
            workspace="test-ws",
            subject={"topic": "APT29"},
            reason="Testing",
        )

        data = req.to_dict()
        assert data["scope"] == "library.promote"
        assert isinstance(data["request_id"], str)
        assert isinstance(data["created_at"], str)


class TestPolicyEngine:
    """Test PolicyEngine decision logic."""

    def test_auto_approve(self):
        """Test auto-approval policy."""
        policies = {
            "library.promote": "auto_approve",
        }
        engine = PolicyEngine(policies)

        req = ConfirmationRequest(
            scope="library.promote",
            action="promote",
            agent="ResearchAgent",
            workspace="test-ws",
            subject={},
            reason="Test",
        )

        outcome = engine.decide(req)
        assert outcome == ConfirmationOutcome.AUTO_APPROVED

    def test_auto_deny(self):
        """Test auto-denial policy."""
        policies = {
            "connector.delete.*": "auto_deny",
        }
        engine = PolicyEngine(policies)

        req = ConfirmationRequest(
            scope="connector.delete.aws",
            action="delete",
            agent="SomeAgent",
            workspace="test-ws",
            subject={},
            reason="Test",
        )

        outcome = engine.decide(req)
        assert outcome == ConfirmationOutcome.AUTO_DENIED

    def test_prompt_policy(self):
        """Test that prompt policies return None (defer to backend)."""
        policies = {
            "report.publish": "prompt",
        }
        engine = PolicyEngine(policies)

        req = ConfirmationRequest(
            scope="report.publish",
            action="publish",
            agent="ReportService",
            workspace="reports",
            subject={},
            reason="Test",
        )

        outcome = engine.decide(req)
        assert outcome is None

    def test_default_action(self):
        """Test fallback to default_action."""
        policies = {}
        engine = PolicyEngine(policies, default_action="prompt_timeout_deny")

        req = ConfirmationRequest(
            scope="unknown.scope",
            action="unknown",
            agent="SomeAgent",
            workspace="test-ws",
            subject={},
            reason="Test",
        )

        outcome = engine.decide(req)
        assert outcome is None

    def test_prefix_matching(self):
        """Test wildcard prefix matching."""
        policies = {
            "connector.write.*": "prompt",
        }
        engine = PolicyEngine(policies)

        req = ConfirmationRequest(
            scope="connector.write.threatq",
            action="write",
            agent="Agent",
            workspace="ws",
            subject={},
            reason="Test",
        )

        outcome = engine.decide(req)
        assert outcome is None


class TestConfirmationBroker:
    """Test ConfirmationBroker orchestration."""

    def test_broker_with_recording_backend(self):
        """Test broker with recording backend."""
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            audit_path = f.name

        try:
            backend = RecordingBackend(ConfirmationOutcome.APPROVED)
            policies = {}
            engine = PolicyEngine(policies)
            from gnat.agents.confirmation.audit import ConfirmationAuditLog

            audit = ConfirmationAuditLog(audit_path)
            broker = ConfirmationBroker(engine, backend, audit)

            req = ConfirmationRequest(
                scope="library.promote",
                action="promote",
                agent="ResearchAgent",
                workspace="test-ws",
                subject={"topic": "APT29"},
                reason="Testing",
            )

            decision = broker.request(req)
            assert decision.outcome == ConfirmationOutcome.APPROVED

            # Check audit log
            events = audit.get_request_history(str(req.request_id))
            assert len(events) == 2  # requested + decided
            assert events[0]["event"] == "requested"
            assert events[1]["event"] == "decided"

        finally:
            import os

            os.unlink(audit_path)

    def test_request_or_raise_approved(self):
        """Test request_or_raise with approval."""
        backend = RecordingBackend(ConfirmationOutcome.APPROVED)
        policies = {}
        engine = PolicyEngine(policies)
        from gnat.agents.confirmation.audit import ConfirmationAuditLog
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name

        try:
            audit = ConfirmationAuditLog(audit_path)
            broker = ConfirmationBroker(engine, backend, audit)

            req = ConfirmationRequest(
                scope="test",
                action="test",
                agent="Test",
                workspace="ws",
                subject={},
                reason="Test",
            )

            # Should not raise
            broker.request_or_raise(req)

        finally:
            import os

            os.unlink(audit_path)

    def test_request_or_raise_denied(self):
        """Test request_or_raise with denial."""
        backend = RecordingBackend(ConfirmationOutcome.DENIED)
        policies = {}
        engine = PolicyEngine(policies)
        from gnat.agents.confirmation.audit import ConfirmationAuditLog
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name

        try:
            audit = ConfirmationAuditLog(audit_path)
            broker = ConfirmationBroker(engine, backend, audit)

            req = ConfirmationRequest(
                scope="test",
                action="test",
                agent="Test",
                workspace="ws",
                subject={},
                reason="Test",
            )

            # Should raise
            with pytest.raises(ConfirmationDenied):
                broker.request_or_raise(req)

        finally:
            import os

            os.unlink(audit_path)


class TestDecorator:
    """Test @requires_confirmation decorator."""

    def test_decorator_sync_approved(self):
        """Test decorator on sync function with approval."""
        import os
        import tempfile

        os.environ.setdefault("GNAT_ENV", "test")

        @requires_confirmation(
            scope="test.action",
            risk="low",
            reason="Test action",
            workspace="test-ws",
        )
        def my_function(x):
            return x * 2

        # Patch the broker to auto-approve
        original_default = ConfirmationBroker.default

        def mock_default():
            backend = RecordingBackend(ConfirmationOutcome.APPROVED)
            policies = {}
            engine = PolicyEngine(policies)
            from gnat.agents.confirmation.audit import ConfirmationAuditLog

            with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
                audit_path = f.name
            audit = ConfirmationAuditLog(audit_path)
            broker = ConfirmationBroker(engine, backend, audit)
            broker._temp_audit_path = audit_path
            return broker

        try:
            ConfirmationBroker.default = mock_default
            result = my_function(5)
            assert result == 10
        finally:
            ConfirmationBroker.default = original_default
            # Cleanup
            broker = mock_default()
            if hasattr(broker, "_temp_audit_path"):
                import os

                os.unlink(broker._temp_audit_path)

    def test_decorator_async_approved(self):
        """Test decorator on async function with approval."""
        import asyncio
        import os
        import tempfile

        os.environ.setdefault("GNAT_ENV", "test")

        @requires_confirmation(
            scope="test.async_action",
            risk="low",
            reason="Test async action",
            workspace="test-ws",
        )
        async def my_async_function(x):
            return x * 2

        # Patch the broker
        original_default = ConfirmationBroker.default

        def mock_default():
            backend = RecordingBackend(ConfirmationOutcome.APPROVED)
            policies = {}
            engine = PolicyEngine(policies)
            from gnat.agents.confirmation.audit import ConfirmationAuditLog

            with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
                audit_path = f.name
            audit = ConfirmationAuditLog(audit_path)
            broker = ConfirmationBroker(engine, backend, audit)
            broker._temp_audit_path = audit_path
            return broker

        try:
            ConfirmationBroker.default = mock_default
            result = asyncio.run(my_async_function(5))
            assert result == 10
        finally:
            ConfirmationBroker.default = original_default
            broker = mock_default()
            if hasattr(broker, "_temp_audit_path"):
                import os

                os.unlink(broker._temp_audit_path)
