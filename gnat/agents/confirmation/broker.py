# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.broker
==================================

ConfirmationBroker — main orchestrator for human-in-the-loop gates.
"""

import os
from typing import Optional, Dict, Any
from pathlib import Path

from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationDecision,
    ConfirmationOutcome,
    ConfirmationDenied,
    ConfirmationTimeout,
)
from gnat.agents.confirmation.audit import ConfirmationAuditLog
from gnat.agents.confirmation.policy import PolicyEngine
from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.backends.null import NullBackend


class ConfirmationBroker:
    """
    Main broker for human-in-the-loop confirmation gates.

    Dispatches requests to the policy engine; if auto-approved/denied,
    returns immediately. Otherwise dispatches to the backend (CLIBackend,
    DashboardBackend, etc.) to prompt the analyst.

    All decisions are logged to an audit trail.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        backend: ConfirmationBackend,
        audit_log: ConfirmationAuditLog,
    ):
        self.policy_engine = policy_engine
        self.backend = backend
        self.audit_log = audit_log

    def request(self, req: ConfirmationRequest) -> ConfirmationDecision:
        """
        Submit a confirmation request and return the decision.

        Args:
            req: The confirmation request

        Returns:
            ConfirmationDecision with outcome

        Raises:
            ConfirmationTimeout: If backend times out (converted to outcome by caller)
        """
        # Log the request
        self.audit_log.record_requested(req)

        # Check policy engine
        immediate_outcome = self.policy_engine.decide(req)
        if immediate_outcome is not None:
            # Policy short-circuited (auto_approve or auto_deny)
            decision = ConfirmationDecision(
                request_id=req.request_id,
                outcome=immediate_outcome,
                decided_by="policy:" + self.policy_engine._find_matching_action(req.scope),
            )
            self.audit_log.record_decided(req, decision)
            self.backend.notify_decided(req, immediate_outcome)
            return decision

        # Policy doesn't auto-decide; dispatch to backend
        action, timeout_becomes = self.policy_engine.get_action_and_timeout_behavior(req)

        try:
            outcome = self.backend.prompt(req)
            decided_by = req.principal_type
            decision = ConfirmationDecision(
                request_id=req.request_id,
                outcome=outcome,
                decided_by=decided_by,
            )
        except ConfirmationTimeout:
            # Backend timed out
            if timeout_becomes is not None:
                outcome = timeout_becomes
            else:
                # Shouldn't happen; policy engine should always provide a timeout outcome
                outcome = ConfirmationOutcome.DENIED

            decision = ConfirmationDecision(
                request_id=req.request_id,
                outcome=ConfirmationOutcome.TIMEOUT,
                decided_by="system:timeout",
            )

        self.audit_log.record_decided(req, decision)
        self.backend.notify_decided(req, decision.outcome)
        return decision

    def request_or_raise(self, req: ConfirmationRequest) -> None:
        """
        Submit a confirmation request; raise ConfirmationDenied if denied.

        Args:
            req: The confirmation request

        Raises:
            ConfirmationDenied: If the outcome is not APPROVED or AUTO_APPROVED
        """
        decision = self.request(req)

        if decision.outcome not in (
            ConfirmationOutcome.APPROVED,
            ConfirmationOutcome.AUTO_APPROVED,
        ):
            raise ConfirmationDenied(decision, req)

    @classmethod
    def default(cls) -> "ConfirmationBroker":
        """
        Load from GNAT config (singleton-ish).

        Reads [confirmation] and [confirmation.policies] sections from config.
        Returns a NullBackend (deny-all) if config is missing.
        """
        try:
            from gnat.config import GNATConfig

            cfg = GNATConfig()
            parser = cfg.parser
        except Exception:
            # Config not found or invalid; use defaults
            parser = None

        # Load confirmation section
        if parser and parser.has_section("confirmation"):
            conf_section = dict(parser["confirmation"])
            backend_name = conf_section.get("backend", "null").lower()
            default_action = conf_section.get("default_action", "prompt_timeout_deny")
            timeout_seconds = int(conf_section.get("default_timeout_seconds", "300"))
            audit_log_path = conf_section.get(
                "audit_log_path",
                str(Path.home() / ".gnat" / "confirmation_audit.jsonl"),
            )
        else:
            backend_name = "null"
            default_action = "prompt_timeout_deny"
            timeout_seconds = 300
            audit_log_path = str(Path.home() / ".gnat" / "confirmation_audit.jsonl")

        # Load policies
        config_dict = {}
        if parser and parser.has_section("confirmation.policies"):
            config_dict = dict(parser["confirmation.policies"])

        policy_engine = PolicyEngine(config_dict, default_action)

        # Load audit log
        audit_log = ConfirmationAuditLog(audit_log_path)

        # Load backend
        backend: ConfirmationBackend
        if backend_name == "auto":
            try:
                from gnat.agents.confirmation.backends.auto import AutoApproveBackend

                backend = AutoApproveBackend()
            except Exception:
                backend = NullBackend()
        elif backend_name == "cli":
            try:
                from gnat.agents.confirmation.backends.cli import CLIBackend

                backend = CLIBackend()
            except Exception:
                backend = NullBackend()
        elif backend_name == "dashboard":
            try:
                from gnat.agents.confirmation.backends.dashboard import DashboardBackend

                backend = DashboardBackend()
            except Exception:
                backend = NullBackend()
        else:
            backend = NullBackend()

        return cls(policy_engine, backend, audit_log)

    @classmethod
    def testing(cls, auto_approve: bool = True) -> "ConfirmationBroker":
        """
        Create a broker for testing with auto-approve backend.

        Args:
            auto_approve: If True, use AutoApproveBackend; else NullBackend

        Returns:
            ConfirmationBroker with test configuration
        """
        os.environ.setdefault("GNAT_ENV", "test")

        policy_engine = PolicyEngine({})
        audit_log = ConfirmationAuditLog(":memory:")  # Won't work; use /tmp/

        if auto_approve:
            try:
                from gnat.agents.confirmation.backends.auto import AutoApproveBackend

                backend = AutoApproveBackend()
            except Exception:
                backend = NullBackend()
        else:
            backend = NullBackend()

        return cls(policy_engine, backend, audit_log)
