# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.broker
==================================

ConfirmationBroker — main orchestrator for human-in-the-loop gates.
"""

import threading
from pathlib import Path
from typing import Optional

from gnat.agents.confirmation.audit import ConfirmationAuditLog
from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.backends.null import NullBackend
from gnat.agents.confirmation.models import (
    ConfirmationDecision,
    ConfirmationDenied,
    ConfirmationOutcome,
    ConfirmationRequest,
    ConfirmationTimeout,
    PromptResult,
)
from gnat.agents.confirmation.policy import PolicyEngine

_default_lock = threading.Lock()
_default_broker: Optional["ConfirmationBroker"] = None


class ConfirmationBroker:
    """
    Main broker for human-in-the-loop confirmation gates.

    Dispatches requests to the policy engine; if auto-approved/denied,
    returns immediately. Otherwise dispatches to the backend (CLIBackend,
    DashboardBackend, etc.) to prompt the analyst.

    All decisions on an enabled broker are logged to an audit trail.

    When ``enabled`` is False — the default when no ``[confirmation]``
    section exists in the config — every request is approved without
    prompting and without audit I/O, so gated call sites like
    ``ResearchLibrary.promote()`` behave exactly as they did before the
    broker existed. Opting in is an explicit config change.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        backend: ConfirmationBackend,
        audit_log: ConfirmationAuditLog,
        enabled: bool = True,
        principal: Optional[str] = None,
    ):
        self.policy_engine = policy_engine
        self.backend = backend
        self.audit_log = audit_log
        self.enabled = enabled
        self.principal = principal

    def request(self, req: ConfirmationRequest) -> ConfirmationDecision:
        """
        Submit a confirmation request and return the decision.

        Parameters
        ----------
        req : ConfirmationRequest
            The confirmation request.

        Returns
        -------
        ConfirmationDecision
            The decision, whether made by policy, backend, or timeout.
        """
        if not self.enabled:
            # Broker not configured/enabled: approve without prompting or
            # audit I/O so unconfigured installs are unaffected.
            return ConfirmationDecision(
                request_id=req.request_id,
                outcome=ConfirmationOutcome.AUTO_APPROVED,
                decided_by="policy:disabled",
            )

        # Fill in the configured principal identity when the caller left
        # the default in place.
        if self.principal and req.principal == "analyst":
            req.principal = self.principal

        self.audit_log.record_requested(req)

        matched_action = self.policy_engine.matched_action(req.scope)

        # Policy short-circuits
        immediate_outcome = self.policy_engine.decide(req)
        if immediate_outcome is not None:
            decision = ConfirmationDecision(
                request_id=req.request_id,
                outcome=immediate_outcome,
                decided_by=f"policy:{matched_action}",
            )
            self.audit_log.record_decided(req, decision)
            self.backend.notify_decided(req, decision.outcome)
            return decision

        # Prompt via backend; timeout semantics come from the matched policy
        try:
            result = self.backend.prompt(req)
            if isinstance(result, PromptResult):
                outcome, note = result.outcome, result.note
            else:
                # Tolerate backends that return a bare outcome
                outcome, note = result, None

            decision = ConfirmationDecision(
                request_id=req.request_id,
                outcome=outcome,
                decided_by=req.principal,
                note=note,
            )
        except ConfirmationTimeout:
            # prompt_timeout_approve converts a timeout into approval;
            # everything else records TIMEOUT, which request_or_raise
            # treats as a denial.
            if matched_action == "prompt_timeout_approve":
                timeout_outcome = ConfirmationOutcome.APPROVED
            else:
                timeout_outcome = ConfirmationOutcome.TIMEOUT

            decision = ConfirmationDecision(
                request_id=req.request_id,
                outcome=timeout_outcome,
                decided_by="system:timeout",
            )

        self.audit_log.record_decided(req, decision)
        self.backend.notify_decided(req, decision.outcome)
        return decision

    def request_or_raise(self, req: ConfirmationRequest) -> ConfirmationDecision:
        """
        Submit a confirmation request; raise ConfirmationDenied unless approved.

        Returns
        -------
        ConfirmationDecision
            The approving decision, so callers can log it.

        Raises
        ------
        ConfirmationDenied
            If the outcome is not APPROVED or AUTO_APPROVED.
        """
        decision = self.request(req)

        if decision.outcome not in (
            ConfirmationOutcome.APPROVED,
            ConfirmationOutcome.AUTO_APPROVED,
        ):
            raise ConfirmationDenied(decision, req)

        return decision

    @classmethod
    def default(cls) -> "ConfirmationBroker":
        """
        Return the process-wide broker built from GNAT config (cached).

        Reads the ``[confirmation]`` and ``[confirmation.policies]``
        sections. If the ``[confirmation]`` section is missing, or has
        ``enabled = false``, the broker is disabled (approve-everything,
        no audit). Call :meth:`reset_default` after config changes.
        """
        global _default_broker
        with _default_lock:
            if _default_broker is None:
                _default_broker = cls._from_config()
            return _default_broker

    @classmethod
    def reset_default(cls) -> None:
        """Drop the cached default broker (e.g. after config changes, in tests)."""
        global _default_broker
        with _default_lock:
            _default_broker = None

    @classmethod
    def _from_config(cls) -> "ConfirmationBroker":
        """Build a broker from the GNAT INI config."""
        try:
            from gnat.config import GNATConfig

            parser = GNATConfig().parser
        except Exception:
            parser = None

        if parser is None or not parser.has_section("confirmation"):
            # Not configured: disabled broker, no filesystem side effects.
            return cls(
                policy_engine=PolicyEngine({}),
                backend=NullBackend(),
                audit_log=ConfirmationAuditLog.null(),
                enabled=False,
            )

        conf = dict(parser["confirmation"])
        enabled = conf.get("enabled", "true").strip().lower() not in ("false", "0", "no")
        backend_name = conf.get("backend", "null").lower()
        default_action = conf.get("default_action", "prompt_timeout_deny")
        default_timeout = int(conf.get("default_timeout_seconds", "300"))
        principal = conf.get("principal") or None
        audit_log_path = conf.get(
            "audit_log_path",
            str(Path.home() / ".gnat" / "confirmation_audit.jsonl"),
        )

        policies = {}
        if parser.has_section("confirmation.policies"):
            policies = dict(parser["confirmation.policies"])

        policy_engine = PolicyEngine(policies, default_action)
        audit_log = ConfirmationAuditLog(audit_log_path)
        backend = cls._load_backend(backend_name, default_timeout)

        return cls(policy_engine, backend, audit_log, enabled=enabled, principal=principal)

    @staticmethod
    def _load_backend(backend_name: str, default_timeout: int) -> ConfirmationBackend:
        """Instantiate the configured backend, falling back to deny-all."""
        try:
            if backend_name == "auto":
                from gnat.agents.confirmation.backends.auto import AutoApproveBackend

                return AutoApproveBackend()
            if backend_name == "cli":
                from gnat.agents.confirmation.backends.cli import CLIBackend

                return CLIBackend()
            if backend_name == "dashboard":
                from gnat.agents.confirmation.backends.dashboard import DashboardBackend

                return DashboardBackend.shared()
        except Exception:
            pass
        return NullBackend()
