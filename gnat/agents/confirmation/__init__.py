# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation
==========================

Human-in-the-loop confirmation broker for sensitive agent actions.

Quick start:

    from gnat.agents.confirmation import (
        ConfirmationBroker,
        requires_confirmation,
    )

    # Gate a function with confirmation
    @requires_confirmation(
        scope="library.promote",
        risk="medium",
        reason="Promoting workspace to library",
    )
    def promote(workspace, topic):
        ...

    # Or manually request confirmation
    broker = ConfirmationBroker.default()
    req = ConfirmationRequest(
        scope="library.promote",
        action="promote",
        agent="ResearchAgent",
        workspace="my-workspace",
        subject={"topic": "APT29"},
        reason="Promote workspace to library",
    )
    try:
        broker.request_or_raise(req)
    except ConfirmationDenied as e:
        print(f"Denied: {e.decision.note}")

For configuration, add to config.ini:

    [confirmation]
    backend = cli
    default_action = prompt_timeout_deny
    default_timeout_seconds = 300
    audit_log_path = ~/.gnat/confirmation_audit.jsonl

    [confirmation.policies]
    library.promote = prompt
    huntgnat.deploy = prompt
    connector.delete.* = prompt
    agent.research.run = auto_approve
"""

from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationDecision,
    ConfirmationOutcome,
    ConfirmationDenied,
    ConfirmationTimeout,
    ConfirmationRisk,
    ConfirmationPrincipal,
)
from gnat.agents.confirmation.broker import ConfirmationBroker
from gnat.agents.confirmation.decorator import requires_confirmation
from gnat.agents.confirmation.audit import ConfirmationAuditLog
from gnat.agents.confirmation.policy import PolicyEngine

__all__ = [
    "ConfirmationRequest",
    "ConfirmationDecision",
    "ConfirmationOutcome",
    "ConfirmationDenied",
    "ConfirmationTimeout",
    "ConfirmationRisk",
    "ConfirmationPrincipal",
    "ConfirmationBroker",
    "requires_confirmation",
    "ConfirmationAuditLog",
    "PolicyEngine",
]
