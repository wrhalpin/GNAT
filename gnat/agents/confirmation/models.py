# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.models
==================================

Data types for the ConfirmationBroker.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional
from uuid import UUID, uuid4


def _utcnow() -> datetime:
    """Timezone-aware UTC now (datetime.utcnow is deprecated)."""
    return datetime.now(timezone.utc)


class ConfirmationOutcome(Enum):
    """Result of a confirmation request."""

    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    AUTO_APPROVED = "auto_approved"
    AUTO_DENIED = "auto_denied"


class ConfirmationRisk(Enum):
    """Risk level of a confirmation request."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    IRREVERSIBLE = "irreversible"


class ConfirmationPrincipal(Enum):
    """Principal type for the confirmation request."""

    ANALYST = "analyst"
    SYSTEM = "system"


@dataclass
class ConfirmationRequest:
    """Request for confirmation of an action."""

    scope: str
    action: str
    agent: str
    workspace: str
    subject: dict[str, Any]
    reason: str
    risk: Literal["low", "medium", "high", "irreversible"] = "medium"
    timeout_seconds: int = 300
    # Who the request is on behalf of. `principal` is the identity recorded
    # in the audit trail (workspace owner by default); `principal_type`
    # distinguishes interactive analyst sessions from scheduled/system jobs
    # so policies can treat them differently.
    principal: str = "analyst"
    principal_type: Literal["analyst", "system"] = "analyst"
    correlation_id: Optional[str] = None
    created_at: datetime = field(default_factory=_utcnow)
    request_id: UUID = field(default_factory=uuid4)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, converting UUID and datetime to strings."""
        data = asdict(self)
        data["request_id"] = str(self.request_id)
        data["created_at"] = self.created_at.isoformat()
        return data


@dataclass
class ConfirmationDecision:
    """Decision on a confirmation request."""

    request_id: UUID
    outcome: ConfirmationOutcome
    decided_at: datetime = field(default_factory=_utcnow)
    decided_by: str = "system"
    note: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, converting UUID, datetime, and enum to strings."""
        return {
            "request_id": str(self.request_id),
            "outcome": self.outcome.value,
            "decided_at": self.decided_at.isoformat(),
            "decided_by": self.decided_by,
            "note": self.note,
        }


@dataclass
class PromptResult:
    """What a backend returns from prompt(): the outcome plus an optional
    analyst note that is carried into the ConfirmationDecision and audit log."""

    outcome: ConfirmationOutcome
    note: Optional[str] = None


class ConfirmationDenied(Exception):
    """Raised when a confirmation is denied."""

    def __init__(
        self, decision: ConfirmationDecision, request: Optional[ConfirmationRequest] = None
    ):
        self.decision = decision
        self.request = request
        msg = f"Confirmation denied: {decision.outcome.value}"
        if decision.note:
            msg += f" ({decision.note})"
        super().__init__(msg)


class ConfirmationTimeout(Exception):
    """Raised when confirmation times out."""

    def __init__(self, request: ConfirmationRequest):
        self.request = request
        super().__init__(f"Confirmation timeout for {request.scope}")
