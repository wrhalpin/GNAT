# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.audit
=================================

Append-only audit log for confirmation decisions.
"""

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationDecision,
    ConfirmationOutcome,
)


class ConfirmationAuditLog:
    """Append-only JSONL audit log for confirmation events."""

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record_requested(self, request: ConfirmationRequest) -> None:
        """Log a confirmation request."""
        event = {
            "event": "requested",
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": str(request.request_id),
            "scope": request.scope,
            "action": request.action,
            "agent": request.agent,
            "workspace": request.workspace,
            "risk": request.risk,
            "principal_type": request.principal_type,
            "timeout_seconds": request.timeout_seconds,
        }
        if request.correlation_id:
            event["correlation_id"] = request.correlation_id

        self._write_event(event)

    def record_decided(
        self,
        request: ConfirmationRequest,
        decision: ConfirmationDecision,
    ) -> None:
        """Log a confirmation decision."""
        event = {
            "event": "decided",
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": str(decision.request_id),
            "outcome": decision.outcome.value,
            "decided_by": decision.decided_by,
        }
        if decision.note:
            event["note"] = decision.note

        self._write_event(event)

    def _write_event(self, event: Dict[str, Any]) -> None:
        """Write a single event to the log (thread-safe)."""
        with self._lock:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(event) + "\n")

    def read_events(
        self,
        workspace: Optional[str] = None,
        request_id: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Read events from the audit log with optional filtering.

        Args:
            workspace: Filter by workspace
            request_id: Filter by request_id
            scope: Filter by scope

        Returns:
            List of matching events in chronological order.
        """
        if not self.log_path.exists():
            return []

        events = []
        with self._lock:
            with open(self.log_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Filter
                    if workspace and event.get("workspace") != workspace:
                        continue
                    if request_id and event.get("request_id") != request_id:
                        continue
                    if scope and event.get("scope") != scope:
                        continue

                    events.append(event)

        return events

    def get_request_history(self, request_id: str) -> List[Dict[str, Any]]:
        """Get all events for a single request."""
        return self.read_events(request_id=request_id)

    def get_workspace_history(self, workspace: str) -> List[Dict[str, Any]]:
        """Get all events for a workspace."""
        return self.read_events(workspace=workspace)

    def get_scope_history(self, scope: str) -> List[Dict[str, Any]]:
        """Get all events for a specific scope."""
        return self.read_events(scope=scope)

    def get_audit_summary(self, workspace: str) -> Dict[str, Any]:
        """
        Generate audit summary for a workspace.

        Returns:
            Dict with counts of approved, denied, timeout outcomes.
        """
        events = self.get_workspace_history(workspace)

        summary = {
            "workspace": workspace,
            "total_requests": 0,
            "approved": 0,
            "auto_approved": 0,
            "denied": 0,
            "auto_denied": 0,
            "timeout": 0,
            "by_scope": {},
        }

        decided_requests = set()

        for event in events:
            if event["event"] == "requested":
                summary["total_requests"] += 1

            elif event["event"] == "decided":
                request_id = event["request_id"]
                if request_id not in decided_requests:
                    decided_requests.add(request_id)
                    outcome = event["outcome"]
                    summary[outcome] = summary.get(outcome, 0) + 1

        return summary
