# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.copilot_audit
===========================

Audit trail integration for Investigation Copilot and Live Analyst Assistant.
Logs all operations to ExecutionContext for compliance and investigation review.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

from gnat.context import ExecutionContext


@dataclass
class CopilotAuditEntry:
    """Single audit entry for copilot operation."""
    operation: str  # "ask_question", "suggest_step", "refine_hypothesis", etc.
    investigation_id: str
    analyst_id: str
    timestamp: datetime
    input_text: Optional[str]
    output_text: Optional[str]
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: float = 0.0
    confidence: float = 0.0
    risk_level: str = "low"
    review_required: bool = False
    review_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> dict:
        """Serialize for audit trail."""
        return {
            "operation": self.operation,
            "investigation_id": self.investigation_id,
            "analyst_id": self.analyst_id,
            "timestamp": self.timestamp.isoformat(),
            "input_text": self.input_text,
            "output_text": self.output_text,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "latency_ms": self.latency_ms,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "review_required": self.review_required,
            "review_id": self.review_id,
            "metadata": self.metadata,
        }


class CopilotAuditLog:
    """
    Audit trail for all copilot/assistant operations.
    Integrates with ExecutionContext for compliance tracking.
    """

    def __init__(self, context: Optional[ExecutionContext] = None):
        """
        Initialize audit log.

        Args:
            context: Optional ExecutionContext (creates default if None)
        """
        self.context = context
        self.entries = []

    async def log_copilot_operation(
        self,
        operation: str,
        investigation_id: str,
        analyst_id: str,
        input_text: str,
        output_text: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
        latency_ms: float = 0.0,
        confidence: float = 0.0,
        risk_level: str = "low",
        review_required: bool = False,
        review_id: Optional[str] = None,
    ) -> CopilotAuditEntry:
        """
        Log a copilot operation.

        Args:
            operation: Type of operation
            investigation_id: Investigation ID
            analyst_id: Analyst performing action
            input_text: Input prompt/question
            output_text: Output response
            tokens_in: Input tokens used
            tokens_out: Output tokens used
            latency_ms: Latency in milliseconds
            confidence: Confidence score of output
            risk_level: Risk level (low/medium/high/critical)
            review_required: Whether analyst review is required
            review_id: Optional review item ID if review submitted

        Returns:
            Audit entry
        """
        entry = CopilotAuditEntry(
            operation=operation,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            timestamp=datetime.utcnow(),
            input_text=input_text,
            output_text=output_text,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            confidence=confidence,
            risk_level=risk_level,
            review_required=review_required,
            review_id=review_id,
        )

        self.entries.append(entry)

        # Log to ExecutionContext if available
        if self.context:
            await self._log_to_context(entry)

        return entry

    async def log_assistant_operation(
        self,
        operation: str,
        investigation_id: str,
        analyst_id: str,
        query: str,
        response: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
        latency_ms: float = 0.0,
    ) -> CopilotAuditEntry:
        """
        Log an assistant operation.

        Args:
            operation: Type of operation (suggest_enrichment, draft_report, explain, search)
            investigation_id: Investigation ID
            analyst_id: Analyst ID
            query: User query
            response: Assistant response
            tokens_in: Input tokens
            tokens_out: Output tokens
            latency_ms: Latency

        Returns:
            Audit entry
        """
        return await self.log_copilot_operation(
            operation=operation,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            input_text=query,
            output_text=response,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            confidence=1.0,  # Assistant is deterministic
            risk_level="low",  # Assistant ops are informational
        )

    async def _log_to_context(self, entry: CopilotAuditEntry) -> None:
        """
        Log entry to ExecutionContext for compliance.

        Args:
            entry: Audit entry
        """
        if not self.context:
            return

        # Append to execution_log with structured format
        # TODO: Use context.execution_log.append() when available
        log_entry = {
            "timestamp": entry.timestamp.isoformat(),
            "event_type": "copilot_operation",
            "operation": entry.operation,
            "investigation_id": entry.investigation_id,
            "analyst_id": entry.analyst_id,
            "metadata": {
                "tokens_in": entry.tokens_in,
                "tokens_out": entry.tokens_out,
                "latency_ms": entry.latency_ms,
                "confidence": entry.confidence,
                "risk_level": entry.risk_level,
                "review_required": entry.review_required,
                "review_id": entry.review_id,
            },
        }

        # In real implementation: self.context.execution_log.append(log_entry)

    def get_audit_trail(
        self,
        investigation_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list:
        """
        Retrieve audit trail entries.

        Args:
            investigation_id: Filter by investigation (optional)
            start_time: Filter by start time (optional)
            end_time: Filter by end time (optional)

        Returns:
            List of audit entries as dicts
        """
        results = self.entries

        if investigation_id:
            results = [e for e in results if e.investigation_id == investigation_id]

        if start_time:
            results = [e for e in results if e.timestamp >= start_time]

        if end_time:
            results = [e for e in results if e.timestamp <= end_time]

        return [e.to_dict() for e in results]

    def get_investigation_summary(self, investigation_id: str) -> Dict[str, Any]:
        """
        Get summary stats for an investigation.

        Args:
            investigation_id: Investigation ID

        Returns:
            Summary dict with operation counts, token usage, etc.
        """
        inv_entries = [e for e in self.entries if e.investigation_id == investigation_id]

        if not inv_entries:
            return {"investigation_id": investigation_id, "operation_count": 0}

        total_tokens = sum(e.tokens_in + e.tokens_out for e in inv_entries)
        avg_latency = sum(e.latency_ms for e in inv_entries) / len(inv_entries)
        avg_confidence = sum(e.confidence for e in inv_entries) / len(inv_entries)
        reviews_required = sum(1 for e in inv_entries if e.review_required)

        return {
            "investigation_id": investigation_id,
            "operation_count": len(inv_entries),
            "copilot_questions": sum(1 for e in inv_entries if "question" in e.operation),
            "copilot_suggestions": sum(1 for e in inv_entries if "suggest" in e.operation),
            "assistant_queries": sum(1 for e in inv_entries if e.operation.startswith("assistant")),
            "total_tokens": total_tokens,
            "avg_latency_ms": round(avg_latency, 2),
            "avg_confidence": round(avg_confidence, 3),
            "reviews_required": reviews_required,
            "reviews_completed": sum(1 for e in inv_entries if e.review_id),
            "first_operation": min(e.timestamp for e in inv_entries).isoformat(),
            "last_operation": max(e.timestamp for e in inv_entries).isoformat(),
        }

    def export_audit_log(self, investigation_id: str, format: str = "json") -> str:
        """
        Export audit log for an investigation.

        Args:
            investigation_id: Investigation ID
            format: Export format ("json" or "csv")

        Returns:
            Serialized audit log
        """
        import json

        entries = self.get_audit_trail(investigation_id=investigation_id)

        if format == "json":
            return json.dumps(entries, indent=2)

        elif format == "csv":
            # CSV export
            import csv
            from io import StringIO

            if not entries:
                return ""

            output = StringIO()
            fieldnames = entries[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(entries)

            return output.getvalue()

        else:
            raise ValueError(f"Unsupported format: {format}")
