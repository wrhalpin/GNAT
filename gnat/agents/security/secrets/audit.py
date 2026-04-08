# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.audit
======================================

Audit utilities and helpers for the GNAT toolkit.
"""
from __future__ import annotations

from datetime import datetime

from .models import AuditEvent, SecretRef


class InMemoryAuditRecorder:
    """InMemoryAuditRecorder implementation."""
    def __init__(self) -> None:
        """Initialize InMemoryAuditRecorder."""
        self.events: list[AuditEvent] = []

    def record(
        self,
        *,
        action: str,
        actor: str,
        ref: SecretRef,
        allowed: bool,
        provider: str,
        reason: str = "",
    ) -> None:
        """Record."""
        self.events.append(
            AuditEvent(action, actor, ref.to_uri(), allowed, provider, datetime.utcnow(), reason)
        )
