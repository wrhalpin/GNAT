from __future__ import annotations
from datetime import datetime
from typing import List
from .models import AuditEvent, SecretRef

class InMemoryAuditRecorder:
    def __init__(self) -> None:
        self.events: List[AuditEvent] = []
    def record(self, *, action: str, actor: str, ref: SecretRef, allowed: bool, provider: str, reason: str = "") -> None:
        self.events.append(AuditEvent(action, actor, ref.to_uri(), allowed, provider, datetime.utcnow(), reason))
