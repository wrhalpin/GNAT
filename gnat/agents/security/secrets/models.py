from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional

@dataclass(slots=True)
class ProviderCapabilities:
    supports_read: bool = True
    supports_write: bool = False
    supports_versioning: bool = False
    supports_rotation: bool = False
    supports_checkout: bool = False
    supports_tagging: bool = False
    supports_soft_delete: bool = False

@dataclass(slots=True)
class SecretRef:
    provider: str
    path: str
    vault: Optional[str] = None
    version: Optional[str] = None
    def to_uri(self) -> str:
        vault = self.vault or "default"
        suffix = f"?version={self.version}" if self.version else ""
        return f"{self.provider}://{vault}/{self.path}{suffix}"

@dataclass(slots=True)
class SecretMetadata:
    path: str
    provider: str
    vault: Optional[str] = None
    version: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

@dataclass(slots=True)
class SecretValue:
    ref: SecretRef
    value: str
    metadata: SecretMetadata

@dataclass(slots=True)
class SecretLease:
    ref: SecretRef
    secret: str
    username: Optional[str] = None
    lease_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, str] = field(default_factory=dict)

@dataclass(slots=True)
class StoreSecretRequest:
    ref: SecretRef
    value: str
    tags: Dict[str, str] = field(default_factory=dict)
    allow_overwrite: bool = False
    created_by: Optional[str] = None

@dataclass(slots=True)
class SecretVersionInfo:
    ref: SecretRef
    version: Optional[str] = None
    created_at: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)

@dataclass(slots=True)
class AuditEvent:
    action: str
    actor: str
    ref_uri: str
    allowed: bool
    provider: str
    timestamp: datetime
    reason: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)
