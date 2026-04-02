from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ProviderCapabilities:
    supports_read: bool = True
    supports_write: bool = False
    supports_versioning: bool = False
    supports_rotation: bool = False
    supports_checkout: bool = False
    supports_tagging: bool = False
    supports_soft_delete: bool = False


@dataclass
class SecretRef:
    provider: str
    path: str
    vault: str | None = None
    version: str | None = None

    def to_uri(self) -> str:
        vault = self.vault or "default"
        suffix = f"?version={self.version}" if self.version else ""
        return f"{self.provider}://{vault}/{self.path}{suffix}"


@dataclass
class SecretMetadata:
    path: str
    provider: str
    vault: str | None = None
    version: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass
class SecretValue:
    ref: SecretRef
    value: str
    metadata: SecretMetadata


@dataclass
class SecretLease:
    ref: SecretRef
    secret: str
    username: str | None = None
    lease_id: str | None = None
    expires_at: datetime | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class StoreSecretRequest:
    ref: SecretRef
    value: str
    tags: dict[str, str] = field(default_factory=dict)
    allow_overwrite: bool = False
    created_by: str | None = None


@dataclass
class SecretVersionInfo:
    ref: SecretRef
    version: str | None = None
    created_at: datetime | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class AuditEvent:
    action: str
    actor: str
    ref_uri: str
    allowed: bool
    provider: str
    timestamp: datetime
    reason: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
