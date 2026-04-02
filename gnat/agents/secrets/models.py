from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SecretPurpose(str, Enum):
    RUNTIME = "runtime"
    CI = "ci"
    ROTATION = "rotation"
    MIGRATION = "migration"
    DEVELOPMENT = "development"


@dataclass(frozen=True)
class SecretRef:
    provider: str
    vault: str
    name: str
    version: str | None = None

    def to_uri(self) -> str:
        version_suffix = f"?version={self.version}" if self.version else ""
        return f"{self.provider}://{self.vault}/{self.name}{version_suffix}"


@dataclass
class SecretPutRequest:
    ref: SecretRef
    value: str
    tags: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    enabled: bool = True
    overwrite: bool = False
    requested_by: str = "system"
    purpose: SecretPurpose = SecretPurpose.RUNTIME


@dataclass
class SecretGetRequest:
    ref: SecretRef
    include_value: bool = True
    requested_by: str = "system"
    purpose: SecretPurpose = SecretPurpose.RUNTIME


@dataclass
class SecretRecord:
    ref: SecretRef
    value: str | None = None
    content_type: str | None = None
    enabled: bool = True
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    provider_metadata: dict[str, Any] = field(default_factory=dict)

    def redacted_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref.to_uri(),
            "has_value": self.value is not None,
            "content_type": self.content_type,
            "enabled": self.enabled,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "provider_metadata": self.provider_metadata,
        }


@dataclass
class LeakFinding:
    path: str
    line_number: int
    rule_id: str
    confidence: str
    matched_text_preview: str
    remediation: str


@dataclass
class DuplicateSecretFinding:
    value_fingerprint: str
    locations: list[str]


@dataclass
class UnsafeSecretFinding:
    secret_name: str
    reason: str
    severity: str
