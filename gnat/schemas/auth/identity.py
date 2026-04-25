# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schemas for API key and OIDC identity models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from gnat.schemas.analysis.tlp import TLPLevelSchema


class APIKeySchema(BaseModel):
    """An API key with associated TLP access level and RBAC role."""

    model_config = ConfigDict(from_attributes=True)

    token: str = Field(
        description="Raw bearer token.",
    )
    tlp_level: TLPLevelSchema = Field(
        description="Maximum TLP level this key can access.",
    )
    label: str = Field(
        default="",
        description="Human-readable label for the key.",
    )
    role: str = Field(
        default="viewer",
        description="RBAC role string.",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Tenant scope.",
    )
    created_at: datetime = Field(
        description="Creation timestamp.",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Optional expiry timestamp.",
    )
    enabled: bool = Field(
        default=True,
        description="Whether the key is active.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary key metadata.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> APIKeySchema:
        """Hydrate from a domain APIKey dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class OIDCIdentitySchema(BaseModel):
    """Identity resolved from an OIDC JWT."""

    model_config = ConfigDict(from_attributes=True)

    subject_id: str = Field(
        description="OIDC sub claim.",
    )
    email: str = Field(
        default="",
        description="Email claim from the ID token.",
    )
    role: str = Field(
        default="viewer",
        description="GNAT role derived from the token's group/role claims.",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Tenant scope derived from a custom claim.",
    )
    tlp_level: TLPLevelSchema = Field(
        default=TLPLevelSchema.AMBER,
        description="Maximum TLP access level.",
    )
    groups: list[str] = Field(
        default_factory=list,
        description="Raw group/role claims from the token.",
    )
    issuer: str = Field(
        default="",
        description="Token issuer (iss claim).",
    )
    expires_at: datetime = Field(
        description="Token expiry (exp claim).",
    )
    raw_claims: dict[str, Any] = Field(
        default_factory=dict,
        description="Full decoded JWT claims for audit.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> OIDCIdentitySchema:
        """Hydrate from a domain OIDCIdentity dataclass."""
        return cls.model_validate(obj, from_attributes=True)
