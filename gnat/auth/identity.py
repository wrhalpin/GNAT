# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.auth.identity
====================

Common identity interface implemented by both API keys and OIDC tokens.

:class:`AuthenticatedIdentity` is a :class:`typing.Protocol` so that
:class:`~gnat.dissemination.api.auth.APIKey` and
:class:`OIDCIdentity` can be used interchangeably by the policy
engine, audit middleware, and downstream endpoints without coupling
those layers to a concrete class.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from gnat.analysis.tlp import TLPLevel


@runtime_checkable
class AuthenticatedIdentity(Protocol):
    """Structural protocol for any authenticated caller."""

    @property
    def subject_id(self) -> str: ...

    @property
    def label(self) -> str: ...

    @property
    def role(self) -> str: ...

    @property
    def tenant_id(self) -> str | None: ...

    @property
    def tlp_level(self) -> TLPLevel: ...

    @property
    def token_hash(self) -> str: ...

    def is_valid(self) -> bool: ...

    def to_dict(self) -> dict[str, Any]: ...


@dataclass
class OIDCIdentity:
    """
    Identity resolved from an OIDC JWT.

    Implements the same interface as
    :class:`~gnat.dissemination.api.auth.APIKey` so it can be used
    interchangeably by the policy engine and downstream endpoints.

    Parameters
    ----------
    subject_id : str
        OIDC ``sub`` claim (e.g. ``"alice@acme.com"``).
    email : str
        Email claim from the ID token.
    role : str
        GNAT role derived from the token's group/role claims.
    tenant_id : str or None
        Tenant scope derived from a custom claim.
    tlp_level : TLPLevel
        Maximum TLP access level.
    groups : list of str
        Raw group/role claims from the token.
    issuer : str
        Token issuer (``iss`` claim).
    expires_at : datetime
        Token expiry (``exp`` claim).
    raw_claims : dict
        Full decoded JWT claims for audit.
    """

    subject_id: str
    email: str = ""
    role: str = "viewer"
    tenant_id: str | None = None
    tlp_level: TLPLevel = TLPLevel.AMBER
    groups: list[str] = field(default_factory=list)
    issuer: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    raw_claims: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"oidc:{self.email or self.subject_id}"

    @property
    def token_hash(self) -> str:
        return hashlib.sha256(self.subject_id.encode()).hexdigest()[:16]

    def is_valid(self) -> bool:
        return datetime.now(tz=timezone.utc) < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "email": self.email,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "tlp_level": self.tlp_level.value,
            "label": self.label,
            "token_hash": self.token_hash,
            "issuer": self.issuer,
            "groups": self.groups,
            "expires_at": self.expires_at.isoformat(),
        }
