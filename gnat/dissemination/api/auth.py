"""
gnat.dissemination.api.auth
============================

API key management for the GNAT dissemination API gateway.

Each API key maps to a :class:`~gnat.analysis.tlp.TLPLevel` that controls
which TAXII collections and report data the holder can access.

Usage::

    from gnat.dissemination.api.auth import APIKey, APIKeyStore
    from gnat.analysis.tlp import TLPLevel

    store = APIKeyStore()
    store.add_key("secret-token-1", TLPLevel.AMBER, label="SIEM integration")
    store.add_key("secret-token-2", TLPLevel.GREEN, label="External partner")

    level = store.get_tlp_level("secret-token-1")   # TLPLevel.AMBER
    key   = store.get_key("secret-token-1")          # APIKey object
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.tlp import TLPLevel


@dataclass
class APIKey:
    """
    An API key with associated TLP access level and RBAC role.

    Parameters
    ----------
    token : str
        Raw bearer token (secret).  Store only the hash in production.
    tlp_level : TLPLevel
        Maximum TLP level this key can access.
    label : str
        Human-readable label for the key (e.g. ``"SIEM integration"``).
    role : str
        RBAC role string (``"viewer"``, ``"analyst"``, etc.).  The
        :class:`~gnat.policy.engine.PolicyEngine` coerces this to a
        :class:`~gnat.policy.models.Role` at evaluation time.
    tenant_id : str | None
        Tenant scope.  When set, the key is restricted to resources
        belonging to this tenant.  ``None`` means no tenant restriction.
    created_at : datetime
        Creation timestamp.
    expires_at : datetime | None
        Optional expiry timestamp.  ``None`` means never expires.
    enabled : bool
        Whether the key is active.
    metadata : dict
        Arbitrary key metadata.
    """

    token: str
    tlp_level: TLPLevel
    label: str = ""
    role: str = "viewer"
    tenant_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    expires_at: datetime | None = None
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def token_hash(self) -> str:
        """SHA-256 hash of the raw token (for safe logging)."""
        return hashlib.sha256(self.token.encode()).hexdigest()[:16]

    def is_valid(self) -> bool:
        """True if the key is enabled and not expired."""
        if not self.enabled:
            return False
        if self.expires_at is not None:
            return datetime.now(tz=timezone.utc) < self.expires_at
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_hash": self.token_hash,
            "tlp_level": self.tlp_level.value,
            "label": self.label,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "enabled": self.enabled,
        }


class APIKeyStore:
    """
    In-memory store of API keys.

    Parameters
    ----------
    keys : list[APIKey], optional
        Pre-seeded keys.

    Notes
    -----
    For production deployments, subclass and override :meth:`get_key` /
    :meth:`add_key` to persist keys in a database or secrets manager.
    """

    def __init__(self, keys: list[APIKey] | None = None) -> None:
        self._keys: dict[str, APIKey] = {}
        for key in keys or []:
            self._keys[key.token] = key

    def add_key(
        self,
        token: str,
        tlp_level: TLPLevel,
        label: str = "",
        role: str = "viewer",
        tenant_id: str | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> APIKey:
        """
        Register an API key.

        Parameters
        ----------
        token : str
            Raw bearer token.
        tlp_level : TLPLevel
            Maximum access level granted.
        label : str
            Human-readable label.
        role : str
            RBAC role (``"viewer"``, ``"analyst"``, ``"senior_analyst"``,
            ``"reviewer"``, ``"admin"``).  Defaults to ``"viewer"``.
        tenant_id : str | None
            Tenant scope.
        expires_at : datetime | None
            Optional expiry.
        metadata : dict | None
            Arbitrary metadata.

        Returns
        -------
        APIKey
        """
        key = APIKey(
            token=token,
            tlp_level=tlp_level,
            label=label,
            role=role,
            tenant_id=tenant_id,
            expires_at=expires_at,
            metadata=metadata or {},
        )
        self._keys[token] = key
        return key

    def generate_key(
        self,
        tlp_level: TLPLevel,
        label: str = "",
        **kwargs: Any,
    ) -> APIKey:
        """
        Generate a cryptographically secure random API key and register it.

        Returns
        -------
        APIKey
            The new key (caller must store the ``token`` securely — it cannot
            be recovered later).
        """
        token = secrets.token_urlsafe(32)
        return self.add_key(token, tlp_level, label=label, **kwargs)

    def get_key(self, token: str) -> APIKey | None:
        """Return the :class:`APIKey` for *token*, or ``None``."""
        return self._keys.get(token)

    def get_tlp_level(self, token: str) -> TLPLevel | None:
        """
        Return the TLP access level for *token*.

        Returns ``None`` if the key does not exist, is disabled, or has expired.
        """
        key = self._keys.get(token)
        if key is None or not key.is_valid():
            return None
        return key.tlp_level

    def revoke_key(self, token: str) -> bool:
        """Disable a key (mark as not enabled).  Returns True if found."""
        key = self._keys.get(token)
        if key is None:
            return False
        key.enabled = False
        return True

    def delete_key(self, token: str) -> bool:
        """Remove a key entirely.  Returns True if found."""
        if token in self._keys:
            del self._keys[token]
            return True
        return False

    def rotate_key(
        self,
        token: str,
        grace_hours: int = 24,
    ) -> APIKey | None:
        """
        Replace *token* with a new key, keeping the old key valid for a grace period.

        The old key's ``expires_at`` is set to ``now + grace_hours`` so
        callers using the old token have time to switch.  The new key
        inherits the old key's role, TLP level, tenant, and label.

        Parameters
        ----------
        token : str
            The token to rotate.
        grace_hours : int
            Hours the old key remains valid after rotation.  Use ``0``
            for immediate expiry.

        Returns
        -------
        APIKey or None
            The newly generated replacement key, or ``None`` if the
            original token was not found.
        """
        old = self._keys.get(token)
        if old is None:
            return None
        from datetime import timedelta

        old.expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=grace_hours)
        return self.generate_key(
            tlp_level=old.tlp_level,
            label=old.label,
            role=old.role,
            tenant_id=old.tenant_id,
            metadata={**old.metadata, "rotated_from": old.token_hash},
        )

    def list_keys(self) -> list[APIKey]:
        """Return all registered keys."""
        return list(self._keys.values())

    def __len__(self) -> int:
        return len(self._keys)
