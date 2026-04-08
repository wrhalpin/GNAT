# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.providers.base
=============================================

Protocol definition for secret provider backends used by the GNAT secrets
hygiene sub-agent.  Any class satisfying :class:`SecretProvider` can be
registered as a backend for resolving, storing, and managing secrets.
"""
from __future__ import annotations

from typing import Protocol

from ..models import (
    ProviderCapabilities,
    SecretLease,
    SecretMetadata,
    SecretRef,
    SecretValue,
    SecretVersionInfo,
    StoreSecretRequest,
)


class SecretProvider(Protocol):
    """Protocol for pluggable secret provider backends.

    Implementations must satisfy all method signatures defined here.
    Each provider exposes a ``name`` attribute identifying the backend
    (e.g. ``"env"``, ``"vault"``, ``"aws-secrets-manager"``).
    """

    name: str

    def capabilities(self) -> ProviderCapabilities:
        """Return the feature flags supported by this provider."""
        ...

    def resolve(self, ref: SecretRef) -> SecretValue:
        """Resolve a secret reference to its plaintext value."""
        ...

    def store(self, request: StoreSecretRequest) -> SecretVersionInfo:
        """Store a secret and return version metadata."""
        ...

    def describe(self, ref: SecretRef) -> SecretMetadata:
        """Return metadata for the given secret reference."""
        ...

    def list_refs(self, prefix: str | None = None) -> list[SecretRef]:
        """List all secret references, optionally filtered by prefix."""
        ...

    def checkout(self, ref: SecretRef) -> SecretLease | None:
        """Check out a secret lease, returning None if unavailable."""
        ...
