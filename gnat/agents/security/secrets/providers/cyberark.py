# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.providers.cyberark
===================================================

Cyberark utilities and helpers for the GNAT toolkit.
"""
from __future__ import annotations

from ..exceptions import UnsupportedProviderAction
from ..models import (
    ProviderCapabilities,
    SecretLease,
    SecretMetadata,
    SecretRef,
    SecretValue,
    SecretVersionInfo,
    StoreSecretRequest,
)


class CyberArkProvider:
    """Capability-first placeholder for CyberArk integration."""

    name = "cyberark"

    def capabilities(self) -> ProviderCapabilities:
        """Capabilities."""
        return ProviderCapabilities(
            supports_read=True, supports_write=False, supports_rotation=True, supports_checkout=True
        )

    def resolve(self, ref: SecretRef) -> SecretValue:
        """Resolve the value from available sources."""
        raise UnsupportedProviderAction(
            "cyberark provider placeholder does not implement direct resolve"
        )

    def store(self, request: StoreSecretRequest) -> SecretVersionInfo:
        """Store."""
        raise UnsupportedProviderAction("cyberark provider placeholder does not implement store")

    def describe(self, ref: SecretRef) -> SecretMetadata:
        """Describe."""
        raise UnsupportedProviderAction("cyberark provider placeholder does not implement describe")

    def list_refs(self, prefix: str | None = None) -> list[SecretRef]:
        """List all refs objects."""
        return []

    def checkout(self, ref: SecretRef) -> SecretLease | None:
        """Checkout."""
        raise UnsupportedProviderAction("cyberark checkout is scaffolded but not implemented")
