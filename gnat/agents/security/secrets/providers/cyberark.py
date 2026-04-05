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
        return ProviderCapabilities(
            supports_read=True, supports_write=False, supports_rotation=True, supports_checkout=True
        )

    def resolve(self, ref: SecretRef) -> SecretValue:
        raise UnsupportedProviderAction(
            "cyberark provider placeholder does not implement direct resolve"
        )

    def store(self, request: StoreSecretRequest) -> SecretVersionInfo:
        raise UnsupportedProviderAction("cyberark provider placeholder does not implement store")

    def describe(self, ref: SecretRef) -> SecretMetadata:
        raise UnsupportedProviderAction("cyberark provider placeholder does not implement describe")

    def list_refs(self, prefix: str | None = None) -> list[SecretRef]:
        return []

    def checkout(self, ref: SecretRef) -> SecretLease | None:
        raise UnsupportedProviderAction("cyberark checkout is scaffolded but not implemented")
