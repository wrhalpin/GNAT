from __future__ import annotations

from ..exceptions import SecretProviderError
from ..models import SecretGetRequest, SecretPutRequest, SecretRecord, SecretRef
from .base import BaseSecretsProvider


class CyberArkProvider(BaseSecretsProvider):
    """Placeholder for CyberArk-backed secret storage.

    CyberArk support will likely require a slightly richer provider contract than
    Azure because some deployments focus on account retrieval/check-out semantics,
    platform policies, and rotation orchestration rather than simple key-value
    storage. This placeholder is included now so the broker design keeps that
    future shape in mind.
    """

    provider_name = "cyberark"

    def __init__(self, *args, **kwargs):
        self.config = kwargs

    def get_secret(self, request: SecretGetRequest) -> SecretRecord:
        raise SecretProviderError("CyberArk provider scaffold only: implementation pending")

    def put_secret(self, request: SecretPutRequest) -> SecretRecord:
        raise SecretProviderError("CyberArk provider scaffold only: implementation pending")

    def list_secret_refs(self, prefix: str | None = None) -> list[SecretRef]:
        raise SecretProviderError("CyberArk provider scaffold only: implementation pending")
