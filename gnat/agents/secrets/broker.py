from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .models import SecretGetRequest, SecretPutRequest, SecretRecord, SecretRef
from .policy import SecretsPolicy
from .providers.base import BaseSecretsProvider


class SecretsBroker:
    """Policy-enforcing front door for all secret storage operations."""

    def __init__(self, providers: Dict[str, BaseSecretsProvider], policy: Optional[SecretsPolicy] = None):
        self.providers = providers
        self.policy = policy or SecretsPolicy.default()

    def _provider_for(self, provider_name: str) -> BaseSecretsProvider:
        try:
            return self.providers[provider_name]
        except KeyError as exc:
            raise ValueError(f"unknown secrets provider: {provider_name}") from exc

    def get_secret(self, request: SecretGetRequest) -> SecretRecord:
        self.policy.authorize(
            action="get",
            ref=request.ref,
            purpose=request.purpose,
            requestor=request.requested_by,
            overwrite=False,
        )
        provider = self._provider_for(request.ref.provider)
        return provider.get_secret(request)

    def put_secret(self, request: SecretPutRequest) -> SecretRecord:
        self.policy.authorize(
            action="put",
            ref=request.ref,
            purpose=request.purpose,
            requestor=request.requested_by,
            overwrite=request.overwrite,
        )
        provider = self._provider_for(request.ref.provider)
        return provider.put_secret(request)

    def list_secret_refs(self, provider_name: str, prefix: str | None = None) -> List[SecretRef]:
        provider = self._provider_for(provider_name)
        return provider.list_secret_refs(prefix=prefix)

    def resolve_connector_secret(self, provider: str, vault: str, connector_name: str, secret_type: str, environment: str) -> SecretRef:
        return SecretRef(provider=provider, vault=vault, name=f"{environment}/{connector_name}/{secret_type}")
