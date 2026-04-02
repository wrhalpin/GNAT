from __future__ import annotations

from typing import List

from ..exceptions import SecretNotFoundError, SecretProviderError
from ..models import SecretGetRequest, SecretPutRequest, SecretRecord, SecretRef
from .base import BaseSecretsProvider


class AzureKeyVaultProvider(BaseSecretsProvider):
    """Azure Key Vault provider for Phase A.

    This implementation is intentionally thin: enough to read and write secrets
    with DefaultAzureCredential, while keeping the broker/provider boundary easy
    to evolve for CyberArk and rotation later.
    """

    provider_name = "azurekeyvault"

    def __init__(self, vault_url: str, credential=None, client=None):
        self.vault_url = vault_url.rstrip("/")
        self._credential = credential
        self._client = client

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:
            raise SecretProviderError(
                "Azure SDK is not installed. Add azure-identity and azure-keyvault-secrets."
            ) from exc
        credential = self._credential or DefaultAzureCredential()
        self._client = SecretClient(vault_url=self.vault_url, credential=credential)
        return self._client

    @staticmethod
    def _to_secret_name(path_name: str) -> str:
        return path_name.replace("/", "--")

    @staticmethod
    def _to_path_name(secret_name: str) -> str:
        return secret_name.replace("--", "/")

    def get_secret(self, request: SecretGetRequest) -> SecretRecord:
        client = self._get_client()
        secret_name = self._to_secret_name(request.ref.name)
        try:
            bundle = client.get_secret(secret_name, version=request.ref.version)
        except Exception as exc:
            message = str(exc).lower()
            if "not found" in message or "secret" in message and "was not found" in message:
                raise SecretNotFoundError(f"secret not found: {request.ref.to_uri()}") from exc
            raise SecretProviderError(f"azure key vault get failed for {request.ref.name}: {exc}") from exc
        resolved_ref = SecretRef(
            provider=self.provider_name,
            vault=request.ref.vault,
            name=request.ref.name,
            version=getattr(bundle.properties, "version", None),
        )
        value = bundle.value if request.include_value else None
        return SecretRecord(
            ref=resolved_ref,
            value=value,
            content_type=getattr(bundle.properties, "content_type", None),
            enabled=getattr(bundle.properties, "enabled", True),
            tags=dict(getattr(bundle.properties, "tags", {}) or {}),
            provider_metadata={
                "vault_url": self.vault_url,
                "secret_name": secret_name,
                "recoverable_days": getattr(bundle.properties, "recoverable_days", None),
            },
        )

    def put_secret(self, request: SecretPutRequest) -> SecretRecord:
        client = self._get_client()
        secret_name = self._to_secret_name(request.ref.name)
        try:
            bundle = client.set_secret(
                secret_name,
                request.value,
                content_type=request.content_type,
                tags=request.tags,
                enabled=request.enabled,
            )
        except Exception as exc:
            raise SecretProviderError(f"azure key vault put failed for {request.ref.name}: {exc}") from exc
        resolved_ref = SecretRef(
            provider=self.provider_name,
            vault=request.ref.vault,
            name=request.ref.name,
            version=getattr(bundle.properties, "version", None),
        )
        return SecretRecord(
            ref=resolved_ref,
            value=request.value,
            content_type=getattr(bundle.properties, "content_type", None),
            enabled=getattr(bundle.properties, "enabled", True),
            tags=dict(getattr(bundle.properties, "tags", {}) or {}),
            provider_metadata={
                "vault_url": self.vault_url,
                "secret_name": secret_name,
            },
        )

    def list_secret_refs(self, prefix: str | None = None) -> List[SecretRef]:
        client = self._get_client()
        refs: List[SecretRef] = []
        try:
            for properties in client.list_properties_of_secrets():
                path_name = self._to_path_name(properties.name)
                if prefix and not path_name.startswith(prefix):
                    continue
                refs.append(
                    SecretRef(
                        provider=self.provider_name,
                        vault=self.vault_url,
                        name=path_name,
                        version=None,
                    )
                )
        except Exception as exc:
            raise SecretProviderError(f"azure key vault listing failed: {exc}") from exc
        return refs
