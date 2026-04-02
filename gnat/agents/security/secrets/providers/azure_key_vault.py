from __future__ import annotations
from typing import List
from ..exceptions import SecretProviderError
from ..models import ProviderCapabilities, SecretLease, SecretMetadata, SecretRef, SecretValue, SecretVersionInfo, StoreSecretRequest

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
except Exception:
    DefaultAzureCredential = None
    SecretClient = None

class AzureKeyVaultProvider:
    name = "azurekeyvault"
    def __init__(self, credential=None) -> None:
        self.credential = credential or (DefaultAzureCredential() if DefaultAzureCredential else None)
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(supports_read=True, supports_write=True, supports_versioning=True, supports_tagging=True, supports_soft_delete=True)
    def _client(self, vault: str):
        if SecretClient is None or self.credential is None: raise SecretProviderError("azure dependencies not installed or credential unavailable")
        return SecretClient(vault_url=f"https://{vault}.vault.azure.net", credential=self.credential)
    def _secret_name(self, path: str) -> str:
        return path.replace("/", "--")
    def resolve(self, ref: SecretRef) -> SecretValue:
        if not ref.vault: raise SecretProviderError("azure key vault ref requires vault name")
        client = self._client(ref.vault)
        secret = client.get_secret(self._secret_name(ref.path), version=ref.version)
        metadata = SecretMetadata(path=ref.path, provider=self.name, vault=ref.vault, version=secret.properties.version, tags=secret.properties.tags or {}, created_at=secret.properties.created_on, updated_at=secret.properties.updated_on)
        return SecretValue(ref=SecretRef(provider=self.name, vault=ref.vault, path=ref.path, version=secret.properties.version), value=secret.value, metadata=metadata)
    def store(self, request: StoreSecretRequest) -> SecretVersionInfo:
        if not request.ref.vault: raise SecretProviderError("azure key vault ref requires vault name")
        client = self._client(request.ref.vault)
        secret = client.set_secret(self._secret_name(request.ref.path), request.value, tags=request.tags or None)
        return SecretVersionInfo(ref=SecretRef(provider=self.name, vault=request.ref.vault, path=request.ref.path, version=secret.properties.version), version=secret.properties.version, created_at=secret.properties.created_on, tags=secret.properties.tags or {})
    def describe(self, ref: SecretRef) -> SecretMetadata:
        return self.resolve(ref).metadata
    def list_refs(self, prefix: str | None = None) -> List[SecretRef]:
        return []
    def checkout(self, ref: SecretRef) -> SecretLease | None:
        return None
