from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import SecretGetRequest, SecretPutRequest, SecretRecord, SecretRef


class BaseSecretsProvider(ABC):
    provider_name: str

    @abstractmethod
    def get_secret(self, request: SecretGetRequest) -> SecretRecord:
        raise NotImplementedError

    @abstractmethod
    def put_secret(self, request: SecretPutRequest) -> SecretRecord:
        raise NotImplementedError

    @abstractmethod
    def list_secret_refs(self, prefix: str | None = None) -> list[SecretRef]:
        raise NotImplementedError
