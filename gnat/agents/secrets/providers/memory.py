from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

from ..exceptions import SecretNotFoundError, SecretProviderError
from ..models import SecretGetRequest, SecretPutRequest, SecretRecord, SecretRef
from .base import BaseSecretsProvider


class InMemorySecretsProvider(BaseSecretsProvider):
    provider_name = "memory"

    def __init__(self) -> None:
        self._records: dict[str, SecretRecord] = {}

    def _key(self, ref: SecretRef) -> str:
        return f"{ref.vault}:{ref.name}:{ref.version or 'latest'}"

    def get_secret(self, request: SecretGetRequest) -> SecretRecord:
        key = self._key(request.ref)
        if key not in self._records:
            latest = f"{request.ref.vault}:{request.ref.name}:latest"
            key = latest if latest in self._records else key
        record = self._records.get(key)
        if record is None:
            raise SecretNotFoundError(f"secret not found: {request.ref.to_uri()}")
        result = deepcopy(record)
        if not request.include_value:
            result.value = None
        return result

    def put_secret(self, request: SecretPutRequest) -> SecretRecord:
        key = self._key(request.ref)
        if key in self._records and not request.overwrite:
            raise SecretProviderError(f"secret already exists: {request.ref.to_uri()}")
        now = datetime.now(timezone.utc)
        record = SecretRecord(
            ref=request.ref,
            value=request.value,
            content_type=request.content_type,
            enabled=request.enabled,
            tags=deepcopy(request.tags),
            created_at=now,
            updated_at=now,
            provider_metadata={"provider": self.provider_name},
        )
        self._records[key] = record
        latest_ref = SecretRef(provider=request.ref.provider, vault=request.ref.vault, name=request.ref.name, version=None)
        self._records[f"{latest_ref.vault}:{latest_ref.name}:latest"] = deepcopy(record)
        self._records[f"{latest_ref.vault}:{latest_ref.name}:latest"].ref = latest_ref
        return deepcopy(record)

    def list_secret_refs(self, prefix: str | None = None) -> list[SecretRef]:
        refs = []
        seen = set()
        for record in self._records.values():
            ref = record.ref
            if ref.version is not None:
                continue
            if prefix and not ref.name.startswith(prefix):
                continue
            uri = ref.to_uri()
            if uri in seen:
                continue
            seen.add(uri)
            refs.append(deepcopy(ref))
        return sorted(refs, key=lambda item: item.name)
