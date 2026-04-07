# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from ..exceptions import SecretProviderError
from ..models import (
    ProviderCapabilities,
    SecretLease,
    SecretMetadata,
    SecretRef,
    SecretValue,
    SecretVersionInfo,
    StoreSecretRequest,
)


class MemorySecretProvider:
    name = "memory"

    def __init__(self) -> None:
        self._store: dict[tuple[str | None, str], dict[str, object]] = {}

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supports_read=True, supports_write=True, supports_versioning=True, supports_tagging=True
        )

    def resolve(self, ref: SecretRef) -> SecretValue:
        record = self._store.get((ref.vault, ref.path))
        if not record:
            raise SecretProviderError(f"secret not found: {ref.to_uri()}")
        metadata = SecretMetadata(
            path=ref.path,
            provider=self.name,
            vault=ref.vault,
            version=record["version"],
            tags=dict(record.get("tags", {})),
            created_at=record.get("created_at"),
            updated_at=record.get("updated_at"),
        )
        return SecretValue(
            ref=replace(ref, version=record["version"]), value=record["value"], metadata=metadata
        )

    def store(self, request: StoreSecretRequest) -> SecretVersionInfo:
        now = datetime.utcnow()
        current = self._store.get((request.ref.vault, request.ref.path))
        if current and not request.allow_overwrite:
            raise SecretProviderError(
                f"secret exists and overwrite disabled: {request.ref.to_uri()}"
            )
        version = str(int(current["version"]) + 1) if current else "1"
        self._store[(request.ref.vault, request.ref.path)] = {
            "value": request.value,
            "version": version,
            "tags": dict(request.tags),
            "created_at": current.get("created_at") if current else now,
            "updated_at": now,
        }
        return SecretVersionInfo(
            ref=replace(request.ref, version=version),
            version=version,
            created_at=now,
            tags=dict(request.tags),
        )

    def describe(self, ref: SecretRef) -> SecretMetadata:
        return self.resolve(ref).metadata

    def list_refs(self, prefix: str | None = None) -> list[SecretRef]:
        out = []
        for (vault, path), record in self._store.items():
            if prefix and not path.startswith(prefix):
                continue
            out.append(
                SecretRef(provider=self.name, vault=vault, path=path, version=record["version"])
            )
        return out

    def checkout(self, ref: SecretRef) -> SecretLease | None:
        return None
