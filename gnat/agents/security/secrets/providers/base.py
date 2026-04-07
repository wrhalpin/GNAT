# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
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
    name: str

    def capabilities(self) -> ProviderCapabilities: ...
    def resolve(self, ref: SecretRef) -> SecretValue: ...
    def store(self, request: StoreSecretRequest) -> SecretVersionInfo: ...
    def describe(self, ref: SecretRef) -> SecretMetadata: ...
    def list_refs(self, prefix: str | None = None) -> list[SecretRef]: ...
    def checkout(self, ref: SecretRef) -> SecretLease | None: ...
