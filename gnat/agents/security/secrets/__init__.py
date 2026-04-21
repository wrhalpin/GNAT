# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets
================================

Public API surface for the ``gnat.agents.security.secrets`` package.
"""

from .broker import SecretsBroker
from .models import (
    AuditEvent,
    ProviderCapabilities,
    SecretLease,
    SecretMetadata,
    SecretRef,
    SecretValue,
    SecretVersionInfo,
    StoreSecretRequest,
)

__all__ = [
    "SecretsBroker",
    "AuditEvent",
    "ProviderCapabilities",
    "SecretLease",
    "SecretMetadata",
    "SecretRef",
    "SecretValue",
    "SecretVersionInfo",
    "StoreSecretRequest",
]
