# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.resolver
=========================================

Resolver utilities and helpers for the GNAT toolkit.
"""

from __future__ import annotations

from typing import Any

from .broker import SecretsBroker


class ConnectorConfigResolver:
    """Configuration container for connector resolver."""

    def __init__(self, broker: SecretsBroker) -> None:
        """Initialize ConnectorConfigResolver."""
        self.broker = broker

    def resolve_credentials(
        self, config: dict[str, Any], *, caller: str = "runtime"
    ) -> dict[str, Any]:
        """Resolve credentials from available sources."""
        resolved = dict(config)
        creds = dict(resolved.get("credentials", {}))
        for k, v in list(creds.items()):
            if isinstance(v, dict) and "secret_ref" in v:
                ref = self.broker.parse_ref(v["secret_ref"])
                creds[k] = self.broker.resolve(ref, caller=caller).value
        resolved["credentials"] = creds
        return resolved
