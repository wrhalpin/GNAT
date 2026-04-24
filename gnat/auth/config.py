# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.auth.config
=================

Reads the ``[auth]`` INI section and constructs an :class:`OIDCProvider`
(when ``provider = oidc``).
"""

from __future__ import annotations

import json
import logging
from configparser import ConfigParser
from typing import Any

from gnat.analysis.tlp import TLPLevel

logger = logging.getLogger(__name__)


class AuthConfig:
    """
    Parse the ``[auth]`` section from a GNAT INI config.

    Parameters
    ----------
    parser : ConfigParser
        An already-loaded :class:`ConfigParser` instance.
    """

    SECTION = "auth"

    def __init__(self, parser: ConfigParser) -> None:
        self.provider: str = parser.get(self.SECTION, "provider", fallback="apikey")
        self.issuer: str = parser.get(self.SECTION, "issuer", fallback="")
        self.client_id: str = parser.get(self.SECTION, "client_id", fallback="")
        self.audience: str = parser.get(self.SECTION, "audience", fallback="")
        self.role_claim: str = parser.get(self.SECTION, "role_claim", fallback="groups")
        self.default_role: str = parser.get(self.SECTION, "default_role", fallback="viewer")
        self.tenant_claim: str = parser.get(
            self.SECTION, "tenant_claim", fallback="x_gnat_tenant"
        )

        tlp_raw = parser.get(self.SECTION, "default_tlp", fallback="amber")
        self.default_tlp: TLPLevel = TLPLevel(tlp_raw)

        role_map_raw = parser.get(self.SECTION, "role_map", fallback="{}")
        self.role_map: dict[str, str] = json.loads(role_map_raw)

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration to a plain dict."""
        return {
            "provider": self.provider,
            "issuer": self.issuer,
            "client_id": self.client_id,
            "audience": self.audience,
            "role_claim": self.role_claim,
            "role_map": self.role_map,
            "default_role": self.default_role,
            "default_tlp": self.default_tlp.value,
            "tenant_claim": self.tenant_claim,
        }
