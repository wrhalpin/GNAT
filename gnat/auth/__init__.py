# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.auth
==========

Unified authentication for the GNAT-o-sphere.

Provides an :class:`AuthenticatedIdentity` protocol that both
:class:`~gnat.dissemination.api.auth.APIKey` and
:class:`~gnat.auth.oidc.OIDCIdentity` implement, plus an
:class:`~gnat.auth.oidc.OIDCProvider` for validating tokens issued
by external identity providers (Okta, Entra ID, etc.).

The OIDC layer is optional — install with ``pip install "gnat[sso]"``.
"""

from gnat.auth.identity import AuthenticatedIdentity, OIDCIdentity

__all__ = [
    "AuthenticatedIdentity",
    "OIDCIdentity",
]
