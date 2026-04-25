# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.auth.oidc
===============

OIDC token validation for external identity providers.

Validates JWT bearer tokens against an OIDC-compliant IdP (Okta,
Entra ID, Keycloak, Auth0, etc.) using JWKS public key verification.

Requires the ``authlib`` package — install with::

    pip install "gnat[sso]"

Usage::

    from gnat.auth.oidc import OIDCProvider

    provider = OIDCProvider(
        issuer="https://your-tenant.okta.com",
        client_id="0oa...",
        audience="https://gnat.internal",
        role_claim="groups",
        role_map={"gnat-admins": "admin", "gnat-analysts": "analyst"},
    )

    identity = provider.validate_token(bearer_token)
    if identity is not None:
        print(f"Authenticated: {identity.subject_id} as {identity.role}")
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.tlp import TLPLevel
from gnat.auth.identity import OIDCIdentity

logger = logging.getLogger(__name__)

try:
    from authlib.jose import JsonWebKey, JsonWebToken
    from authlib.jose.errors import (
        BadSignatureError,
        DecodeError,
        ExpiredTokenError,
        InvalidClaimError,
    )

    _AUTHLIB_AVAILABLE = True
except ImportError:
    _AUTHLIB_AVAILABLE = False


def _require_authlib() -> None:
    if not _AUTHLIB_AVAILABLE:
        raise ImportError(
            "authlib is required for OIDC authentication. Install with: pip install 'gnat[sso]'"
        )


class OIDCProvider:
    """
    Validates OIDC JWT tokens against an external identity provider.

    Parameters
    ----------
    issuer : str
        OIDC issuer URL (e.g. ``"https://your-tenant.okta.com"``).
    client_id : str
        OAuth2 client ID registered with the IdP.
    audience : str
        Expected ``aud`` claim in the JWT.  Often the same as *client_id*.
    role_claim : str
        JWT claim that contains group/role information.  Common values:
        ``"groups"`` (Okta), ``"roles"`` (Entra ID), ``"realm_access"``
        (Keycloak).
    role_map : dict
        Maps IdP group/role strings to GNAT roles.  Example:
        ``{"gnat-admins": "admin", "gnat-analysts": "analyst"}``.
    default_role : str
        GNAT role when no matching group is found in the token.
    default_tlp : str
        TLP level for OIDC-authenticated users.
    tenant_claim : str or None
        JWT claim that carries the GNAT tenant ID.  ``None`` means
        OIDC users are not tenant-scoped.
    tlp_claim : str or None
        JWT claim for per-user TLP level override.
    jwks_cache_ttl : int
        Seconds to cache the JWKS key set.  Default 3600 (1 hour).
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        audience: str | None = None,
        role_claim: str = "groups",
        role_map: dict[str, str] | None = None,
        default_role: str = "viewer",
        default_tlp: str = "amber",
        tenant_claim: str | None = None,
        tlp_claim: str | None = None,
        jwks_cache_ttl: int = 3600,
    ) -> None:
        _require_authlib()
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        self._audience = audience or client_id
        self._role_claim = role_claim
        self._role_map = role_map or {}
        self._default_role = default_role
        self._default_tlp = default_tlp
        self._tenant_claim = tenant_claim
        self._tlp_claim = tlp_claim
        self._jwks_cache_ttl = jwks_cache_ttl
        self._jwks: Any = None
        self._jwks_fetched_at: float = 0
        self._jwt = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384"])

    def validate_token(self, token: str) -> OIDCIdentity | None:
        """
        Validate a JWT bearer token and return an :class:`OIDCIdentity`.

        Returns ``None`` if the token is invalid, expired, or cannot be
        verified against the IdP's JWKS.
        """
        jwks = self._get_jwks()
        if jwks is None:
            logger.warning("OIDCProvider: failed to fetch JWKS from %s", self._issuer)
            return None

        try:
            claims = self._jwt.decode(token, jwks)
            claims.validate()
        except ExpiredTokenError:
            logger.debug("OIDCProvider: token expired")
            return None
        except (BadSignatureError, DecodeError) as exc:
            logger.debug("OIDCProvider: token validation failed: %s", exc)
            return None
        except InvalidClaimError as exc:
            logger.debug("OIDCProvider: invalid claim: %s", exc)
            return None
        except Exception as exc:
            logger.warning("OIDCProvider: unexpected error validating token: %s", exc)
            return None

        return self._claims_to_identity(dict(claims))

    def _claims_to_identity(self, claims: dict[str, Any]) -> OIDCIdentity:
        sub = str(claims.get("sub", ""))
        email = str(claims.get("email", claims.get("preferred_username", "")))
        issuer = str(claims.get("iss", self._issuer))

        groups = self._extract_groups(claims)
        role = self._resolve_role(groups)
        tenant_id = self._extract_tenant(claims)
        tlp_level = self._extract_tlp(claims)

        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        else:
            expires_at = datetime.now(tz=timezone.utc)

        return OIDCIdentity(
            subject_id=sub,
            email=email,
            role=role,
            tenant_id=tenant_id,
            tlp_level=tlp_level,
            groups=groups,
            issuer=issuer,
            expires_at=expires_at,
            raw_claims=claims,
        )

    def _extract_groups(self, claims: dict[str, Any]) -> list[str]:
        raw = claims.get(self._role_claim, [])
        if isinstance(raw, str):
            return [raw]
        if isinstance(raw, list):
            return [str(g) for g in raw]
        if isinstance(raw, dict):
            roles = raw.get("roles", [])
            if isinstance(roles, list):
                return [str(r) for r in roles]
        return []

    def _resolve_role(self, groups: list[str]) -> str:
        role_priority = {"admin": 5, "reviewer": 4, "senior_analyst": 3, "analyst": 2, "viewer": 1}
        best_role = self._default_role
        best_priority = role_priority.get(best_role, 0)

        for group in groups:
            mapped = self._role_map.get(group)
            if mapped and role_priority.get(mapped, 0) > best_priority:
                best_role = mapped
                best_priority = role_priority.get(mapped, 0)
        return best_role

    def _extract_tenant(self, claims: dict[str, Any]) -> str | None:
        if self._tenant_claim is None:
            return None
        val = claims.get(self._tenant_claim)
        return str(val) if val is not None else None

    def _extract_tlp(self, claims: dict[str, Any]) -> TLPLevel:
        if self._tlp_claim:
            val = claims.get(self._tlp_claim)
            if val:
                try:
                    return TLPLevel(str(val).lower())
                except ValueError:
                    pass
        try:
            return TLPLevel(self._default_tlp.lower())
        except ValueError:
            return TLPLevel.AMBER

    def _get_jwks(self) -> Any:
        now = time.monotonic()
        if self._jwks is not None and (now - self._jwks_fetched_at) < self._jwks_cache_ttl:
            return self._jwks

        try:
            jwks_data = self._fetch_jwks()
            self._jwks = JsonWebKey.import_key_set(jwks_data)
            self._jwks_fetched_at = now
            logger.debug("OIDCProvider: refreshed JWKS from %s", self._issuer)
            return self._jwks
        except Exception as exc:
            logger.warning("OIDCProvider: JWKS fetch failed: %s", exc)
            return self._jwks

    def _fetch_jwks(self) -> dict[str, Any]:
        import urllib3

        http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=10, read=10))

        oidc_url = f"{self._issuer}/.well-known/openid-configuration"
        resp = http.request("GET", oidc_url)
        if resp.status != 200:
            raise RuntimeError(f"OIDC discovery failed: HTTP {resp.status}")
        config = json.loads(resp.data.decode("utf-8"))

        jwks_uri = config.get("jwks_uri")
        if not jwks_uri:
            raise RuntimeError("No jwks_uri in OIDC discovery document")

        resp = http.request("GET", jwks_uri)
        if resp.status != 200:
            raise RuntimeError(f"JWKS fetch failed: HTTP {resp.status}")
        return json.loads(resp.data.decode("utf-8"))


def create_oidc_provider_from_config(config: dict[str, str]) -> OIDCProvider | None:
    """
    Create an :class:`OIDCProvider` from an ``[auth]`` INI config section.

    Returns ``None`` if OIDC is not configured (no ``issuer`` key).
    """
    issuer = config.get("issuer", "").strip()
    if not issuer:
        return None

    client_id = config.get("client_id", "").strip()
    if not client_id:
        return None

    role_map_raw = config.get("role_map", "{}")
    try:
        role_map = json.loads(role_map_raw)
    except (json.JSONDecodeError, TypeError):
        role_map = {}

    return OIDCProvider(
        issuer=issuer,
        client_id=client_id,
        audience=config.get("audience", "").strip() or None,
        role_claim=config.get("role_claim", "groups"),
        role_map=role_map,
        default_role=config.get("default_role", "viewer"),
        default_tlp=config.get("default_tlp", "amber"),
        tenant_claim=config.get("tenant_claim") or None,
        tlp_claim=config.get("tlp_claim") or None,
    )
