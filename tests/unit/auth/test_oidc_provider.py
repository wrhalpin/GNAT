# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/auth/test_oidc_provider.py
======================================

Unit tests for :class:`~gnat.auth.oidc.OIDCProvider`.

The JWKS endpoint and JWT validation are fully mocked — no real network
traffic or IdP is required.  The module is skipped if ``authlib`` is not
installed.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# Skip entire module when authlib is not available.
authlib = pytest.importorskip("authlib")

from authlib.jose import JsonWebKey, JsonWebToken  # noqa: E402
from authlib.jose.errors import (  # noqa: E402
    BadSignatureError,
    DecodeError,
    ExpiredTokenError,
)

from gnat.analysis.tlp import TLPLevel  # noqa: E402
from gnat.auth.identity import OIDCIdentity  # noqa: E402
from gnat.auth.oidc import OIDCProvider  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "test-client-id"
_AUDIENCE = "https://gnat.internal"

# RSA key pair for signing test JWTs.
_RSA_KEY = JsonWebKey.generate_key("RSA", 2048, is_private=True)
_JWKS = {"keys": [_RSA_KEY.as_dict(is_private=False)]}

_ROLE_MAP = {
    "gnat-admins": "admin",
    "gnat-analysts": "analyst",
    "gnat-viewers": "viewer",
}


def _make_jwt(claims: dict, key=None) -> str:
    """Sign a JWT with the test RSA key."""
    header = {"alg": "RS256"}
    tok = JsonWebToken(["RS256"])
    key = key or _RSA_KEY
    return tok.encode(header, claims, key).decode("utf-8")


def _make_provider(**overrides) -> OIDCProvider:
    """Build an OIDCProvider with sensible test defaults."""
    kwargs = {
        "issuer": _ISSUER,
        "client_id": _CLIENT_ID,
        "audience": _AUDIENCE,
        "role_claim": "groups",
        "role_map": _ROLE_MAP,
        "default_role": "viewer",
        "default_tlp": "amber",
        "tenant_claim": "x_gnat_tenant",
    }
    kwargs.update(overrides)
    return OIDCProvider(**kwargs)


def _patch_jwks(provider: OIDCProvider, jwks: dict | None = None) -> None:
    """Inject a cached JWKS into the provider so no HTTP is needed."""
    key_set = JsonWebKey.import_key_set(jwks or _JWKS)
    provider._jwks = key_set
    provider._jwks_fetched_at = time.monotonic()


def _valid_claims(**overrides) -> dict:
    """Build a minimal valid JWT payload."""
    now = int(datetime.now(tz=timezone.utc).timestamp())
    defaults = {
        "iss": _ISSUER,
        "sub": "alice@acme.com",
        "aud": _AUDIENCE,
        "email": "alice@acme.com",
        "iat": now,
        "exp": now + 3600,
        "groups": ["gnat-analysts"],
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Valid token
# ---------------------------------------------------------------------------


class TestValidateTokenValid:
    """Happy-path: a correctly signed, non-expired JWT."""

    def test_returns_oidc_identity(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims())
        identity = provider.validate_token(token)
        assert identity is not None
        assert isinstance(identity, OIDCIdentity)

    def test_subject_id_from_sub_claim(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(sub="bob@acme.com"))
        identity = provider.validate_token(token)
        assert identity.subject_id == "bob@acme.com"

    def test_email_from_claim(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(email="carol@acme.com"))
        identity = provider.validate_token(token)
        assert identity.email == "carol@acme.com"

    def test_issuer_from_claim(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims())
        identity = provider.validate_token(token)
        assert identity.issuer == _ISSUER


# ---------------------------------------------------------------------------
# Expired / invalid tokens
# ---------------------------------------------------------------------------


class TestValidateTokenInvalid:
    """Expired and tampered tokens must return None."""

    def test_expired_jwt_returns_none(self):
        provider = _make_provider()
        _patch_jwks(provider)
        past = int((datetime.now(tz=timezone.utc) - timedelta(hours=2)).timestamp())
        token = _make_jwt(_valid_claims(exp=past, iat=past - 3600))
        identity = provider.validate_token(token)
        assert identity is None

    def test_invalid_signature_returns_none(self):
        provider = _make_provider()
        _patch_jwks(provider)
        # Sign with a different key that is NOT in the JWKS.
        other_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        token = _make_jwt(_valid_claims(), key=other_key)
        identity = provider.validate_token(token)
        assert identity is None

    def test_garbage_token_returns_none(self):
        provider = _make_provider()
        _patch_jwks(provider)
        identity = provider.validate_token("not.a.jwt")
        assert identity is None

    def test_empty_token_returns_none(self):
        provider = _make_provider()
        _patch_jwks(provider)
        identity = provider.validate_token("")
        assert identity is None


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------


class TestRoleMapping:
    """JWT groups claim mapped via role_map config."""

    def test_group_mapped_to_role(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(groups=["gnat-analysts"]))
        identity = provider.validate_token(token)
        assert identity.role == "analyst"

    def test_admin_group_mapped(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(groups=["gnat-admins"]))
        identity = provider.validate_token(token)
        assert identity.role == "admin"

    def test_multiple_groups_highest_role_wins(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(groups=["gnat-viewers", "gnat-admins"]))
        identity = provider.validate_token(token)
        assert identity.role == "admin"

    def test_default_role_when_no_matching_group(self):
        provider = _make_provider(default_role="viewer")
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(groups=["unrelated-group"]))
        identity = provider.validate_token(token)
        assert identity.role == "viewer"

    def test_default_role_when_no_groups_claim(self):
        provider = _make_provider(default_role="viewer")
        _patch_jwks(provider)
        claims = _valid_claims()
        del claims["groups"]
        token = _make_jwt(claims)
        identity = provider.validate_token(token)
        assert identity.role == "viewer"

    def test_groups_stored_on_identity(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(groups=["gnat-analysts", "extra"]))
        identity = provider.validate_token(token)
        assert "gnat-analysts" in identity.groups
        assert "extra" in identity.groups


# ---------------------------------------------------------------------------
# Tenant extraction
# ---------------------------------------------------------------------------


class TestTenantExtraction:
    """Tenant ID from a custom JWT claim."""

    def test_tenant_from_custom_claim(self):
        provider = _make_provider(tenant_claim="x_gnat_tenant")
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(x_gnat_tenant="tenant-42"))
        identity = provider.validate_token(token)
        assert identity.tenant_id == "tenant-42"

    def test_tenant_none_when_claim_missing(self):
        provider = _make_provider(tenant_claim="x_gnat_tenant")
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims())
        identity = provider.validate_token(token)
        assert identity.tenant_id is None

    def test_tenant_none_when_no_tenant_claim_configured(self):
        provider = _make_provider(tenant_claim=None)
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims(x_gnat_tenant="should-be-ignored"))
        identity = provider.validate_token(token)
        assert identity.tenant_id is None


# ---------------------------------------------------------------------------
# TLP level
# ---------------------------------------------------------------------------


class TestTLPLevel:
    """Default TLP assignment for OIDC users."""

    def test_default_tlp_amber(self):
        provider = _make_provider(default_tlp="amber")
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims())
        identity = provider.validate_token(token)
        assert identity.tlp_level is TLPLevel.AMBER

    def test_default_tlp_green(self):
        provider = _make_provider(default_tlp="green")
        _patch_jwks(provider)
        token = _make_jwt(_valid_claims())
        identity = provider.validate_token(token)
        assert identity.tlp_level is TLPLevel.GREEN


# ---------------------------------------------------------------------------
# JWKS fetching
# ---------------------------------------------------------------------------


class TestJWKSFetching:
    """JWKS discovery via .well-known/openid-configuration."""

    def test_fetches_jwks_via_discovery(self):
        provider = _make_provider()
        # No cached JWKS — force a fetch.
        oidc_config = json.dumps(
            {"jwks_uri": f"{_ISSUER}/oauth2/v1/keys"}
        ).encode()
        jwks_body = json.dumps(_JWKS).encode()

        with patch("urllib3.PoolManager") as MockPM:
            mock_http = MockPM.return_value
            resp_oidc = MagicMock()
            resp_oidc.status = 200
            resp_oidc.data = oidc_config
            resp_jwks = MagicMock()
            resp_jwks.status = 200
            resp_jwks.data = jwks_body
            mock_http.request.side_effect = [resp_oidc, resp_jwks]

            token = _make_jwt(_valid_claims())
            identity = provider.validate_token(token)

        assert identity is not None
        assert identity.subject_id == "alice@acme.com"

    def test_jwks_cache_reuse(self):
        provider = _make_provider()
        _patch_jwks(provider)
        token1 = _make_jwt(_valid_claims(sub="user-1"))
        token2 = _make_jwt(_valid_claims(sub="user-2"))

        id1 = provider.validate_token(token1)
        id2 = provider.validate_token(token2)

        assert id1.subject_id == "user-1"
        assert id2.subject_id == "user-2"
        # JWKS was cached from the _patch_jwks call — no HTTP should
        # have been triggered.


# ---------------------------------------------------------------------------
# Constructor guard
# ---------------------------------------------------------------------------


class TestAuthlibGuard:
    """OIDCProvider raises ImportError when authlib is unavailable."""

    def test_import_error_without_authlib(self):
        with patch("gnat.auth.oidc._AUTHLIB_AVAILABLE", False):
            with pytest.raises(ImportError, match="authlib"):
                OIDCProvider(
                    issuer=_ISSUER,
                    client_id=_CLIENT_ID,
                )
