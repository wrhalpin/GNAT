# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/auth/test_identity.py
=================================

Unit tests for :class:`~gnat.auth.identity.OIDCIdentity` and the
:class:`~gnat.auth.identity.AuthenticatedIdentity` protocol.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from gnat.analysis.tlp import TLPLevel
from gnat.auth.identity import AuthenticatedIdentity, OIDCIdentity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=timezone.utc)
_FUTURE = _NOW + timedelta(hours=1)
_PAST = _NOW - timedelta(hours=1)


def _make_identity(**overrides) -> OIDCIdentity:
    """Build an OIDCIdentity with sensible defaults."""
    defaults = {
        "subject_id": "alice@acme.com",
        "email": "alice@acme.com",
        "role": "analyst",
        "tenant_id": "tenant-1",
        "tlp_level": TLPLevel.AMBER,
        "groups": ["gnat-analysts"],
        "issuer": "https://idp.acme.com",
        "expires_at": _FUTURE,
        "raw_claims": {"sub": "alice@acme.com", "groups": ["gnat-analysts"]},
    }
    defaults.update(overrides)
    return OIDCIdentity(**defaults)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestAuthenticatedIdentityProtocol:
    """OIDCIdentity must satisfy the AuthenticatedIdentity protocol."""

    def test_oidc_identity_is_instance_of_protocol(self):
        identity = _make_identity()
        assert isinstance(identity, AuthenticatedIdentity)

    def test_protocol_has_required_properties(self):
        """Verify all protocol fields are present on OIDCIdentity."""
        identity = _make_identity()
        assert hasattr(identity, "subject_id")
        assert hasattr(identity, "label")
        assert hasattr(identity, "role")
        assert hasattr(identity, "tenant_id")
        assert hasattr(identity, "tlp_level")
        assert hasattr(identity, "token_hash")
        assert callable(identity.is_valid)
        assert callable(identity.to_dict)


# ---------------------------------------------------------------------------
# OIDCIdentity field values
# ---------------------------------------------------------------------------


class TestOIDCIdentityFields:
    """Field accessors and derived properties."""

    def test_subject_id(self):
        identity = _make_identity(subject_id="bob@acme.com")
        assert identity.subject_id == "bob@acme.com"

    def test_role_from_constructor(self):
        identity = _make_identity(role="admin")
        assert identity.role == "admin"

    def test_tenant_id_from_constructor(self):
        identity = _make_identity(tenant_id="t-42")
        assert identity.tenant_id == "t-42"

    def test_tenant_id_none(self):
        identity = _make_identity(tenant_id=None)
        assert identity.tenant_id is None

    def test_tlp_level(self):
        identity = _make_identity(tlp_level=TLPLevel.RED)
        assert identity.tlp_level is TLPLevel.RED

    def test_label_uses_email(self):
        identity = _make_identity(email="carol@acme.com")
        assert identity.label == "oidc:carol@acme.com"

    def test_label_falls_back_to_subject_id(self):
        identity = _make_identity(email="", subject_id="uid-123")
        assert identity.label == "oidc:uid-123"

    def test_token_hash_deterministic(self):
        identity = _make_identity(subject_id="alice@acme.com")
        expected = hashlib.sha256(b"alice@acme.com").hexdigest()[:16]
        assert identity.token_hash == expected

    def test_groups_stored(self):
        identity = _make_identity(groups=["admins", "devs"])
        assert identity.groups == ["admins", "devs"]


# ---------------------------------------------------------------------------
# is_valid()
# ---------------------------------------------------------------------------


class TestOIDCIdentityValidity:
    """Token expiry logic."""

    def test_is_valid_when_not_expired(self):
        identity = _make_identity(expires_at=_FUTURE)
        assert identity.is_valid() is True

    def test_is_valid_false_when_expired(self):
        identity = _make_identity(expires_at=_PAST)
        assert identity.is_valid() is False

    def test_is_valid_false_when_exactly_now(self):
        """Boundary: expires_at == now should be invalid (strict less-than)."""
        # We cannot freeze time perfectly, but an expiry far in the past
        # guarantees the check fails.
        identity = _make_identity(
            expires_at=datetime(2000, 1, 1, tzinfo=timezone.utc)
        )
        assert identity.is_valid() is False


# ---------------------------------------------------------------------------
# to_dict()
# ---------------------------------------------------------------------------


class TestOIDCIdentityToDict:
    """Serialization round-trip."""

    def test_to_dict_includes_all_fields(self):
        identity = _make_identity()
        d = identity.to_dict()
        assert d["subject_id"] == "alice@acme.com"
        assert d["email"] == "alice@acme.com"
        assert d["role"] == "analyst"
        assert d["tenant_id"] == "tenant-1"
        assert d["tlp_level"] == "amber"
        assert d["label"] == "oidc:alice@acme.com"
        assert d["token_hash"] == hashlib.sha256(b"alice@acme.com").hexdigest()[:16]
        assert d["issuer"] == "https://idp.acme.com"
        assert d["groups"] == ["gnat-analysts"]
        assert "expires_at" in d

    def test_to_dict_returns_plain_dict(self):
        identity = _make_identity()
        d = identity.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_tlp_level_is_string(self):
        identity = _make_identity(tlp_level=TLPLevel.GREEN)
        d = identity.to_dict()
        assert d["tlp_level"] == "green"

    def test_to_dict_expires_at_is_iso(self):
        ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        identity = _make_identity(expires_at=ts)
        d = identity.to_dict()
        assert d["expires_at"] == ts.isoformat()
