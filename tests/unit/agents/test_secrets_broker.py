# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/agents/test_secrets_broker.py
============================================

Tests for :class:`SecretsBroker` under ``gnat.agents.security.secrets``.

The previous version of this file imported from a non-existent path
(``gnat.agents.secrets.*``) with classes that were never implemented
(``SecretsBroker.put_secret`` / ``SecretGetRequest`` / ``SecretPurpose``
/ ``SecretsPolicy``).  This rewrite exercises the real public API:
:class:`SecretsBroker`, :class:`SecretPolicyEngine`, :class:`PolicyRule`,
and :class:`MemorySecretProvider`.
"""

from __future__ import annotations

import pytest

from gnat.agents.security.secrets.broker import SecretsBroker
from gnat.agents.security.secrets.exceptions import (
    SecretPolicyError,
    SecretProviderError,
    UnsupportedProviderAction,
)
from gnat.agents.security.secrets.models import (
    SecretRef,
    SecretValue,
    StoreSecretRequest,
)
from gnat.agents.security.secrets.policy import PolicyRule, SecretPolicyEngine
from gnat.agents.security.secrets.providers.memory import MemorySecretProvider

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _permissive_engine() -> SecretPolicyEngine:
    """Return a policy engine that allows store+resolve for 'developer' on dev/*."""
    return SecretPolicyEngine(
        rules=[
            PolicyRule(
                path_prefix="dev/",
                actions=("resolve", "store"),
                allowed_callers=("developer", "ci"),
                overwrite=True,
            ),
            PolicyRule(
                path_prefix="prod/",
                actions=("resolve",),
                allowed_callers=("runtime",),
            ),
        ]
    )


def _build_broker() -> SecretsBroker:
    """Return a broker pre-loaded with the memory provider + permissive policy."""
    return SecretsBroker(
        providers={"memory": MemorySecretProvider()},
        policy=_permissive_engine(),
    )


# ---------------------------------------------------------------------------
# Core store + resolve flow
# ---------------------------------------------------------------------------


class TestStoreResolveFlow:
    def test_store_then_resolve_roundtrip(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/alienvault/api-key")
        broker.store(
            StoreSecretRequest(ref=ref, value="super-secret-value", created_by="developer"),
            caller="developer",
        )
        retrieved = broker.resolve(ref, caller="developer")
        assert isinstance(retrieved, SecretValue)
        assert retrieved.value == "super-secret-value"

    def test_resolve_missing_secret_raises(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/missing/key")
        with pytest.raises(SecretProviderError, match="secret not found"):
            broker.resolve(ref, caller="developer")

    def test_store_returns_version_info(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/misp/api-key")
        info = broker.store(
            StoreSecretRequest(ref=ref, value="v1"),
            caller="developer",
        )
        assert info.version == "1"

    def test_store_with_overwrite_increments_version(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/misp/api-key")
        broker.store(StoreSecretRequest(ref=ref, value="v1"), caller="developer")
        info = broker.store(
            StoreSecretRequest(ref=ref, value="v2", allow_overwrite=True),
            caller="developer",
        )
        assert info.version == "2"

    def test_resolve_returns_metadata(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/misp/api-key")
        broker.store(
            StoreSecretRequest(ref=ref, value="v1", tags={"owner": "sec-team"}),
            caller="developer",
        )
        retrieved = broker.resolve(ref, caller="developer")
        assert retrieved.metadata.tags == {"owner": "sec-team"}
        assert retrieved.metadata.provider == "memory"


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------


class TestPolicyEnforcement:
    def test_unknown_caller_denied(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/misp/api-key")
        with pytest.raises(SecretPolicyError, match="no matching policy rule"):
            broker.store(
                StoreSecretRequest(ref=ref, value="leaked"),
                caller="attacker",
            )

    def test_prod_write_denied(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="prod", path="prod/splunk/token")
        # Policy only grants prod resolve for runtime; developer store is denied
        with pytest.raises(SecretPolicyError):
            broker.store(
                StoreSecretRequest(ref=ref, value="leaked"),
                caller="developer",
            )

    def test_prod_read_by_runtime_allowed(self) -> None:
        # First seed a value as the memory provider directly
        provider = MemorySecretProvider()
        ref = SecretRef(provider="memory", vault="prod", path="prod/splunk/token")
        provider.store(StoreSecretRequest(ref=ref, value="real-token"))

        broker = SecretsBroker(providers={"memory": provider}, policy=_permissive_engine())
        retrieved = broker.resolve(ref, caller="runtime")
        assert retrieved.value == "real-token"

    def test_overwrite_without_policy_permission_denied(self) -> None:
        engine = SecretPolicyEngine(
            rules=[
                PolicyRule(
                    path_prefix="dev/",
                    actions=("resolve", "store"),
                    allowed_callers=("developer",),
                    overwrite=False,  # explicit: no overwrites
                )
            ]
        )
        broker = SecretsBroker(providers={"memory": MemorySecretProvider()}, policy=engine)
        ref = SecretRef(provider="memory", vault="dev", path="dev/x/key")
        broker.store(StoreSecretRequest(ref=ref, value="v1"), caller="developer")
        with pytest.raises(SecretPolicyError, match="overwrite not permitted"):
            broker.store(
                StoreSecretRequest(ref=ref, value="v2", allow_overwrite=True),
                caller="developer",
            )


# ---------------------------------------------------------------------------
# Provider routing + error surfacing
# ---------------------------------------------------------------------------


class TestProviderRouting:
    def test_unknown_provider_name_raises(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="does_not_exist", vault=None, path="dev/x/key")
        with pytest.raises(SecretProviderError, match="unknown provider"):
            broker.resolve(ref, caller="developer")

    def test_parse_ref_roundtrip(self) -> None:
        broker = _build_broker()
        ref = broker.parse_ref("memory://gnat-dev/dev/alienvault/api-key?version=3")
        assert ref.provider == "memory"
        assert ref.vault == "gnat-dev"
        assert ref.path == "dev/alienvault/api-key"
        assert ref.version == "3"

    def test_parse_ref_without_version(self) -> None:
        broker = _build_broker()
        ref = broker.parse_ref("memory://vault/path/key")
        assert ref.version is None

    def test_checkout_unsupported_raises(self) -> None:
        # Policy must allow the action before we reach the capability check.
        engine = SecretPolicyEngine(
            rules=[
                PolicyRule(
                    path_prefix="dev/",
                    actions=("checkout",),
                    allowed_callers=("developer",),
                )
            ]
        )
        broker = SecretsBroker(providers={"memory": MemorySecretProvider()}, policy=engine)
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/x/key")
        # MemorySecretProvider does not advertise supports_checkout
        with pytest.raises(UnsupportedProviderAction, match="checkout"):
            broker.checkout(ref, caller="developer")


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


class TestAuditTrail:
    def test_successful_store_is_audited(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="gnat-dev", path="dev/x/key")
        broker.store(StoreSecretRequest(ref=ref, value="v"), caller="developer")
        events = list(broker.audit.events)
        assert events, "expected at least one audit event"
        assert events[-1].action == "store"
        assert events[-1].allowed is True

    def test_denied_store_is_audited(self) -> None:
        broker = _build_broker()
        ref = SecretRef(provider="memory", vault="prod", path="prod/x/key")
        with pytest.raises(SecretPolicyError):
            broker.store(StoreSecretRequest(ref=ref, value="v"), caller="developer")
        events = list(broker.audit.events)
        assert any(e.action == "store" and not e.allowed for e in events)
