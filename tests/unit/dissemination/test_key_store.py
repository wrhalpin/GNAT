# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/dissemination/test_key_store.py
==========================================

Unit tests for :class:`~gnat.dissemination.api.auth.APIKeyStore`,
:class:`~gnat.dissemination.api.auth.APIKey`, and the optional
:class:`~gnat.dissemination.api.key_store_db.SQLAlchemyKeyStore`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from gnat.analysis.tlp import TLPLevel
from gnat.dissemination.api.auth import APIKey, APIKeyStore


# ---------------------------------------------------------------------------
# APIKey — tenant_id field
# ---------------------------------------------------------------------------


class TestAPIKeyTenantId:
    """Verify ``tenant_id`` is a first-class field on APIKey."""

    def test_tenant_id_defaults_to_none(self):
        key = APIKey(token="tok-1", tlp_level=TLPLevel.GREEN)
        assert key.tenant_id is None

    def test_tenant_id_set_explicitly(self):
        key = APIKey(token="tok-2", tlp_level=TLPLevel.AMBER, tenant_id="tenant-abc")
        assert key.tenant_id == "tenant-abc"

    def test_to_dict_includes_tenant_id_when_set(self):
        key = APIKey(token="tok-3", tlp_level=TLPLevel.RED, tenant_id="tenant-xyz")
        d = key.to_dict()
        assert "tenant_id" in d
        assert d["tenant_id"] == "tenant-xyz"

    def test_to_dict_includes_tenant_id_when_none(self):
        key = APIKey(token="tok-4", tlp_level=TLPLevel.WHITE)
        d = key.to_dict()
        assert "tenant_id" in d
        assert d["tenant_id"] is None


# ---------------------------------------------------------------------------
# APIKeyStore — add_key with tenant_id
# ---------------------------------------------------------------------------


class TestAPIKeyStoreAddKey:
    """Verify ``add_key`` propagates ``tenant_id``."""

    def test_add_key_with_tenant_id(self):
        store = APIKeyStore()
        key = store.add_key(
            "secret-1",
            TLPLevel.AMBER,
            label="SIEM feed",
            tenant_id="tenant-1",
        )
        assert key.tenant_id == "tenant-1"
        retrieved = store.get_key("secret-1")
        assert retrieved is not None
        assert retrieved.tenant_id == "tenant-1"

    def test_add_key_without_tenant_id_defaults_none(self):
        store = APIKeyStore()
        key = store.add_key("secret-2", TLPLevel.GREEN, label="partner")
        assert key.tenant_id is None


# ---------------------------------------------------------------------------
# APIKeyStore — generate_key with tenant_id
# ---------------------------------------------------------------------------


class TestAPIKeyStoreGenerateKey:
    """Verify ``generate_key`` accepts and stores ``tenant_id``."""

    def test_generate_key_with_tenant_id(self):
        store = APIKeyStore()
        key = store.generate_key(
            TLPLevel.RED,
            label="sandbox-svc",
            tenant_id="tenant-sandbox",
        )
        assert key.tenant_id == "tenant-sandbox"
        assert len(key.token) > 0
        assert store.get_key(key.token) is key

    def test_generate_key_without_tenant_id(self):
        store = APIKeyStore()
        key = store.generate_key(TLPLevel.GREEN, label="anon")
        assert key.tenant_id is None


# ---------------------------------------------------------------------------
# APIKeyStore — rotate_key
# ---------------------------------------------------------------------------


class TestAPIKeyStoreRotateKey:
    """Verify ``rotate_key`` creates a replacement and applies a grace period."""

    def test_rotate_key_creates_new_key(self):
        store = APIKeyStore()
        old = store.add_key(
            "old-token",
            TLPLevel.AMBER,
            label="rotate-me",
            tenant_id="t-1",
        )
        new = store.rotate_key("old-token", grace_hours=24)

        # New key exists with same metadata
        assert new is not None
        assert new.token != "old-token"
        assert new.label == old.label
        assert new.tlp_level == old.tlp_level
        assert new.tenant_id == old.tenant_id
        assert new.role == old.role
        assert new.enabled is True

        # Old key still exists but has an expiry within ~24 h
        old_refreshed = store.get_key("old-token")
        assert old_refreshed is not None
        assert old_refreshed.expires_at is not None
        delta = old_refreshed.expires_at - datetime.now(tz=timezone.utc)
        # Should be roughly 24 hours (allow 5 min tolerance)
        assert timedelta(hours=23, minutes=55) < delta < timedelta(hours=24, minutes=5)

    def test_rotate_key_with_zero_grace_expires_immediately(self):
        store = APIKeyStore()
        store.add_key("imm-token", TLPLevel.GREEN, label="immediate")
        new = store.rotate_key("imm-token", grace_hours=0)

        assert new is not None
        old = store.get_key("imm-token")
        assert old is not None
        # Grace of 0 means expires_at <= now — key is no longer valid
        assert not old.is_valid()

    def test_rotate_nonexistent_key_returns_none(self):
        store = APIKeyStore()
        result = store.rotate_key("does-not-exist")
        assert result is None


# ---------------------------------------------------------------------------
# SQLAlchemyKeyStore — CRUD with in-memory SQLite
# ---------------------------------------------------------------------------

try:
    from gnat.dissemination.api.key_store_db import SQLAlchemyKeyStore

    _SA_AVAILABLE = True
except ImportError:
    _SA_AVAILABLE = False


@pytest.mark.skipif(not _SA_AVAILABLE, reason="sqlalchemy not installed")
class TestSQLAlchemyKeyStoreCRUD:
    """CRUD operations on the database-backed key store."""

    def _make_store(self, url: str = "sqlite:///:memory:") -> SQLAlchemyKeyStore:
        store = SQLAlchemyKeyStore(url)
        store.create_all()
        return store

    def test_save_and_get(self):
        store = self._make_store()
        key = APIKey(
            token="db-tok-1",
            tlp_level=TLPLevel.AMBER,
            label="db-test",
            tenant_id="tenant-db",
        )
        store.save(key)
        retrieved = store.get_key("db-tok-1")
        assert retrieved is not None
        assert retrieved.label == "db-test"
        assert retrieved.tlp_level == TLPLevel.AMBER
        assert retrieved.tenant_id == "tenant-db"
        assert retrieved.enabled is True

    def test_list_keys(self):
        store = self._make_store()
        store.save(APIKey(token="k1", tlp_level=TLPLevel.GREEN, label="one"))
        store.save(APIKey(token="k2", tlp_level=TLPLevel.RED, label="two"))
        keys = store.list_keys()
        assert len(keys) == 2
        labels = {k.label for k in keys}
        assert labels == {"one", "two"}

    def test_revoke_key(self):
        store = self._make_store()
        store.save(APIKey(token="rev-tok", tlp_level=TLPLevel.GREEN, label="revocable"))
        assert store.revoke_key("rev-tok") is True
        key = store.get_key("rev-tok")
        assert key is not None
        assert key.enabled is False
        assert not key.is_valid()

    def test_revoke_nonexistent_returns_false(self):
        store = self._make_store()
        assert store.revoke_key("nope") is False

    def test_get_nonexistent_returns_none(self):
        store = self._make_store()
        assert store.get_key("missing") is None


@pytest.mark.skipif(not _SA_AVAILABLE, reason="sqlalchemy not installed")
class TestSQLAlchemyKeyStorePersistence:
    """Verify data survives across store instances sharing the same database."""

    def test_persists_across_instances(self, tmp_path):
        db_path = tmp_path / "keys.db"
        db_url = f"sqlite:///{db_path}"

        # Instance 1: create and save a key
        store1 = SQLAlchemyKeyStore(db_url)
        store1.create_all()
        store1.save(
            APIKey(
                token="persist-tok",
                tlp_level=TLPLevel.AMBER,
                label="persistent",
                tenant_id="t-persist",
            )
        )

        # Instance 2: same DB, different object — should see the key
        store2 = SQLAlchemyKeyStore(db_url)
        store2.create_all()
        key = store2.get_key("persist-tok")
        assert key is not None
        assert key.label == "persistent"
        assert key.tenant_id == "t-persist"
        assert key.tlp_level == TLPLevel.AMBER
