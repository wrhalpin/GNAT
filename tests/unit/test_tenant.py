# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/test_tenant.py
==========================
Unit tests for multi-tenant workspace isolation (gnat.context.tenant).

Tests cover:
1.  Tenant dataclass — construction, validation, auto-display-name
2.  TenantRegistry — register, get, list, update, delete, persistence
3.  TenantRegistry — duplicate registration, invalid tenant_id
4.  TenantWorkspaceManager — name scoping (_scoped / _unscoped)
5.  TenantWorkspaceManager — create delegates to manager with prefix
6.  TenantWorkspaceManager — open delegates with prefix
7.  TenantWorkspaceManager — list filters to own tenant, strips prefix
8.  TenantWorkspaceManager — delete scoped
9.  TenantWorkspaceManager — purge deletes all tenant workspaces
10. TenantWorkspaceManager — isolation (two tenants, same workspace name)
11. TenantWorkspaceManager — workspace_names()
12. TenantWorkspaceManager — invalid tenant_id raises ValueError
13. WorkspaceManager.for_tenant() returns TenantWorkspaceManager
14. CLI — gnat tenant list / create / delete / info / workspaces
15. CLI — invalid tenant_id at create time
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from gnat.context.tenant import (
    TENANT_SEPARATOR,
    Tenant,
    TenantRegistry,
    TenantWorkspaceManager,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_manager(workspaces: dict | None = None) -> MagicMock:
    """Build a mock WorkspaceManager with a fake backing store."""
    if workspaces is None:
        workspaces = {}
    manager = MagicMock()

    def _list():
        return [{"name": name, "description": "", "object_count": 0} for name in workspaces]

    def _create(name, description=""):
        workspaces[name] = []
        ws = MagicMock()
        ws.name = name
        return ws

    def _open(name):
        if name not in workspaces:
            raise KeyError(name)
        ws = MagicMock()
        ws.name = name
        return ws

    def _get_or_create(name, **kwargs):
        if name not in workspaces:
            workspaces[name] = []
        ws = MagicMock()
        ws.name = name
        return ws

    def _delete(name):
        if name in workspaces:
            del workspaces[name]
            return True
        return False

    manager.list.side_effect = _list
    manager.create.side_effect = _create
    manager.open.side_effect = _open
    manager.get_or_create.side_effect = _get_or_create
    manager.delete.side_effect = _delete
    return manager


# ---------------------------------------------------------------------------
# 1. Tenant dataclass
# ---------------------------------------------------------------------------


class TestTenant:
    def test_basic_construction(self):
        t = Tenant(tenant_id="acme", display_name="Acme Corp")
        assert t.tenant_id == "acme"
        assert t.display_name == "Acme Corp"

    def test_auto_display_name_from_id(self):
        t = Tenant(tenant_id="acme")
        assert t.display_name == "acme"

    def test_created_at_auto_set(self):
        t = Tenant(tenant_id="acme")
        assert t.created_at  # non-empty

    def test_invalid_id_uppercase(self):
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            Tenant(tenant_id="ACME")

    def test_invalid_id_starts_with_hyphen(self):
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            Tenant(tenant_id="-acme")

    def test_invalid_id_empty(self):
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            Tenant(tenant_id="")

    def test_valid_id_with_hyphens(self):
        t = Tenant(tenant_id="customer-a")
        assert t.tenant_id == "customer-a"

    def test_valid_id_with_underscores(self):
        t = Tenant(tenant_id="tenant_42")
        assert t.tenant_id == "tenant_42"

    def test_config_path_optional(self):
        t = Tenant(tenant_id="acme")
        assert t.config_path is None

    def test_config_path_stored(self):
        t = Tenant(tenant_id="acme", config_path="/etc/gnat/acme.ini")
        assert t.config_path == "/etc/gnat/acme.ini"


# ---------------------------------------------------------------------------
# 2 & 3. TenantRegistry
# ---------------------------------------------------------------------------


class TestTenantRegistry:
    def test_empty_registry(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        assert r.list() == []
        assert len(r) == 0

    def test_register_and_get(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        t = r.register("acme", display_name="Acme Corp")
        assert t.tenant_id == "acme"
        assert r.get("acme") is not None
        assert r.get("acme").display_name == "Acme Corp"

    def test_register_persists(self, tmp_path):
        path = str(tmp_path / "tenants.json")
        r1 = TenantRegistry(path)
        r1.register("acme")
        r2 = TenantRegistry(path)
        assert r2.get("acme") is not None

    def test_list_sorted_by_id(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        r.register("zebra")
        r.register("alpha")
        r.register("middle")
        ids = [t.tenant_id for t in r.list()]
        assert ids == ["alpha", "middle", "zebra"]

    def test_duplicate_registration_raises(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        r.register("acme")
        with pytest.raises(ValueError, match="already registered"):
            r.register("acme")

    def test_invalid_id_raises(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            r.register("ACME")

    def test_delete_existing(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        r.register("acme")
        assert r.delete("acme") is True
        assert r.get("acme") is None

    def test_delete_nonexistent_returns_false(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        assert r.delete("nope") is False

    def test_delete_persists(self, tmp_path):
        path = str(tmp_path / "tenants.json")
        r = TenantRegistry(path)
        r.register("acme")
        r.delete("acme")
        r2 = TenantRegistry(path)
        assert r2.get("acme") is None

    def test_update_display_name(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        r.register("acme", display_name="Old Name")
        r.update("acme", display_name="New Name")
        assert r.get("acme").display_name == "New Name"

    def test_update_config_path(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        r.register("acme")
        r.update("acme", config_path="/etc/acme.ini")
        assert r.get("acme").config_path == "/etc/acme.ini"

    def test_update_nonexistent_raises(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        with pytest.raises(KeyError, match="nope"):
            r.update("nope", display_name="X")

    def test_get_nonexistent_returns_none(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        assert r.get("nobody") is None

    def test_repr(self, tmp_path):
        r = TenantRegistry(str(tmp_path / "tenants.json"))
        assert "TenantRegistry" in repr(r)

    def test_default_factory(self):
        r = TenantRegistry.default()
        assert isinstance(r, TenantRegistry)


# ---------------------------------------------------------------------------
# 4. Name scoping helpers
# ---------------------------------------------------------------------------


class TestNameScoping:
    def test_scoped(self):
        mgr = _mock_manager()
        twm = TenantWorkspaceManager("acme", mgr)
        assert twm._scoped("ws1") == "acme::ws1"

    def test_unscoped(self):
        mgr = _mock_manager()
        twm = TenantWorkspaceManager("acme", mgr)
        assert twm._unscoped("acme::ws1") == "ws1"

    def test_separator_constant(self):
        assert TENANT_SEPARATOR == "::"

    def test_scoped_roundtrip(self):
        mgr = _mock_manager()
        twm = TenantWorkspaceManager("acme", mgr)
        assert twm._unscoped(twm._scoped("some-name")) == "some-name"


# ---------------------------------------------------------------------------
# 5. create delegates with prefix
# ---------------------------------------------------------------------------


class TestCreate:
    def test_create_uses_scoped_name(self):
        mgr = _mock_manager()
        twm = TenantWorkspaceManager("acme", mgr)
        twm.create("apt28")
        mgr.create.assert_called_once_with("acme::apt28", description="")

    def test_create_passes_description(self):
        mgr = _mock_manager()
        twm = TenantWorkspaceManager("acme", mgr)
        twm.create("ws", description="Test workspace")
        mgr.create.assert_called_once_with("acme::ws", description="Test workspace")


# ---------------------------------------------------------------------------
# 6. open delegates with prefix
# ---------------------------------------------------------------------------


class TestOpen:
    def test_open_uses_scoped_name(self):
        mgr = _mock_manager({"acme::ws1": []})
        twm = TenantWorkspaceManager("acme", mgr)
        twm.open("ws1")
        mgr.open.assert_called_once_with("acme::ws1")

    def test_open_nonexistent_raises_keyerror(self):
        mgr = _mock_manager()
        twm = TenantWorkspaceManager("acme", mgr)
        with pytest.raises(KeyError):
            twm.open("nope")


# ---------------------------------------------------------------------------
# 7. list filters and strips prefix
# ---------------------------------------------------------------------------


class TestList:
    def test_list_returns_own_workspaces_only(self):
        mgr = _mock_manager(
            {
                "acme::ws1": [],
                "acme::ws2": [],
                "beta::ws1": [],
                "other": [],
            }
        )
        acme = TenantWorkspaceManager("acme", mgr)
        names = [ws["name"] for ws in acme.list()]
        assert sorted(names) == ["ws1", "ws2"]

    def test_list_strips_prefix(self):
        mgr = _mock_manager({"acme::apt28": []})
        acme = TenantWorkspaceManager("acme", mgr)
        ws = acme.list()[0]
        assert ws["name"] == "apt28"
        assert "::" not in ws["name"]

    def test_list_adds_tenant_id_key(self):
        mgr = _mock_manager({"acme::ws": []})
        acme = TenantWorkspaceManager("acme", mgr)
        ws = acme.list()[0]
        assert ws["tenant_id"] == "acme"

    def test_list_empty_when_no_workspaces(self):
        mgr = _mock_manager({"beta::ws": []})
        acme = TenantWorkspaceManager("acme", mgr)
        assert acme.list() == []

    def test_list_empty_manager(self):
        mgr = _mock_manager()
        acme = TenantWorkspaceManager("acme", mgr)
        assert acme.list() == []


# ---------------------------------------------------------------------------
# 8. delete scoped
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_uses_scoped_name(self):
        mgr = _mock_manager({"acme::ws": []})
        twm = TenantWorkspaceManager("acme", mgr)
        twm.delete("ws")
        mgr.delete.assert_called_once_with("acme::ws")

    def test_delete_returns_true_when_found(self):
        mgr = _mock_manager({"acme::ws": []})
        twm = TenantWorkspaceManager("acme", mgr)
        assert twm.delete("ws") is True

    def test_delete_returns_false_when_not_found(self):
        mgr = _mock_manager()
        twm = TenantWorkspaceManager("acme", mgr)
        assert twm.delete("nope") is False


# ---------------------------------------------------------------------------
# 9. purge
# ---------------------------------------------------------------------------


class TestPurge:
    def test_purge_deletes_all_tenant_workspaces(self):
        mgr = _mock_manager(
            {
                "acme::ws1": [],
                "acme::ws2": [],
                "beta::ws1": [],
            }
        )
        acme = TenantWorkspaceManager("acme", mgr)
        count = acme.purge()
        assert count == 2
        # Beta workspace still present
        assert "beta::ws1" in {"beta::ws1"}

    def test_purge_empty_returns_zero(self):
        mgr = _mock_manager()
        acme = TenantWorkspaceManager("acme", mgr)
        assert acme.purge() == 0


# ---------------------------------------------------------------------------
# 10. Isolation between tenants
# ---------------------------------------------------------------------------


class TestIsolation:
    def test_same_name_different_tenants_no_collision(self):
        store: dict = {}
        mgr = _mock_manager(store)
        acme = TenantWorkspaceManager("acme", mgr)
        beta = TenantWorkspaceManager("beta", mgr)

        acme.create("apt28")
        beta.create("apt28")

        assert "acme::apt28" in store
        assert "beta::apt28" in store

    def test_list_does_not_cross_tenant_boundary(self):
        mgr = _mock_manager(
            {
                "acme::ws-a": [],
                "beta::ws-b": [],
            }
        )
        acme = TenantWorkspaceManager("acme", mgr)
        beta = TenantWorkspaceManager("beta", mgr)

        assert [w["name"] for w in acme.list()] == ["ws-a"]
        assert [w["name"] for w in beta.list()] == ["ws-b"]

    def test_delete_does_not_affect_other_tenant(self):
        store = {"acme::ws": [], "beta::ws": []}
        mgr = _mock_manager(store)
        acme = TenantWorkspaceManager("acme", mgr)
        acme.delete("ws")
        assert "acme::ws" not in store
        assert "beta::ws" in store


# ---------------------------------------------------------------------------
# 11. workspace_names
# ---------------------------------------------------------------------------


class TestWorkspaceNames:
    def test_workspace_names_returns_unscoped(self):
        mgr = _mock_manager({"acme::a": [], "acme::b": [], "beta::c": []})
        acme = TenantWorkspaceManager("acme", mgr)
        names = sorted(acme.workspace_names())
        assert names == ["a", "b"]


# ---------------------------------------------------------------------------
# 12. Invalid tenant_id
# ---------------------------------------------------------------------------


class TestInvalidTenantId:
    def test_uppercase_raises(self):
        mgr = _mock_manager()
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            TenantWorkspaceManager("ACME", mgr)

    def test_starts_with_hyphen_raises(self):
        mgr = _mock_manager()
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            TenantWorkspaceManager("-acme", mgr)

    def test_empty_raises(self):
        mgr = _mock_manager()
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            TenantWorkspaceManager("", mgr)


# ---------------------------------------------------------------------------
# 13. WorkspaceManager.for_tenant()
# ---------------------------------------------------------------------------


class TestForTenant:
    def test_for_tenant_returns_tenant_manager(self):
        from gnat.context.workspace import WorkspaceManager

        mgr = MagicMock(spec=WorkspaceManager)
        # Patch the import inside for_tenant
        with patch.object(
            WorkspaceManager, "for_tenant", lambda self, tid: TenantWorkspaceManager(tid, self)
        ):
            twm = WorkspaceManager.for_tenant(mgr, "acme")
            assert isinstance(twm, TenantWorkspaceManager)
            assert twm.tenant_id == "acme"

    def test_for_tenant_real_call(self):
        from gnat.context.workspace import WorkspaceManager

        mgr = MagicMock(spec=WorkspaceManager)
        mgr.list.return_value = []
        mgr.create.return_value = MagicMock()
        mgr.open.side_effect = KeyError
        mgr.delete.return_value = False
        twm = WorkspaceManager.for_tenant(mgr, "acme")
        assert isinstance(twm, TenantWorkspaceManager)
        assert twm.tenant_id == "acme"


# ---------------------------------------------------------------------------
# 14 & 15. CLI
# ---------------------------------------------------------------------------


class TestCLITenant:
    def test_tenant_list_empty(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        ret = main(["tenant", "list", "--registry", reg_path])
        assert ret == 0

    def test_tenant_create(self, tmp_path):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        ret = main(
            [
                "tenant",
                "create",
                "acme",
                "--display-name",
                "Acme Corp",
                "--registry",
                reg_path,
            ]
        )
        assert ret == 0
        # Verify it was persisted
        r = TenantRegistry(reg_path)
        assert r.get("acme") is not None
        assert r.get("acme").display_name == "Acme Corp"

    def test_tenant_create_invalid_id(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        ret = main(["tenant", "create", "INVALID", "--registry", reg_path])
        assert ret == 1

    def test_tenant_list_shows_tenants(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        r = TenantRegistry(reg_path)
        r.register("acme", display_name="Acme Corp")
        r.register("beta", display_name="Beta Ltd")
        ret = main(["tenant", "list", "--registry", reg_path])
        assert ret == 0
        captured = capsys.readouterr()
        assert "acme" in captured.out
        assert "beta" in captured.out

    def test_tenant_delete_with_yes(self, tmp_path):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        r = TenantRegistry(reg_path)
        r.register("acme")
        ret = main(["tenant", "delete", "acme", "--yes", "--registry", reg_path])
        assert ret == 0
        assert TenantRegistry(reg_path).get("acme") is None

    def test_tenant_delete_nonexistent(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        ret = main(["tenant", "delete", "nobody", "--yes", "--registry", reg_path])
        assert ret == 1

    def test_tenant_info(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        r = TenantRegistry(reg_path)
        r.register("acme", display_name="Acme Corp", description="Test tenant")
        ret = main(["tenant", "info", "acme", "--registry", reg_path])
        assert ret == 0
        captured = capsys.readouterr()
        assert "acme" in captured.out
        assert "Acme Corp" in captured.out

    def test_tenant_info_nonexistent(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        ret = main(["tenant", "info", "nobody", "--registry", reg_path])
        assert ret == 1

    def test_tenant_no_subcommand(self, tmp_path, capsys):
        from gnat.cli.main import main

        ret = main(["tenant"])
        assert ret == 0  # prints help

    def test_tenant_workspaces_no_workspaces(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        # Works even without registered tenant (just shows empty list)
        with patch("gnat.context.tenant.TenantWorkspaceManager.default") as mock_def:
            mock_twm = MagicMock()
            mock_twm.list.return_value = []
            mock_def.return_value = mock_twm
            ret = main(["tenant", "workspaces", "acme", "--registry", reg_path])
        assert ret == 0

    def test_tenant_workspaces_with_workspaces(self, tmp_path, capsys):
        from gnat.cli.main import main

        reg_path = str(tmp_path / "tenants.json")
        with patch("gnat.context.tenant.TenantWorkspaceManager.default") as mock_def:
            mock_twm = MagicMock()
            mock_twm.list.return_value = [
                {"name": "apt28", "object_count": 42, "description": "APT28 intel"},
            ]
            mock_def.return_value = mock_twm
            ret = main(["tenant", "workspaces", "acme", "--registry", reg_path])
        assert ret == 0
        captured = capsys.readouterr()
        assert "apt28" in captured.out
