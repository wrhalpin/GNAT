"""
tests/unit/test_cli_phase4.py
==============================
Unit tests for Phase 4 CLI subcommands:
  - gnat investigation (list / create / get / transition / note / link)
  - gnat plugins (list / load)
  - gnat db (upgrade / downgrade / current / revision / stamp)
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


# ── Parser registration ────────────────────────────────────────────────────────

class TestCliParserRegistration:
    def test_investigation_subcommand_registered(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["investigation", "list"])
        assert args.command == "investigation"

    def test_plugins_subcommand_registered(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["plugins", "list"])
        assert args.command == "plugins"

    def test_db_subcommand_registered(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["db", "upgrade"])
        assert args.command == "db"

    def test_investigation_help_exits_zero(self):
        from gnat.cli.main import main

        with pytest.raises(SystemExit) as exc:
            main(["investigation", "--help"])
        assert exc.value.code == 0

    def test_plugins_help_exits_zero(self):
        from gnat.cli.main import main

        with pytest.raises(SystemExit) as exc:
            main(["plugins", "--help"])
        assert exc.value.code == 0

    def test_db_help_exits_zero(self):
        from gnat.cli.main import main

        with pytest.raises(SystemExit) as exc:
            main(["db", "--help"])
        assert exc.value.code == 0


# ── investigation list ────────────────────────────────────────────────────────

class TestInvestigationList:
    def _make_inv(self, idx=1):
        from datetime import datetime, timezone
        inv = MagicMock()
        inv.id         = f"inv-{'0' * 31}{idx}"
        inv.title      = f"Test Investigation {idx}"
        inv.status     = MagicMock(value="open")
        inv.classification = MagicMock(value="green")
        inv.created_by = "alice"
        inv.updated_at = datetime(2026, 1, idx, tzinfo=timezone.utc)
        return inv

    # Lazy imports inside _cmd_investigation live in their source modules
    _STORE_PATCH = "gnat.analysis.investigations.storage.InvestigationStore"
    _SVC_PATCH   = "gnat.analysis.investigations.service.InvestigationService"

    def test_list_returns_0_on_success(self, monkeypatch):
        from gnat.cli.main import _cmd_investigation

        with (
            patch(self._STORE_PATCH) as MockStore,
            patch(self._SVC_PATCH) as MockSvc,
        ):
            MockStore.return_value.create_all.return_value = None
            MockSvc.return_value.list.return_value = [self._make_inv(1)]

            args = MagicMock()
            args.inv_command = "list"
            args.status      = None
            args.created_by  = None
            args.tag         = None
            args.text        = None
            args.page        = 1
            args.page_size   = 25
            args.config      = None

            monkeypatch.setenv("GNAT_DB_URL", "sqlite:///:memory:")
            result = _cmd_investigation(args)

        assert result == 0

    def test_list_empty_returns_0(self, monkeypatch):
        from gnat.cli.main import _cmd_investigation

        with (
            patch(self._STORE_PATCH) as MockStore,
            patch(self._SVC_PATCH) as MockSvc,
        ):
            MockStore.return_value.create_all.return_value = None
            MockSvc.return_value.list.return_value = []

            args = MagicMock()
            args.inv_command = "list"
            args.status = args.created_by = args.tag = args.text = None
            args.page = 1; args.page_size = 25; args.config = None

            monkeypatch.setenv("GNAT_DB_URL", "sqlite:///:memory:")
            result = _cmd_investigation(args)

        assert result == 0

    def test_list_missing_sqlalchemy_returns_1(self, monkeypatch):
        """If SQLAlchemy import fails inside the function, returns exit code 1."""
        from gnat.cli.main import _cmd_investigation

        args = MagicMock()
        args.inv_command = "list"
        args.config      = None

        with patch.dict(sys.modules, {"gnat.analysis.investigations.storage": None}):
            result = _cmd_investigation(args)
        assert result == 1


# ── investigation create ──────────────────────────────────────────────────────

class TestInvestigationCreate:
    _STORE_PATCH = "gnat.analysis.investigations.storage.InvestigationStore"
    _SVC_PATCH   = "gnat.analysis.investigations.service.InvestigationService"

    def test_create_returns_0(self, monkeypatch):
        from gnat.cli.main import _cmd_investigation

        inv = MagicMock()
        inv.id     = "inv-" + "a" * 32
        inv.title  = "My inv"
        inv.status = MagicMock(value="open")

        with (
            patch(self._STORE_PATCH) as MockStore,
            patch(self._SVC_PATCH) as MockSvc,
        ):
            MockStore.return_value.create_all.return_value = None
            MockSvc.return_value.create.return_value = inv

            args = MagicMock()
            args.inv_command  = "create"
            args.title        = "My inv"
            args.created_by   = "alice"
            args.description  = ""
            args.tlp          = "green"
            args.tags         = ""
            args.config       = None

            monkeypatch.setenv("GNAT_DB_URL", "sqlite:///:memory:")
            result = _cmd_investigation(args)

        assert result == 0

    def test_create_invalid_tlp_returns_1(self, monkeypatch):
        from gnat.cli.main import _cmd_investigation

        with (
            patch(self._STORE_PATCH) as MockStore,
            patch(self._SVC_PATCH),
        ):
            MockStore.return_value.create_all.return_value = None

            args = MagicMock()
            args.inv_command  = "create"
            args.title        = "T"
            args.created_by   = "alice"
            args.description  = ""
            args.tlp          = "INVALID_TLP"
            args.tags         = ""
            args.config       = None

            monkeypatch.setenv("GNAT_DB_URL", "sqlite:///:memory:")
            result = _cmd_investigation(args)

        assert result == 1


# ── investigation transition ──────────────────────────────────────────────────

class TestInvestigationTransition:
    _STORE_PATCH = "gnat.analysis.investigations.storage.InvestigationStore"
    _SVC_PATCH   = "gnat.analysis.investigations.service.InvestigationService"

    def test_transition_returns_0(self, monkeypatch):
        from gnat.cli.main import _cmd_investigation

        inv = MagicMock()
        inv.status = MagicMock(value="in_progress")

        with (
            patch(self._STORE_PATCH) as MockStore,
            patch(self._SVC_PATCH) as MockSvc,
        ):
            MockStore.return_value.create_all.return_value = None
            MockSvc.return_value.transition.return_value = inv

            args = MagicMock()
            args.inv_command = "transition"
            args.id          = "inv-" + "b" * 32
            args.status      = "in_progress"
            args.note        = "moving ahead"
            args.author      = "bob"
            args.config      = None

            monkeypatch.setenv("GNAT_DB_URL", "sqlite:///:memory:")
            result = _cmd_investigation(args)

        assert result == 0

    def test_transition_error_returns_1(self, monkeypatch):
        from gnat.cli.main import _cmd_investigation

        with (
            patch(self._STORE_PATCH) as MockStore,
            patch(self._SVC_PATCH) as MockSvc,
        ):
            MockStore.return_value.create_all.return_value = None
            MockSvc.return_value.transition.side_effect = RuntimeError("invalid transition")

            args = MagicMock()
            args.inv_command = "transition"
            args.id          = "inv-" + "c" * 32
            args.status      = "closed"
            args.note        = ""
            args.author      = "alice"
            args.config      = None

            monkeypatch.setenv("GNAT_DB_URL", "sqlite:///:memory:")
            result = _cmd_investigation(args)

        assert result == 1


# ── plugins list / load ────────────────────────────────────────────────────────

class TestPluginsSubcommand:
    # _cmd_plugins imports PluginRegistry lazily from its source module
    _REG_PATCH = "gnat.plugins.registry.PluginRegistry"

    def test_plugins_list_no_plugins_returns_0(self):
        from gnat.cli.main import _cmd_plugins

        args = MagicMock()
        args.plg_command = "list"

        with patch(self._REG_PATCH) as MockReg:
            MockReg.return_value.list.return_value = []
            result = _cmd_plugins(args)

        assert result == 0

    def test_plugins_list_with_plugins_returns_0(self):
        from gnat.cli.main import _cmd_plugins

        plugin = MagicMock()
        plugin.name         = "test.plugin"
        plugin.version      = "1.0.0"
        plugin.capabilities = [MagicMock(value="CONNECTOR")]
        plugin.description  = "A test plugin"

        args = MagicMock()
        args.plg_command = "list"

        with patch(self._REG_PATCH) as MockReg:
            MockReg.return_value.list.return_value = [plugin]
            result = _cmd_plugins(args)

        assert result == 0

    def test_plugins_load_returns_0(self, tmp_path):
        from gnat.cli.main import _cmd_plugins

        args = MagicMock()
        args.plg_command = "load"
        args.directory   = str(tmp_path)

        with patch(self._REG_PATCH) as MockReg:
            MockReg.return_value.load_directory.return_value = 0
            result = _cmd_plugins(args)

        assert result == 0

    def test_plugins_load_error_returns_1(self, tmp_path):
        from gnat.cli.main import _cmd_plugins

        args = MagicMock()
        args.plg_command = "load"
        args.directory   = "/nonexistent/path"

        with patch(self._REG_PATCH) as MockReg:
            MockReg.return_value.load_directory.side_effect = OSError("not found")
            result = _cmd_plugins(args)

        assert result == 1


# ── db subcommand ─────────────────────────────────────────────────────────────
# run_db_command is imported lazily inside _cmd_db, so we patch it at its source.
_DB_PATCH = "gnat.migrations.cli.run_db_command"


class TestDbSubcommand:
    def test_db_upgrade_returns_0(self):
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command = "upgrade"

        with patch(_DB_PATCH) as mock_run:
            mock_run.return_value = None
            result = _cmd_db(args)

        assert result == 0

    def test_db_downgrade_passes_minus_one(self):
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command = "downgrade"

        with patch(_DB_PATCH) as mock_run:
            mock_run.return_value = None
            _cmd_db(args)
            call_args = mock_run.call_args[0][0]
            assert "-1" in call_args

    def test_db_current_returns_0(self):
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command = "current"

        with patch(_DB_PATCH) as mock_run:
            mock_run.return_value = None
            result = _cmd_db(args)

        assert result == 0

    def test_db_revision_passes_message(self):
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command    = "revision"
        args.message       = "add_tags_column"
        args.autogenerate  = False

        with patch(_DB_PATCH) as mock_run:
            mock_run.return_value = None
            _cmd_db(args)
            call_args = mock_run.call_args[0][0]
            assert "add_tags_column" in call_args

    def test_db_revision_autogenerate_flag(self):
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command   = "revision"
        args.message      = "auto"
        args.autogenerate = True

        with patch(_DB_PATCH) as mock_run:
            mock_run.return_value = None
            _cmd_db(args)
            call_args = mock_run.call_args[0][0]
            assert "--autogenerate" in call_args

    def test_db_stamp_passes_revision(self):
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command = "stamp"
        args.revision   = "head"

        with patch(_DB_PATCH) as mock_run:
            mock_run.return_value = None
            _cmd_db(args)
            call_args = mock_run.call_args[0][0]
            assert "head" in call_args

    def test_db_missing_alembic_returns_1(self):
        """If gnat.migrations.cli is not importable, returns exit code 1."""
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command = "upgrade"

        with patch.dict(sys.modules, {"gnat.migrations.cli": None}):
            result = _cmd_db(args)
        assert result == 1

    def test_db_command_error_returns_1(self):
        from gnat.cli.main import _cmd_db

        args = MagicMock()
        args.db_command = "upgrade"

        with patch(_DB_PATCH, side_effect=RuntimeError("migration failed")):
            result = _cmd_db(args)

        assert result == 1
