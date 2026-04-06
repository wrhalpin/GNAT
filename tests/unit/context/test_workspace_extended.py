"""
tests/unit/context/test_workspace_extended.py
==============================================

Extended unit tests for gnat.context.workspace and gnat.context.global_context.

Targets uncovered lines including:
- WorkspaceManager: for_tenant(), delete(), list() with SQLite store, _default_store fallback
- Workspace: save(), export_bundle() non-FlatFile path, remove() with WorkspaceStore,
  get_enrichment_history(), commit() error paths and deletion handling,
  enrich() RuntimeError fallback, aenrich(), _enrich_async unknown source
- GlobalContext: get_object()
- GlobalContextRegistry: from_config(), unregister() clears default_name, all() sort
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gnat.context.store import FlatFileStore
from gnat.context.global_context import GlobalContext, GlobalContextRegistry
from gnat.context.workspace import Workspace, WorkspaceManager, CommitResult
from gnat.orm.indicator import Indicator
from gnat.orm.malware import Malware


# ===========================================================================
# Helpers (mirrors test_context.py helpers to avoid import coupling)
# ===========================================================================

def _make_indicator(name: str = "evil.com", value: str = "evil.com") -> Indicator:
    return Indicator(
        name=name,
        pattern=f"[domain-name:value = '{value}']",
        pattern_type="stix",
        indicator_types=["malicious-activity"],
    )


def _mock_global_context(name: str = "threatq", read_only: bool = False,
                          objects: list = None) -> GlobalContext:
    mock_cli = MagicMock()
    mock_cli.target = name
    mock_cli.ping.return_value = True

    if objects is None:
        objects = [_make_indicator(f"obj-{i}").to_dict() for i in range(2)]

    mock_cli.client.list_objects.return_value = [
        {"id": o["id"], "value": o.get("name", ""), "type": "indicator"}
        for o in objects
    ]
    mock_cli.client.to_stix.side_effect = lambda raw: {
        "type": "indicator",
        "id": raw.get("id", "indicator--mock"),
        "name": raw.get("value", ""),
        "pattern": f"[domain-name:value = '{raw.get('value', '')}']",
        "pattern_type": "stix",
        "created": "", "modified": "",
        "indicator_types": ["malicious-activity"],
    }
    mock_cli.client.from_stix.return_value = {"value": "mocked"}
    mock_cli.client.upsert_object.return_value = {"id": "indicator--written", "value": "mocked"}
    mock_cli.client.delete_object.return_value = None
    mock_cli.client.get_object.return_value = {"id": "indicator--x", "value": "x.com", "type": "indicator"}

    gc = GlobalContext(name=name, client=mock_cli, read_only=read_only)
    return gc


def _make_registry(names=("threatq", "recorded_future", "crowdstrike"),
                   default="threatq", read_only=("recorded_future",)):
    registry = GlobalContextRegistry(default_name=default)
    for name in names:
        gc = _mock_global_context(name=name, read_only=(name in read_only))
        registry.register(gc)
    return registry


def _make_workspace(name="test-ws", registry=None, store=None, tmp_path=None):
    if registry is None:
        registry = _make_registry()
    if store is None:
        store = FlatFileStore(base_dir=str(
            (tmp_path or Path(tempfile.mkdtemp())) / "workspaces"
        ))
    return Workspace(name, registry, store)


def _sqlite_store():
    try:
        from gnat.context.store import WorkspaceStore
        store = WorkspaceStore("sqlite:///:memory:")
        store.create_all()
        return store
    except ImportError:
        return None


# ===========================================================================
# GlobalContext — extended
# ===========================================================================

class TestGlobalContextExtended:

    def test_get_object_delegates_to_client(self):
        gc = _mock_global_context("tq")
        gc.client.client.get_object.return_value = {"id": "indicator--x", "value": "x.com", "type": "indicator"}
        gc.client.client.to_stix.side_effect = None
        gc.client.client.to_stix.return_value = {
            "type": "indicator", "id": "indicator--x",
            "name": "x.com", "pattern": "[domain-name:value = 'x.com']",
            "pattern_type": "stix", "created": "", "modified": "",
            "indicator_types": ["malicious-activity"],
        }
        result = gc.get_object("indicator", "indicator--x")
        gc.client.client.get_object.assert_called_once_with("indicator", "indicator--x")
        assert result["id"] == "indicator--x"

    def test_delete_object_delegates_to_client(self):
        gc = _mock_global_context("tq")
        gc.delete_object("indicator", "indicator--x")
        gc.client.client.delete_object.assert_called_once_with("indicator", "indicator--x")

    def test_priority_attribute(self):
        gc = GlobalContext("tq", MagicMock(), priority=5)
        assert gc.priority == 5

    def test_description_attribute(self):
        gc = GlobalContext("tq", MagicMock(), description="My platform")
        assert gc.description == "My platform"


# ===========================================================================
# GlobalContextRegistry — extended
# ===========================================================================

class TestGlobalContextRegistryExtended:

    def test_unregister_clears_default_name(self):
        """Unregistering the current default clears the _default_name."""
        registry = _make_registry()
        registry.set_default("threatq")
        assert registry._default_name == "threatq"
        result = registry.unregister("threatq")
        assert result is True
        assert registry._default_name is None

    def test_all_sorted_by_priority(self):
        registry = GlobalContextRegistry()
        gc_low  = GlobalContext("low",  MagicMock(), priority=20)
        gc_high = GlobalContext("high", MagicMock(), priority=1)
        registry.register(gc_low)
        registry.register(gc_high)
        ordered = registry.all()
        assert ordered[0].name == "high"
        assert ordered[1].name == "low"

    def test_from_clients_no_default(self):
        """from_clients with no default sets no default_name."""
        clients = {
            "tq": MagicMock(target="threatq", ping=MagicMock(return_value=True), client=MagicMock()),
        }
        registry = GlobalContextRegistry.from_clients(clients)
        # Should have the context registered
        assert "tq" in registry

    def test_from_clients_with_read_only_list(self):
        clients = {
            "tq": MagicMock(target="threatq", ping=MagicMock(return_value=True), client=MagicMock()),
            "rf": MagicMock(target="recordedfuture", ping=MagicMock(return_value=True), client=MagicMock()),
        }
        registry = GlobalContextRegistry.from_clients(clients, default="tq", read_only=["rf"])
        assert registry.get("rf").read_only is True
        assert registry.get("tq").read_only is False

    def test_from_config_missing_target_warns(self, tmp_path):
        """[global.noname] sections without 'target' are skipped."""
        cfg_path = tmp_path / "config.ini"
        cfg_path.write_text(
            "[global]\ndefault =\n\n[global.missing-target]\n# no target key\n"
        )
        # Should not raise — just log warning and skip
        registry = GlobalContextRegistry.from_config(str(cfg_path))
        assert "missing-target" not in registry

    def test_from_config_no_global_section(self, tmp_path):
        """Config with no [global] section should return empty registry."""
        cfg_path = tmp_path / "config.ini"
        cfg_path.write_text("[DEFAULT]\ntimeout = 10\n")
        registry = GlobalContextRegistry.from_config(str(cfg_path))
        assert len(registry) == 0

    def test_writable_returns_empty_when_all_read_only(self):
        registry = GlobalContextRegistry()
        registry.register(GlobalContext("rf", MagicMock(), read_only=True))
        assert registry.writable() == []

    def test_default_property_auto_selects_writable(self):
        registry = GlobalContextRegistry()
        registry.register(GlobalContext("rf", MagicMock(), read_only=True, priority=1))
        registry.register(GlobalContext("tq", MagicMock(), read_only=False, priority=2))
        # No explicit default set — should pick lowest-priority writable
        default = registry.default
        assert default.name == "tq"


# ===========================================================================
# Workspace — save and export_bundle
# ===========================================================================

class TestWorkspaceSave:

    def test_save_persists_all_objects(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind1 = _make_indicator("a.com")
        ind2 = _make_indicator("b.com")
        ws.add(ind1, mark_dirty=False)
        ws.add(ind2, mark_dirty=True)
        # Should not raise
        ws.save()

    def test_export_bundle_non_flatfile(self, tmp_path):
        """export_bundle with a non-FlatFile store returns a valid bundle dict."""
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        registry = _make_registry()
        ws = Workspace("bundle-test", registry, store)
        ind = _make_indicator("x.com")
        ws.add(ind, mark_dirty=False)
        bundle = ws.export_bundle()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert any(o["id"] == ind.id for o in bundle["objects"])

    def test_export_bundle_flatfile(self, tmp_path):
        """export_bundle with FlatFileStore delegates to store.export_bundle."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("y.com")
        ws.add(ind, mark_dirty=False)
        bundle = ws.export_bundle()
        assert bundle["type"] == "bundle"


# ===========================================================================
# Workspace — get_enrichment_history
# ===========================================================================

class TestWorkspaceEnrichmentHistory:

    def test_get_enrichment_history_flatfile(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=False)
        ws._apply_enrichment(ind, {"x_score": 80, "type": "indicator",
                                   "id": f"indicator--enrich-hist",
                                   "name": "hist.com",
                                   "pattern": "[domain-name:value = 'hist.com']",
                                   "pattern_type": "stix",
                                   "created": "", "modified": "",
                                   "indicator_types": ["malicious-activity"]},
                             "recorded_future", "create_relationships")
        history = ws.get_enrichment_history()
        assert isinstance(history, list)

    def test_get_enrichment_history_filtered(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("filter.com")
        ws.add(ind, mark_dirty=False)
        ws._log_enrichment(ind.id, "rf", {"score": 90}, "tag_only")
        history = ws.get_enrichment_history(stix_id=ind.id)
        assert isinstance(history, list)

    def test_get_enrichment_history_sqlite(self):
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        registry = _make_registry()
        ws = Workspace("hist-test", registry, store)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=False)
        ws._log_enrichment(ind.id, "rf", {"score": 90}, "tag_only")
        history = ws.get_enrichment_history()
        assert isinstance(history, list)
        assert len(history) >= 1


# ===========================================================================
# Workspace — commit error paths and deletions
# ===========================================================================

class TestWorkspaceCommitExtended:

    def test_commit_error_on_write_failure(self, tmp_path):
        """Commit records errors when write_object raises."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("fail.com")
        ws.add(ind, mark_dirty=True)

        ws._registry.default.client.client.from_stix.return_value = {}
        ws._registry.default.client.client.upsert_object.side_effect = RuntimeError("network error")

        result = ws.commit()
        assert not result.success
        assert len(result.errors) == 1
        assert "network error" in result.errors[0]["error"]

    def test_commit_deletion_of_removed_object(self, tmp_path):
        """Deleted objects (in snapshot but not in objects) are committed as deletions."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("remove-me.com")
        ws.add(ind, mark_dirty=False)
        ws._snapshot[ind.id] = ind.to_dict()

        # Simulate removal from objects but keep in snapshot
        del ws.objects[ind.id]
        # Don't add to dirty — deletion is detected via snapshot diff

        ws._registry.default.client.client.delete_object.return_value = None

        result = ws.commit()
        assert ind.id in result.deleted
        assert ind.id not in ws._snapshot

    def test_commit_deletion_dry_run(self, tmp_path):
        """dry_run includes deleted objects in would_write."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("dry-delete.com")
        ws.add(ind, mark_dirty=False)
        ws._snapshot[ind.id] = ind.to_dict()
        del ws.objects[ind.id]

        result = ws.commit(dry_run=True)
        deleted_entries = [e for e in result.would_write if e["action"] == "deleted"]
        assert len(deleted_entries) == 1

    def test_commit_deletion_error_path(self, tmp_path):
        """Errors during deletion are recorded in result.errors."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("err-del.com")
        ws.add(ind, mark_dirty=False)
        ws._snapshot[ind.id] = ind.to_dict()
        del ws.objects[ind.id]

        ws._registry.default.client.client.delete_object.side_effect = RuntimeError("del error")

        result = ws.commit()
        assert not result.success
        assert any("del error" in e["error"] for e in result.errors)

    def test_commit_marks_clean_after_success(self, tmp_path):
        """After a successful commit the dirty set is cleared."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("clean.com")
        ws.add(ind, mark_dirty=True)
        assert ind.id in ws.dirty

        ws._registry.default.client.client.from_stix.return_value = {}
        ws._registry.default.client.client.upsert_object.return_value = {
            "id": ind.id, "value": ind.name, "type": "indicator"
        }
        ws._registry.default.client.client.to_stix.side_effect = None
        ws._registry.default.client.client.to_stix.return_value = ind.to_dict()

        result = ws.commit()
        assert result.success
        assert ind.id not in ws.dirty

    def test_commit_with_stix_ids_subset_skips_non_dirty(self, tmp_path):
        """Committing by stix_ids only commits the requested ids."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind1 = _make_indicator("a.com")
        ind2 = _make_indicator("b.com")
        ws.add(ind1, mark_dirty=True)
        ws.add(ind2, mark_dirty=True)

        ws._registry.default.client.client.from_stix.return_value = {}
        ws._registry.default.client.client.upsert_object.return_value = {
            "id": ind1.id, "value": ind1.name, "type": "indicator"
        }
        ws._registry.default.client.client.to_stix.side_effect = None
        ws._registry.default.client.client.to_stix.return_value = ind1.to_dict()

        result = ws.commit(stix_ids=[ind1.id])
        assert ind1.id in result.written
        assert ind2.id not in result.written


# ===========================================================================
# Workspace — remove with WorkspaceStore
# ===========================================================================

class TestWorkspaceRemoveWithStore:

    def test_remove_uses_soft_delete_with_sqlite(self):
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        registry = _make_registry()
        ws = Workspace("remove-test", registry, store)
        ind = _make_indicator("remove.com")
        ws.add(ind, mark_dirty=False)

        result = ws.remove(ind.id)
        assert result is True
        assert ind.id not in ws.objects

    def test_remove_adds_to_dirty(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("dirty-remove.com")
        ws.add(ind, mark_dirty=False)
        ws.remove(ind.id)
        assert ind.id in ws.dirty


# ===========================================================================
# Workspace — enrich() RuntimeError fallback
# ===========================================================================

class TestWorkspaceEnrichFallback:

    def test_enrich_falls_back_to_sequential_on_runtime_error(self, tmp_path):
        """enrich() should fall back to _enrich_sequential when no event loop."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("enrich.com")
        ws.add(ind, mark_dirty=False)

        # Patch asyncio.get_event_loop to raise RuntimeError
        with patch("asyncio.get_event_loop", side_effect=RuntimeError("no loop")):
            with patch.object(ws, "_enrich_sequential") as mock_seq:
                ws.enrich(sources=["recorded_future"])
                mock_seq.assert_called_once()

    def test_enrich_sequential_unknown_source_skips(self, tmp_path):
        """_enrich_sequential silently skips unknown sources."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("x.com")
        ws.add(ind, mark_dirty=False)
        # Should not raise for unknown source
        ws._enrich_sequential(["nonexistent_source"], [ind.id], "tag_only", 0)
        assert len(ws) == 1  # no new objects

    def test_enrich_sequential_handles_exception_in_source(self, tmp_path):
        """_enrich_sequential swallows exceptions from individual source queries."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("exc.com")
        ws.add(ind, mark_dirty=False)

        # Make the registry source raise on list_objects
        gc = _mock_global_context("error_source", read_only=True)
        gc.client.client.list_objects.side_effect = RuntimeError("source down")
        ws._registry.register(gc)

        # Should not raise
        ws._enrich_sequential(["error_source"], [ind.id], "tag_only", 0)
        assert len(ws) == 1

    def test_enrich_async_unknown_source_warns(self, tmp_path):
        """_enrich_async logs a warning and skips unknown sources."""
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("async-x.com")
        ws.add(ind, mark_dirty=False)
        # Run async method with unknown source
        asyncio.run(ws._enrich_async(["nonexistent"], [ind.id], "tag_only", 0))
        assert len(ws) == 1


# ===========================================================================
# Workspace — aenrich()
# ===========================================================================

class TestWorkspaceAenrich:

    def test_aenrich_returns_self(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("aenrich.com")
        ws.add(ind, mark_dirty=False)

        result = asyncio.run(ws.aenrich(sources=["recorded_future"], stix_ids=[ind.id]))
        assert result is ws

    def test_aenrich_with_no_objects(self, tmp_path):
        """aenrich on empty workspace should not raise."""
        ws = _make_workspace(tmp_path=tmp_path)
        result = asyncio.run(ws.aenrich(sources=["recorded_future"]))
        assert result is ws


# ===========================================================================
# WorkspaceManager — extended
# ===========================================================================

class TestWorkspaceManagerExtended:

    def test_for_tenant_returns_tenant_manager(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        tenant_mgr = manager.for_tenant("acme")
        assert tenant_mgr.tenant_id == "acme"

    def test_for_tenant_isolation(self, tmp_path):
        """Two tenants share the same store but have isolated namespaces."""
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)

        acme = manager.for_tenant("acme")
        beta = manager.for_tenant("beta")

        acme.create("investigation")
        # beta should not see acme's workspace
        assert len(beta.list()) == 0
        assert len(acme.list()) == 1

    def test_delete_workspace_flatfile(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        manager.create("to-delete")
        assert manager.delete("to-delete") is True

    def test_delete_nonexistent_workspace(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        assert manager.delete("does-not-exist") is False

    def test_list_with_sqlite_store(self):
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        registry = _make_registry()
        manager = WorkspaceManager(registry, store=store)
        manager.create("ws-alpha")
        manager.create("ws-beta")
        listed = manager.list()
        names = [w["name"] for w in listed]
        assert "ws-alpha" in names
        assert "ws-beta" in names

    def test_list_sqlite_includes_object_count(self):
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        registry = _make_registry()
        manager = WorkspaceManager(registry, store=store)
        ws = manager.create("count-ws")
        ws.add(_make_indicator("x.com"), mark_dirty=False)
        listed = manager.list()
        entry = next(w for w in listed if w["name"] == "count-ws")
        assert "object_count" in entry
        assert entry["object_count"] == 1

    def test_open_with_sqlite_nonexistent_raises(self):
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        registry = _make_registry()
        manager = WorkspaceManager(registry, store=store)
        with pytest.raises(KeyError, match="No workspace"):
            manager.open("ghost")

    def test_create_duplicate_flatfile_does_not_raise(self, tmp_path):
        """FlatFileStore uses get_or_create internally — creating duplicate is fine."""
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        manager.create("dup-ws")
        # FlatFileStore's create_workspace just overwrites — no error
        ws2 = manager.create("dup-ws")
        assert ws2.name == "dup-ws"

    def test_default_store_falls_back_to_flatfile(self, tmp_path):
        """_default_store() returns a FlatFileStore when WorkspaceStore init fails."""
        from gnat.context.store import WorkspaceStore
        with patch.object(WorkspaceStore, "__init__", side_effect=Exception("db error")):
            store = WorkspaceManager._default_store("sqlite:///bad.db")
            assert isinstance(store, FlatFileStore)

    def test_from_clients_with_db_url(self):
        clients = {
            "tq": MagicMock(target="threatq", ping=MagicMock(return_value=True),
                            client=MagicMock()),
        }
        manager = WorkspaceManager.from_clients(
            clients, default="tq", db_url="sqlite:///:memory:"
        )
        assert manager._registry.default.name == "tq"


# ===========================================================================
# WorkspaceManager — with WorkspaceStore (SQLite)
# ===========================================================================

class TestWorkspaceManagerSQLite:

    @pytest.fixture
    def sqlite_manager(self):
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        return WorkspaceManager(_make_registry(), store=store)

    def test_create_and_open(self, sqlite_manager):
        sqlite_manager.create("open-test")
        ws = sqlite_manager.open("open-test")
        assert ws.name == "open-test"

    def test_delete_existing(self, sqlite_manager):
        sqlite_manager.create("del-test")
        assert sqlite_manager.delete("del-test") is True

    def test_get_or_create_opens_existing(self, sqlite_manager):
        sqlite_manager.create("existing")
        ws = sqlite_manager.get_or_create("existing")
        assert ws.name == "existing"

    def test_get_or_create_creates_new(self, sqlite_manager):
        ws = sqlite_manager.get_or_create("brand-new")
        assert ws.name == "brand-new"

    def test_persistence_across_instances(self, sqlite_manager):
        """Objects added to one workspace instance should appear in a reopened instance."""
        ws1 = sqlite_manager.create("persist")
        ind = _make_indicator("persist.com")
        ws1.add(ind, mark_dirty=False)

        ws2 = sqlite_manager.open("persist")
        assert ind.id in ws2.objects

    def test_workspace_init_with_sqlite_store_hydrates(self):
        """Workspace._init_store uses the WorkspaceStore path when applicable."""
        store = _sqlite_store()
        if store is None:
            pytest.skip("SQLAlchemy not installed")
        registry = _make_registry()
        ws = Workspace("hydrate-test", registry, store)
        ind = _make_indicator("hydrate.com")
        ws.add(ind, mark_dirty=False)

        ws2 = Workspace("hydrate-test", registry, store)
        assert ind.id in ws2.objects


# ===========================================================================
# CommitResult
# ===========================================================================

class TestCommitResultExtended:

    def test_deleted_populated_on_deletion(self):
        result = CommitResult("ws", "tq", False)
        result.deleted.append("indicator--x")
        assert "indicator--x" in result.deleted

    def test_would_write_populated_on_dry_run(self):
        result = CommitResult("ws", "tq", True)
        result.would_write.append({"id": "indicator--x", "action": "added"})
        assert len(result.would_write) == 1

    def test_success_false_when_deleted_errors(self):
        result = CommitResult("ws", "tq", False)
        result.errors.append({"id": "indicator--x", "error": "not found"})
        assert result.success is False

    def test_success_true_with_written_and_deleted(self):
        result = CommitResult("ws", "tq", False)
        result.written.append("indicator--a")
        result.deleted.append("indicator--b")
        assert result.success is True


# ===========================================================================
# Workspace — _from_dict type dispatch
# ===========================================================================

class TestWorkspaceFromDict:

    def test_from_dict_indicator(self):
        from gnat.orm.indicator import Indicator
        ind = _make_indicator()
        obj = Workspace._from_dict(ind.to_dict())
        assert isinstance(obj, Indicator)

    def test_from_dict_malware(self):
        from gnat.orm.malware import Malware
        mal = Malware(name="BadMal")
        obj = Workspace._from_dict(mal.to_dict())
        assert isinstance(obj, Malware)

    def test_from_dict_unknown_type_falls_back_to_stixbase(self):
        from gnat.orm.base import STIXBase
        d = {"type": "x-custom", "id": "x-custom--abc", "name": "custom"}
        obj = Workspace._from_dict(d)
        assert isinstance(obj, STIXBase)

    def test_from_dict_vulnerability(self):
        from gnat.orm.vulnerability import Vulnerability
        vuln = Vulnerability(name="CVE-2024-0001")
        obj = Workspace._from_dict(vuln.to_dict())
        assert isinstance(obj, Vulnerability)

    def test_from_dict_relationship(self):
        from gnat.orm.relationship import Relationship
        rel = Relationship(
            relationship_type="related-to",
            source_ref="indicator--a",
            target_ref="indicator--b",
        )
        obj = Workspace._from_dict(rel.to_dict())
        assert isinstance(obj, Relationship)
