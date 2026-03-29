"""
tests/unit/context/test_context.py
====================================

Unit tests for the GNAT context system.

Covers:
- FlatFileStore: create/get/list/delete workspaces, object CRUD,
  enrichment log, export_bundle
- WorkspaceStore: same surface via SQLite in-memory
- GlobalContext: delegation, read-only guard
- GlobalContextRegistry: register, default, writable/read-only lists,
  from_clients
- Workspace: load, add, remove, diff, commit, enrich strategies
  (create_relationships, merge_extensions, tag_only),
  persist-on-mutation, export_bundle
- WorkspaceManager: create/open/get_or_create/list/delete,
  from_clients factory, auto-fallback to FlatFileStore
- CommitResult: success flag, dry_run
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gnat.context.store import FlatFileStore
from gnat.context.global_context import GlobalContext, GlobalContextRegistry
from gnat.context.workspace import Workspace, WorkspaceManager, CommitResult
from gnat.orm.indicator import Indicator
from gnat.orm.malware import Malware


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def tmp_flat_store(tmp_path):
    """FlatFileStore backed by a temporary directory."""
    return FlatFileStore(base_dir=str(tmp_path / "workspaces"))


@pytest.fixture
def sqlite_store():
    """WorkspaceStore backed by in-memory SQLite."""
    try:
        from gnat.context.store import WorkspaceStore
        store = WorkspaceStore("sqlite:///:memory:")
        store.create_all()
        return store
    except ImportError:
        pytest.skip("SQLAlchemy not installed")


def _make_indicator(name: str = "evil.com", value: str = "evil.com") -> Indicator:
    return Indicator(
        name=name,
        pattern=f"[domain-name:value = '{value}']",
        pattern_type="stix",
        indicator_types=["malicious-activity"],
    )


def _make_stix_dict(stix_id: str = None, name: str = "evil.com",
                    stix_type: str = "indicator") -> dict:
    ind = _make_indicator(name)
    d = ind.to_dict()
    if stix_id:
        d["id"] = stix_id
    return d


def _mock_global_context(name: str = "threatq", read_only: bool = False,
                         objects: list = None) -> GlobalContext:
    """Create a GlobalContext with a mocked GNATClient."""
    mock_cli = MagicMock()
    mock_cli.target = name
    mock_cli.ping.return_value = True

    if objects is None:
        objects = [_make_stix_dict(name=f"obj-{i}") for i in range(3)]

    mock_cli.client.list_objects.return_value = [
        {"id": o["id"], "value": o.get("name", ""), "type": "indicator"}
        for o in objects
    ]
    mock_cli.client.to_stix.side_effect = lambda raw: {
        "type": "indicator",
        "id": raw.get("id", f"indicator--mock"),
        "name": raw.get("value", ""),
        "pattern": f"[domain-name:value = '{raw.get('value', '')}']",
        "pattern_type": "stix",
        "created": "", "modified": "",
        "indicator_types": ["malicious-activity"],
    }
    mock_cli.client.from_stix.return_value = {"value": "mocked"}
    mock_cli.client.upsert_object.return_value = {"id": "indicator--written", "value": "mocked"}
    mock_cli.client.delete_object.return_value = None

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


# ===========================================================================
# FlatFileStore
# ===========================================================================

class TestFlatFileStore:

    def test_create_workspace(self, tmp_flat_store):
        meta = tmp_flat_store.create_workspace("inv1", description="Test investigation")
        assert meta["name"] == "inv1"
        assert meta["description"] == "Test investigation"

    def test_get_workspace(self, tmp_flat_store):
        tmp_flat_store.create_workspace("inv2")
        ws = tmp_flat_store.get_workspace("inv2")
        assert ws is not None
        assert ws["name"] == "inv2"

    def test_get_nonexistent_workspace_returns_none(self, tmp_flat_store):
        assert tmp_flat_store.get_workspace("nonexistent") is None

    def test_get_or_create(self, tmp_flat_store):
        ws1 = tmp_flat_store.get_or_create_workspace("inv3")
        ws2 = tmp_flat_store.get_or_create_workspace("inv3")
        assert ws1["name"] == ws2["name"]

    def test_list_workspaces(self, tmp_flat_store):
        tmp_flat_store.create_workspace("a")
        tmp_flat_store.create_workspace("b")
        lst = tmp_flat_store.list_workspaces()
        names = [w["name"] for w in lst]
        assert "a" in names and "b" in names

    def test_delete_workspace(self, tmp_flat_store):
        tmp_flat_store.create_workspace("to-delete")
        assert tmp_flat_store.delete_workspace("to-delete") is True
        assert tmp_flat_store.get_workspace("to-delete") is None

    def test_delete_nonexistent_returns_false(self, tmp_flat_store):
        assert tmp_flat_store.delete_workspace("nope") is False

    def test_save_and_get_object(self, tmp_flat_store):
        tmp_flat_store.create_workspace("obj-ws")
        stix = _make_stix_dict(name="evil.com")
        tmp_flat_store.save_object("obj-ws", stix, source_platform="threatq")
        objects = tmp_flat_store.get_objects("obj-ws")
        assert len(objects) == 1
        assert objects[0]["name"] == "evil.com"

    def test_get_objects_filtered_by_type(self, tmp_flat_store):
        tmp_flat_store.create_workspace("type-ws")
        ind = _make_stix_dict(stix_type="indicator", name="evil.com")
        mal = Malware(name="BadMal").to_dict()
        tmp_flat_store.save_object("type-ws", ind)
        tmp_flat_store.save_object("type-ws", mal)
        indicators = tmp_flat_store.get_objects("type-ws", stix_type="indicator")
        assert all(o["type"] == "indicator" for o in indicators)

    def test_dirty_objects(self, tmp_flat_store):
        tmp_flat_store.create_workspace("dirty-ws")
        stix = _make_stix_dict()
        tmp_flat_store.save_object("dirty-ws", stix, is_dirty=True)
        dirty = tmp_flat_store.get_dirty_objects("dirty-ws")
        assert len(dirty) == 1

    def test_delete_object(self, tmp_flat_store):
        tmp_flat_store.create_workspace("del-ws")
        stix = _make_stix_dict()
        stix_id = stix["id"]
        tmp_flat_store.save_object("del-ws", stix)
        assert tmp_flat_store.delete_object("del-ws", stix_id) is True
        assert len(tmp_flat_store.get_objects("del-ws")) == 0

    def test_object_count(self, tmp_flat_store):
        tmp_flat_store.create_workspace("count-ws")
        for i in range(4):
            tmp_flat_store.save_object("count-ws", _make_stix_dict(name=f"obj{i}"))
        assert tmp_flat_store.object_count("count-ws") == 4

    def test_enrichment_log(self, tmp_flat_store):
        tmp_flat_store.create_workspace("enrich-ws")
        stix = _make_stix_dict()
        tmp_flat_store.log_enrichment("enrich-ws", stix["id"], "rf",
                                      {"score": 85}, "create_relationships")
        log = tmp_flat_store.get_enrichment_history("enrich-ws")
        assert len(log) == 1
        assert log[0]["source_platform"] == "rf"
        assert log[0]["data"]["score"] == 85

    def test_enrichment_log_filtered_by_id(self, tmp_flat_store):
        tmp_flat_store.create_workspace("log-ws")
        id1 = _make_stix_dict(name="a")["id"]
        id2 = _make_stix_dict(name="b")["id"]
        tmp_flat_store.log_enrichment("log-ws", id1, "rf", {}, "tag_only")
        tmp_flat_store.log_enrichment("log-ws", id2, "cs", {}, "tag_only")
        log = tmp_flat_store.get_enrichment_history("log-ws", stix_id=id1)
        assert len(log) == 1 and log[0]["stix_id"] == id1

    def test_export_bundle(self, tmp_flat_store):
        tmp_flat_store.create_workspace("bundle-ws")
        for i in range(3):
            tmp_flat_store.save_object("bundle-ws", _make_stix_dict(name=f"obj{i}"))
        bundle = tmp_flat_store.export_bundle("bundle-ws")
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) == 3


# ===========================================================================
# WorkspaceStore (SQLAlchemy / SQLite in-memory)
# ===========================================================================

class TestWorkspaceStore:

    def test_create_and_get_workspace(self, sqlite_store):
        ws = sqlite_store.create_workspace("sql-ws", description="SQL test")
        assert ws.name == "sql-ws"
        fetched = sqlite_store.get_workspace("sql-ws")
        assert fetched is not None
        assert fetched.name == "sql-ws"

    def test_list_workspaces(self, sqlite_store):
        sqlite_store.create_workspace("a")
        sqlite_store.create_workspace("b")
        names = [w.name for w in sqlite_store.list_workspaces()]
        assert "a" in names and "b" in names

    def test_delete_workspace(self, sqlite_store):
        sqlite_store.create_workspace("del-sql")
        assert sqlite_store.delete_workspace("del-sql") is True
        assert sqlite_store.get_workspace("del-sql") is None

    def test_upsert_and_get_objects(self, sqlite_store):
        ws = sqlite_store.create_workspace("obj-sql")
        stix = _make_stix_dict(name="test.com")
        sqlite_store.upsert_object(ws.id, stix, source_platform="threatq")
        objects = sqlite_store.get_objects(ws.id)
        assert len(objects) == 1
        assert objects[0]["name"] == "test.com"

    def test_upsert_updates_existing(self, sqlite_store):
        ws = sqlite_store.create_workspace("update-sql")
        stix = _make_stix_dict(name="original.com")
        sqlite_store.upsert_object(ws.id, stix)
        stix["name"] = "updated.com"
        sqlite_store.upsert_object(ws.id, stix)
        objects = sqlite_store.get_objects(ws.id)
        assert len(objects) == 1  # not duplicated
        assert objects[0]["name"] == "updated.com"

    def test_dirty_tracking(self, sqlite_store):
        ws = sqlite_store.create_workspace("dirty-sql")
        stix = _make_stix_dict()
        sqlite_store.upsert_object(ws.id, stix, is_dirty=True)
        dirty = sqlite_store.get_dirty_objects(ws.id)
        assert len(dirty) == 1
        sqlite_store.mark_clean(ws.id)
        assert len(sqlite_store.get_dirty_objects(ws.id)) == 0

    def test_soft_delete(self, sqlite_store):
        ws = sqlite_store.create_workspace("soft-del")
        stix = _make_stix_dict()
        sqlite_store.upsert_object(ws.id, stix)
        sqlite_store.soft_delete_object(ws.id, stix["id"])
        objects = sqlite_store.get_objects(ws.id, include_deleted=False)
        assert len(objects) == 0
        objects_with_deleted = sqlite_store.get_objects(ws.id, include_deleted=True)
        assert len(objects_with_deleted) == 1

    def test_enrichment_log(self, sqlite_store):
        ws = sqlite_store.create_workspace("enrich-sql")
        stix = _make_stix_dict()
        sqlite_store.log_enrichment(ws.id, stix["id"], "rf", {"score": 90}, "tag_only")
        log = sqlite_store.get_enrichment_history(ws.id)
        assert len(log) == 1
        assert log[0]["source_platform"] == "rf"

    def test_object_count(self, sqlite_store):
        ws = sqlite_store.create_workspace("count-sql")
        for i in range(5):
            sqlite_store.upsert_object(ws.id, _make_stix_dict(name=f"obj{i}"))
        assert sqlite_store.object_count(ws.id) == 5


# ===========================================================================
# GlobalContext
# ===========================================================================

class TestGlobalContext:

    def test_target_property(self):
        gc = _mock_global_context("threatq")
        assert gc.target == "threatq"

    def test_ping_delegates(self):
        gc = _mock_global_context()
        assert gc.ping() is True

    def test_list_objects_returns_stix(self):
        gc = _mock_global_context(objects=[_make_stix_dict()])
        results = gc.list_objects("indicator")
        assert isinstance(results, list)
        assert all("type" in r for r in results)

    def test_write_object_raises_on_read_only(self):
        gc = _mock_global_context(read_only=True)
        with pytest.raises(PermissionError, match="read-only"):
            gc.write_object(_make_stix_dict())

    def test_delete_object_raises_on_read_only(self):
        gc = _mock_global_context(read_only=True)
        with pytest.raises(PermissionError, match="read-only"):
            gc.delete_object("indicator", "indicator--123")

    def test_write_object_delegates_to_client(self):
        gc = _mock_global_context()
        gc.client.client.to_stix.return_value = _make_stix_dict()
        result = gc.write_object(_make_stix_dict())
        gc.client.client.upsert_object.assert_called_once()
        assert isinstance(result, dict)


# ===========================================================================
# GlobalContextRegistry
# ===========================================================================

class TestGlobalContextRegistry:

    def test_register_and_get(self):
        registry = GlobalContextRegistry()
        gc = _mock_global_context("tq")
        registry.register(gc)
        assert registry.get("tq") is gc

    def test_get_missing_raises(self):
        registry = GlobalContextRegistry()
        with pytest.raises(KeyError):
            registry.get("missing")

    def test_set_default(self):
        registry = _make_registry()
        registry.set_default("crowdstrike")
        assert registry.default.name == "crowdstrike"

    def test_set_default_missing_raises(self):
        registry = GlobalContextRegistry()
        with pytest.raises(KeyError):
            registry.set_default("nope")

    def test_default_falls_back_to_first_writable(self):
        registry = GlobalContextRegistry()
        registry.register(_mock_global_context("rf", read_only=True))
        registry.register(_mock_global_context("tq", read_only=False))
        assert registry.default.name == "tq"

    def test_default_raises_if_all_read_only(self):
        registry = GlobalContextRegistry()
        registry.register(_mock_global_context("rf", read_only=True))
        with pytest.raises(RuntimeError, match="No writable"):
            _ = registry.default

    def test_writable_excludes_read_only(self):
        registry = _make_registry(
            names=("tq", "rf", "cs"),
            read_only=("rf",),
        )
        writable = registry.writable()
        assert all(not g.read_only for g in writable)
        assert not any(g.name == "rf" for g in writable)

    def test_read_only_contexts(self):
        registry = _make_registry(read_only=("recorded_future",))
        ro = registry.read_only_contexts()
        assert all(g.read_only for g in ro)

    def test_from_clients(self):
        clients = {
            "tq": MagicMock(target="threatq"),
            "rf": MagicMock(target="recordedfuture"),
        }
        for c in clients.values():
            c.ping.return_value = True
            c.client = MagicMock()
        registry = GlobalContextRegistry.from_clients(
            clients, default="tq", read_only=["rf"]
        )
        assert registry.default.name == "tq"
        assert registry.get("rf").read_only is True

    def test_unregister(self):
        registry = _make_registry()
        assert registry.unregister("crowdstrike") is True
        assert "crowdstrike" not in registry

    def test_len_and_iter(self):
        registry = _make_registry(names=("a", "b", "c"))
        assert len(registry) == 3
        names = [g.name for g in registry]
        assert set(names) == {"a", "b", "c"}

    def test_contains(self):
        registry = _make_registry()
        assert "threatq" in registry
        assert "nonexistent" not in registry


# ===========================================================================
# Workspace
# ===========================================================================

class TestWorkspace:

    def test_empty_workspace(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        assert len(ws) == 0
        assert list(ws) == []

    def test_add_object(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind)
        assert ind.id in ws
        assert len(ws) == 1

    def test_add_marks_dirty(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=True)
        assert ind.id in ws.dirty

    def test_add_not_dirty(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=False)
        assert ind.id not in ws.dirty

    def test_remove_object(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=False)
        assert ws.remove(ind.id) is True
        assert ind.id not in ws.objects

    def test_remove_nonexistent_returns_false(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        assert ws.remove("indicator--nonexistent") is False

    def test_contains(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=False)
        assert ind.id in ws
        assert "indicator--nope" not in ws

    def test_persistence_across_instances(self, tmp_path):
        """Objects added to ws1 should be visible when ws2 opens the same workspace."""
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        registry = _make_registry()
        ws1 = Workspace("persist-test", registry, store)
        ind = _make_indicator("persistent.com")
        ws1.add(ind, mark_dirty=False)

        ws2 = Workspace("persist-test", registry, store)
        assert ind.id in ws2.objects
        assert ws2.objects[ind.id].name == "persistent.com"

    def test_load_from_global(self, tmp_path):
        registry = _make_registry()
        # The mock returns 3 objects
        ws = _make_workspace(registry=registry, tmp_path=tmp_path)
        ws.load("indicator", source="threatq")
        assert len(ws) == 3

    def test_diff_added(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=True)
        diff = ws.diff()
        assert ind.id in diff
        assert diff[ind.id]["action"] == "added"

    def test_diff_modified(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=False)
        # Modify after add — simulate by mutating snapshot separately
        ws._snapshot[ind.id] = dict(ind.to_dict())
        ind.description = "Modified"
        ws.objects[ind.id] = ind
        diff = ws.diff()
        assert diff[ind.id]["action"] == "modified"
        assert "description" in diff[ind.id]["changed_fields"]

    def test_diff_empty_when_clean(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=False)
        ws._snapshot[ind.id] = ind.to_dict()   # snapshot matches
        assert ws.diff() == {}

    def test_export_bundle(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ws.add(_make_indicator("a.com"), mark_dirty=False)
        ws.add(_make_indicator("b.com"), mark_dirty=False)
        bundle = ws.export_bundle()
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 2


# ===========================================================================
# Workspace enrichment strategies
# ===========================================================================

class TestWorkspaceEnrichment:

    def _ws_with_one_object(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator("target.com")
        ws.add(ind, mark_dirty=False)
        ws._snapshot[ind.id] = ind.to_dict()
        return ws, ind

    def _enrichment_dict(self, name="rf-result.com", score=90):
        return {
            "type":          "indicator",
            "id":            f"indicator--rf-{name}",
            "name":          name,
            "pattern":       f"[domain-name:value = '{name}']",
            "pattern_type":  "stix",
            "created":       "",
            "modified":      "",
            "indicator_types": ["malicious-activity"],
            "x_rf_risk_score": score,
            "confidence":    score,
        }

    def test_strategy_create_relationships(self, tmp_path):
        ws, ind = self._ws_with_one_object(tmp_path)
        enrichment = self._enrichment_dict()
        gc = _mock_global_context("recorded_future", read_only=True)
        ws._registry.register(gc)

        ws._apply_enrichment(ind, enrichment, "recorded_future", "create_relationships")

        # Should have added: original + enrichment object + relationship
        assert len(ws) == 3
        rel_objects = [o for o in ws.objects.values() if o.stix_type == "relationship"]
        assert len(rel_objects) == 1
        assert rel_objects[0].relationship_type == "related-to"
        assert rel_objects[0].source_ref == ind.id

    def test_strategy_merge_extensions(self, tmp_path):
        ws, ind = self._ws_with_one_object(tmp_path)
        enrichment = self._enrichment_dict(score=95)

        ws._apply_enrichment(ind, enrichment, "recorded_future", "merge_extensions")

        # Original object should now have x_rf_risk_score
        assert ws.objects[ind.id]._properties.get("x_rf_risk_score") == 95
        assert ind.id in ws.dirty
        # No new objects added
        assert len(ws) == 1

    def test_strategy_tag_only(self, tmp_path):
        ws, ind = self._ws_with_one_object(tmp_path)
        enrichment = self._enrichment_dict()

        ws._apply_enrichment(ind, enrichment, "recorded_future", "tag_only")

        tags = ws.objects[ind.id]._properties.get("x_enrichment_tags", [])
        assert "recorded_future:enriched" in tags
        assert len(ws) == 1  # no new objects

    def test_invalid_strategy_raises(self, tmp_path):
        ws, ind = self._ws_with_one_object(tmp_path)
        with pytest.raises(ValueError, match="Unknown enrichment strategy"):
            ws._apply_enrichment(ind, {}, "src", "invalid_strategy")

    def test_confidence_floor_filters(self, tmp_path):
        """Enrichment below confidence_floor should be dropped."""
        ws, ind = self._ws_with_one_object(tmp_path)
        # Set up enrichment source that returns low-confidence data
        gc = _mock_global_context("rf", read_only=True)
        gc.client.client.list_objects.return_value = [
            {"id": "indicator--low", "value": "low.com", "type": "indicator"}
        ]
        # Clear side_effect so return_value is used (side_effect takes priority in MagicMock)
        gc.client.client.to_stix.side_effect = None
        gc.client.client.to_stix.return_value = {
            "type": "indicator", "id": "indicator--low",
            "name": "low.com", "pattern": "[domain-name:value = 'low.com']",
            "pattern_type": "stix", "created": "", "modified": "",
            "confidence": 10,  # below floor
        }
        ws._registry.register(gc)
        ws._enrich_sequential(["rf"], [ind.id], "create_relationships", confidence_floor=50)
        # Low-confidence enrichment should be filtered out — no new objects
        assert len(ws) == 1


# ===========================================================================
# Workspace commit
# ===========================================================================

class TestWorkspaceCommit:

    def test_commit_writes_dirty_objects(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=True)

        # Mock the write
        ws._registry.default.client.client.upsert_object.return_value = {
            "id": ind.id, "value": ind.name, "type": "indicator"
        }
        ws._registry.default.client.client.to_stix.return_value = ind.to_dict()
        ws._registry.default.client.client.from_stix.return_value = {"value": ind.name}

        result = ws.commit()
        assert result.success
        assert ind.id in result.written
        # After commit, object should not be dirty
        assert ind.id not in ws.dirty

    def test_dry_run_does_not_write(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=True)

        result = ws.commit(dry_run=True)
        assert result.dry_run is True
        assert len(result.would_write) == 1
        assert result.would_write[0]["action"] == "added"
        # Client should not have been called
        ws._registry.default.client.client.upsert_object.assert_not_called()

    def test_commit_to_specific_target(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind = _make_indicator()
        ws.add(ind, mark_dirty=True)
        ws._registry.default.client.client.to_stix.return_value = ind.to_dict()
        ws._registry.default.client.client.from_stix.return_value = {}

        result = ws.commit(target="threatq")
        assert result.target_platform == "threatq"

    def test_commit_to_read_only_raises(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ws.add(_make_indicator(), mark_dirty=True)
        with pytest.raises(PermissionError, match="read-only"):
            ws.commit(target="recorded_future")

    def test_commit_result_success_flag(self):
        result = CommitResult("ws", "tq", False)
        assert result.success is True
        result.errors.append({"id": "x", "error": "fail"})
        assert result.success is False

    def test_commit_subset_of_ids(self, tmp_path):
        ws = _make_workspace(tmp_path=tmp_path)
        ind1 = _make_indicator("a.com")
        ind2 = _make_indicator("b.com")
        ws.add(ind1, mark_dirty=True)
        ws.add(ind2, mark_dirty=True)

        ws._registry.default.client.client.to_stix.return_value = ind1.to_dict()
        ws._registry.default.client.client.from_stix.return_value = {}

        result = ws.commit(stix_ids=[ind1.id])
        assert ind1.id in result.written
        assert ind2.id not in result.written


# ===========================================================================
# WorkspaceManager
# ===========================================================================

class TestWorkspaceManager:

    def test_create_workspace(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        ws = manager.create("new-ws", description="Test")
        assert ws.name == "new-ws"
        assert len(ws) == 0

    def test_create_duplicate_raises(self, tmp_path):
        try:
            from gnat.context.store import WorkspaceStore
            store = WorkspaceStore("sqlite:///:memory:")
            store.create_all()
            manager = WorkspaceManager(_make_registry(), store=store)
            manager.create("dup-ws")
            with pytest.raises(ValueError, match="already exists"):
                manager.create("dup-ws")
        except ImportError:
            pytest.skip("SQLAlchemy not installed")

    def test_open_existing(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        registry = _make_registry()
        manager = WorkspaceManager(registry, store=store)
        ws1 = manager.create("open-test")
        ws1.add(_make_indicator(), mark_dirty=False)

        ws2 = manager.open("open-test")
        assert ws2.name == "open-test"
        assert len(ws2) == 1

    def test_open_nonexistent_raises(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        with pytest.raises(KeyError, match="No workspace"):
            manager.open("does-not-exist")

    def test_get_or_create(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        ws1 = manager.get_or_create("auto-ws")
        ws2 = manager.get_or_create("auto-ws")
        assert ws1.name == ws2.name

    def test_list(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        manager.create("alpha")
        manager.create("beta")
        names = [w["name"] for w in manager.list()]
        assert "alpha" in names and "beta" in names

    def test_delete(self, tmp_path):
        store = FlatFileStore(base_dir=str(tmp_path / "workspaces"))
        manager = WorkspaceManager(_make_registry(), store=store)
        manager.create("to-del")
        assert manager.delete("to-del") is True
        with pytest.raises(KeyError):
            manager.open("to-del")

    def test_from_clients_factory(self):
        clients = {
            "tq": MagicMock(target="threatq", ping=MagicMock(return_value=True),
                            client=MagicMock()),
            "rf": MagicMock(target="recordedfuture", ping=MagicMock(return_value=True),
                            client=MagicMock()),
        }
        manager = WorkspaceManager.from_clients(
            clients, default="tq", read_only=["rf"],
            db_url="sqlite:///:memory:"
        )
        assert manager._registry.default.name == "tq"
        assert manager._registry.get("rf").read_only is True

    def test_default_no_config_raises(self, tmp_path):
        """default() propagates FileNotFoundError when no config exists."""
        with pytest.raises(FileNotFoundError):
            WorkspaceManager.default(config_path=str(tmp_path / "nonexistent.ini"))

    def test_default_with_config(self, minimal_config):
        """default() builds a valid WorkspaceManager from a config file."""
        manager = WorkspaceManager.default(config_path=minimal_config)
        assert isinstance(manager, WorkspaceManager)
        assert manager._store is not None

    def test_default_returns_workspace_manager_type(self, minimal_config):
        """default() always returns a WorkspaceManager instance."""
        manager = WorkspaceManager.default(config_path=minimal_config)
        assert type(manager).__name__ == "WorkspaceManager"
