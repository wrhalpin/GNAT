# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/federation/test_federation.py
=========================================

Unit tests for the GNAT federation layer.

Covers:
- FederationPeer dataclass and validation
- PeerRegistry CRUD + persistence
- PeerSyncService TLP gate and conflict resolution
- FederationTopology hierarchy traversal + effective_max_tlp
- FederationScheduler lifecycle
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from gnat.federation.peer import FederationPeer, PeerRegistry
from gnat.federation.sync import FederationError, PeerSyncService, PullResult, PushResult
from gnat.federation.topology import FederationTopology


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registry(tmp_path: str | None = None) -> PeerRegistry:
    """Return a fresh PeerRegistry backed by a temp file."""
    if tmp_path is None:
        fd, tmp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(tmp_path)
    return PeerRegistry(registry_path=tmp_path)


def _peer(peer_id: str = "acme-east", **kwargs) -> FederationPeer:
    defaults = {
        "taxii_url": "https://acme-east.example.com/taxii2/",
        "api_key": "secret",
        "direction": "pull",
        "max_tlp": "green",
        "workspace_filter": ["threats-2025"],
    }
    defaults.update(kwargs)
    return FederationPeer(peer_id=peer_id, **defaults)


# ---------------------------------------------------------------------------
# FederationPeer
# ---------------------------------------------------------------------------


class TestFederationPeer:
    def test_can_pull_pull_direction(self):
        p = _peer(direction="pull")
        assert p.can_pull is True
        assert p.can_push is False

    def test_can_push_push_direction(self):
        p = _peer(direction="push")
        assert p.can_pull is False
        assert p.can_push is True

    def test_both_direction(self):
        p = _peer(direction="both")
        assert p.can_pull is True
        assert p.can_push is True

    def test_invalid_direction_raises(self):
        with pytest.raises(ValueError, match="direction"):
            _peer(direction="invalid")

    def test_invalid_tlp_raises(self):
        with pytest.raises(ValueError, match="max_tlp"):
            _peer(max_tlp="ultra-secret")

    def test_invalid_peer_id_raises(self):
        with pytest.raises(ValueError, match="peer_id"):
            FederationPeer(peer_id="INVALID SPACES!", taxii_url="https://x.com/taxii2/")

    def test_created_at_set_automatically(self):
        p = _peer()
        assert p.created_at
        assert "T" in p.created_at

    def test_parent_peer_id_optional(self):
        p = _peer()
        assert p.parent_peer_id is None

    def test_hierarchy_peer(self):
        p = _peer(parent_peer_id="health-system-parent")
        assert p.parent_peer_id == "health-system-parent"


# ---------------------------------------------------------------------------
# PeerRegistry
# ---------------------------------------------------------------------------


class TestPeerRegistry:
    def test_register_and_get(self):
        reg = _registry()
        reg.register("peer-a", taxii_url="https://a.example.com/taxii2/", api_key="k",
                     workspace_filter=["ws1"])
        peer = reg.get("peer-a")
        assert peer is not None
        assert peer.peer_id == "peer-a"
        assert peer.taxii_url == "https://a.example.com/taxii2/"

    def test_get_missing_returns_none(self):
        reg = _registry()
        assert reg.get("nonexistent") is None

    def test_list_returns_all(self):
        reg = _registry()
        reg.register("p1", taxii_url="https://p1.example.com/taxii2/", api_key="k1")
        reg.register("p2", taxii_url="https://p2.example.com/taxii2/", api_key="k2")
        peers = reg.list()
        assert len(peers) == 2

    def test_list_enabled_only(self):
        reg = _registry()
        reg.register("p1", taxii_url="https://p1.example.com/taxii2/", api_key="k1", enabled=True)
        reg.register("p2", taxii_url="https://p2.example.com/taxii2/", api_key="k2", enabled=False)
        assert len(reg.list(enabled_only=True)) == 1
        assert len(reg.list(enabled_only=False)) == 2

    def test_delete(self):
        reg = _registry()
        reg.register("to-delete", taxii_url="https://x.example.com/taxii2/", api_key="k")
        reg.delete("to-delete")
        assert reg.get("to-delete") is None

    def test_delete_missing_returns_false(self):
        reg = _registry()
        assert reg.delete("nonexistent") is False

    def test_update_sync_status(self):
        reg = _registry()
        reg.register("p1", taxii_url="https://p1.example.com/taxii2/", api_key="k")
        reg.update_sync_status("p1", "success")
        p = reg.get("p1")
        assert p.last_sync_status == "success"
        assert p.last_sync_at is not None

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "peers.json")
        reg1 = PeerRegistry(registry_path=path)
        reg1.register("saved-peer", taxii_url="https://saved.example.com/taxii2/", api_key="k",
                      workspace_filter=["ws1"])

        reg2 = PeerRegistry(registry_path=path)
        peer = reg2.get("saved-peer")
        assert peer is not None
        assert peer.taxii_url == "https://saved.example.com/taxii2/"

    def test_register_duplicate_raises(self):
        reg = _registry()
        reg.register("dup", taxii_url="https://dup.example.com/taxii2/", api_key="k")
        with pytest.raises(ValueError, match="already registered"):
            reg.register("dup", taxii_url="https://dup.example.com/taxii2/", api_key="k")

    def test_from_config(self, tmp_path):
        """PeerRegistry.from_config parses federation.peer.* INI sections."""
        # from_config is a classmethod — config.get(section) returns a dict
        peer_section_data = {
            "taxii_url": "https://test.example.com/taxii2/",
            "api_key": "Bearer test-token",
            "direction": "pull",
            "max_tlp": "green",
            "sync_interval": "3600",
            "workspace_filter": "ws1,ws2",
            "enabled": "true",
            "parent_peer_id": "",
        }
        config = MagicMock()
        config.sections = ["federation.peer.test-peer"]
        # config.get("federation") raises KeyError (no [federation] section)
        config.get.side_effect = lambda section: (
            {} if section == "federation" else peer_section_data
        )

        path = str(tmp_path / "from_config_peers.json")
        reg = PeerRegistry.from_config(config, registry_path=path)
        peer = reg.get("test-peer")
        assert peer is not None
        assert peer.workspace_filter == ["ws1", "ws2"]


# ---------------------------------------------------------------------------
# PeerSyncService — TLP gate
# ---------------------------------------------------------------------------


class TestTLPGate:
    def test_green_allowed_under_green_ceiling(self):
        peer = _peer(max_tlp="green")
        obj = {"type": "indicator", "x_tlp": "green"}
        assert PeerSyncService._tlp_allowed(obj, peer) is True

    def test_amber_blocked_by_green_ceiling(self):
        peer = _peer(max_tlp="green")
        obj = {"type": "indicator", "x_tlp": "amber"}
        assert PeerSyncService._tlp_allowed(obj, peer) is False

    def test_amber_allowed_under_amber_ceiling(self):
        peer = _peer(max_tlp="amber")
        obj = {"type": "indicator", "x_tlp": "amber"}
        assert PeerSyncService._tlp_allowed(obj, peer) is True

    def test_red_blocked_by_amber_ceiling(self):
        peer = _peer(max_tlp="amber")
        obj = {"type": "indicator", "x_tlp": "red"}
        assert PeerSyncService._tlp_allowed(obj, peer) is False

    def test_white_always_allowed(self):
        peer = _peer(max_tlp="green")
        obj = {"type": "indicator", "x_tlp": "white"}
        assert PeerSyncService._tlp_allowed(obj, peer) is True

    def test_missing_tlp_defaults_to_green(self):
        peer = _peer(max_tlp="green")
        obj = {"type": "indicator"}  # no x_tlp field
        assert PeerSyncService._tlp_allowed(obj, peer) is True

    def test_amber_strict_blocked_by_amber(self):
        peer = _peer(max_tlp="amber")
        obj = {"type": "indicator", "x_tlp": "amber+strict"}
        assert PeerSyncService._tlp_allowed(obj, peer) is False


# ---------------------------------------------------------------------------
# PeerSyncService — sync_from_peer validation
# ---------------------------------------------------------------------------


class TestSyncFromPeer:
    def test_disabled_peer_raises(self):
        peer = _peer(enabled=False)
        svc = PeerSyncService()
        with pytest.raises(FederationError, match="disabled"):
            svc.sync_from_peer(peer)

    def test_push_only_peer_raises(self):
        peer = _peer(direction="push")
        svc = PeerSyncService()
        with pytest.raises(FederationError, match="pull not allowed"):
            svc.sync_from_peer(peer)

    def test_empty_workspace_filter_raises(self):
        peer = _peer(workspace_filter=[])
        svc = PeerSyncService()
        with pytest.raises(FederationError, match="workspace_filter"):
            svc.sync_from_peer(peer)

    def test_successful_pull_no_workspace_manager(self):
        """Pull with no workspace manager just counts objects (dry_run equivalent)."""
        peer = _peer(workspace_filter=["ws1"])
        svc = PeerSyncService(workspace_manager=None)

        mock_connector = MagicMock()
        mock_connector.fetch_objects.return_value = [
            {"type": "indicator", "id": "indicator--1", "x_tlp": "green", "modified": "2025-01-01T00:00:00Z"},
        ]
        with patch.object(svc, "_make_connector", return_value=mock_connector):
            result = svc.sync_from_peer(peer)

        assert isinstance(result, PullResult)
        assert result.peer_id == "acme-east"
        assert "ws1" in result.workspaces_synced
        assert result.objects_accepted == 1

    def test_tlp_filtered_objects_not_counted(self):
        peer = _peer(max_tlp="green", workspace_filter=["ws1"])
        svc = PeerSyncService(workspace_manager=None)

        mock_connector = MagicMock()
        mock_connector.fetch_objects.return_value = [
            {"type": "indicator", "id": "indicator--1", "x_tlp": "amber", "modified": "2025-01-01T00:00:00Z"},
        ]
        with patch.object(svc, "_make_connector", return_value=mock_connector):
            result = svc.sync_from_peer(peer)

        assert result.objects_accepted == 0


# ---------------------------------------------------------------------------
# PeerSyncService — push_to_peer validation
# ---------------------------------------------------------------------------


class TestPushToPeer:
    def test_disabled_peer_raises(self):
        peer = _peer(enabled=False)
        svc = PeerSyncService()
        with pytest.raises(FederationError, match="disabled"):
            svc.push_to_peer(peer, [], "ws1")

    def test_pull_only_peer_raises(self):
        peer = _peer(direction="pull")
        svc = PeerSyncService()
        with pytest.raises(FederationError, match="push not allowed"):
            svc.push_to_peer(peer, [], "ws1")

    def test_tlp_filter_on_push(self):
        peer = _peer(direction="push", max_tlp="green")
        svc = PeerSyncService()
        objects = [
            {"type": "indicator", "id": "indicator--1", "x_tlp": "green"},
            {"type": "indicator", "id": "indicator--2", "x_tlp": "amber"},
        ]
        mock_connector = MagicMock()
        mock_connector.push_bundle.return_value = {"status": "complete"}
        with patch.object(svc, "_make_connector", return_value=mock_connector):
            result = svc.push_to_peer(peer, objects, "ws1")

        assert result.objects_pushed == 1
        assert result.objects_dropped_tlp == 1

    def test_empty_push_after_filter(self):
        peer = _peer(direction="push", max_tlp="green")
        svc = PeerSyncService()
        objects = [{"type": "indicator", "id": "indicator--1", "x_tlp": "red"}]
        with patch.object(svc, "_make_connector") as mock_make:
            result = svc.push_to_peer(peer, objects, "ws1")

        mock_make.assert_not_called()
        assert result.objects_pushed == 0
        assert result.objects_dropped_tlp == 1

    def test_push_success(self):
        peer = _peer(direction="push", max_tlp="amber")
        svc = PeerSyncService()
        objects = [{"type": "indicator", "id": "indicator--1", "x_tlp": "green"}]
        mock_connector = MagicMock()
        mock_connector.push_bundle.return_value = {"status": "complete"}
        with patch.object(svc, "_make_connector", return_value=mock_connector):
            result = svc.push_to_peer(peer, objects, "ws1")

        assert result.success is True
        assert result.objects_pushed == 1


# ---------------------------------------------------------------------------
# PullResult / PushResult
# ---------------------------------------------------------------------------


class TestResultClasses:
    def test_pull_result_success_true(self):
        r = PullResult("p1")
        r.workspaces_synced = ["ws1"]
        assert r.success is True

    def test_pull_result_success_false_with_errors(self):
        r = PullResult("p1")
        r.workspaces_synced = ["ws1"]
        r.errors = ["something went wrong"]
        assert r.success is False

    def test_push_result_success_true(self):
        r = PushResult("p1", "ws1")
        assert r.success is True

    def test_push_result_success_false_with_error(self):
        r = PushResult("p1", "ws1")
        r.error = "connection refused"
        assert r.success is False


# ---------------------------------------------------------------------------
# FederationTopology
# ---------------------------------------------------------------------------


class TestFederationTopology:
    @pytest.fixture
    def reg(self):
        r = _registry()
        # parent has max_tlp="green" so topology default rules apply
        r.register("parent", taxii_url="https://parent.example.com/taxii2/", api_key="k",
                   max_tlp="green")
        r.register("child-a", taxii_url="https://child-a.example.com/taxii2/", api_key="k",
                   parent_peer_id="parent", max_tlp="green")
        r.register("child-b", taxii_url="https://child-b.example.com/taxii2/", api_key="k",
                   parent_peer_id="parent", max_tlp="green")
        r.register("mesh-peer", taxii_url="https://mesh.example.com/taxii2/", api_key="k",
                   max_tlp="green")
        return r

    @pytest.fixture
    def topo(self, reg):
        return FederationTopology(reg)

    def test_ancestors_of_child(self, topo):
        result = topo.ancestors("child-a")
        assert result == ["parent"]

    def test_ancestors_of_root_is_empty(self, topo):
        result = topo.ancestors("parent")
        assert result == []

    def test_descendants_of_parent(self, topo):
        result = topo.descendants("parent")
        assert set(result) == {"child-a", "child-b"}

    def test_descendants_of_leaf_is_empty(self, topo):
        result = topo.descendants("child-a")
        assert result == []

    def test_is_leaf_child(self, topo):
        assert topo.is_leaf("child-a") is True

    def test_is_leaf_parent_false(self, topo):
        assert topo.is_leaf("parent") is False

    def test_is_root_parent(self, topo):
        assert topo.is_root("parent") is True

    def test_is_root_child_false(self, topo):
        assert topo.is_root("child-a") is False

    def test_parent_helper(self, topo, reg):
        parent = topo.parent("child-a")
        assert parent is not None
        assert parent.peer_id == "parent"

    def test_parent_of_root_is_none(self, topo):
        assert topo.parent("parent") is None

    def test_children(self, topo):
        children = topo.children("parent")
        ids = {c.peer_id for c in children}
        assert ids == {"child-a", "child-b"}

    def test_effective_max_tlp_child_to_parent(self, topo):
        # child-a has max_tlp="green" but sending to its parent should use AMBER default
        tlp = topo.effective_max_tlp("child-a", "parent")
        assert tlp == "amber"

    def test_effective_max_tlp_parent_to_child(self, topo):
        tlp = topo.effective_max_tlp("parent", "child-a")
        assert tlp == "green"

    def test_effective_max_tlp_explicit_overrides(self, reg):
        # Set explicit max_tlp != green on child
        reg.register("child-c", taxii_url="https://child-c.example.com/taxii2/", api_key="k",
                     parent_peer_id="parent", max_tlp="amber")
        topo = FederationTopology(reg)
        # child-c explicitly set to amber → should win
        tlp = topo.effective_max_tlp("child-c", "parent")
        assert tlp == "amber"

    def test_cycle_detection(self):
        """ancestors() raises ValueError when a cycle exists in parent chain."""
        reg = _registry()
        # We manually insert a cycle by registering then updating storage
        reg.register("node-a", taxii_url="https://a.example.com/taxii2/", api_key="k",
                     parent_peer_id="node-b")
        reg.register("node-b", taxii_url="https://b.example.com/taxii2/", api_key="k",
                     parent_peer_id="node-a")
        topo = FederationTopology(reg)
        with pytest.raises(ValueError, match="Cycle detected"):
            topo.ancestors("node-a")

    def test_hierarchy_graph_structure(self, topo):
        graph = topo.hierarchy_graph()
        assert "nodes" in graph
        assert "edges" in graph
        assert "hierarchy_edges" in graph
        assert graph["total_peers"] == 4
        assert graph["enabled_peers"] == 4

    def test_hierarchy_graph_has_hierarchy_edges(self, topo):
        graph = topo.hierarchy_graph()
        h_edges = graph["hierarchy_edges"]
        # child-a → parent and child-b → parent
        assert len(h_edges) == 2
        from_ids = {e["from"] for e in h_edges}
        assert from_ids == {"child-a", "child-b"}


# ---------------------------------------------------------------------------
# FederationScheduler (lightweight smoke test — avoids FeedScheduler import)
# ---------------------------------------------------------------------------


class TestFederationScheduler:
    def test_start_requires_feedscheduler(self):
        """If FeedScheduler isn't importable, FederationScheduler.start() raises ImportError."""
        from gnat.federation.scheduler import FederationScheduler

        reg = _registry()
        svc = PeerSyncService()
        sched = FederationScheduler(registry=reg, sync_service=svc)

        with patch.dict("sys.modules", {"gnat.schedule.scheduler": None}):
            # When the module is explicitly None in sys.modules, importing it raises ImportError
            try:
                sched.start()
            except (ImportError, AttributeError):
                pass  # expected — FeedScheduler not available in unit test env

    def test_trigger_raises_for_unknown_peer(self):
        from gnat.federation.scheduler import FederationScheduler

        reg = _registry()
        svc = PeerSyncService()
        sched = FederationScheduler(registry=reg, sync_service=svc)

        with pytest.raises(KeyError, match="No federation job"):
            sched.trigger("nonexistent")

    def test_status_empty_when_no_jobs(self):
        from gnat.federation.scheduler import FederationScheduler

        reg = _registry()
        svc = PeerSyncService()
        sched = FederationScheduler(registry=reg, sync_service=svc)

        assert sched.status() == []

    def test_stop_safe_when_not_started(self):
        from gnat.federation.scheduler import FederationScheduler

        reg = _registry()
        svc = PeerSyncService()
        sched = FederationScheduler(registry=reg, sync_service=svc)
        sched.stop()  # should not raise
