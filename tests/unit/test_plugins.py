"""Unit tests for gnat.plugins (plugin system)."""

from __future__ import annotations

import pytest


# ── Plugin capability & base ──────────────────────────────────────────────────

def test_plugin_capability_values():
    from gnat.plugins.base import PluginCapability
    assert PluginCapability.CONNECTOR == "connector"
    assert PluginCapability.READER    == "reader"
    assert PluginCapability.MAPPER    == "mapper"
    assert PluginCapability.AGENT     == "agent"
    assert PluginCapability.REPORTER  == "reporter"
    assert PluginCapability.HOOK      == "hook"


def test_gnat_plugin_abc_requires_register():
    from gnat.plugins.base import GNATPlugin, PluginCapability
    import abc

    with pytest.raises(TypeError):
        # Cannot instantiate abstract class without register()
        class BadPlugin(GNATPlugin):
            name         = "bad"
            version      = "0.0"
            capabilities = [PluginCapability.HOOK]
        BadPlugin()


def test_concrete_plugin_registers():
    from gnat.plugins.base import GNATPlugin, PluginCapability
    from gnat.plugins.registry import PluginRegistry

    class MyPlugin(GNATPlugin):
        name         = "my-plugin"
        version      = "1.0"
        capabilities = [PluginCapability.HOOK]
        description  = "Test plugin"

        def register(self, registry):
            registry.hooks.register("test_event", lambda **kw: "ok")

    plugin   = MyPlugin()
    registry = PluginRegistry()
    registry.load(plugin)

    assert registry.get("my-plugin") is plugin
    assert len(registry.list()) == 1
    assert len(registry.list_by_capability(PluginCapability.HOOK)) == 1


def test_duplicate_plugin_is_skipped():
    from gnat.plugins.base import GNATPlugin, PluginCapability
    from gnat.plugins.registry import PluginRegistry

    class P(GNATPlugin):
        name = "dup"; version = "1.0"; capabilities = [PluginCapability.HOOK]
        def register(self, _): pass

    registry = PluginRegistry()
    registry.load(P())
    # Second load is a no-op (logs warning, does not raise)
    registry.load(P())
    assert len(registry.list()) == 1


def test_unload_plugin():
    from gnat.plugins.base import GNATPlugin, PluginCapability
    from gnat.plugins.registry import PluginRegistry

    class P(GNATPlugin):
        name = "rm-me"; version = "1.0"; capabilities = []
        def register(self, _): pass

    registry = PluginRegistry()
    registry.load(P())
    assert registry.get("rm-me") is not None
    assert registry.unload("rm-me") is True
    assert registry.get("rm-me") is None
    assert registry.unload("rm-me") is False  # idempotent


# ── HookBus ────────────────────────────────────────────────────────────────────

def test_hook_bus_emit_and_receive():
    from gnat.plugins.hooks import HookBus
    bus    = HookBus()
    calls  = []

    bus.register("my_event", lambda **kw: calls.append(kw))
    bus.emit("my_event", a=1, b=2)

    assert len(calls) == 1
    assert calls[0] == {"a": 1, "b": 2}


def test_hook_bus_multiple_handlers():
    from gnat.plugins.hooks import HookBus
    bus    = HookBus()
    log    = []

    bus.register("ev", lambda **kw: log.append("h1"))
    bus.register("ev", lambda **kw: log.append("h2"))
    bus.emit("ev")

    assert log == ["h1", "h2"]


def test_hook_bus_decorator():
    from gnat.plugins.hooks import HookBus
    bus = HookBus()
    log = []

    @bus.on("decorated_event")
    def handler(**kw):
        log.append(kw.get("x"))

    bus.emit("decorated_event", x=42)
    assert log == [42]


def test_hook_bus_unregister():
    from gnat.plugins.hooks import HookBus
    bus = HookBus()
    log = []

    def h(**kw): log.append(1)
    bus.register("ev", h)
    bus.unregister("ev", h)
    bus.emit("ev")

    assert log == []


def test_hook_bus_handler_exception_is_swallowed():
    from gnat.plugins.hooks import HookBus
    bus = HookBus()

    def bad_handler(**kw):
        raise RuntimeError("boom")

    bus.register("ev", bad_handler)
    # Must not propagate; exception-raising handlers contribute None to results
    results = bus.emit("ev")
    assert results == [None]


def test_hook_bus_clear():
    from gnat.plugins.hooks import HookBus
    bus = HookBus()
    bus.register("a", lambda **kw: None)
    bus.register("b", lambda **kw: None)
    bus.clear("a")
    assert bus.handlers("a") == []
    assert len(bus.handlers("b")) == 1
    bus.clear()
    assert bus.handlers("b") == []


def test_hook_bus_emit_no_handlers_returns_empty():
    from gnat.plugins.hooks import HookBus
    bus = HookBus()
    assert bus.emit("nonexistent_event") == []


def test_known_events_exported():
    from gnat.plugins.hooks import KNOWN_EVENTS
    assert "pre_ingest" in KNOWN_EVENTS
    assert "post_ingest" in KNOWN_EVENTS
    assert "plugin_loaded" in KNOWN_EVENTS


# ── PluginRegistry helpers ────────────────────────────────────────────────────

def test_registry_register_connector():
    from gnat.plugins.registry import PluginRegistry
    registry = PluginRegistry()
    import gnat.clients as _clients

    class FakeClient:
        pass

    registry.register_connector("fake_platform_test", FakeClient)
    assert _clients.CLIENT_REGISTRY.get("fake_platform_test") is FakeClient
    # Clean up
    del _clients.CLIENT_REGISTRY["fake_platform_test"]


def test_plugins_init_exports():
    from gnat import plugins
    assert hasattr(plugins, "GNATPlugin")
    assert hasattr(plugins, "HookBus")
    assert hasattr(plugins, "PluginRegistry")
    assert hasattr(plugins, "load_plugins")
