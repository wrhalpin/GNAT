"""
gnat.plugins.registry
======================

The :class:`PluginRegistry` is a process-level singleton that manages the
lifecycle of all GNAT plugins and wraps the existing ``CLIENT_REGISTRY``,
reader, and mapper registries.

Design
------
The registry is intentionally thin — it *wraps* existing GNAT registries
rather than replacing them.  When a connector plugin calls
``registry.register_connector("my_platform", MyClient)``, the entry is
added directly to ``gnat.clients.CLIENT_REGISTRY`` so that all existing
code that uses that dict continues to work without modification.

The same principle applies to readers and mappers.

Usage::

    from gnat.plugins.registry import PluginRegistry

    registry = PluginRegistry.instance()
    registry.load_entry_points()         # auto-discover installed plugins
    registry.load_directory("./plugins") # or from filesystem

    # Manual registration
    registry.register_connector("my_platform", MyPlatformClient)

    # Inspect
    for plugin in registry.list():
        print(plugin.name, plugin.version)
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
import threading
from pathlib import Path

from gnat.plugins.base import GNATPlugin, PluginCapability
from gnat.plugins.hooks import HookBus

logger = logging.getLogger(__name__)

_ENTRY_POINTS_GROUP = "gnat.plugins"


class PluginRegistry:
    """
    Process-level registry for GNAT plugins.

    Use :meth:`instance` to get the singleton.
    """

    _instance: "PluginRegistry | None" = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._plugins: dict[str, GNATPlugin] = {}
        self._reg_lock = threading.RLock()
        self._hooks = HookBus.instance()

    # ── Singleton ─────────────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "PluginRegistry":
        """Return the process-level singleton :class:`PluginRegistry`."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        with cls._lock:
            cls._instance = None

    # ── Plugin lifecycle ──────────────────────────────────────────────────

    def load(self, plugin: GNATPlugin) -> None:
        """
        Register *plugin* and call its :meth:`~GNATPlugin.register` method.

        Parameters
        ----------
        plugin : GNATPlugin
            A plugin instance to register.
        """
        with self._reg_lock:
            if plugin.name in self._plugins:
                logger.warning(
                    "PluginRegistry: %r is already loaded — skipping.", plugin.name
                )
                return
            try:
                plugin.register(self)
                self._plugins[plugin.name] = plugin
                self._hooks.emit("plugin_loaded", plugin=plugin)
                logger.info(
                    "PluginRegistry: loaded plugin %r v%s", plugin.name, plugin.version
                )
            except Exception as exc:
                logger.error(
                    "PluginRegistry: failed to load plugin %r: %s", plugin.name, exc
                )
                raise

    def unload(self, name: str) -> bool:
        """
        Remove a plugin by name and call its :meth:`~GNATPlugin.unload` method.

        Returns True if found, False if not registered.
        """
        with self._reg_lock:
            plugin = self._plugins.pop(name, None)
            if plugin is None:
                return False
            try:
                plugin.unload()
            except Exception as exc:
                logger.warning("PluginRegistry: error unloading %r: %s", name, exc)
            self._hooks.emit("plugin_unloaded", plugin=plugin)
            logger.info("PluginRegistry: unloaded plugin %r", name)
            return True

    def get(self, name: str) -> GNATPlugin | None:
        """Return the plugin with *name*, or ``None``."""
        with self._reg_lock:
            return self._plugins.get(name)

    def list(self) -> list[GNATPlugin]:
        """Return all loaded plugins."""
        with self._reg_lock:
            return list(self._plugins.values())

    def list_by_capability(self, capability: PluginCapability) -> list[GNATPlugin]:
        """Return plugins that declare *capability*."""
        with self._reg_lock:
            return [p for p in self._plugins.values() if capability in p.capabilities]

    # ── Discovery ─────────────────────────────────────────────────────────

    def load_entry_points(self, group: str = _ENTRY_POINTS_GROUP) -> int:
        """
        Discover and load plugins registered via setuptools entry points.

        Each entry point must point to a :class:`GNATPlugin` *class* (not instance).

        Example ``pyproject.toml``::

            [project.entry-points."gnat.plugins"]
            my_plugin = "my_package.plugin:MyConnectorPlugin"

        Returns the number of successfully loaded plugins.
        """
        loaded = 0
        try:
            from importlib.metadata import entry_points
            eps = entry_points(group=group)
        except Exception as exc:
            logger.warning("PluginRegistry: could not read entry points: %s", exc)
            return 0

        for ep in eps:
            try:
                plugin_cls = ep.load()
                if not (isinstance(plugin_cls, type) and issubclass(plugin_cls, GNATPlugin)):
                    logger.warning(
                        "PluginRegistry: entry point %r is not a GNATPlugin subclass — skipped.",
                        ep.name,
                    )
                    continue
                self.load(plugin_cls())
                loaded += 1
            except Exception as exc:
                logger.error(
                    "PluginRegistry: failed to load entry point %r: %s", ep.name, exc
                )

        return loaded

    def load_directory(self, directory: str | Path) -> int:
        """
        Load plugins from ``*.py`` files in *directory*.

        Each file that defines a class named ``Plugin`` (or any
        :class:`GNATPlugin` subclass) is loaded.

        Returns the number of successfully loaded plugins.
        """
        directory = Path(directory)
        if not directory.is_dir():
            logger.warning("PluginRegistry: %r is not a directory.", directory)
            return 0

        loaded = 0
        for py_file in sorted(directory.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"gnat_plugin_{py_file.stem}", py_file
                )
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)  # type: ignore[union-attr]

                # Find all GNATPlugin subclasses defined in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, GNATPlugin)
                        and attr is not GNATPlugin
                        and attr.__module__ == module.__name__
                    ):
                        self.load(attr())
                        loaded += 1
            except Exception as exc:
                logger.error(
                    "PluginRegistry: error loading %r: %s", py_file, exc
                )

        return loaded

    # ── Convenience registration helpers ──────────────────────────────────

    def register_connector(self, name: str, client_class: type) -> None:
        """
        Add *client_class* to ``gnat.clients.CLIENT_REGISTRY`` under *name*.

        This makes the connector discoverable by :class:`~gnat.client.GNATClient`
        and all code that reads ``CLIENT_REGISTRY``.
        """
        try:
            from gnat.clients import CLIENT_REGISTRY
            CLIENT_REGISTRY[name] = client_class
            logger.debug("PluginRegistry: registered connector %r", name)
        except ImportError:
            logger.warning("PluginRegistry: gnat.clients not available; connector %r not registered.", name)

    def register_reader(self, reader_class: type) -> None:
        """
        Add *reader_class* to the ingest source reader registry.

        The class must be a :class:`~gnat.ingest.base.SourceReader` subclass.
        """
        try:
            import gnat.ingest.sources as sources_mod
            name = reader_class.__name__
            if not hasattr(sources_mod, name):
                setattr(sources_mod, name, reader_class)
                if name not in sources_mod.__all__:
                    sources_mod.__all__.append(name)
            logger.debug("PluginRegistry: registered reader %r", name)
        except ImportError:
            logger.warning("PluginRegistry: gnat.ingest not available.")

    def register_mapper(self, mapper_class: type) -> None:
        """
        Add *mapper_class* to the ingest mapper registry.

        The class must be a :class:`~gnat.ingest.base.RecordMapper` subclass.
        """
        try:
            import gnat.ingest.mappers as mappers_mod
            name = mapper_class.__name__
            if not hasattr(mappers_mod, name):
                setattr(mappers_mod, name, mapper_class)
                if name not in mappers_mod.__all__:
                    mappers_mod.__all__.append(name)
            logger.debug("PluginRegistry: registered mapper %r", name)
        except ImportError:
            logger.warning("PluginRegistry: gnat.ingest not available.")

    @property
    def hooks(self) -> HookBus:
        """The :class:`~gnat.plugins.hooks.HookBus` associated with this registry."""
        return self._hooks

    def sync_from_client_registry(self) -> None:
        """
        Mark all connectors in ``CLIENT_REGISTRY`` as known to the registry.

        This does NOT load them as plugins (they have no plugin metadata),
        but allows :meth:`list_by_capability` to reflect them if needed.
        """
        # No-op by design: CLIENT_REGISTRY connectors are not GNATPlugin instances.
        # Plugins that add connectors go through register_connector().

    def __len__(self) -> int:
        with self._reg_lock:
            return len(self._plugins)

    def __repr__(self) -> str:
        return f"PluginRegistry(loaded={len(self)})"
