"""
gnat.plugins.base
==================

Base classes and capability declarations for the GNAT plugin system.

A GNAT plugin is any Python object that inherits from :class:`GNATPlugin`
and implements ``name``, ``version``, ``capabilities``, and ``register()``.

Plugin types
------------
- **CONNECTOR** — adds a new platform connector to ``CLIENT_REGISTRY``
- **READER** — adds a new :class:`~gnat.ingest.base.SourceReader`
- **MAPPER** — adds a new :class:`~gnat.ingest.base.RecordMapper`
- **AGENT** — adds a new AI agent or workflow step
- **REPORTER** — adds a new report renderer or template set
- **HOOK** — registers event hooks without adding new components

Minimal plugin example::

    from gnat.plugins.base import GNATPlugin, PluginCapability
    from gnat.plugins.registry import PluginRegistry

    class MyConnectorPlugin(GNATPlugin):
        name    = "acme.my-platform"
        version = "1.0.0"
        capabilities = [PluginCapability.CONNECTOR]

        def register(self, registry: PluginRegistry) -> None:
            from acme_gnat.client import AcmePlatformClient
            registry.register_connector("acme_platform", AcmePlatformClient)

        def unload(self) -> None:
            pass   # optional cleanup
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gnat.plugins.registry import PluginRegistry


class PluginCapability(str, Enum):
    """Capability flag declaring what a plugin contributes."""

    CONNECTOR = "connector"  # Platform connector (CLIENT_REGISTRY entry)
    READER = "reader"  # SourceReader subclass
    MAPPER = "mapper"  # RecordMapper subclass
    AGENT = "agent"  # AI agent or workflow step
    REPORTER = "reporter"  # Report renderer or template
    HOOK = "hook"  # Event hook registration only


class GNATPlugin(ABC):
    """
    Abstract base class for all GNAT plugins.

    Subclass this and implement :meth:`register` to make a valid plugin.

    Attributes
    ----------
    name : str
        Globally unique plugin identifier in reverse-domain notation,
        e.g. ``"acme.my-platform"`` or ``"community.custom-reader"``.
    version : str
        Semantic version string, e.g. ``"1.0.0"``.
    capabilities : list of PluginCapability
        What this plugin contributes.  Used for filtering/discovery.
    description : str
        Human-readable description (optional).
    """

    name: str
    version: str
    capabilities: list[PluginCapability]
    description: str = ""

    @abstractmethod
    def register(self, registry: PluginRegistry) -> None:
        """
        Register this plugin's contributions with *registry*.

        Called once during plugin loading.  Use :meth:`PluginRegistry.register_connector`,
        :meth:`~PluginRegistry.register_reader`, :meth:`~PluginRegistry.register_mapper`,
        or :meth:`~PluginRegistry.hooks` to contribute.
        """

    def unload(self) -> None:  # noqa: B027
        """
        Unload the plugin and release any held resources.

        Called when the plugin is removed from the registry.  Override
        to tear down threads, close connections, etc.  Default no-op.
        """
