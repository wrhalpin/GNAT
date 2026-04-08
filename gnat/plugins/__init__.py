"""
gnat.plugins
============

Formal plugin/extension system for GNAT.

Formalises the existing ``CLIENT_REGISTRY`` + ``SourceReader`` + ``ConnectorMixin``
patterns into a discoverable lifecycle with lifecycle hooks.

Quick start
-----------

**Installing a community plugin package:**

    pip install gnat-plugin-my-platform

The package registers itself via the ``gnat.plugins`` entry point group and
is automatically discovered the next time :func:`~gnat.plugins.loader.load_plugins`
is called.

**Writing a plugin:**

    from gnat.plugins import GNATPlugin, PluginCapability, PluginRegistry

    class MyPlugin(GNATPlugin):
        name    = "acme.my-platform"
        version = "1.0.0"
        capabilities = [PluginCapability.CONNECTOR]

        def register(self, registry: PluginRegistry) -> None:
            from acme_gnat.client import AcmePlatformClient
            registry.register_connector("acme_platform", AcmePlatformClient)

**Subscribing to hooks:**

    from gnat.plugins import HookBus

    bus = HookBus.instance()

    @bus.on("report_published")
    def notify_slack(report, **ctx):
        slack.post(f"New report: {report.title}")

**Manual loading:**

    from gnat.plugins.loader import load_plugins
    load_plugins()
"""

from gnat.plugins.base import GNATPlugin, PluginCapability
from gnat.plugins.hooks import HookBus, KNOWN_EVENTS
from gnat.plugins.loader import load_plugins
from gnat.plugins.registry import PluginRegistry

__all__ = [
    "GNATPlugin",
    "PluginCapability",
    "HookBus",
    "KNOWN_EVENTS",
    "PluginRegistry",
    "load_plugins",
]
