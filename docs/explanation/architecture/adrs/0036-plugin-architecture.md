# ADR-0036 — Plugin Architecture

**Date:** 2026-04-08  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT has 100+ built-in connectors, 14 source readers, and 12 record mappers — all registered via simple dicts or `__all__` lists. As the platform matures, external teams need to:

1. Add proprietary connectors without forking core
2. Extend the ingest pipeline with custom readers/mappers
3. Subscribe to lifecycle events (post-ingest, report-published) for notifications and audit
4. Package and distribute GNAT extensions via PyPI

The challenge is formalising these patterns without breaking any existing code.

---

## Decision

Introduce a **thin plugin layer** that wraps existing registries rather than replacing them:

### GNATPlugin ABC

A plugin is any class that inherits `GNATPlugin` and implements:
- `name: str` — reverse-domain unique identifier
- `version: str` — semantic version
- `capabilities: list[PluginCapability]` — what it contributes
- `register(registry)` — called once on load
- `unload()` — called on remove (optional, no-op default)

### PluginRegistry (singleton)

- Manages plugin lifecycle (load, unload, list)
- `register_connector(name, cls)` → adds to `CLIENT_REGISTRY`
- `register_reader(cls)` → adds to `gnat.ingest.sources`
- `register_mapper(cls)` → adds to `gnat.ingest.mappers`
- `load_entry_points()` → discovers via `gnat.plugins` setuptools group
- `load_directory(path)` → scans `*.py` files for GNATPlugin subclasses
- `hooks` property → returns the `HookBus`

### HookBus (singleton)

Thread-safe pub/sub event bus. Built-in events:
- `pre_ingest` / `post_ingest`
- `pre_enrich` / `post_enrich`
- `pre_export` / `post_export`
- `investigation_opened` / `investigation_closed`
- `report_published`
- `plugin_loaded` / `plugin_unloaded`

Handlers can be sync functions or async coroutines. Exceptions in handlers are logged but never propagated.

### Discovery

Two mechanisms:
1. **Entry points** — installed packages declare `[project.entry-points."gnat.plugins"]`
2. **Filesystem** — `GNAT_PLUGIN_DIRS` env var or `[plugins] directories` INI key

---

## Consequences

### Positive

- Zero breaking changes: `CLIENT_REGISTRY`, `SourceReader`, `ConnectorMixin` all unchanged
- Ecosystem growth: third-party connectors installable via `pip install gnat-plugin-*`
- Community contributions possible without core access
- Hook bus enables notification integrations without modifying pipeline code

### Negative / Trade-offs

- Plugin isolation: plugins run in-process; a buggy plugin can crash the host
- No versioning constraints: GNAT doesn't enforce compatibility beyond "is a GNATPlugin subclass"
- No sandboxing: plugins have full access to the Python interpreter

### Deferred

- Plugin signing and trust verification
- Dynamic unload of connector-type plugins from `CLIENT_REGISTRY`
- Plugin configuration UI in the TUI/dashboard
