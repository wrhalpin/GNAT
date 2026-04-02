# How-to: Use Workspaces

Manage investigation workspaces and a global context registry.

---

## Create and use a workspace

```python
from gnat.context import GlobalContextRegistry, GlobalContext, Workspace, FlatFileStore
from gnat.context.workspace import WorkspaceManager

# Setup
store   = FlatFileStore(base_dir="~/.gnat/workspaces")
manager = WorkspaceManager(global_registry, store=store)

# Create / open
ws = manager.get_or_create("apt29-investigation")

# Add objects
ws.add(indicator, mark_dirty=True)
ws.add(actor, mark_dirty=True)

# Diff — what changed since last commit
diff = ws.diff()
print(diff["added"], diff["modified"])

# Commit to ThreatQ
ws.commit(client=threatq_client)

# Export STIX bundle
bundle = ws.export_bundle()
```

---

## Global context registry

Register multiple platforms and set a default write target:

```python
from gnat.context import GlobalContextRegistry, GlobalContext

reg = GlobalContextRegistry()
reg.register(GlobalContext("tq",    threatq_client,      priority=10))
reg.register(GlobalContext("rf",    rf_client,           priority=20, read_only=True))
reg.register(GlobalContext("cs",    crowdstrike_client,  priority=15))
reg.set_default("tq")

# Enrich from all contexts
ws.enrich(strategy="create_relationships")
```

---

## See Also

- [How-to: Export Indicators](export-indicators.md)
- [How-to: Use the Research Library](use-research-library.md)
- [Explanation: Context System](../explanation/architecture/adrs/0005-context-system.md)
- [Explanation: Workspace Persistence](../explanation/architecture/adrs/0006-workspace-persistence.md)
