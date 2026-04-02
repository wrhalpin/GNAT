# ADR-0006: Workspace Persistence

**Decision:** SQLAlchemy stores serialized STIX JSON alongside indexed metadata
columns. Objects are **not** SQLAlchemy models.

**Backend selection:**
```
WorkspaceStore (SQLAlchemy) ← preferred
    └── SQLite (WAL mode)   ← default, single-file, zero-config
    └── PostgreSQL           ← team-shared contexts

FlatFileStore               ← zero-dependency fallback
    └── Auto-selected when SQLAlchemy is not installed
    └── One JSON file per object in ~/.gnat/workspaces/<name>/objects/
    └── JSONL enrichment log per workspace
```

**SQLite WAL mode** is set on every connection via `PRAGMA journal_mode=WAL`.
This allows concurrent readers without blocking writers — important for
notebook workflows where multiple cells read the workspace simultaneously.

**Dirty tracking:**
`is_dirty=True` in the DB + `stix_id in ws.dirty` in memory.
`mark_clean()` clears both after a successful `commit()`.
`soft_delete` sets `is_deleted=True` rather than removing rows — the
object stays in the DB for audit purposes, just not returned by
`get_objects()`.

**Snapshot vs. objects:**
- `ws._snapshot` holds STIX dicts as they were at load time (from platform).
- `ws.objects` holds live Python objects.
- `diff()` compares them — objects NOT in snapshot are "added", objects
  IN snapshot with changed fields are "modified".
- **Key rule:** `_add_object(mark_dirty=False)` → goes into snapshot.
  `_add_object(mark_dirty=True)` → does NOT go into snapshot (so `diff()`
  shows it as "added").

**Live object reference bug (fixed):**
`_add_object()` creates a new Python object via `_from_dict()`. The
original reference passed to `add()` is not the same object as
`ws.objects[id]`. All enrichment strategies (`merge_extensions`,
`tag_only`) must operate on `self.objects.get(original.id, original)`,
not on `original` directly.
