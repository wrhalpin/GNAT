# ADR-0011: CLI Design

**Decision:** `argparse` subcommand tree, no external CLI framework.

**Why not Click or Typer:**
- Click adds a dependency.
- Typer adds Click + type annotation reflection.
- argparse is stdlib, zero overhead, sufficient for this command surface.

**`gnat` entry point tree:**
```
gnat
├── ping    --target NAME
├── query   --target NAME --type STIX_TYPE --id OBJECT_ID
├── list    --target NAME --type STIX_TYPE [--limit N] [--filter K=V ...]
├── ingest  --target NAME --source PATH --format FORMAT [--dry-run]
│           formats: plaintext csv json jsonl stix-bundle misp cef openioc nvd
├── codegen --spec PATH --name NAME [--auth oauth2|api_key|basic]
├── config  --show | --validate | --init
└── viz
    ├── table     --workspace NAME [--type TYPE] [--file out.html|.csv|.xlsx]
    ├── graph     --workspace NAME [--file out.html] [--types TYPE ...]
    ├── serve     [--port 3001] [--host 0.0.0.0]
    ├── dashboard --workspace NAME [--file dashboard.json]
    └── powerbi   --workspace NAME [--file workspace.xlsx]
```

**Global flags apply to all subcommands:**
`--config PATH`, `--output json|table|stix`, `--quiet`, `--no-color`, `--debug`

**`--dry-run` on ingest:**
Maps objects and prints/returns them without calling `write_to()` on any
client. Use for validating format mappings before committing.

**Exit codes:**
- `0` — success
- `1` — error (exception, missing config, unknown target)
- `2` — partial success (ingest completed with some errors)

---

*Licensed under the Apache License, Version 2.0*
