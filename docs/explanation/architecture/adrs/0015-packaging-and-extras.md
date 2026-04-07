# ADR-0015: Packaging and Extras

**Optional dependency groups:**

| Extra | Installs | Required for |
|---|---|---|
| `yaml` | `pyyaml` | YAML OpenAPI specs in codegen |
| `taxii` | `taxii2-client` | TAXII 2.x feed ingestion |
| `rss` | `feedparser` | RSS/Atom feed ingestion |
| `ingest` | `taxii2-client`, `feedparser` | All ingest extras |
| `async` | `httpx` | Async client |
| `persist` | `sqlalchemy` | SQLAlchemy workspace store |
| `viz` | `plotly`, `networkx`, `openpyxl` | Graph + Excel |
| `serve` | `fastapi`, `uvicorn` | Grafana datasource server |
| `dev` | all of the above + `pytest`, `ruff`, `mypy` | Development |
| `all` | everything except dev tools | Full install |

**Install for development:**
```bash
pip install -e ".[dev]" httpx
```

**`py.typed` marker:**
Present at `gnat/py.typed` — signals mypy and other type checkers
that the package provides inline types (PEP 561).

**Entry points:**
```
gnat        → gnat.cli.main:main
gnat-codegen → gnat.codegen.openapi_generator:_main
```

**OIDC PyPI publishing:**
`release.yml` uses `pypa/gh-action-pypi-publish` with `id-token: write`
permission. No API token needed — configure trusted publishing in PyPI
project settings under the repo name.

**Version bump workflow:**
1. Update `version` in `pyproject.toml`
2. Add `## [X.Y.Z]` section to `CHANGELOG.md`
3. `git tag vX.Y.Z && git push --tags`
4. Release workflow fires automatically

---

*Licensed under the Apache License, Version 2.0*
