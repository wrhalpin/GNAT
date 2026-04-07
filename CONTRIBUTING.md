# Contributing to GNAT

Thank you for considering a contribution. This document covers the workflow
for bug reports, new connectors, new ingest readers/mappers, and general
improvements.

---

## Table of Contents

1. [Development setup](#development-setup)
2. [Running tests](#running-tests)
3. [Adding a new connector](#adding-a-new-connector)
4. [Adding a new ingest reader or mapper](#adding-a-new-ingest-reader-or-mapper)
5. [Code style](#code-style)
6. [Pull request checklist](#pull-request-checklist)

---

## Development Setup

```bash
git clone https://github.com/your-org/gnat.git
cd gnat
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Verify everything works:

```bash
make test
```

---

## Running Tests

```bash
# All unit tests
make test

# With coverage report
make coverage

# A specific test file
pytest tests/unit/ingest/test_ingest.py -v

# Integration tests (requires real credentials in ~/.gnat/config.ini)
GNAT_CONFIG=/path/to/real.ini pytest tests/integration/ --run-integration -v
```

---

## Adding a New Connector

The fastest path is the built-in code generator:

```bash
# Download the platform's OpenAPI spec, then:
gnat-codegen \
    --spec    ./specs/myplatform-openapi.json \
    --name    myplatform \
    --auth    oauth2
```

This scaffolds `gnat/connectors/myplatform/client.py` and a test file.
Then:

1. **Fill in `authenticate()`** — inject the correct auth header(s).
2. **Implement `to_stix(native)`** — map platform fields → STIX 2.1 dict.
3. **Implement `from_stix(stix_dict)`** — map STIX → platform request payload.
4. **Implement `get_object()`, `list_objects()`, `upsert_object()`, `delete_object()`**.
5. **Register the connector** in `gnat/clients/__init__.py`:

   ```python
   from gnat.connectors.myplatform.client import MyplatformClient
   CLIENT_REGISTRY["myplatform"] = MyplatformClient
   ```

6. **Add a config section** to `config/config.ini.example`.
7. **Run the generated tests** and add more assertions covering your STIX
   translation edge cases.

### Connector contract

Every connector must inherit from both `BaseClient` and `ConnectorMixin`:

```python
from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

class MyplatformClient(BaseClient, ConnectorMixin):
    stix_type_map = {"indicator": "ioc", ...}

    def authenticate(self) -> None: ...
    def health_check(self) -> bool: ...
    def to_stix(self, native: dict) -> dict: ...
    def from_stix(self, stix_dict: dict) -> dict: ...
    def get_object(self, stix_type: str, object_id: str) -> dict: ...
    def list_objects(self, stix_type, filters=None, page=1, page_size=100): ...
    def upsert_object(self, stix_type: str, payload: dict) -> dict: ...
    def delete_object(self, stix_type: str, object_id: str) -> None: ...
```

### `to_stix` / `from_stix` contract

`to_stix` must return a dict with at minimum:

```python
{"type": "<stix-type>", "id": "<stix-type>--<uuid>", "created": "...", "modified": "..."}
```

Use `x_` prefixes for non-standard extension fields (e.g. `x_rf_risk_score`).

---

## Adding a New Ingest Reader or Mapper

### New SourceReader

1. Subclass `gnat.ingest.base.SourceReader`.
2. Implement `_iter_records(self) -> Iterator[RawRecord]`.
3. Override `open()` / `close()` if you manage external resources.
4. Export from `gnat/ingest/sources/__init__.py` and `gnat/__init__.py`.
5. Add unit tests in `tests/unit/ingest/test_ingest.py`.

```python
class MyReader(SourceReader):
    """One-line summary.

    Extended description, parameters, examples.
    """
    def __init__(self, source, **kwargs):
        super().__init__(source_id=str(source), **kwargs)
        self._source = source

    def _iter_records(self):
        # yield plain dicts
        for item in self._load():
            yield {"value": item["ip"], "type": "ip", ...}
```

### New RecordMapper

1. Subclass `gnat.ingest.base.RecordMapper`.
2. Implement `map(self, record: RawRecord) -> Iterator[STIXBase]`.
3. Use `self._client`, `self.tlp_marking`, `self.confidence` for consistency.
4. Export from `gnat/ingest/mappers/__init__.py` and `gnat/__init__.py`.
5. Add unit tests.

```python
class MyMapper(RecordMapper):
    """Convert MySource records to STIX Indicators."""

    def map(self, record):
        value = record.get("ip", "").strip()
        if not value:
            return
        yield Indicator(
            client=self._client,
            name=value,
            pattern=f"[ipv4-addr:value = '{value}']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            valid_from=record.get("timestamp", _utcnow()),
            x_tlp=self.tlp_marking,
            confidence=self.confidence,
        )
```

---

## Code Style

GNAT uses **Ruff** for linting and formatting:

```bash
make lint       # ruff check + ruff format --check
make fmt        # ruff format (auto-fix)
make typecheck  # mypy
```

Key conventions:

- All public classes, methods, and module-level functions must have
  **NumPy-style docstrings** with `Parameters`, `Returns`, `Raises`, and
  `Examples` sections where applicable.
- Private helpers use single-underscore prefix (`_iter_records`).
- No bare `except Exception` — use `except Exception as exc` and log or
  re-raise.
- Use `logger = logging.getLogger(__name__)` per module; never `print()`.
- Type annotations on all public signatures; `TYPE_CHECKING` guards for
  circular imports.

---

## Pull Request Checklist

Before opening a PR:

- [ ] `make test` passes with no failures
- [ ] New code has unit tests (`tests/unit/`)
- [ ] Docstrings present on all public classes and methods
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] `config/config.ini.example` updated if new config keys added
- [ ] `gnat/__init__.py` updated if new public symbols added
- [ ] `make lint` and `make typecheck` clean (or known suppressions documented)

---

*Licensed under the Apache License, Version 2.0*
