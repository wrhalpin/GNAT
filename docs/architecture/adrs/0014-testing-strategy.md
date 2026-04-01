# ADR-0014: Testing Strategy

**Unit test structure:**
```
tests/unit/
├── test_orm.py          # 40+ assertions: STIXBase + all domain types
├── test_client.py       # GNATConfig, GNATClient (6 targets), BaseClient HTTP
├── connectors/
│   └── test_connectors.py   # auth, CRUD, to_stix/from_stix for all connectors
├── ingest/
│   └── test_ingest.py       # 300+ assertions: all readers, mappers, pipeline
├── context/
│   └── test_context.py      # store, registry, workspace, enrichment, commit
└── viz/
    └── test_viz.py          # tabular, graph, export, Grafana server
```

**Mock pattern for connectors:**
```python
def _authenticated(connector_cls, **kwargs):
    c = connector_cls(host="https://fake.example.com", **kwargs)
    c._authenticated = True   # bypass authenticate()
    return c
```

**Mock pattern for HTTP layer:**
```python
monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [...]}))
```
Never mock `_request()` directly — mock the public HTTP methods (`get`,
`post`, `put`, `delete`) so retry/header logic is still exercised.

**`to_stix` contract assertion (use in every connector test):**
```python
def _assert_stix_contract(stix_dict):
    assert isinstance(stix_dict, dict)
    assert "type" in stix_dict
    assert "id" in stix_dict
    assert "--" in stix_dict["id"]  # valid STIX id format
```

**Integration tests opt-in:**
```bash
GNAT_CONFIG=/path/to/real.ini pytest tests/integration/ --run-integration -v
```
Never run in CI without real credentials. The GitHub Actions `ci.yml`
does not include `--run-integration`.

**`DeduplicationCache` truthiness:**
An empty cache is falsy via `__len__`. Always guard with
`if cache is not None` not `if cache`. This is a known footgun.
