# ADR-0003: Connector Architecture

**Decision:** Dual inheritance — `BaseClient` + `ConnectorMixin`.

```python
class MyConnector(BaseClient, ConnectorMixin):
    stix_type_map = {"indicator": "ioc", ...}
    def authenticate(self): ...
    def to_stix(self, native): ...
    def from_stix(self, stix_dict): ...
    def get_object(self, stix_type, object_id): ...
    def list_objects(self, stix_type, filters, page, page_size): ...
    def upsert_object(self, stix_type, payload): ...
    def delete_object(self, stix_type, object_id): ...
    def health_check(self): ...
```

**`stix_type_map`:**
Maps STIX type strings to platform-native resource names/codes.
Used by `_resolve_resource()` helpers. Must be populated at class level.

**Authentication patterns implemented:**
| Pattern | Platforms | Implementation |
|---|---|---|
| OAuth2 client-credentials | ThreatQ, CrowdStrike, GreyMatter | `post("/token", data={grant_type, client_id, client_secret})` |
| API token header | Netskope, Recorded Future, Feedly, Splunk | Set `_auth_headers` in `authenticate()` |
| HTTP Basic | Proofpoint, RiskRecon | `base64.b64encode(f"{user}:{pass}")` |
| API key header | XSOAR, Whistic | Direct header injection |

**`authenticate()` is called lazily:**
`_authenticated` flag ensures it runs exactly once per client instance.
The first HTTP request triggers it. Tests must either mock `authenticate()`
or set `client._authenticated = True` to bypass it.

**`to_stix()` contract:**
Must return a dict with at minimum:
```python
{"type": "<stix-type>", "id": "<stix-type>--<uuid>", "created": "...", "modified": "..."}
```
Use `x_` prefix for platform-specific extension fields.

**Read-only connectors:**
Platforms that don't support writes (Recorded Future, Proofpoint, Feedly)
should raise `GNATClientError` from `upsert_object` and `delete_object`
with a clear "read-only" message. The `GlobalContextRegistry` marks them
with `read_only=True` which prevents `Workspace.commit()` targeting them.

**`CLIENT_REGISTRY` in `gnat/clients/__init__.py`:**
Must be updated for every new connector. Keys are lowercase, hyphens
replaced with underscores (e.g. `"greymatter"`, `"riskrecon"`).
