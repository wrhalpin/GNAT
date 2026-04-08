# ADR-0028: TAXII 2.1 Server

**Decision:** FastAPI implementation of TAXII 2.1; each GNAT workspace is exposed as a collection under a single `gnat` API root.

**Why workspace-as-collection:**
TAXII collections map naturally to GNAT workspaces — both are bounded sets of STIX objects
with a defined identity. The workspace name becomes the collection ID. Creating a new
workspace automatically makes it available as a TAXII collection.

**Authentication:**
TAXII 2.1 requires HTTPS + HTTP Basic auth in production. The server validates credentials
against the `[taxii]` INI section. The discovery endpoint (`GET /taxii2/`) is intentionally
unauthenticated per the TAXII 2.1 spec.

**Pagination:**
`GET /collections/{collection-id}/objects/` uses `added_after` (ISO timestamp) and `limit`/`next`
link headers per the TAXII 2.1 pagination model. GNAT's `WorkspaceStore.list_objects_after()`
implements the server-side cursor.

**STIX version filtering:**
The `Accept` header (`application/taxii+json;version=2.1`) is enforced; only STIX 2.1
bundles are served. Clients requesting TAXII 2.0 receive a `406 Not Acceptable`.

---

*Licensed under the Apache License, Version 2.0*
