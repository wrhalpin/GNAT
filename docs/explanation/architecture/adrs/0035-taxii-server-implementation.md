# ADR-0035: TAXII 2.1 Server Implementation

**Decision:** Implement a lightweight TAXII 2.1 server in `gnat.dissemination.taxii`
using FastAPI (already a dependency in `[serve]`) with TLP-based collection
access control.  No third-party TAXII library is introduced at this stage.

**TAXII 2.1 endpoints implemented (read-only Phase 4):**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/taxii2/` | Discovery endpoint |
| GET | `/taxii2/{api-root}/` | API root information |
| GET | `/taxii2/{api-root}/collections/` | List collections |
| GET | `/taxii2/{api-root}/collections/{id}/` | Collection metadata |
| GET | `/taxii2/{api-root}/collections/{id}/objects/` | Fetch STIX objects |
| GET | `/taxii2/{api-root}/collections/{id}/manifest/` | Object manifest |

Write endpoints (POST objects) are internal-only in Phase 4 — external
consumers are read-only.  Full write access is deferred to a future release.

**Why FastAPI over a dedicated TAXII library:**
- `taxii2-server` (pip) is unmaintained as of 2023
- `libtaxii2` targets TAXII 1.x
- FastAPI is already present for `gnat.serve`; sharing the dependency avoids
  a second HTTP framework
- TAXII 2.1 is a thin REST protocol over STIX JSON — the spec is
  implementable in ~300 lines without a framework

**Collection model — one per TLP level:**
Each TLP level maps to a named collection.  API key grants read access to
collections up to and including its authorised TLP level:

| Collection | Contents | Required access level |
|------------|----------|-----------------------|
| `tlp-white` | TLP:WHITE published reports | Any valid key |
| `tlp-green` | TLP:GREEN + WHITE | green or above |
| `tlp-amber` | TLP:AMBER + below | amber or above |
| `tlp-red`   | TLP:RED + below | red (explicit grant) |

**Authentication:** Bearer token (API key) passed in `Authorization` header.
Key → TLP level mapping is stored in `gnat.dissemination.api.auth.APIKeyStore`.

**Content-Type:** TAXII 2.1 requires `application/taxii+json;version=2.1`.
FastAPI response classes are customised to emit this content type.

**Pagination:** TAXII 2.1 uses `added_after`, `limit`, and `next` cursor
parameters.  Implementation uses offset-based pagination over the report store
(keyed on `published_at`); `next` cursor is base64-encoded offset.

**Why not a separate TAXII process:**
GNAT already exposes a FastAPI server in `gnat.serve`.  The TAXII router is
mounted as a sub-application prefix (`/taxii2`) on the same process, avoiding
a second service to operate and monitor.
