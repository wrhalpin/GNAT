"""
gnat.dissemination.taxii.server
================================

TAXII 2.1 server implemented as a FastAPI router.

Mount on an existing FastAPI application::

    from gnat.dissemination.taxii.server import build_taxii_router
    from gnat.dissemination.api.auth import APIKeyStore

    key_store = APIKeyStore()
    key_store.add_key("my-secret-key", TLPLevel.AMBER, role="senior_analyst")

    router = build_taxii_router(report_store=store, key_store=key_store)
    app.include_router(router, prefix="/taxii2")

The router implements all TAXII 2.1 endpoints:

**Read endpoints (all TLP levels):**
- GET  /taxii2/ — discovery
- GET  /taxii2/{api-root}/ — API root information
- GET  /taxii2/{api-root}/collections/ — list collections
- GET  /taxii2/{api-root}/collections/{id}/ — collection metadata
- GET  /taxii2/{api-root}/collections/{id}/objects/ — fetch STIX objects
- GET  /taxii2/{api-root}/collections/{id}/manifest/ — object manifest

**Write endpoints (TLP:AMBER+ collections and WRITE_TAXII permission):**
- POST   /taxii2/{api-root}/collections/{id}/objects/ — push STIX bundle
- DELETE /taxii2/{api-root}/collections/{id}/objects/{stix-id} — soft-delete
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from gnat.analysis.tlp import TLPLevel
from gnat.dissemination.taxii.collections import (
    COLLECTION_BY_ID,
    COLLECTIONS,
    collections_for_key,
    tlp_filter_for_collection,
)

logger = logging.getLogger(__name__)

# TAXII 2.1 media type
_TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
_STIX_CONTENT_TYPE  = "application/stix+json;version=2.1"

_API_ROOT = "intelligence"  # single API root name


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def _decode_cursor(cursor: str) -> int:
    try:
        return int(base64.urlsafe_b64decode(cursor.encode()).decode())
    except Exception:
        return 0


def build_taxii_router(
    report_store:  Any,
    key_store:     Any,
    policy_engine: Any | None = None,
) -> Any:
    """
    Build a FastAPI router implementing TAXII 2.1.

    Parameters
    ----------
    report_store : ReportStore
        Persistence backend for published intelligence reports.
    key_store : APIKeyStore
        Maps Bearer tokens → TLP access levels and RBAC roles.
    policy_engine : PolicyEngine, optional
        Used to enforce ``WRITE_TAXII`` permission on write endpoints.
        If ``None``, a default :class:`~gnat.policy.engine.PolicyEngine`
        is created.

    Returns
    -------
    fastapi.APIRouter
    """
    try:
        from fastapi import APIRouter, Depends, Header, HTTPException, Query
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "FastAPI is required for the TAXII server. "
            "Install it with: pip install 'gnat[serve]'"
        ) from exc

    from gnat.policy import PolicyEngine, Permission

    router  = APIRouter()
    _engine = policy_engine or PolicyEngine()

    # ── Auth dependencies ─────────────────────────────────────────────────────

    def _require_api_key(authorization: str = Header(default="")) -> TLPLevel:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer token.")
        token    = authorization.removeprefix("Bearer ").strip()
        tlp_level = key_store.get_tlp_level(token)
        if tlp_level is None:
            raise HTTPException(status_code=401, detail="Invalid API key.")
        return tlp_level

    # Dependency that resolves the full APIKey (needed for role checks)
    _require_write_taxii = _engine.require(
        Permission.WRITE_TAXII, key_store=key_store
    )

    def _taxii_response(data: dict | list, status: int = 200) -> JSONResponse:
        return JSONResponse(
            content     = data,
            status_code = status,
            headers     = {"Content-Type": _TAXII_CONTENT_TYPE},
        )

    # ── Endpoints ─────────────────────────────────────────────────────────────

    @router.get("/")
    def taxii_discovery(
        key_tlp: TLPLevel = Depends(_require_api_key),
    ) -> JSONResponse:
        """GET /taxii2/ — Discovery endpoint."""
        body = {
            "title":            "GNAT Threat Intelligence TAXII Server",
            "description":      "TAXII 2.1 feed for GNAT finished intelligence reports.",
            "contact":          "gnat@example.com",
            "default":          f"/taxii2/{_API_ROOT}/",
            "api_roots":        [f"/taxii2/{_API_ROOT}/"],
        }
        return _taxii_response(body)

    @router.get("/{api_root}/")
    def api_root_info(
        api_root: str,
        key_tlp:  TLPLevel = Depends(_require_api_key),
    ) -> JSONResponse:
        """GET /taxii2/{api-root}/ — API root information."""
        if api_root != _API_ROOT:
            from fastapi import HTTPException as _HTTPException
            raise _HTTPException(status_code=404, detail=f"Unknown API root: {api_root!r}")
        body = {
            "title":       "GNAT Intelligence API Root",
            "description": "Published finished intelligence accessible via TLP level.",
            "versions":    ["application/taxii+json;version=2.1"],
            "max_content_length": 10 * 1024 * 1024,
        }
        return _taxii_response(body)

    @router.get("/{api_root}/collections/")
    def list_collections(
        api_root: str,
        key_tlp:  TLPLevel = Depends(_require_api_key),
    ) -> JSONResponse:
        """GET /taxii2/{api-root}/collections/ — List accessible collections."""
        if api_root != _API_ROOT:
            raise HTTPException(status_code=404, detail=f"Unknown API root: {api_root!r}")
        accessible = collections_for_key(key_tlp)
        body = {"collections": [c.to_taxii_dict() for c in accessible]}
        return _taxii_response(body)

    @router.get("/{api_root}/collections/{collection_id}/")
    def get_collection(
        api_root:      str,
        collection_id: str,
        key_tlp:       TLPLevel = Depends(_require_api_key),
    ) -> JSONResponse:
        """GET /taxii2/{api-root}/collections/{id}/ — Collection metadata."""
        if api_root != _API_ROOT:
            raise HTTPException(status_code=404, detail=f"Unknown API root: {api_root!r}")
        col = COLLECTION_BY_ID.get(collection_id)
        if col is None:
            raise HTTPException(status_code=404, detail=f"Collection not found: {collection_id!r}")
        if not col.is_accessible(key_tlp):
            raise HTTPException(status_code=403, detail="Insufficient TLP access level.")
        return _taxii_response(col.to_taxii_dict())

    @router.get("/{api_root}/collections/{collection_id}/objects/")
    def get_objects(
        api_root:      str,
        collection_id: str,
        added_after:   str  | None = Query(default=None),
        limit:         int         = Query(default=100, ge=1, le=1000),
        next_cursor:   str  | None = Query(default=None, alias="next"),
        key_tlp:       TLPLevel    = Depends(_require_api_key),
    ) -> JSONResponse:
        """GET /taxii2/{api-root}/collections/{id}/objects/ — Fetch STIX objects."""
        if api_root != _API_ROOT:
            raise HTTPException(status_code=404, detail=f"Unknown API root: {api_root!r}")
        col = COLLECTION_BY_ID.get(collection_id)
        if col is None:
            raise HTTPException(status_code=404, detail=f"Collection not found: {collection_id!r}")
        if not col.is_accessible(key_tlp):
            raise HTTPException(status_code=403, detail="Insufficient TLP access level.")

        offset     = _decode_cursor(next_cursor) if next_cursor else 0
        tlp_values = tlp_filter_for_collection(collection_id)

        # Fetch published reports filtered by TLP level
        all_reports = _fetch_reports(report_store, tlp_values, added_after)
        page        = all_reports[offset : offset + limit]
        objects     = [_report_to_stix_envelope(r) for r in page]

        headers: dict[str, str] = {"Content-Type": _STIX_CONTENT_TYPE}
        has_more = (offset + limit) < len(all_reports)
        if has_more:
            headers["X-TAXII-Next"] = _encode_cursor(offset + limit)

        envelope = {
            "type":    "bundle",
            "id":      f"bundle--{collection_id}",
            "objects": objects,
        }
        if has_more:
            envelope["next"] = _encode_cursor(offset + limit)

        return JSONResponse(content=envelope, headers=headers)

    @router.get("/{api_root}/collections/{collection_id}/manifest/")
    def get_manifest(
        api_root:      str,
        collection_id: str,
        added_after:   str  | None = Query(default=None),
        limit:         int         = Query(default=100, ge=1, le=1000),
        next_cursor:   str  | None = Query(default=None, alias="next"),
        key_tlp:       TLPLevel    = Depends(_require_api_key),
    ) -> JSONResponse:
        """GET /taxii2/{api-root}/collections/{id}/manifest/ — Object manifest."""
        if api_root != _API_ROOT:
            raise HTTPException(status_code=404, detail=f"Unknown API root: {api_root!r}")
        col = COLLECTION_BY_ID.get(collection_id)
        if col is None:
            raise HTTPException(status_code=404, detail=f"Collection not found: {collection_id!r}")
        if not col.is_accessible(key_tlp):
            raise HTTPException(status_code=403, detail="Insufficient TLP access level.")

        offset     = _decode_cursor(next_cursor) if next_cursor else 0
        tlp_values = tlp_filter_for_collection(collection_id)

        all_reports = _fetch_reports(report_store, tlp_values, added_after)
        page        = all_reports[offset : offset + limit]

        manifest_entries = []
        for r in page:
            stix_id  = getattr(r, "stix_id", None) or f"report--{r.id}"
            modified = (
                r.published_at.isoformat() if r.published_at else
                r.updated_at.isoformat()
            )
            manifest_entries.append({
                "id":       stix_id,
                "date_added": modified,
                "version":  modified,
                "media_types": ["application/stix+json;version=2.1"],
            })

        body: dict[str, Any] = {"objects": manifest_entries}
        has_more = (offset + limit) < len(all_reports)
        if has_more:
            body["next"] = _encode_cursor(offset + limit)

        return _taxii_response(body)

    # ── Write endpoints ───────────────────────────────────────────────────────

    @router.post("/{api_root}/collections/{collection_id}/objects/")
    def add_objects(
        api_root:      str,
        collection_id: str,
        body:          dict[str, Any],
        api_key:       Any     = Depends(_require_write_taxii),
        key_tlp:       TLPLevel = Depends(_require_api_key),
    ) -> JSONResponse:
        """
        POST /taxii2/{api-root}/collections/{id}/objects/

        Push a STIX 2.1 bundle into the collection.

        Access requirements:
        - Bearer token must be valid and have ``WRITE_TAXII`` permission.
        - The collection must have ``can_write=True`` (TLP:AMBER and TLP:RED only).
        - The key's TLP level must be >= the collection's minimum access level.

        The server extracts STIX objects from the bundle, routes ``report``
        type objects to the report store, and logs all others.
        """
        if api_root != _API_ROOT:
            raise HTTPException(status_code=404, detail=f"Unknown API root: {api_root!r}")
        col = COLLECTION_BY_ID.get(collection_id)
        if col is None:
            raise HTTPException(status_code=404, detail=f"Collection not found: {collection_id!r}")
        if not col.can_write:
            raise HTTPException(status_code=405, detail="Collection does not allow writes.")
        if not col.is_accessible(key_tlp):
            raise HTTPException(status_code=403, detail="Insufficient TLP access level.")

        if body.get("type") != "bundle":
            raise HTTPException(
                status_code=422,
                detail="Request body must be a STIX 2.1 bundle (type='bundle').",
            )

        ingested, skipped = _ingest_stix_objects(body, report_store)

        status_record = {
            "id":               f"status--{collection_id}",
            "status":           "complete",
            "request_timestamp": "",
            "total_count":      ingested + skipped,
            "success_count":    ingested,
            "failure_count":    0,
            "pending_count":    0,
        }
        return JSONResponse(content=status_record, status_code=202,
                            headers={"Content-Type": _TAXII_CONTENT_TYPE})

    @router.delete("/{api_root}/collections/{collection_id}/objects/{stix_id:path}")
    def delete_object(
        api_root:      str,
        collection_id: str,
        stix_id:       str,
        api_key:       Any     = Depends(_require_write_taxii),
        key_tlp:       TLPLevel = Depends(_require_api_key),
    ) -> JSONResponse:
        """
        DELETE /taxii2/{api-root}/collections/{id}/objects/{stix-id}

        Soft-delete a STIX object by its STIX ID.

        Access requirements: same as POST (``WRITE_TAXII`` + collection TLP).

        The server attempts to locate a report whose ``stix_id`` matches
        *stix_id* and marks it as deleted.  Returns 200 on success, 404 if
        not found, 405 if the collection does not support writes.
        """
        if api_root != _API_ROOT:
            raise HTTPException(status_code=404, detail=f"Unknown API root: {api_root!r}")
        col = COLLECTION_BY_ID.get(collection_id)
        if col is None:
            raise HTTPException(status_code=404, detail=f"Collection not found: {collection_id!r}")
        if not col.can_write:
            raise HTTPException(status_code=405, detail="Collection does not allow writes.")
        if not col.is_accessible(key_tlp):
            raise HTTPException(status_code=403, detail="Insufficient TLP access level.")

        deleted = _soft_delete_object(stix_id, report_store)
        if not deleted:
            raise HTTPException(
                status_code=404,
                detail=f"Object not found: {stix_id!r}",
            )

        return JSONResponse(
            content={"deleted": True, "id": stix_id},
            status_code=200,
            headers={"Content-Type": _TAXII_CONTENT_TYPE},
        )

    return router


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ingest_stix_objects(bundle: dict[str, Any], store: Any) -> tuple[int, int]:
    """
    Extract STIX objects from *bundle* and route them to *store*.

    ``report``-type objects are forwarded to the report store's
    ``ingest_stix()`` method if present, otherwise logged.  All other
    object types are logged only (no storage yet).

    Returns
    -------
    (ingested, skipped) : tuple[int, int]
        Counts of successfully stored and skipped objects.
    """
    objects  = bundle.get("objects", [])
    ingested = 0
    skipped  = 0

    for obj in objects:
        obj_type = obj.get("type", "unknown")
        obj_id   = obj.get("id", "")
        if obj_type == "report":
            try:
                if hasattr(store, "ingest_stix"):
                    store.ingest_stix(obj)
                    ingested += 1
                else:
                    logger.info("TAXII ingest: report %s received (no store.ingest_stix)", obj_id)
                    ingested += 1
            except Exception as exc:
                logger.warning("TAXII ingest: failed to store report %s: %s", obj_id, exc)
                skipped += 1
        else:
            logger.info("TAXII ingest: received %s %s (no handler — logged only)", obj_type, obj_id)
            skipped += 1

    return ingested, skipped


def _soft_delete_object(stix_id: str, store: Any) -> bool:
    """
    Attempt to soft-delete the object identified by *stix_id*.

    Tries ``store.delete_by_stix_id(stix_id)`` first; falls back to
    scanning ``store.list()`` for a matching ``stix_id`` attribute and
    calling ``store.delete(r.id)``.

    Returns True if the object was found and (soft-)deleted.
    """
    # Direct API (preferred)
    if hasattr(store, "delete_by_stix_id"):
        try:
            return bool(store.delete_by_stix_id(stix_id))
        except Exception as exc:
            logger.warning("TAXII delete: delete_by_stix_id(%s) failed: %s", stix_id, exc)
            return False

    # Fallback: scan and delete
    try:
        all_reports = store.list(page_size=10_000)
    except Exception:
        return False

    for r in all_reports:
        if getattr(r, "stix_id", None) == stix_id:
            try:
                store.delete(r.id)
                return True
            except Exception as exc:
                logger.warning("TAXII delete: store.delete(%s) failed: %s", r.id, exc)
                return False

    return False


def _fetch_reports(
    store:       Any,
    tlp_values:  list[str],
    added_after: str | None,
) -> list[Any]:
    """
    Return published reports whose TLP level is in *tlp_values*.

    Ordered by published_at ascending (oldest first, TAXII convention).
    """
    try:
        reports = store.list(
            status     = "published",
            page_size  = 10_000,  # fetch all; paginate in caller
        )
    except Exception:
        try:
            reports = store.list(page_size=10_000)
        except Exception:
            return []

    filtered = []
    for r in reports:
        # Filter by TLP
        tlp = _get_tlp_value(r)
        if tlp not in tlp_values:
            continue
        # Filter by added_after (ISO 8601)
        if added_after:
            published = getattr(r, "published_at", None)
            if published is None:
                continue
            pub_str = published.isoformat() if hasattr(published, "isoformat") else str(published)
            if pub_str <= added_after:
                continue
        filtered.append(r)

    # Sort by published_at ascending
    filtered.sort(
        key=lambda r: (
            getattr(r, "published_at", None) or getattr(r, "updated_at", None) or ""
        )
    )
    return filtered


def _get_tlp_value(report: Any) -> str:
    """Extract TLP string value from a report object."""
    classification = getattr(report, "classification", None)
    if classification is None:
        return "white"
    if isinstance(classification, str):
        return classification.lower()
    # TLPLevel or object with .value
    return str(getattr(classification, "value", classification)).lower()


def _report_to_stix_envelope(report: Any) -> dict[str, Any]:
    """
    Convert a report to a minimal STIX envelope dict.

    Prefers cached ``stix_bundle_json``; falls back to a lightweight dict.
    """
    cached = getattr(report, "stix_bundle_json", None)
    if cached:
        try:
            bundle = json.loads(cached)
            objects = bundle.get("objects", [])
            # Return the first report SDO if present, else wrap
            for obj in objects:
                if obj.get("type") == "report":
                    return obj
        except Exception:
            pass

    # Minimal fallback STIX report dict
    stix_id = getattr(report, "stix_id", None) or f"report--{report.id}"
    published = getattr(report, "published_at", None) or getattr(report, "updated_at", None)
    pub_str   = published.isoformat() if hasattr(published, "isoformat") else str(published or "")
    return {
        "type":         "report",
        "spec_version": "2.1",
        "id":           stix_id,
        "name":         getattr(report, "title", ""),
        "description":  getattr(report, "executive_summary", "") or "",
        "published":    pub_str,
        "created":      pub_str,
        "modified":     pub_str,
        "object_refs":  [],
    }
