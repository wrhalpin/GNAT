# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.taxii.app
====================
FastAPI application implementing the TAXII 2.1 protocol.

TAXII 2.1 spec: https://docs.oasis-open.org/cti/taxii/v2.1/

Architecture
------------
* One API root: ``gnat``
* Each GNAT workspace → one TAXII collection
* Collection ID  = workspace name (unchanged; alphanumeric + hyphens)
* Read/write controlled by ``can_read`` / ``can_write`` (both True by default)
* API key auth via ``X-Api-Key`` header (reuses ``gnat.serve.auth``)
* TAXII media type enforced on responses: ``application/taxii+json;version=2.1``

Pagination
----------
Objects are paginated via ``?next=<token>`` + ``?limit=<n>`` query params.
The ``next`` token is an opaque base64-encoded cursor (object-list offset).

STIX bundle format
------------------
``GET .../objects/`` returns a standard STIX 2.1 bundle envelope::

    {"type":"bundle","id":"bundle--<uuid>","spec_version":"2.1","objects":[...]}

Adding objects (``POST .../objects/``) accepts the same bundle format and
upserts each object into the target workspace.
"""

from __future__ import annotations

import base64
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.context.workspace import WorkspaceManager

logger = logging.getLogger(__name__)

# TAXII 2.1 media type (spec §3.1)
_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
_API_ROOT_ID = "gnat"

# FastAPI imports at module level so `from __future__ import annotations`
# does not break Request type-hint resolution in route handlers.
try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
    from fastapi.responses import JSONResponse

    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FASTAPI_AVAILABLE = False


def _require_fastapi() -> None:
    """Raise ImportError when FastAPI / uvicorn are not installed."""
    if not _FASTAPI_AVAILABLE:
        raise ImportError("FastAPI and uvicorn are required: pip install 'gnat[serve]'")
    import importlib.util

    if importlib.util.find_spec("uvicorn") is None:
        raise ImportError("uvicorn is required: pip install 'gnat[serve]'")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _taxii_response(content: Any, status_code: int = 200) -> JSONResponse:
    """Return a JSONResponse with the TAXII 2.1 media type header."""
    return JSONResponse(
        content=content,
        status_code=status_code,
        media_type=_TAXII_MEDIA_TYPE,
    )


def _utcnow_iso() -> str:
    """Internal helper for utcnow iso."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _workspace_to_collection(ws_meta: dict) -> dict:
    """Convert a WorkspaceManager list-entry to a TAXII collection object."""
    name = ws_meta.get("name", "")
    desc = ws_meta.get("description", "")
    return {
        "id": name,
        "title": name,
        "description": desc,
        "can_read": True,
        "can_write": True,
        "media_types": ["application/stix+json;version=2.1"],
    }


def _encode_cursor(offset: int) -> str:
    """Encode a pagination offset as an opaque base64 token."""
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def _decode_cursor(token: str) -> int:
    """Decode a pagination token back to an integer offset; returns 0 on error."""
    try:
        return int(base64.urlsafe_b64decode(token.encode()).decode())
    except Exception:  # noqa: BLE001
        return 0


# ---------------------------------------------------------------------------
# Auth dependency (reuses gnat.serve.auth pattern)
# ---------------------------------------------------------------------------


class _TaxiiAPIKeyAuth:
    """FastAPI callable dependency — validates ``X-Api-Key`` header."""

    def __init__(self, api_key: str) -> None:
        """Initialize _TaxiiAPIKeyAuth."""
        import hmac as _hmac

        self._key = api_key.encode("utf-8")
        self._hmac = _hmac

    def __call__(
        self,
        x_api_key: str = Header(default="", alias="X-Api-Key"),
    ) -> str:
        """Validate the API key; raise 401 on mismatch."""
        try:
            provided = x_api_key.encode("utf-8")
        except AttributeError:
            provided = b""
        if not self._hmac.compare_digest(provided, self._key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Api-Key",
            )
        return x_api_key


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def build_taxii_app(
    manager: WorkspaceManager,
    api_key: str = "",
    title: str = "GNAT TAXII 2.1 Server",
    contact: str = "",
) -> Any:
    """
    Build and return a FastAPI app implementing TAXII 2.1.

    Parameters
    ----------
    manager : WorkspaceManager
        The workspace manager whose workspaces are exposed as collections.
    api_key : str
        API key for ``X-Api-Key`` header auth.  Empty string disables auth.
    title : str
        Server title returned in the discovery endpoint.
    contact : str
        Contact email returned in the discovery endpoint.

    Returns
    -------
    fastapi.FastAPI
    """
    _require_fastapi()

    auth = _TaxiiAPIKeyAuth(api_key) if api_key else None
    auth_dep = [Depends(auth)] if auth else []

    app = FastAPI(
        title=title,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # ── Discovery (unauthenticated — spec §4.1) ────────────────────────────
    @app.get("/taxii2/", include_in_schema=False)
    def discovery() -> JSONResponse:
        """TAXII 2.1 discovery endpoint — returns server metadata."""
        body: dict = {
            "title": title,
            "description": "GNAT threat intelligence workspaces",
            "contact": contact,
            "default": f"/taxii2/roots/{_API_ROOT_ID}/",
            "api_roots": [f"/taxii2/roots/{_API_ROOT_ID}/"],
        }
        return _taxii_response(body)

    # ── API Root info (unauthenticated — spec §4.2) ────────────────────────
    @app.get(
        f"/taxii2/roots/{_API_ROOT_ID}/",
        include_in_schema=False,
    )
    def api_root_info() -> JSONResponse:
        """TAXII 2.1 API root information."""
        body = {
            "title": "GNAT workspaces",
            "description": "All GNAT analyst workspaces",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10_485_760,  # 10 MB
        }
        return _taxii_response(body)

    # ── Collections list ────────────────────────────────────────────────────
    @app.get(
        f"/taxii2/roots/{_API_ROOT_ID}/collections/",
        include_in_schema=False,
        dependencies=auth_dep,
    )
    def list_collections() -> JSONResponse:
        """Return all workspaces as TAXII collections."""
        try:
            workspaces = manager.list()
        except Exception as exc:  # noqa: BLE001
            logger.error("TAXII list_collections error: %s", exc)
            workspaces = []
        return _taxii_response({"collections": [_workspace_to_collection(w) for w in workspaces]})

    # ── Collection detail ───────────────────────────────────────────────────
    @app.get(
        f"/taxii2/roots/{_API_ROOT_ID}/collections/{{collection_id}}/",
        include_in_schema=False,
        dependencies=auth_dep,
    )
    def collection_detail(collection_id: str) -> JSONResponse:
        """Return metadata for a single TAXII collection (workspace)."""
        workspaces = manager.list()
        for ws_meta in workspaces:
            if ws_meta.get("name") == collection_id:
                return _taxii_response(_workspace_to_collection(ws_meta))
        raise HTTPException(status_code=404, detail=f"Collection {collection_id!r} not found")

    # ── Objects GET ─────────────────────────────────────────────────────────
    @app.get(
        f"/taxii2/roots/{_API_ROOT_ID}/collections/{{collection_id}}/objects/",
        include_in_schema=False,
        dependencies=auth_dep,
    )
    def get_objects(
        collection_id: str,
        request: Request,
        limit: int = 100,
        next_page: str | None = None,
        added_after: str | None = None,
        match_id: str | None = None,
        match_type: str | None = None,
        match_spec_version: str | None = None,
    ) -> JSONResponse:
        """
        Return STIX objects from a workspace as a TAXII 2.1 envelope.

        Supports ``limit``, ``next`` (pagination cursor), ``added_after``
        (ISO 8601 timestamp filter), ``match[id]``, and ``match[type]``
        query filters per the TAXII 2.1 spec.
        """
        # Parse match[] params from raw query string (FastAPI doesn't
        # auto-parse bracket notation).
        query_params = dict(request.query_params)
        if match_id is None:
            match_id = query_params.get("match[id]")
        if match_type is None:
            match_type = query_params.get("match[type]")

        try:
            ws = manager.open(collection_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Collection {collection_id!r} not found")

        # Collect all objects from workspace
        all_objects: list[dict] = []
        for obj in ws:
            d = obj.to_dict()
            # added_after filter
            if added_after:
                ts = d.get("modified") or d.get("created", "")
                if ts and ts < added_after:
                    continue
            # match[id] filter
            if match_id and d.get("id") != match_id:
                continue
            # match[type] filter
            if match_type and d.get("type") != match_type:
                continue
            all_objects.append(d)

        # Pagination
        offset = _decode_cursor(next_page) if next_page else 0
        page = all_objects[offset : offset + limit]
        more = (offset + limit) < len(all_objects)

        envelope: dict = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": page,
        }
        if more:
            envelope["next"] = _encode_cursor(offset + limit)

        headers = {
            "X-TAXII-Date-Added-First": page[0].get("created", "") if page else "",
            "X-TAXII-Date-Added-Last": page[-1].get("created", "") if page else "",
        }
        return JSONResponse(
            content=envelope,
            status_code=200,
            media_type=_TAXII_MEDIA_TYPE,
            headers={k: v for k, v in headers.items() if v},
        )

    # ── Objects POST (add to collection) ───────────────────────────────────
    @app.post(
        f"/taxii2/roots/{_API_ROOT_ID}/collections/{{collection_id}}/objects/",
        include_in_schema=False,
        dependencies=auth_dep,
    )
    async def add_objects(
        collection_id: str,
        request: Request,
    ) -> JSONResponse:
        """
        Add STIX objects to a workspace from a TAXII 2.1 envelope.

        Accepts ``application/stix+json;version=2.1`` or
        ``application/json`` request body containing a STIX bundle.
        Returns a TAXII 2.1 status resource.
        """
        try:
            ws = manager.get_or_create(collection_id)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc))

        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        if body.get("type") != "bundle":
            raise HTTPException(status_code=422, detail="Body must be a STIX bundle")

        objects_in = body.get("objects") or []
        successes: list[str] = []
        failures: list[dict] = []

        from gnat.orm.base import STIXBase

        for raw in objects_in:
            try:
                obj = STIXBase.from_dict(raw)
                ws.objects[obj.id] = obj
                ws.dirty.add(obj.id)
                successes.append(raw.get("id", "unknown"))
            except Exception as exc:  # noqa: BLE001
                failures.append({"id": raw.get("id", "unknown"), "message": str(exc)})

        try:
            ws.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("TAXII add_objects commit error: %s", exc)

        status_resource = {
            "id": str(uuid.uuid4()),
            "status": "complete" if not failures else "pending",
            "request_timestamp": _utcnow_iso(),
            "total_count": len(objects_in),
            "success_count": len(successes),
            "failure_count": len(failures),
            "pending_count": 0,
            "successes": [{"id": s, "version": _utcnow_iso()} for s in successes],
            "failures": failures,
            "pendings": [],
        }
        return _taxii_response(status_resource, status_code=202)

    # ── Manifest ────────────────────────────────────────────────────────────
    @app.get(
        f"/taxii2/roots/{_API_ROOT_ID}/collections/{{collection_id}}/manifest/",
        include_in_schema=False,
        dependencies=auth_dep,
    )
    def get_manifest(
        collection_id: str,
        limit: int = 100,
        next_page: str | None = None,
        added_after: str | None = None,
        match_type: str | None = None,
    ) -> JSONResponse:
        """
        Return the object manifest for a collection.

        The manifest lists object IDs, versions, and media types without
        returning full object bodies — useful for sync/delta operations.
        """
        try:
            ws = manager.open(collection_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Collection {collection_id!r} not found")

        entries: list[dict] = []
        for obj in ws:
            d = obj.to_dict()
            if added_after:
                ts = d.get("modified") or d.get("created", "")
                if ts and ts < added_after:
                    continue
            if match_type and d.get("type") != match_type:
                continue
            entries.append(
                {
                    "id": d.get("id", ""),
                    "date_added": d.get("created", _utcnow_iso()),
                    "version": d.get("modified") or d.get("created") or _utcnow_iso(),
                    "media_type": "application/stix+json;version=2.1",
                }
            )

        offset = _decode_cursor(next_page) if next_page else 0
        page = entries[offset : offset + limit]
        more = (offset + limit) < len(entries)

        body: dict = {"objects": page}
        if more:
            body["next"] = _encode_cursor(offset + limit)

        return _taxii_response(body)

    # ── Single object ───────────────────────────────────────────────────────
    @app.get(
        f"/taxii2/roots/{_API_ROOT_ID}/collections/{{collection_id}}/objects/{{object_id}}/",
        include_in_schema=False,
        dependencies=auth_dep,
    )
    def get_object(
        collection_id: str,
        object_id: str,
    ) -> JSONResponse:
        """Return a single STIX object by ID as a one-item TAXII bundle."""
        try:
            ws = manager.open(collection_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Collection {collection_id!r} not found")

        obj = ws.objects.get(object_id)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Object {object_id!r} not found")

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [obj.to_dict()],
        }
        return _taxii_response(bundle)

    # ── Versions (spec §5.5) ────────────────────────────────────────────────
    @app.get(
        f"/taxii2/roots/{_API_ROOT_ID}/collections/{{collection_id}}/objects/{{object_id}}/versions/",
        include_in_schema=False,
        dependencies=auth_dep,
    )
    def get_object_versions(
        collection_id: str,
        object_id: str,
    ) -> JSONResponse:
        """Return available versions for a single STIX object."""
        try:
            ws = manager.open(collection_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Collection {collection_id!r} not found")

        obj = ws.objects.get(object_id)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Object {object_id!r} not found")

        d = obj.to_dict()
        version = d.get("modified") or d.get("created") or _utcnow_iso()
        return _taxii_response({"versions": [version]})

    return app


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------


def run_taxii_server(
    manager: WorkspaceManager,
    host: str = "127.0.0.1",
    port: int = 8090,
    api_key: str = "",
    title: str = "GNAT TAXII 2.1 Server",
    contact: str = "",
) -> None:
    """
    Start the TAXII 2.1 server with uvicorn.

    Parameters
    ----------
    manager : WorkspaceManager
        Workspace manager to expose.
    host : str
        Bind address.  Default ``"127.0.0.1"``.
    port : int
        TCP port.  Default ``8090``.
    api_key : str
        API key for ``X-Api-Key`` auth.  Generated and printed if empty.
    title : str
        Server title in TAXII discovery response.
    contact : str
        Contact email in TAXII discovery response.
    """
    _require_fastapi()
    import secrets
    import sys

    import uvicorn  # type: ignore[import]

    if not api_key:
        api_key = secrets.token_hex(32)
        print(
            f"[gnat taxii] Generated API key: {api_key}",
            file=sys.stderr,
        )

    app = build_taxii_app(manager, api_key=api_key, title=title, contact=contact)
    uvicorn.run(app, host=host, port=port, log_level="info")
