"""
gnat.dissemination.api.gateway
================================

FastAPI REST gateway for the GNAT dissemination layer.

Provides authenticated REST endpoints for:
- Exporting reports (STIX / JSON / PDF)
- Querying report metadata
- Managing API keys (admin endpoints)
- Health check

Mount alongside TAXII::

    from gnat.dissemination.api.gateway import build_gateway_router
    from gnat.dissemination.api.auth import APIKeyStore
    from gnat.dissemination.export import ExportService

    key_store  = APIKeyStore()
    export_svc = ExportService(report_store)
    router     = build_gateway_router(export_svc, key_store)

    app.include_router(router, prefix="/api/v1")
"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

from gnat.analysis.tlp import TLPLevel
from gnat.dissemination.api.auth import APIKey, APIKeyStore
from gnat.dissemination.export import ExportFormat, ExportService

logger = logging.getLogger(__name__)


def build_gateway_router(
    export_service: ExportService,
    key_store:      APIKeyStore,
    report_store:   Any | None = None,
) -> Any:
    """
    Build a FastAPI router for the GNAT dissemination REST gateway.

    Parameters
    ----------
    export_service : ExportService
        Service used to export report content.
    key_store : APIKeyStore
        API key → TLP level mapping.
    report_store : ReportStore, optional
        If provided, enables the ``/reports`` listing endpoint.

    Returns
    -------
    fastapi.APIRouter
    """
    try:
        from fastapi import APIRouter, Depends, Header, HTTPException, Query
        from fastapi.responses import FileResponse, JSONResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "FastAPI is required for the gateway. "
            "Install it with: pip install 'gnat[serve]'"
        ) from exc

    router = APIRouter()

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _require_api_key(authorization: str = Header(default="")) -> APIKey:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer token.")
        token = authorization.removeprefix("Bearer ").strip()
        key   = key_store.get_key(token)
        if key is None or not key.is_valid():
            raise HTTPException(status_code=401, detail="Invalid or expired API key.")
        return key

    # ── Health ────────────────────────────────────────────────────────────────

    @router.get("/health")
    def health() -> JSONResponse:
        """Health check — no authentication required."""
        return JSONResponse({"status": "ok", "service": "gnat-dissemination"})

    # ── Reports ───────────────────────────────────────────────────────────────

    @router.get("/reports")
    def list_reports(
        page:      int  = Query(default=1, ge=1),
        page_size: int  = Query(default=50, ge=1, le=500),
        api_key:   APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """List published reports accessible at the caller's TLP level."""
        if report_store is None:
            raise HTTPException(status_code=501, detail="Report store not configured.")

        try:
            reports = report_store.list(
                status    = "published",
                page      = page,
                page_size = page_size,
            )
        except Exception:
            reports = report_store.list(page=page, page_size=page_size)

        result = []
        for r in reports:
            report_tlp = _extract_tlp_rank(r)
            if report_tlp > api_key.tlp_level.rank:
                continue
            result.append({
                "id":          str(r.id),
                "title":       r.title,
                "report_type": getattr(getattr(r, "report_type", None), "value", ""),
                "tlp":         getattr(getattr(r, "classification", None), "value", ""),
                "status":      getattr(getattr(r, "status", None), "value", ""),
                "published_at": (
                    r.published_at.isoformat()
                    if getattr(r, "published_at", None) else None
                ),
            })

        return JSONResponse({
            "page":      page,
            "page_size": page_size,
            "count":     len(result),
            "reports":   result,
        })

    @router.get("/reports/{report_id}")
    def get_report(
        report_id: str,
        api_key:   APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """Fetch report metadata by ID."""
        if report_store is None:
            raise HTTPException(status_code=501, detail="Report store not configured.")
        r = report_store.get(report_id)
        if r is None:
            raise HTTPException(status_code=404, detail=f"Report not found: {report_id!r}")
        if _extract_tlp_rank(r) > api_key.tlp_level.rank:
            raise HTTPException(status_code=403, detail="Insufficient TLP access level.")
        return JSONResponse(r.to_dict() if hasattr(r, "to_dict") else {"id": report_id})

    # ── Export ────────────────────────────────────────────────────────────────

    @router.get("/reports/{report_id}/export/stix")
    def export_stix(
        report_id: str,
        api_key:   APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """
        Export a report as a STIX 2.1 bundle (in-memory, no disk write).

        Returns
        -------
        JSONResponse
            STIX bundle as JSON.
        """
        try:
            bundle = export_service.export_stix_bundle(report_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        # TLP access check
        report_tlp = _bundle_tlp_rank(bundle)
        if report_tlp > api_key.tlp_level.rank:
            raise HTTPException(status_code=403, detail="Insufficient TLP access level.")

        return JSONResponse(bundle, headers={"Content-Type": "application/stix+json;version=2.1"})

    @router.get("/reports/{report_id}/export/json")
    def export_json(
        report_id: str,
        api_key:   APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """Export a report as GNAT internal JSON."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            tmp_path = fh.name
        try:
            result = export_service.export(report_id, ExportFormat.JSON, tmp_path)
            import json as _json
            with open(tmp_path, "rb") as fh:
                data = _json.loads(fh.read())
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        finally:
            _safe_unlink(tmp_path)

        return JSONResponse({
            "report_id":  result.report_id,
            "format":     result.format.value,
            "size_bytes": result.size_bytes,
            "checksum":   result.checksum,
            "data":       data,
        })

    @router.get("/reports/{report_id}/export/pdf")
    def export_pdf(
        report_id: str,
        api_key:   APIKey = Depends(_require_api_key),
    ) -> Any:
        """Export a report as PDF (download)."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as fh:
            tmp_path = fh.name
        try:
            export_service.export(report_id, ExportFormat.PDF, tmp_path)
        except ValueError as exc:
            _safe_unlink(tmp_path)
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        return FileResponse(
            path         = tmp_path,
            filename     = f"report-{report_id}.pdf",
            media_type   = "application/pdf",
            background   = _cleanup_background(tmp_path),
        )

    # ── Admin: key management ─────────────────────────────────────────────────

    @router.get("/admin/keys")
    def list_keys(
        api_key: APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """List all API keys (RED-level admin only)."""
        _require_admin(api_key)
        return JSONResponse({
            "keys": [k.to_dict() for k in key_store.list_keys()]
        })

    @router.post("/admin/keys")
    def create_key(
        body:    dict[str, Any],
        api_key: APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """
        Create a new API key.

        Request body
        ------------
        ``tlp_level`` : str  (e.g. ``"amber"``)
        ``label``     : str  (optional)
        """
        _require_admin(api_key)
        try:
            tlp = TLPLevel(body.get("tlp_level", "white").lower())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid tlp_level.")
        new_key = key_store.generate_key(tlp, label=body.get("label", ""))
        return JSONResponse(
            {**new_key.to_dict(), "token": new_key.token},
            status_code=201,
        )

    @router.delete("/admin/keys/{token_prefix}")
    def revoke_key(
        token_prefix: str,
        api_key:      APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """Revoke an API key by its full token or a unique prefix."""
        _require_admin(api_key)
        # Find by prefix
        matches = [
            k for k in key_store.list_keys()
            if k.token.startswith(token_prefix)
        ]
        if not matches:
            raise HTTPException(status_code=404, detail="Key not found.")
        if len(matches) > 1:
            raise HTTPException(
                status_code=400,
                detail="Token prefix matches multiple keys — use a longer prefix.",
            )
        key_store.revoke_key(matches[0].token)
        return JSONResponse({"revoked": True, "token_hash": matches[0].token_hash})

    return router


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_tlp_rank(report: Any) -> int:
    classification = getattr(report, "classification", None)
    if isinstance(classification, TLPLevel):
        return classification.rank
    try:
        return TLPLevel(str(classification).lower()).rank
    except Exception:
        return 0


def _bundle_tlp_rank(bundle: dict[str, Any]) -> int:
    for obj in bundle.get("objects", []):
        for ref in obj.get("object_marking_refs", []):
            ref_lower = str(ref).lower()
            if "red" in ref_lower:
                return TLPLevel.RED.rank
            if "amber+strict" in ref_lower:
                return TLPLevel.AMBER_STRICT.rank
            if "amber" in ref_lower:
                return TLPLevel.AMBER.rank
            if "green" in ref_lower:
                return TLPLevel.GREEN.rank
    return TLPLevel.WHITE.rank


def _require_admin(api_key: APIKey) -> None:
    from fastapi import HTTPException
    if api_key.tlp_level.rank < TLPLevel.RED.rank:
        raise HTTPException(
            status_code=403,
            detail="Admin endpoints require RED-level access.",
        )


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except Exception:
        pass


def _cleanup_background(path: str) -> Any:
    """Return a BackgroundTask that deletes *path* after the response is sent."""
    try:
        from starlette.background import BackgroundTask
        return BackgroundTask(_safe_unlink, path)
    except ImportError:
        return None
