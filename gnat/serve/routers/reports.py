"""
gnat.serve.routers.reports
==========================
FastAPI router for the Reports API.

Endpoints
---------
GET /api/reports                    — List reports in the configured directory
GET /api/reports/{report_name}      — Serve an HTML report inline or return metadata
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _get_reports_dir(request: Request) -> Optional[str]:
    return getattr(request.app.state, "reports_dir", None)


def _fmt_size(n: int) -> str:
    if n >= 1_048_576:
        return f"{n // 1_048_576} MB"
    return f"{max(1, n // 1024)} KB"


def _scan_dir(rdir: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    try:
        for p in Path(rdir).iterdir():
            if not p.is_file():
                continue
            stat = p.stat()
            entries.append(
                {
                    "name": p.stem,
                    "filename": p.name,
                    "fmt": p.suffix.lstrip(".").lower(),
                    "size": _fmt_size(stat.st_size),
                    "modified": int(stat.st_mtime),
                }
            )
    except OSError:
        pass
    entries.sort(key=lambda e: e["modified"], reverse=True)
    return entries


@router.get("")
def list_reports(request: Request) -> Dict[str, Any]:
    """List all report files in the configured reports directory."""
    rdir = _get_reports_dir(request)
    if not rdir or not os.path.isdir(rdir):
        return {"reports": [], "count": 0}
    entries = _scan_dir(rdir)
    return {"reports": entries, "count": len(entries)}


@router.get("/{report_name:path}")
def get_report(report_name: str, request: Request):
    """Serve an HTML report inline; return metadata for other formats."""
    # Prevent path traversal
    if ".." in report_name or report_name.startswith("/"):
        raise HTTPException(400, "Invalid report name")
    rdir = _get_reports_dir(request)
    if not rdir:
        raise HTTPException(503, "Reports directory not configured on this server")
    path = Path(rdir) / report_name
    # Resolve and confirm the resolved path is still inside rdir
    try:
        resolved = path.resolve()
        base = Path(rdir).resolve()
        resolved.relative_to(base)  # raises ValueError if outside
    except (ValueError, OSError):
        raise HTTPException(400, "Invalid report path")
    if not resolved.exists():
        raise HTTPException(404, f"Report '{report_name}' not found")
    if resolved.suffix.lower() == ".html":
        try:
            content = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise HTTPException(500, str(exc))
        return HTMLResponse(content=content)
    stat = resolved.stat()
    return {
        "name": resolved.stem,
        "filename": resolved.name,
        "fmt": resolved.suffix.lstrip(".").lower(),
        "size": _fmt_size(stat.st_size),
        "modified": int(stat.st_mtime),
    }
