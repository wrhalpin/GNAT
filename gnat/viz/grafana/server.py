"""
ctm_sak.viz.grafana.server
===========================

Lightweight FastAPI server that exposes workspace data as a Grafana
SimpleJSON / JSON API datasource.

Grafana connects to this server as a data source, and analysts can build
dashboards without needing Microsoft licenses or complex integrations.

Setup
-----
1. Install extras: ``pip install "ctm-sak[viz,serve]"``
2. Start the server::

       ctm-sak viz serve --workspace apt28 --port 3001

   Or programmatically::

       from ctm_sak.viz.grafana.server import GrafanaServer
       server = GrafanaServer(workspace_manager)
       server.run(port=3001)

3. In Grafana: **Add data source → SimpleJSON** and point it at
   ``http://localhost:3001``.

Endpoints
---------
``GET  /``                  — Health check (returns 200 OK)
``POST /search``            — Returns available metric names (STIX types)
``POST /query``             — Returns time-series or table data
``POST /annotations``       — Returns enrichment events as annotations
``GET  /workspaces``        — Lists available workspaces
``POST /tag-keys``          — Grafana ad-hoc filter keys
``POST /tag-values``        — Grafana ad-hoc filter values

Query targets
-------------
Format: ``<workspace>/<stix_type>[/<field>]``

Examples:
  * ``apt28/indicator``                     → table of all indicators
  * ``apt28/indicator/confidence``          → time-series of confidence over time
  * ``apt28/vulnerability/x_cvss_score``    → time-series of CVSS scores
  * ``apt28/summary``                       → object-count bar chart data
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ctm_sak.context.workspace import WorkspaceManager

logger = logging.getLogger(__name__)


def _require_fastapi():
    try:
        import fastapi   # noqa: F401
        import uvicorn   # noqa: F401
    except ImportError:
        raise ImportError(
            "FastAPI and uvicorn are required for the Grafana server: "
            "pip install 'ctm-sak[serve]'"
        )


def build_app(manager: "WorkspaceManager") -> Any:
    """
    Build and return the FastAPI application.

    Parameters
    ----------
    manager : WorkspaceManager
        The workspace manager to serve data from.

    Returns
    -------
    fastapi.FastAPI
    """
    _require_fastapi()
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse

    app = FastAPI(
        title="CTM-SAK Grafana Datasource",
        description="Serves CTM-SAK workspace data as a Grafana SimpleJSON datasource",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _parse_target(target: str) -> tuple:
        """Parse 'workspace/stix_type/field' into components."""
        parts = target.split("/", 2)
        ws_name   = parts[0] if len(parts) > 0 else ""
        stix_type = parts[1] if len(parts) > 1 else "indicator"
        field     = parts[2] if len(parts) > 2 else None
        return ws_name, stix_type, field

    def _ts(obj: Any) -> Optional[int]:
        """Convert a STIX created/modified timestamp to milliseconds."""
        ts_str = obj._properties.get("created", "")
        if not ts_str:
            return None
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except ValueError:
            return None

    def _obj_to_row(obj: Any, cols: List[str]) -> List[Any]:
        row = []
        for col in cols:
            if col == "type":
                row.append(obj.stix_type)
            elif col == "timestamp":
                row.append(_ts(obj) or 0)
            elif hasattr(obj, col):
                val = getattr(obj, col, None)
                row.append(str(val) if val is not None else "")
            else:
                val = obj._properties.get(col)
                row.append(str(val) if val is not None else "")
        return row

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.get("/")
    async def health():
        return {"status": "ok", "service": "ctm-sak-grafana"}

    @app.get("/workspaces")
    async def list_workspaces():
        return manager.list()

    @app.post("/search")
    async def search(request: Request):
        """Return available target strings for Grafana's metric browser."""
        targets = []
        for ws_meta in manager.list():
            name = ws_meta["name"]
            targets.append(f"{name}/summary")
            try:
                ws = manager.open(name)
                types_seen = set(obj.stix_type for obj in ws)
                for stype in types_seen:
                    targets.append(f"{name}/{stype}")
                    targets.append(f"{name}/{stype}/confidence")
                    if stype == "vulnerability":
                        targets.append(f"{name}/{stype}/x_cvss_score")
                    if stype == "indicator":
                        targets.append(f"{name}/{stype}/x_rf_risk_score")
            except Exception:  # noqa: BLE001
                pass
        return targets

    @app.post("/query")
    async def query(request: Request):
        """
        Handle a Grafana query request.

        Returns either time-series data (for numeric field queries) or
        table data (for type/summary queries).
        """
        body = await request.json()
        targets  = body.get("targets", [])
        range_   = body.get("range", {})
        results  = []

        for target_spec in targets:
            target = target_spec.get("target", "")
            ws_name, stix_type, field = _parse_target(target)

            try:
                ws = manager.open(ws_name)
            except KeyError:
                continue

            objs = [obj for obj in ws if obj.stix_type == stix_type]

            # ── Summary: object count by type ─────────────────────────────
            if stix_type == "summary":
                type_counts: Dict[str, int] = {}
                for obj in ws:
                    type_counts[obj.stix_type] = type_counts.get(obj.stix_type, 0) + 1
                results.append({
                    "columns": [
                        {"text": "STIX Type", "type": "string"},
                        {"text": "Count",     "type": "number"},
                    ],
                    "rows": [[t, c] for t, c in sorted(type_counts.items())],
                    "type": "table",
                })
                continue

            # ── Table: all objects of a type ──────────────────────────────
            if field is None:
                from ctm_sak.viz.tabular import _COLUMNS
                cols = _COLUMNS.get(stix_type, _COLUMNS["_default"])
                columns = [{"text": c, "type": "string"} for c in cols]
                rows = [_obj_to_row(obj, cols) for obj in objs]
                results.append({
                    "columns": columns,
                    "rows":    rows,
                    "type":    "table",
                })
                continue

            # ── Time-series: numeric field over created time ───────────────
            datapoints = []
            for obj in objs:
                ts = _ts(obj)
                if ts is None:
                    continue
                val = obj._properties.get(field)
                if val is None and hasattr(obj, field):
                    val = getattr(obj, field)
                try:
                    datapoints.append([float(val), ts])
                except (TypeError, ValueError):
                    pass
            datapoints.sort(key=lambda p: p[1])
            results.append({
                "target":     target,
                "datapoints": datapoints,
            })

        return results

    @app.post("/annotations")
    async def annotations(request: Request):
        """Return enrichment events as Grafana annotations."""
        body       = await request.json()
        ann_query  = body.get("annotation", {})
        query_text = ann_query.get("query", "")  # format: "<workspace>"
        ws_name    = query_text.strip() or (manager.list() or [{}])[0].get("name", "")

        results = []
        try:
            ws = manager.open(ws_name)
            for entry in ws.get_enrichment_history():
                ts_str = entry.get("created_at", "")
                ts = 0
                try:
                    dt = datetime.fromisoformat(ts_str)
                    ts = int(dt.timestamp() * 1000)
                except ValueError:
                    pass
                results.append({
                    "annotation": ann_query,
                    "time":       ts,
                    "title":      f"Enrichment: {entry['source_platform']}",
                    "text":       (
                        f"Object: {entry['stix_id'][:40]}<br>"
                        f"Strategy: {entry['strategy']}"
                    ),
                    "tags":       [entry["source_platform"], entry["strategy"]],
                })
        except Exception:  # noqa: BLE001
            pass

        return results

    @app.post("/tag-keys")
    async def tag_keys():
        return [
            {"type": "string", "text": "stix_type"},
            {"type": "string", "text": "tlp"},
            {"type": "string", "text": "source_platform"},
        ]

    @app.post("/tag-values")
    async def tag_values(request: Request):
        body = await request.json()
        key  = body.get("key", "stix_type")
        if key == "stix_type":
            types: set = set()
            for ws_meta in manager.list():
                try:
                    ws = manager.open(ws_meta["name"])
                    types.update(obj.stix_type for obj in ws)
                except Exception:  # noqa: BLE001
                    pass
            return [{"text": t} for t in sorted(types)]
        if key == "tlp":
            return [{"text": t} for t in ("white", "green", "amber", "red")]
        return []

    return app


class GrafanaServer:
    """
    Runnable wrapper around the FastAPI Grafana datasource application.

    Parameters
    ----------
    manager : WorkspaceManager
        The workspace manager to serve.
    host : str
        Bind address.  Default ``"0.0.0.0"``.
    port : int
        Port number.  Default ``3001``.

    Examples
    --------
    ::

        server = GrafanaServer(manager, port=3001)
        server.run()   # blocking

        # Background thread (for notebooks / scripts)
        server.run_in_background()
    """

    def __init__(
        self,
        manager: "WorkspaceManager",
        host: str = "0.0.0.0",
        port: int = 3001,
    ):
        self._manager = manager
        self._host    = host
        self._port    = port
        self._app     = None

    @property
    def app(self) -> Any:
        if self._app is None:
            self._app = build_app(self._manager)
        return self._app

    def run(self, **kwargs: Any) -> None:
        """Start the server (blocking)."""
        _require_fastapi()
        import uvicorn
        logger.info("Starting CTM-SAK Grafana datasource on %s:%d", self._host, self._port)
        uvicorn.run(
            self.app,
            host=self._host,
            port=self._port,
            log_level="warning",
            **kwargs,
        )

    def run_in_background(self) -> Any:
        """
        Start the server in a daemon thread.

        Returns the ``threading.Thread`` object.  Call ``.join()`` to wait.
        """
        import threading
        thread = threading.Thread(
            target=self.run, daemon=True,
            name="ctm-sak-grafana",
        )
        thread.start()
        logger.info("Grafana server started in background thread (port %d)", self._port)
        return thread

    def url(self) -> str:
        host = "localhost" if self._host in ("0.0.0.0", "") else self._host
        return f"http://{host}:{self._port}"

    def __repr__(self) -> str:  # pragma: no cover
        return f"GrafanaServer(url={self.url()!r})"
