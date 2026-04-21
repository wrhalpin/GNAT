# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.app
==============
FastAPI web dashboard for GNAT.

Provides a browser-based interface for:

* **Research Library** — search, filter, promote/reject staging entries
* **Reports** — list and view generated HTML/PDF reports
* **Scheduler** — monitor feed jobs and trigger them manually

Security
--------
* All ``/api/*`` endpoints require an ``X-Api-Key`` header.
* Binds to ``127.0.0.1`` by default — expose via nginx+TLS for network access.
* Input validation on all query parameters.
* Rate limiting: 100 req/min per API key.

Launch::

    from gnat.serve.app import run
    run(api_key="secret", port=8088)

Or via CLI::

    gnat serve --api-key secret --port 8088
"""

from __future__ import annotations

import asyncio
import json as _json

from fastapi import Depends, FastAPI
from fastapi import Request as _SSERequest
from fastapi.responses import HTMLResponse, StreamingResponse

from .auth import APIKeyAuth
from .rate_limit import RateLimiter
from .routers import (
    analysis,
    analytics,
    federation,
    investigations,
    library,
    reports,
    review,
    scheduler,
    workflows,
)

# ---------------------------------------------------------------------------
# Embedded single-page dashboard
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GNAT Dashboard</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 1.1rem; font-weight: 600; color: #58a6ff; letter-spacing: .04em; }
  header span.badge { background: #21262d; color: #8b949e; font-size: .75rem; padding: 2px 8px; border-radius: 12px; border: 1px solid #30363d; }
  nav { background: #161b22; padding: 0 24px; display: flex; gap: 4px; border-bottom: 1px solid #30363d; }
  nav button { background: none; border: none; color: #8b949e; padding: 10px 16px; cursor: pointer; font-size: .9rem; border-bottom: 2px solid transparent; transition: color .15s; }
  nav button:hover { color: #c9d1d9; }
  nav button.active { color: #58a6ff; border-bottom-color: #58a6ff; }
  main { padding: 24px; max-width: 1200px; margin: 0 auto; }
  .panel { display: none; }
  .panel.active { display: block; }
  .toolbar { display: flex; gap: 10px; margin-bottom: 16px; align-items: center; flex-wrap: wrap; }
  input[type=text], input[type=password] { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; border-radius: 6px; padding: 7px 12px; font-size: .9rem; outline: none; }
  input[type=text]:focus, input[type=password]:focus { border-color: #58a6ff; }
  button.btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; border-radius: 6px; padding: 7px 14px; cursor: pointer; font-size: .85rem; transition: background .15s; }
  button.btn:hover { background: #30363d; }
  button.btn.primary { background: #1f6feb; border-color: #1f6feb; color: #fff; }
  button.btn.primary:hover { background: #388bfd; }
  button.btn.danger { background: #6e1b1b; border-color: #f85149; color: #f85149; }
  button.btn.danger:hover { background: #f85149; color: #fff; }
  button.btn.success { background: #1b4a1b; border-color: #3fb950; color: #3fb950; }
  button.btn.success:hover { background: #3fb950; color: #000; }
  table { width: 100%; border-collapse: collapse; font-size: .88rem; }
  thead th { background: #21262d; color: #8b949e; text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; font-weight: 600; text-transform: uppercase; font-size: .75rem; letter-spacing: .05em; }
  tbody tr { border-bottom: 1px solid #21262d; transition: background .1s; }
  tbody tr:hover { background: #161b22; }
  tbody td { padding: 9px 12px; vertical-align: middle; }
  .tag { display: inline-block; background: #21262d; border: 1px solid #30363d; border-radius: 12px; padding: 1px 8px; font-size: .75rem; }
  .tag.green { border-color: #3fb950; color: #3fb950; }
  .tag.red   { border-color: #f85149; color: #f85149; }
  .tag.blue  { border-color: #58a6ff; color: #58a6ff; }
  .tag.gray  { color: #8b949e; }
  .msg { padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: .9rem; }
  .msg.error { background: #2d1414; border: 1px solid #f85149; color: #f85149; }
  .msg.info  { background: #0d2137; border: 1px solid #58a6ff; color: #58a6ff; }
  .empty { color: #8b949e; text-align: center; padding: 40px; font-style: italic; }
  #keyOverlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.7); z-index:100; align-items:center; justify-content:center; }
  #keyOverlay.show { display:flex; }
  .keyBox { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 28px 32px; width: 360px; }
  .keyBox h2 { margin-bottom: 12px; font-size: 1rem; }
  .keyBox p  { color: #8b949e; font-size: .85rem; margin-bottom: 16px; }
  .keyBox input { width: 100%; margin-bottom: 12px; }
  #health { font-size: .8rem; padding: 4px 10px; border-radius: 12px; border: 1px solid #30363d; color: #8b949e; }
  #health.ok  { border-color: #3fb950; color: #3fb950; }
  #health.err { border-color: #f85149; color: #f85149; }
</style>
</head>
<body>

<div id="keyOverlay" class="show">
  <div class="keyBox">
    <h2>GNAT Dashboard</h2>
    <p>Enter your API key to continue. The key is sent via the <code>X-Api-Key</code> header and stored for this session only.</p>
    <input type="password" id="keyInput" placeholder="API key…" autocomplete="off">
    <button class="btn primary" style="width:100%" onclick="saveKey()">Connect</button>
  </div>
</div>

<header>
  <h1>&#9670; GNAT</h1>
  <span class="badge">Web Dashboard</span>
  <span id="health" style="margin-left:auto">&#9679; connecting…</span>
  <button class="btn" style="font-size:.8rem" onclick="changeKey()">API Key</button>
</header>

<nav>
  <button class="active" onclick="switchTab('library',this)">Library</button>
  <button onclick="switchTab('reports',this)">Reports</button>
  <button onclick="switchTab('scheduler',this)">Scheduler</button>
</nav>

<main>
  <div id="panel-library" class="panel active">
    <div class="toolbar">
      <input type="text" id="libQ" placeholder="Search…" style="width:280px" onkeydown="if(event.key==='Enter')searchLib()">
      <input type="text" id="libTopic" placeholder="Topic" style="width:140px">
      <select id="libTlp" style="background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:7px 10px;font-size:.9rem">
        <option value="">All TLP</option>
        <option>WHITE</option><option>GREEN</option><option>AMBER</option><option>RED</option>
      </select>
      <button class="btn primary" onclick="searchLib()">Search</button>
    </div>
    <div id="libMsg"></div>
    <table id="libTable">
      <thead><tr><th>ID</th><th>Title / Name</th><th>Type</th><th>TLP</th><th>Topic</th><th>Actions</th></tr></thead>
      <tbody id="libBody"><tr><td colspan="6" class="empty">Enter a search query above</td></tr></tbody>
    </table>
  </div>

  <div id="panel-reports" class="panel">
    <div class="toolbar">
      <button class="btn primary" onclick="loadReports()">Refresh</button>
    </div>
    <div id="rptMsg"></div>
    <table id="rptTable">
      <thead><tr><th>Name</th><th>Format</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead>
      <tbody id="rptBody"><tr><td colspan="5" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>

  <div id="panel-scheduler" class="panel">
    <div class="toolbar">
      <button class="btn primary" onclick="loadJobs()">Refresh</button>
    </div>
    <div id="schedMsg"></div>
    <table id="schedTable">
      <thead><tr><th>Job ID</th><th>Enabled</th><th>Last Run</th><th>Next Run</th><th>Runs</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody id="schedBody"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>
</main>

<script>
  var _key = sessionStorage.getItem('gnat_api_key') || '';
  if (_key) document.getElementById('keyOverlay').classList.remove('show');

  function saveKey() {
    _key = document.getElementById('keyInput').value.trim();
    if (!_key) return;
    sessionStorage.setItem('gnat_api_key', _key);
    document.getElementById('keyOverlay').classList.remove('show');
    checkHealth();
    loadReports();
    loadJobs();
  }

  function changeKey() {
    document.getElementById('keyInput').value = '';
    document.getElementById('keyOverlay').classList.add('show');
  }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ 'X-Api-Key': _key }, opts.headers || {});
    return fetch(path, opts);
  }

  function checkHealth() {
    api('/health').then(function(r) {
      var el = document.getElementById('health');
      if (r.ok) { el.textContent = '\\u25CF healthy'; el.className = 'ok'; }
      else       { el.textContent = '\\u25CF error';   el.className = 'err'; }
    }).catch(function() {
      var el = document.getElementById('health');
      el.textContent = '\\u25CF unreachable'; el.className = 'err';
    });
  }

  function switchTab(name, btn) {
    document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('nav button').forEach(function(b){ b.classList.remove('active'); });
    document.getElementById('panel-' + name).classList.add('active');
    btn.classList.add('active');
    if (name === 'reports') loadReports();
    if (name === 'scheduler') loadJobs();
  }

  function showMsg(id, text, type) {
    var el = document.getElementById(id);
    el.innerHTML = '<div class="msg ' + type + '">' + esc(text) + '</div>';
    setTimeout(function(){ el.innerHTML = ''; }, 5000);
  }

  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  // ── Library ────────────────────────────────────────────────────────────────
  function searchLib() {
    var q = document.getElementById('libQ').value;
    var topic = document.getElementById('libTopic').value;
    var tlp = document.getElementById('libTlp').value;
    var url = '/api/library?limit=100' + (q ? '&q=' + encodeURIComponent(q) : '') +
      (topic ? '&topic=' + encodeURIComponent(topic) : '') +
      (tlp ? '&tlp=' + encodeURIComponent(tlp) : '');
    api(url).then(function(r){ return r.json(); }).then(function(data){
      var tbody = document.getElementById('libBody');
      if (!data.results || !data.results.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No results</td></tr>';
        return;
      }
      tbody.innerHTML = data.results.map(function(r){
        var id = esc(r.id || r.stix_id || '');
        var name = esc(r.name || r.value || r.indicator_value || id.slice(0,40));
        var type = esc(r.type || '');
        var tlp = esc(r.tlp || r.x_tlp || '');
        var topic = esc(r.topic || r.x_topic || '');
        return '<tr>' +
          '<td><code style="font-size:.8rem">' + id.slice(0,36) + '</code></td>' +
          '<td>' + name + '</td>' +
          '<td><span class="tag">' + type + '</span></td>' +
          '<td><span class="tag' + (tlp==='RED'?' red':tlp==='AMBER'?' blue':tlp==='GREEN'?' green':' gray') + '">' + (tlp||'—') + '</span></td>' +
          '<td>' + (topic||'—') + '</td>' +
          '<td style="white-space:nowrap">' +
            '<button class="btn success" style="padding:4px 10px;font-size:.8rem" onclick="promoteEntry(\'' + id + '\')">&#8593; Promote</button> ' +
            '<button class="btn danger"  style="padding:4px 10px;font-size:.8rem" onclick="rejectEntry(\'' + id + '\')">&#10005; Reject</button>' +
          '</td></tr>';
      }).join('');
    }).catch(function(e){ showMsg('libMsg', e, 'error'); });
  }

  function promoteEntry(id) {
    api('/api/library/' + encodeURIComponent(id) + '/promote', { method: 'POST' })
      .then(function(r){ return r.json(); })
      .then(function(){ showMsg('libMsg','Promoted: ' + id, 'info'); searchLib(); })
      .catch(function(e){ showMsg('libMsg', e, 'error'); });
  }

  function rejectEntry(id) {
    api('/api/library/' + encodeURIComponent(id) + '/reject', { method: 'POST' })
      .then(function(r){ return r.json(); })
      .then(function(){ showMsg('libMsg','Rejected: ' + id, 'info'); searchLib(); })
      .catch(function(e){ showMsg('libMsg', e, 'error'); });
  }

  // ── Reports ────────────────────────────────────────────────────────────────
  function loadReports() {
    api('/api/reports').then(function(r){ return r.json(); }).then(function(data){
      var tbody = document.getElementById('rptBody');
      if (!data.reports || !data.reports.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No reports found</td></tr>';
        return;
      }
      tbody.innerHTML = data.reports.map(function(r){
        var fn = esc(r.filename || (r.name + '.' + r.fmt));
        var ts = r.modified ? new Date(r.modified * 1000).toLocaleString() : '—';
        var viewBtn = r.fmt === 'html'
          ? '<a href="/api/reports/' + encodeURIComponent(fn) + '" target="_blank"><button class="btn primary" style="padding:4px 10px;font-size:.8rem">View</button></a>'
          : '<span class="tag gray">' + esc(r.fmt.toUpperCase()) + '</span>';
        return '<tr>' +
          '<td>' + esc(r.name) + '</td>' +
          '<td><span class="tag">' + esc(r.fmt) + '</span></td>' +
          '<td>' + esc(r.size) + '</td>' +
          '<td>' + ts + '</td>' +
          '<td>' + viewBtn + '</td></tr>';
      }).join('');
    }).catch(function(e){ showMsg('rptMsg', e, 'error'); });
  }

  // ── Scheduler ──────────────────────────────────────────────────────────────
  function loadJobs() {
    api('/api/scheduler/jobs').then(function(r){ return r.json(); }).then(function(data){
      var tbody = document.getElementById('schedBody');
      if (!data.jobs || !data.jobs.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No jobs registered</td></tr>';
        return;
      }
      tbody.innerHTML = data.jobs.map(function(j){
        var enabled = j.enabled
          ? '<span class="tag green">&#10003; enabled</span>'
          : '<span class="tag red">&#10007; disabled</span>';
        var status = j.status
          ? '<span class="tag ' + (j.status==='ok'?'green':j.status==='error'?'red':'gray') + '">' + esc(j.status) + '</span>'
          : '<span class="tag gray">—</span>';
        return '<tr>' +
          '<td><code>' + esc(j.job_id) + '</code></td>' +
          '<td>' + enabled + '</td>' +
          '<td>' + esc(j.last_run||'—') + '</td>' +
          '<td>' + esc(j.next_run||'—') + '</td>' +
          '<td>' + esc(j.run_count) + '</td>' +
          '<td>' + status + '</td>' +
          '<td><button class="btn primary" style="padding:4px 10px;font-size:.8rem" onclick="triggerJob(\'' + esc(j.job_id) + '\')">&#9654; Run</button></td>' +
          '</tr>';
      }).join('');
    }).catch(function(e){ showMsg('schedMsg', e, 'error'); });
  }

  function triggerJob(jobId) {
    api('/api/scheduler/jobs/' + encodeURIComponent(jobId) + '/trigger', { method: 'POST' })
      .then(function(r){ return r.json(); })
      .then(function(){ showMsg('schedMsg', 'Triggered: ' + jobId, 'info'); })
      .catch(function(e){ showMsg('schedMsg', e, 'error'); });
  }

  // Init
  if (_key) { checkHealth(); loadReports(); loadJobs(); }
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    api_key: str,
    library_backend=None,
    scheduler_backend=None,
    reports_dir: str | None = None,
    investigation_service=None,
    graph_query=None,
    gap_detector=None,
    report_drafting_assistant=None,
    export_service=None,
    metrics_aggregator=None,
    federation_registry=None,
    federation_scheduler=None,
    federation_sync_service=None,
    trend_detector=None,
    workspace_stats=None,
    search_index=None,
    workflow_store=None,
) -> FastAPI:
    """
    Build and return the GNAT web dashboard FastAPI application.

    Parameters
    ----------
    api_key : str
        Required ``X-Api-Key`` value for all ``/api/*`` requests.
    library_backend : ResearchLibrary, optional
        Pre-constructed library instance.  When ``None`` the library
        endpoints return ``503``.
    scheduler_backend : FeedScheduler, optional
        Pre-constructed scheduler instance.  When ``None`` the scheduler
        endpoints return ``503``.
    reports_dir : str, optional
        Directory to scan for generated reports.
    """
    auth = APIKeyAuth(api_key)
    limiter = RateLimiter(max_requests=100, window_seconds=60)

    app = FastAPI(
        title="GNAT Web Dashboard",
        version="0.1.0",
        docs_url=None,  # no Swagger UI exposed publicly
        redoc_url=None,
        openapi_url=None,
    )

    # Store backends in app state for router access
    app.state.library = library_backend
    app.state.scheduler = scheduler_backend
    app.state.reports_dir = reports_dir
    app.state.investigation_service = investigation_service
    app.state.graph_query = graph_query
    app.state.gap_detector = gap_detector
    app.state.report_drafting_assistant = report_drafting_assistant
    app.state.export_service = export_service
    app.state.metrics_aggregator = metrics_aggregator
    app.state.federation_registry = federation_registry
    app.state.federation_scheduler = federation_scheduler
    app.state.federation_sync_service = federation_sync_service
    app.state.trend_detector = trend_detector
    app.state.workspace_stats = workspace_stats
    app.state.search_index = search_index
    app.state.workflow_store = workflow_store

    # ── Unauthenticated endpoints ──────────────────────────────────────────
    @app.get("/health", tags=["health"], include_in_schema=False)
    def health_check():
        """Perform a lightweight connectivity check against the remote API."""
        return {"status": "ok", "service": "gnat-webui"}

    @app.get("/api/stream", tags=["stream"], include_in_schema=False)
    async def sse_stream(request: _SSERequest):
        """
        Server-Sent Events endpoint for real-time dashboard updates.

        Emits events for: ``review_pending``, ``investigation_updated``, ``job_complete``.
        Clients should reconnect automatically (standard SSE behaviour).

        Authentication: ``X-Api-Key`` header (same as other API endpoints).
        """
        api_key_header = request.headers.get("X-Api-Key", "")
        # Validate API key manually since SSE can't use Depends easily
        if api_key_header != api_key:
            from fastapi import HTTPException

            raise HTTPException(status_code=403, detail="Invalid API key")

        async def _event_generator():

            yield "data: " + _json.dumps({"type": "connected", "service": "gnat-sse"}) + "\n\n"

            while True:
                if await request.is_disconnected():
                    break

                events = []

                # Review pending count
                svc = getattr(request.app.state, "investigation_service", None)
                if svc is not None:
                    try:
                        # Only emit if review service is wired to app state
                        review_svc = getattr(request.app.state, "review_service", None)
                        if review_svc is not None:
                            items = review_svc.list(status="pending", page=1, page_size=1)
                            total = getattr(
                                items, "total", len(items) if isinstance(items, list) else 0
                            )
                            events.append({"type": "review_pending", "count": total})
                    except Exception:
                        pass

                # Scheduler job events
                scheduler = getattr(request.app.state, "scheduler", None)
                if scheduler is not None:
                    try:
                        running = [
                            j.job_id for j in scheduler.jobs if getattr(j, "_is_running", False)
                        ]
                        if running:
                            events.append({"type": "job_running", "job_ids": running})
                    except Exception:
                        pass

                for ev in events:
                    yield "data: " + _json.dumps(ev) + "\n\n"

                await asyncio.sleep(15)

        return StreamingResponse(
            _event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/", include_in_schema=False)
    def dashboard():
        """Dashboard."""
        return HTMLResponse(content=_DASHBOARD_HTML)

    # ── Authenticated API routers ──────────────────────────────────────────
    _api_deps = [Depends(auth), Depends(limiter)]
    app.include_router(library.router, dependencies=_api_deps)
    app.include_router(reports.router, dependencies=_api_deps)
    app.include_router(scheduler.router, dependencies=_api_deps)
    app.include_router(investigations.router, dependencies=_api_deps)
    app.include_router(review.router, dependencies=_api_deps)
    app.include_router(analysis.router, dependencies=_api_deps)
    app.include_router(analytics.router, dependencies=_api_deps)
    app.include_router(federation.router, dependencies=_api_deps)
    app.include_router(workflows.router, dependencies=_api_deps)

    return app


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------


def run(
    api_key: str,
    host: str = "127.0.0.1",
    port: int = 8088,
    library_backend=None,
    scheduler_backend=None,
    reports_dir: str | None = None,
    investigation_service=None,
    graph_query=None,
    gap_detector=None,
    report_drafting_assistant=None,
    export_service=None,
    metrics_aggregator=None,
    federation_registry=None,
    federation_scheduler=None,
    federation_sync_service=None,
) -> None:
    """
    Launch the GNAT web dashboard with uvicorn.

    Used by the ``gnat serve`` CLI subcommand.
    """
    import uvicorn  # optional dep — fastapi[standard] or uvicorn

    app = create_app(
        api_key=api_key,
        library_backend=library_backend,
        scheduler_backend=scheduler_backend,
        reports_dir=reports_dir,
        investigation_service=investigation_service,
        graph_query=graph_query,
        gap_detector=gap_detector,
        report_drafting_assistant=report_drafting_assistant,
        export_service=export_service,
        metrics_aggregator=metrics_aggregator,
        federation_registry=federation_registry,
        federation_scheduler=federation_scheduler,
        federation_sync_service=federation_sync_service,
    )
    uvicorn.run(app, host=host, port=port, log_level="warning")
