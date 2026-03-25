"""
ctm_sak.viz
============

Visualization layer for CTM-SAK workspaces.

Components
----------

TabularView
    Filterable tables: terminal (rich), Jupyter, HTML, CSV, Excel/Power BI.
    ``pip install "ctm-sak[viz]"`` for Excel support (openpyxl).

GraphView
    3D force-directed STIX relationship graph via Plotly.
    ``pip install "ctm-sak[viz]"`` (plotly + networkx).

GrafanaServer
    FastAPI SimpleJSON datasource server for Grafana dashboards.
    ``pip install "ctm-sak[serve]"`` (fastapi + uvicorn).

PowerBIExporter
    Excel workbook export with Power BI data model JSON.

grafana_dashboard / save_grafana_dashboard
    Pre-built Grafana dashboard JSON templates.

Quick start::

    from ctm_sak.viz import TabularView, GraphView

    view = TabularView(workspace)
    view.show()
    view.to_html("report.html")
    view.to_excel("workspace.xlsx")

    graph = GraphView(workspace)
    graph.show()
    graph.to_html("graph.html")

    from ctm_sak.viz import GrafanaServer, save_grafana_dashboard
    server = GrafanaServer(manager)
    server.run_in_background()
    save_grafana_dashboard("apt28", "dashboard.json")
"""

from ctm_sak.viz.tabular import TabularView
from ctm_sak.viz.graph   import GraphView
from ctm_sak.viz.export  import PowerBIExporter, grafana_dashboard, save_grafana_dashboard

try:
    from ctm_sak.viz.grafana.server import GrafanaServer, build_app
    _HAS_GRAFANA = True
except ImportError:
    _HAS_GRAFANA = False

__all__ = [
    "TabularView",
    "GraphView",
    "PowerBIExporter",
    "grafana_dashboard",
    "save_grafana_dashboard",
    "GrafanaServer",
]
