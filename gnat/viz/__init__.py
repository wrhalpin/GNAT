# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.viz
============

Visualization layer for GNAT workspaces.

Components
----------

TabularView
    Filterable tables: terminal (rich), Jupyter, HTML, CSV, Excel/Power BI.
    ``pip install "gnat[viz]"`` for Excel support (openpyxl).

GraphView
    3D force-directed STIX relationship graph via Plotly.
    ``pip install "gnat[viz]"`` (plotly + networkx).

GrafanaServer
    FastAPI SimpleJSON datasource server for Grafana dashboards.
    ``pip install "gnat[serve]"`` (fastapi + uvicorn).

PowerBIExporter
    Excel workbook export with Power BI data model JSON.

grafana_dashboard / save_grafana_dashboard
    Pre-built Grafana dashboard JSON templates.

Quick start::

    from gnat.viz import TabularView, GraphView

    view = TabularView(workspace)
    view.show()
    view.to_html("report.html")
    view.to_excel("workspace.xlsx")

    graph = GraphView(workspace)
    graph.show()
    graph.to_html("graph.html")

    from gnat.viz import GrafanaServer, save_grafana_dashboard
    server = GrafanaServer(manager)
    server.run_in_background()
    save_grafana_dashboard("apt28", "dashboard.json")
"""

from gnat.viz.export import PowerBIExporter, grafana_dashboard, save_grafana_dashboard
from gnat.viz.graph import GraphView
from gnat.viz.tabular import TabularView

try:
    from gnat.viz.grafana.server import GrafanaServer

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
