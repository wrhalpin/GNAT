# How-to: Visualize Data

Render relationship graphs, timelines, risk heatmaps, and tabular views of workspace objects.

---

## GraphView — intent-driven

```python
from gnat.viz import GraphView

view = GraphView(workspace)

# How are objects connected?
view.render_relationship_graph()

# What types are in this workspace?
view.render_type_graph(show_edges=False)

# What connects to this threat actor? (ego network)
view.render_campaign_graph(
    seed_ids  = [actor.id],
    depth     = 2,
    path      = "campaign.html",
)

# Objects on a time axis
view.render_timeline_graph(
    stix_types = ["indicator", "vulnerability"],
    path       = "timeline.html",
)

# Risk scatter (confidence vs RF risk score)
view.render_risk_heatmap(
    x_field = "confidence",
    y_field = "x_rf_risk_score",
    path    = "risk.html",
)
```

---

## TabularView

```python
from gnat.viz import TabularView

view = TabularView(workspace)

view.show()                              # terminal output (rich)
view.to_html("table.html")              # dark-theme HTML
view.to_csv("indicators.csv")           # CSV export
view.to_excel("intel.xlsx")             # Excel / Power BI
```

---

## See Also

- [Explanation: Tabular Visualization](../explanation/architecture/adrs/0008-visualization-tabular.md)
- [Explanation: Graph Visualization](../explanation/architecture/adrs/0009-visualization-graph.md)
- [Explanation: Grafana vs Power BI](../explanation/architecture/adrs/0010-visualization-grafana-vs-power-bi.md)

---

*Licensed under the Apache License, Version 2.0*
