# ADR-0009: Visualization — Graph

**Decision:** Tiered renderer + tiered layout based on node count.

### Layout algorithm selection

| Node count | Algorithm | Complexity | Approx. time |
|---|---|---|---|
| ≤ 200 | Fruchterman-Reingold (networkx) | O(n²) | < 0.1s |
| 200–1000 | Barnes-Hut ForceAtlas2 (pure Python) | O(n log n) | 0.1–2s |
| > 1000 | Type-cluster (Fibonacci spiral) | O(n) | < 0.01s |

**Barnes-Hut implementation details:**
- Custom `_QuadTree` class — no scipy, no numpy
- `theta=0.8` is the accuracy parameter. Lower = more accurate, slower.
  0.5 gives near-exact results; 1.2 is fast but visually coarser.
  0.8 is the sweet spot for threat intel graphs.
- `kr=10.0` (repulsion), `ka=0.1` (attraction), `gravity=0.5`
  These can be tuned if your workspace has highly variable node degrees.
- Step size decays by `step_ratio=0.95` per iteration — simulated annealing.

**Type-cluster layout tradeoff:**
At 1000+ nodes, type-cluster sacrifices topological accuracy for speed.
You see *where types are* but not *how individual nodes relate*. If the
relationship structure is the signal (e.g., tracing a specific campaign),
override: `GraphView(ws, cluster_threshold=5000).to_html(...)` to force
Barnes-Hut even at large scale.

### Renderer selection

| Node count | Renderer | Technology | Notes |
|---|---|---|---|
| ≤ 300 | Plotly 3D | WebGL (Plotly) | 3D, Jupyter-native, ~3MB JS |
| > 300 | sigma.js | WebGL (sigma) | 2D, 100K node capacity, ~50KB JS |

**sigma.js HTML features:**
- Real-time label search (filters nodes by name substring)
- Type filter dropdown (hides/shows entire STIX types)
- Edge toggle (show/hide all edges)
- Hover tooltips (all `x_` attributes displayed)
- Camera reset button
- Legend with clickable type rows
- Dark theme matching the tabular HTML report

**`to_graph_json()` format:**
```json
{
  "nodes": [
    {"key": "indicator--abc", "label": "evil.com", "x": 1.2, "y": -0.8,
     "size": 12, "color": "#4ea8de", "type": "indicator",
     "attributes": {"confidence": 80, "x_rf_risk_score": 90}}
  ],
  "edges": [
    {"key": "e-0", "source": "indicator--abc", "target": "malware--xyz",
     "label": "indicates", "color": "#4ea8de"}
  ]
}
```
Use this to feed the Grafana Node Graph panel or build custom sigma.js apps.

**Intent-driven rendering API — primary user-facing interface:**

The five intent methods remove the need to know layout algorithms or renderer names.
Each one encodes "what you want to see" and configures everything automatically:

| Method | Primary question | Layout | Renderer | Edges |
|---|---|---|---|---|
| `render_relationship_graph()` | How are objects connected? | Barnes-Hut (always) | sigma/Plotly | Prominent (opacity 0.7) |
| `render_type_graph()` | What types are in this workspace? | Type-cluster (always) | sigma/Plotly | Secondary (opacity 0.25) |
| `render_campaign_graph()` | What connects to these seeds? | Barnes-Hut + BFS ego | sigma/Plotly | Standard (0.65) |
| `render_timeline_graph()` | How did this evolve over time? | X=timestamp, Y=type lane | sigma only | Standard |
| `render_risk_heatmap()` | What has high risk vs low confidence? | X=field, Y=field (value-driven) | sigma only | None |

**Key design decisions in intent methods:**

`render_relationship_graph` overrides `cluster_threshold` to `n+1` so Barnes-Hut
is used at any scale — type-cluster would hide the relational topology that is the
entire point of this view.

`render_type_graph` overrides `cluster_threshold` to `0` so type-cluster is always
used — and sets `uniform_node_size=True` so visual density reflects object counts
rather than score distribution.

`render_campaign_graph` uses BFS from seed nodes. Auto-seeds to top-3 by degree
centrality if no `seed_ids` given. Result is always a strict subgraph of the
workspace — never shows disconnected objects.

`render_timeline_graph` places objects at X = (timestamp - min) / range × 20,
Y = type-lane index × 4 + jitter. Objects without a parseable timestamp get X = -5
(visibly outside the axis, not hidden). Uses sigma always because timelines can be
very wide.

`render_risk_heatmap` places objects at X = x_field/10, Y = y_field/10.
Objects missing either field get random jitter near origin — they cluster visibly
at (0,0) so the "coverage gap" is itself informative. No edges drawn.

**Plotly fallback in `_render_intent`:**
If plotly is not installed and the graph is below `plotly_threshold`, the intent
methods automatically fall back to sigma.js rather than raising ImportError.
The low-level `figure()` method still raises ImportError as documented.

**`max_nodes` caps by degree centrality:**
Keeps the most-connected nodes. For large workspaces this means hub
indicators (seen by many sources) survive the cap; isolated singletons
are dropped. Run `view.summary()` first to understand the graph before capping.

---

*Licensed under the Apache License, Version 2.0*
