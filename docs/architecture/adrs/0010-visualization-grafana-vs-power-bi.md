# ADR-0010: Visualization — Grafana vs Power BI

**Decision:** Grafana as live dashboard, Power BI as static export.

**Why not a live Power BI API connector:**
- Power BI streaming datasets are POST-only with no query capability.
- Push datasets require a workspace ID + Azure AD token refresh.
- DirectQuery requires a gateway or Azure-hosted source.
- The net result is more authentication plumbing than threat intel value.

**Grafana advantages for this use case:**
- SimpleJSON protocol = 6 HTTP endpoints, ~150 lines to implement fully.
- Node Graph panel is purpose-built for relationship visualization.
- Self-hostable, open source, no per-seat licensing.
- Annotation support maps the enrichment log to timeline markers.

**SimpleJSON query target format:**
`<workspace_name>/<stix_type>` → table data
`<workspace_name>/<stix_type>/<field>` → time-series of numeric field
`<workspace_name>/summary` → object-count bar chart

**Running the Grafana server:**
```bash
gnat viz serve --port 3001
# In Grafana: Add data source → SimpleJSON → http://localhost:3001
```

**Power BI import workflow:**
1. `gnat viz powerbi --workspace apt28 --file workspace.xlsx`
2. Power BI Desktop → Get Data → Excel → select `workspace.xlsx`
3. Load all sheets. Relationships sheet auto-creates the graph visual.
4. `to_model_json()` optional — auto-wires foreign keys if imported via
   Power BI Desktop's "Transform Data" flow.
