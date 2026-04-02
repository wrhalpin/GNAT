# ADR-0008: Visualization — Tabular

**Decision:** Five output targets from one `TabularView` class.

**Format selection logic:**
- `view.show()` → terminal (`rich` if installed, plain ASCII fallback)
- `view.display()` → Jupyter `IPython.display(HTML(...))`
- `view.to_html(path)` → self-contained dark-theme HTML, sortable columns
- `view.to_csv(path)` → UTF-8-BOM CSV (Power BI-compatible)
- `view.to_excel(path)` → openpyxl, one sheet per STIX type

**Column definitions in `_COLUMNS` dict:**
Maps STIX type → list of fields to display. Update this when adding new
ORM types or important `x_` extension fields. The `_default` key is the
fallback for unknown types.

**Sort order for numeric fields:**
`_sort()` negates numeric values so they sort descending by default.
Confidence 90 appears before confidence 10.

**Power BI Excel compatibility notes:**
- Column types are inferred by Power BI from cell values — ensure numeric
  fields (`confidence`, `x_cvss_score`) contain actual numbers, not strings.
- The `Relationships` sheet uses `source_ref`/`target_ref` columns that
  Power BI's graph visual maps to from/to node ids. Do not rename these.
- `to_model_json()` generates the data model descriptor with foreign key
  relationships pre-wired.
