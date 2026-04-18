# ADR-0053: Infrastructure Graph Labels

**Decision:** Classify EvidenceGraph OBSERVABLE nodes by infrastructure
role (C2, staging, exfiltration, delivery, proxy, credential_harvest)
during correlation, storing roles as a node-level field and a graph-level
index, and exposing filtering through GraphQuery and a dedicated API
endpoint.

**Problem statement:**
The EvidenceGraph correlator (ADR-0031) links nodes by shared IOCs,
hostnames, usernames, campaigns, and tickets — but says nothing about
*what role* each indicator plays in an attack. An IP that serves as
a C2 server is fundamentally different from one used for delivery or
exfiltration, yet both appear as undifferentiated OBSERVABLE nodes.
Analysts querying the graph cannot filter by infrastructure function
without manually inspecting each node's STIX metadata.

## Classification during correlation, not ingestion

Infrastructure roles are assigned in `classify_infrastructure(graph)`
which runs at the end of `correlate()`, after all correlation indexes
are built and cross-platform edges are emitted.

**Why not at ingestion time:**
At ingestion, an indicator may lack the metadata needed for accurate
classification. Kill-chain phase hints, infrastructure_types, and port
associations are often added by enrichment passes or by cross-platform
correlation. Classifying after correlation ensures all available
context is present.

**Why not as a separate post-processing step:**
Running classification as part of `correlate()` means every graph that
goes through the standard pipeline gets infrastructure labels
automatically. A separate step would require callers to remember to
invoke it — an easy source of inconsistency.

## `by_infra_role` index follows existing pattern

The new index on `EvidenceGraph`:

```python
by_infra_role: dict[str, list[str]] = field(default_factory=dict)
```

mirrors the existing `by_ioc`, `by_hostname`, `by_username`,
`by_campaign`, and `by_ticket` indexes. Each maps a key (role string)
to a list of node IDs. This provides O(1) lookup by role and is
consistent with how all other graph correlation data is accessed.

**Alternative considered:** A nested structure grouping roles by
confidence level → rejected because it adds query complexity for
minimal benefit. Confidence is already available on the classified
node; callers can filter by it after role lookup.

## Node-level field, not separate storage

```python
# On EvidenceNode
infrastructure_roles: list[str] = field(default_factory=list)
```

Roles are stored directly on `EvidenceNode` as a `list[str]`,
analogous to `campaign_labels` and `ioc_values`.

**Alternative considered:** Store `InfrastructureNode` objects
(from `gnat/analysis/attribution/infrastructure.py`) in a parallel
collection and link via `indicator_id` → rejected because:
1. It requires a join to determine a node's roles during graph queries
2. `InfrastructureNode` carries fields (hosting_provider, ASN,
   registrar) that are enrichment concerns, not correlation concerns
3. The simpler `list[str]` is sufficient for filtering and display

The full `InfrastructureNode` model from the attribution module remains
available for detailed infrastructure analysis; the graph label is a
lightweight projection for fast querying.

## "unknown" role not stored

Nodes classified as `InfrastructureRole.UNKNOWN` do not get the role
appended to `infrastructure_roles`. This keeps the index sparse:

- Only meaningful classifications appear in `by_infra_role`
- Filtering by `infra_roles=["c2"]` returns only confirmed C2 nodes,
  not every observable in the graph
- `len(graph.by_infra_role["c2"])` gives an accurate count of
  classified C2 infrastructure

## Reuses existing InfrastructureClassifier

No new classification logic was written. The correlator calls
`InfrastructureClassifier.classify()` from
`gnat/analysis/attribution/infrastructure.py` (ADR-0051) for each
OBSERVABLE node, extracting inputs from the node's STIX dict:

| Input | STIX source |
|-------|-------------|
| `ioc_type` | `stix.x_gnat_ioc_type` or `stix.type` |
| `ioc_value` | First entry in `node.ioc_values` |
| `kill_chain_phases` | `stix.kill_chain_phases[*].phase_name` |
| `infrastructure_types` | `stix.x_gnat_infrastructure_types` |
| `ports` | `stix.x_gnat_ports` |

Non-OBSERVABLE nodes (INCIDENT, ASSET, IDENTITY, etc.) are skipped —
infrastructure classification only applies to network indicators.

## GraphQuery integration

`GraphQuery.filter()` gains an `infra_roles: list[str] | None`
parameter that retains only nodes whose `infrastructure_roles`
intersect the requested set. When `None` (default), no filtering
occurs — backward compatible.

`GraphContext.to_dict()` includes `infrastructure_roles` in the
serialized node output when the list is non-empty, omits it otherwise
to keep API responses lean.

## API endpoint

```
POST /api/graph/infrastructure
→ {"roles": {"c2": ["n1", "n3"], "delivery": ["n2"]},
   "counts": {"c2": 2, "delivery": 1}}
```

Returns the full `by_infra_role` index for the current graph. No
request body required — reads directly from the graph attached to
`app.state.graph_query`.

→ See: `gnat/investigations/correlator.py:classify_infrastructure()`
→ See: `gnat/analysis/graph.py:GraphQuery.filter()`
→ See: `gnat/serve/routers/analysis.py:graph_infrastructure()`
→ Related: ADR-0031 (Analysis Layer — EvidenceGraph architecture)
→ Related: ADR-0051 (Attribution — InfrastructureClassifier reuse)
