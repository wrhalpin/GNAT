# Configuration Reference

Complete reference for the GNAT INI configuration file format.
All examples assume `gnat` is installed.

---

## File Discovery

GNAT searches for configuration in this order:

1. Path in the `GNAT_CONFIG` environment variable
2. `~/.gnat/config.ini`
3. `./gnat.ini`

Copy `config/config.ini.example` to get started.

---

## Minimal config.ini

```ini
[DEFAULT]
timeout    = 30
verify_ssl = true

[threatq]
host          = https://threatq.example.com
client_id     = my-client-id
client_secret = s3cr3t
auth_type     = oauth2

[claude]
api_key               = sk-ant-...
model                 = claude-sonnet-4-6
ai_confidence_ceiling = 60

[sector_aliases]
healthcare = Healthcare, Health, Medical, H-ISAC, Hospitals and Health Centers
financial  = Financial Services, Finance, Banking, FS-ISAC
```

---

## Loading Config in Python

```python
from gnat.config import GNATConfig

cfg = GNATConfig()                          # auto-finds ~/.gnat/config.ini
cfg = GNATConfig("/path/to/config.ini")     # explicit path
cfg = GNATConfig(os.environ["MY_CONFIG"])   # from env var

section = cfg.get("threatq")
print(section["host"])
```

---

## Section Reference

### `[DEFAULT]`

Global defaults applied to every section unless overridden.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `timeout` | int | `30` | HTTP request timeout in seconds |
| `verify_ssl` | bool | `true` | Verify TLS certificates |

### `[claude]`

AI agent configuration.

| Key | Type | Description |
|-----|------|-------------|
| `api_key` | str | Anthropic API key (`sk-ant-…`) |
| `model` | str | Claude model name (e.g. `claude-sonnet-4-6`) |
| `ai_confidence_ceiling` | int | Maximum confidence assigned to AI-extracted objects (0–100) |

### `[sector_aliases]`

Comma-separated lists of alternate sector names mapped to a canonical label.
Used by `SectorFilter` during export and report generation.

```ini
[sector_aliases]
healthcare = Healthcare, Health, Medical, H-ISAC
financial  = Financial Services, Finance, Banking, FS-ISAC
```

### `[search]`

Optional Solr full-text search sidecar.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `solr_url` | str | — | Solr core URL (e.g. `http://localhost:8983/solr/gnat`) |
| `enabled` | bool | `false` | Enable automatic indexing on write |
| `batch_size` | int | `100` | Records per Solr batch |

### `[analysis]`

Controls the analysis layer (`gnat.analysis`).  Requires `sqlalchemy>=2.0`
(included in the `[analysis]` or `[persist]` extras).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_url` | str | `sqlite:///~/.gnat/gnat.db` | SQLAlchemy database URL for `InvestigationStore` |
| `default_tlp` | str | `amber` | Default TLP level assigned to new investigations (`white`/`clear`/`green`/`amber`/`amber+strict`/`red`) |

```ini
[analysis]
db_url      = sqlite:///~/.gnat/gnat.db
default_tlp = amber
```

### `[reporting]`

Controls the reporting layer (`gnat.reporting`).  Requires `sqlalchemy>=2.0`
(included in the `[reporting]` or `[persist]` extras).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_url` | str | `sqlite:///~/.gnat/gnat.db` | SQLAlchemy database URL for `ReportStore` (may share the analysis DB) |
| `default_tlp` | str | `amber` | Default TLP level assigned to new reports |
| `auto_approve` | bool | `false` | When `true`, collapses REVIEW → APPROVED → PUBLISHED into a single step |

```ini
[reporting]
db_url       = sqlite:///~/.gnat/gnat.db
default_tlp  = amber
auto_approve = false
```

### `[agent_policy]`

Controls the `AgentGovernor` permission matrix and rate limits (Phase 4D).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_calls_per_window` | int | `100` | Maximum connector calls an agent may make within `window_seconds` |
| `window_seconds` | int | `60` | Sliding-window size for rate limiting |
| `approval_timeout_seconds` | int | `3600` | Seconds before a pending HITL review is auto-rejected |
| `default_impact_level` | str | `"low"` | Assumed impact level for actions that don't specify one (`low`/`medium`/`high`/`critical`) |

```ini
[agent_policy]
max_calls_per_window     = 100
window_seconds           = 60
approval_timeout_seconds = 3600
default_impact_level     = low
```

Per-agent permission overrides use the pattern `{agent_id}.{action_type}`:

```ini
[agent_policy]
; Allow research-agent-1 to trigger SOAR playbooks despite semi_trusted level
research-agent-1.trigger_playbook = true

; Deny threat-hunter-2 from deleting STIX objects even if trust level permits
threat-hunter-2.delete_stix = false
```

### `[connector_limits]`

Per-connector rate limits and cost overrides (Phase 4E).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `{connector}.cost_unit` | int | per-class `COST_UNIT` | Override the cost-per-request for a named connector |
| `{connector}.max_calls_per_minute` | int | unlimited | Hard ceiling on calls per minute for a specific connector |

```ini
[connector_limits]
; VirusTotal has strict rate limits on the free tier
virustotal.cost_unit           = 5
virustotal.max_calls_per_minute = 4

; Splunk bulk exports are expensive
splunk.cost_unit = 10

; RecordedFuture lookups count as standard
recordedfuture.cost_unit = 1
```

### `[workspace_defaults]`

Default isolation settings applied to newly created workspaces (Phase 4E).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `trust_boundary` | str | `"semi_trusted"` | Minimum connector `TRUST_LEVEL` required for workspace access |
| `allowed_connector_refs` | str | `""` (all) | Comma-separated connector class names that may access this workspace; empty = no restriction |

```ini
[workspace_defaults]
trust_boundary         = semi_trusted
; Leave allowed_connector_refs empty to permit all connectors that meet trust_boundary
allowed_connector_refs =
```

To lock a workspace to only internal connectors:

```ini
[workspace_defaults]
trust_boundary         = trusted_internal
allowed_connector_refs = SplunkClient, SentinelClient, ElasticClient
```

### `[execution_context]`

Controls default `ExecutionContext` parameters (Phase 4A).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_policy_set` | str | `"default"` | Policy set name written to every `execution_log` row |
| `default_budget_units` | int | `0` (unlimited) | Max query budget units per context; 0 = no budget enforced |

```ini
[execution_context]
default_policy_set   = default
default_budget_units = 0
```

### Platform sections

Each platform connector reads its own INI section.
See `config/config.ini.example` for the full list of connector keys.

---

## See Also

- [How-to: Connect to Platforms](../how-to/connect-to-platforms.md)
- [How-to: Use the Analysis Layer](../how-to/use-analysis-layer.md)
- [How-to: Use Execution Context](../how-to/use-execution-context.md)
- [How-to: Use the Reasoning Engine](../how-to/use-reasoning-engine.md)
- [How-to: Agent Governance](../how-to/agent-governance.md)
- [How-to: Create Intelligence Reports](../how-to/create-intelligence-reports.md)
- `config/config.ini.example`

---

*Licensed under the Apache License, Version 2.0*
