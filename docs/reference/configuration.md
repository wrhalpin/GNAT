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

### Platform sections

Each platform connector reads its own INI section.
See `config/config.ini.example` for the full list of connector keys.

---

## See Also

- [How-to: Connect to Platforms](../how-to/connect-to-platforms.md)
- `config/config.ini.example`

---

*Licensed under the Apache License, Version 2.0*
