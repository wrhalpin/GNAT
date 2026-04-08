# ADR-0013: Configuration

**INI file search order:**
1. Explicit `config_path=` parameter
2. `GNAT_CONFIG` environment variable
3. `~/.gnat/config.ini`
4. `./gnat.ini`

**Section naming:**
- `[DEFAULT]` — inherited by all sections
- `[threatq]`, `[crowdstrike]`, etc. — single-platform sections
- `[global]` — context system default name
- `[global.<name>]` — named global context configs

**Required keys per platform:**

| Platform | Required keys |
|---|---|
| threatq | `host`, `client_id`, `client_secret` |
| crowdstrike | `host`, `client_id`, `client_secret` |
| proofpoint | `host`, `service_principal`, `secret` |
| netskope | `host`, `api_token` |
| xsoar | `host`, `api_key` |
| recordedfuture | `host`, `api_token` |
| greymatter | `host`, `client_id`, `client_secret` |
| whistic | `host`, `api_key` |
| riskrecon | `host`, `client_id`, `client_secret` |
| feedly | `host`, `api_token` |
| splunk | `host`, `api_token` (or `username`+`password`) |

**Override at runtime:**
Any INI key can be overridden by passing it to `connect()`:
```python
cli.connect("threatq", client_secret="runtime-secret")
```

---

*Licensed under the Apache License, Version 2.0*
