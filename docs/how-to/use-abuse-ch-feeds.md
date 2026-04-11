# How-to: Use the Abuse.ch Feed Family

The `abusech` connector is a **unified** facade over five abuse.ch free
threat-intel feeds. A single `AbuseChClient` dispatches to the right
sub-feed based on `filters["feed"]` (or via the `query_*` domain helpers).

| Feed key | Source | Primary output |
|---|---|---|
| `urlhaus` | URLhaus | Malicious URLs |
| `malwarebazaar` | MalwareBazaar | Malware sample hashes + metadata |
| `threatfox` | ThreatFox | Actor-attributed IOCs |
| `feodotracker` | Feodo Tracker | Emotet / Dridex / TrickBot C2 IPs |
| `sslbl` | SSL Blacklist | Malicious TLS certs (SHA-1 + JA3) |

All five are read-only. All five are free. An optional `auth_key` raises
your per-IP rate limit ceiling on every feed simultaneously.

---

## Configuration

```ini
[abusech]
host         = https://abuse.ch
auth_key     = YOUR_ABUSE_CH_KEY   ; optional; higher rate limit when set
default_feed = threatfox           ; used when list_objects filters["feed"] is missing
```

---

## Basic usage

```python
from gnat.client import GNATClient

gnat = GNATClient()
client = gnat.connect(target="abusech")

# Default feed (threatfox) — recent botnet_cc and payload_delivery IOCs
recent = client.list_objects("indicator", filters={"days": 1})
for rec in recent[:5]:
    stix = client.to_stix(rec)
    print(stix["type"], stix["name"])
```

## Dispatching to a specific feed

```python
# URLhaus — recent malicious URLs
urlhaus = client.list_objects("indicator", filters={"feed": "urlhaus"})

# MalwareBazaar — recent samples (default selector is "time")
mb = client.list_objects("indicator", filters={"feed": "malwarebazaar"})

# Feodo Tracker — static C2 IP blocklist
feodo = client.list_objects("indicator", filters={"feed": "feodotracker"})

# SSL Blacklist — static x509 SHA-1 blocklist
sslbl = client.list_objects("indicator", filters={"feed": "sslbl"})
```

## Single-IOC lookups via domain helpers

When you already know what you're looking for, skip `list_objects` and call
the feed-specific helper directly:

```python
# URLhaus URL / host lookups
client.query_urlhaus_url("http://evil.example/malware.exe")
client.query_urlhaus_host("evil.example")

# MalwareBazaar hash lookup (SHA-256)
client.query_mb_hash("abc123...")

# ThreatFox IOC search
client.query_threatfox_ioc("1.2.3.4")

# Bulk blocklist downloads
feodo_list = client.get_feodo_blocklist()
sslbl_list  = client.get_sslbl_blocklist()
```

All helpers return dicts (or lists of dicts) with a `_feed` marker already
stamped so you can feed them straight back into `client.to_stix()`.

## STIX output shape

Every record produces a STIX 2.1 `indicator` SDO with:

- a **deterministic UUID-5 id** (repeating the same lookup always yields
  the same id — idempotent to ingest),
- a `pattern` appropriate to the observable type (`[url:value = ...]`,
  `[file:hashes.'SHA-256' = ...]`, `[ipv4-addr:value = ...]`, etc.),
- a `labels: ["malicious-activity"]` marker,
- a per-feed extension block: `x_urlhaus`, `x_malwarebazaar`,
  `x_threatfox`, `x_feodotracker`, or `x_sslbl`, containing the raw
  vendor fields.

---

## Write operations

The abuse.ch connector is **read-only**. `upsert_object` and
`delete_object` raise `GNATClientError`.

## Health check

`client.health_check()` pings Feodo Tracker (the smallest static feed)
and returns `True`/`False`. It does not exercise per-feed credentials or
rate limits beyond that single GET.

---

## See also

- [Connect to Platforms](connect-to-platforms.md)
- [Work with STIX Objects](work-with-stix-objects.md)
- [Run the Ingest Pipeline](run-ingest-pipeline.md)
- abuse.ch: <https://abuse.ch>
- URLhaus API docs: <https://urlhaus-api.abuse.ch/>
- MalwareBazaar API docs: <https://bazaar.abuse.ch/api/>
- ThreatFox API docs: <https://threatfox.abuse.ch/api/>

---

*Licensed under the Apache License, Version 2.0*
