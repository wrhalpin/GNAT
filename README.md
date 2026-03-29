# GNAT 🪰💪

**GNAT's Not Another TIP**

A universal CTM toolkit including Python client and STIX 2.1-compatible ORM for interacting with security platforms. GNAT provides a uniform abstraction layer so you can write the same code regardless of which platform sits underneath.

---

## Supported Platforms

| Target key | Platform |
|---|---|
| `threatq` | ThreatQ Threat Intelligence Platform |
| `proofpoint` | Proofpoint TAP (Targeted Attack Protection) |
| `netskope` | Netskope SASE / SSE |
| `crowdstrike` | CrowdStrike Falcon |
| `xsoar` | Palo Alto XSOAR 6 |
| `recordedfuture` | Recorded Future Connect API |
| `splunk` | Splunk Enterprise / Splunk ES |
| `virustotal` | VirusTotal |
| `shadowserver` | Shadowserver Foundation |
| `rapid7` | Rapid7 InsightVM / InsightIDR |
| `nucleus` | Nucleus Security |
| `greymatter` | GreyMatter |
| `whistic` | Whistic |
| `riskrecon` | RiskRecon |
| `feedly` | Feedly Threat Intelligence |
| `controlup` | ControlUp DEX |
| `alienvault` | AlienVault OTX |
| `elastic` | Elastic SIEM / Security |
| `graylog` | Graylog |
| `misp` | MISP Threat Sharing Platform |
| `opencti` | OpenCTI |
| `ossim` | OSSIM / AlienVault SIEM |
| `qradar` | IBM QRadar |
| `security_onion` | Security Onion |
| `sentinel` | Microsoft Sentinel |
| `snort` | Snort IDS |
| `suricata` | Suricata IDS/IPS |
| `wazuh` | Wazuh SIEM/XDR |
| `zeek` | Zeek Network Monitor |

---

## Installation

```bash
pip install gnat
# Optional: YAML support for the OpenAPI code generator
pip install "gnat[yaml]"
```

---

## Quick Start

### 1. Configure

Copy `config/config.ini.example` to `~/.gnat/config.ini` and fill in your credentials:

```ini
[DEFAULT]
timeout    = 30
verify_ssl = true

[threatq]
host          = https://threatq.example.com
client_id     = my-client-id
client_secret = s3cr3t
auth_type     = oauth2

[crowdstrike]
host          = https://api.crowdstrike.com
client_id     = cs-cid
client_secret = cs-secret
auth_type     = oauth2
```

### 2. Connect and use

```python
import gnat

# --- Classic client usage ---
cli = gnat.GNATClient()
cli.connect(target="threatq")

# Ping to verify connectivity
print(cli.ping())   # True

# --- ORM usage ---
# Fetch an existing indicator by id
ind = gnat.Indicator(client=cli)
ind.id = "indicator--12345"
ind.select()
print(ind.name, ind.pattern)

# Create a new indicator
new_ind = gnat.Indicator(
    client=cli,
    name="Malicious IP",
    pattern="[ipv4-addr:value = '198.51.100.99']",
    indicator_types=["malicious-activity"],
)
new_ind.save()
print(new_ind.id)   # server-assigned id after save

# Update a field and push
new_ind.description = "Seen in phishing campaign Q1-2025"
new_ind.save()

# Delete
new_ind.delete()

# --- Other ORM types ---
actor = gnat.ThreatActor(client=cli, name="APT-XYZ")
actor.save()

malware = gnat.Malware(client=cli, name="BlackCat", is_family=True)
malware.save()

vuln = gnat.Vulnerability(client=cli, name="CVE-2024-12345")
vuln.save()

rel = gnat.Relationship(
    client=cli,
    relationship_type="uses",
    source_ref=actor.id,
    target_ref=malware.id,
)
rel.save()
```

### 3. Switch platforms — zero code changes

```python
# Point at CrowdStrike instead
cli.connect(target="crowdstrike")

# Exact same ORM calls work
ind = gnat.Indicator(client=cli, name="Evil Hash")
ind.save()
```

### 4. Override config at runtime

```python
cli = gnat.GNATClient()
cli.connect(
    target="netskope",
    host="https://mytenant.goskope.com",
    api_token="runtime-token",
)
```

---

## STIX 2.1 Serialisation

Every ORM object is STIX 2.1 wire-format compatible:

```python
ind = gnat.Indicator(name="Evil Domain", pattern="[domain-name:value = 'evil.com']")

# Single object as dict
print(ind.to_dict())

# Wrapped in a STIX bundle
import json
bundle = ind.to_stix_bundle()
print(json.dumps(bundle, indent=2))

# Restore from dict
restored = gnat.Indicator.from_dict(ind.to_dict(), client=cli)
```

---

## Adding a New Connector (Code Generation)

GNAT ships with an OpenAPI-based code generator. Given any OpenAPI 3.x or Swagger 2.x spec you get a fully scaffolded connector in seconds:

```bash
# CLI
gnat-codegen \
    --spec    ./specs/myplatform-openapi.json \
    --name    myplatform \
    --auth    oauth2 \
    --out-dir ./gnat/connectors

# Python API
from gnat.codegen import generate_connector
generate_connector(
    spec_path="./myplatform.yaml",
    connector_name="myplatform",
    auth_type="api_key",
)
```

This generates:
- `gnat/connectors/myplatform/client.py` — fully structured, ready to fill in `to_stix()` / `from_stix()`
- `gnat/connectors/myplatform/__init__.py`
- `tests/unit/connectors/test_myplatform.py` — complete pytest scaffold

Then register the new connector in `gnat/clients/__init__.py`:

```python
from gnat.connectors.myplatform.client import MyplatformClient

CLIENT_REGISTRY = {
    ...
    "myplatform": MyplatformClient,
}
```

---

## Project Structure

```
gnat/
├── __init__.py              # Public API surface
├── client.py                # GNATClient — top-level facade
├── config.py                # INI file loader
├── clients/
│   ├── __init__.py          # CLIENT_REGISTRY
│   └── base.py              # urllib3 BaseClient + GNATClientError
├── orm/
│   ├── base.py              # STIXBase — STIX 2.1 ORM base
│   ├── indicator.py
│   ├── threat_actor.py
│   ├── malware.py
│   ├── vulnerability.py
│   ├── attack_pattern.py
│   ├── observable.py        # IPv4Address, DomainName, URL, File, Email
│   └── relationship.py
├── connectors/              # 29 platform connectors
│   ├── base_connector.py    # ConnectorMixin (STIX translation contract)
│   ├── threatq/             # ThreatQ TIP
│   ├── crowdstrike/         # CrowdStrike Falcon
│   ├── netskope/            # Netskope SASE
│   ├── proofpoint/          # Proofpoint TAP
│   ├── xsoar/               # Palo Alto XSOAR
│   ├── recordedfuture/      # Recorded Future
│   ├── splunk/              # Splunk Enterprise / ES
│   ├── virustotal/          # VirusTotal
│   ├── shadowserver/        # Shadowserver
│   ├── rapid7/              # Rapid7 InsightVM/IDR
│   ├── nucleus/             # Nucleus Security
│   ├── greymatter/          # GreyMatter
│   ├── whistic/             # Whistic
│   ├── riskrecon/           # RiskRecon
│   ├── feedly/              # Feedly Threat Intel
│   ├── controlup/           # ControlUp DEX
│   ├── alienvault/          # AlienVault OTX
│   ├── elastic/             # Elastic SIEM
│   ├── graylog/             # Graylog
│   ├── misp/                # MISP
│   ├── opencti/             # OpenCTI
│   ├── ossim/               # OSSIM
│   ├── qradar/              # IBM QRadar
│   ├── security_onion/      # Security Onion
│   ├── sentinel/            # Microsoft Sentinel
│   ├── snort/               # Snort IDS
│   ├── suricata/            # Suricata IDS/IPS
│   ├── wazuh/               # Wazuh SIEM/XDR
│   └── zeek/                # Zeek Network Monitor
├── search/                  # Solr full-text search sidecar
│   ├── index.py             # GNATIndexer (Solr document management)
│   ├── mixin.py             # SearchMixin for connectors
│   ├── orm_with_mixin.py    # ORM integration
│   ├── pipeline_patch.py    # Ingest pipeline integration
│   ├── library_patch.py     # ResearchLibrary integration
│   └── solr_schema_gnat.xml # Solr 9.x schema
├── codegen/
│   └── openapi_generator.py # CLI + Python API for connector generation
└── utils/
    └── stix_helpers.py      # Bundle helpers, ID validation

tests/
├── conftest.py              # Shared fixtures
├── unit/
│   ├── test_orm.py          # ORM + STIXBase tests
│   ├── test_client.py       # GNATClient, GNATConfig, BaseClient tests
│   └── connectors/
│       └── test_connectors.py  # Connector tests
└── integration/
    └── test_integration.py  # Live API tests (opt-in)

config/
└── config.ini.example       # Copy to ~/.gnat/config.ini
```

---

## Running Tests

```bash
# Unit tests (no credentials required)
pytest tests/unit/ -v

# With coverage
pytest tests/unit/ --cov=gnat --cov-report=term-missing

# Integration tests (requires real credentials in config)
GNAT_CONFIG=/path/to/real.ini pytest tests/integration/ --run-integration -v
```

---

## Architecture

```
GNATClient
    └── connect(target) ──► CLIENT_REGISTRY[target] ──► ConnectorClient
                                                              │
                                         ┌────────────────────┘
                                         │
                                    BaseClient (urllib3)
                                    ConnectorMixin
                                         │
                          ┌──────────────┴──────────────┐
                          │                             │
                     authenticate()            to_stix() / from_stix()
                     get/post/put/patch/delete  get_object / list_objects
                                               upsert_object / delete_object

ORM Objects (Indicator, ThreatActor, Malware, ...)
    └── STIXBase
            ├── to_dict() / from_dict() / to_stix_bundle()
            └── select() / save() / delete() / refresh()
                    └── delegates to client.get_object() / upsert_object() / ...
```

---

## License

MIT

---

## Ingestion Framework

GNAT includes a composable ingestion layer for pulling threat intelligence from any external source into STIX 2.1 objects.

### Architecture

```
SourceReader  ──yields──►  RawRecord (plain dict)
     │
     ▼
RecordMapper  ──yields──►  STIXBase (Indicator, ThreatActor, …)
     │
     ▼
IngestPipeline ──(optionally writes to)──► GNATClient
```

### Quick Examples

**Plaintext IOC list → ThreatQ:**
```python
import gnat

cli = gnat.GNATClient().connect("threatq")

result = (
    gnat.IngestPipeline("daily-blocklist")
    .read_from(gnat.PlainTextReader("blocklist.txt"))
    .map_with(gnat.FlatIOCMapper(tlp_marking="amber", confidence=75))
    .write_to(cli)
    .deduplicate(key_fields=["name"])
    .filter(lambda o: getattr(o, "confidence", 0) >= 50)
    .run()
)
print(result)  # IngestResult: 1204 records → 1198 STIX objects, 1102 written …
```

**STIX/TAXII feed → CrowdStrike:**
```python
from taxii2client.v21 import Server

server = Server("https://limo.anomali.com/api/v1/taxii2/", user="guest", password="guest")
collection = server.api_roots[0].collections[0]

result = (
    gnat.IngestPipeline("taxii-feed")
    .read_from(gnat.TAXIICollectionReader(collection, stix_types=["indicator"]))
    .map_with(gnat.STIXPassthroughMapper(client=cli))
    .write_to(cli)
    .deduplicate()
    .run()
)
```

**Relational database → XSOAR:**
```python
import psycopg2

conn = psycopg2.connect("host=db dbname=ti user=ro password=secret")
cli = gnat.GNATClient().connect("xsoar")

result = (
    gnat.IngestPipeline("postgres-iocs")
    .read_from(gnat.SQLReader(
        conn,
        query="SELECT value, type, confidence, notes FROM indicators WHERE active = %s",
        params=(True,),
        column_map={"notes": "description"},
    ))
    .map_with(gnat.SQLRowMapper(
        value_col="value", type_col="type",
        description_col="description", client=cli,
    ))
    .write_to(cli)
    .run()
)
```

**MISP export → Recorded Future:**
```python
result = (
    gnat.IngestPipeline("misp-export")
    .read_from(gnat.MISPReader("misp_export.json", attribute_types=["ip-dst", "domain", "md5"]))
    .map_with(gnat.MISPAttributeMapper(require_to_ids=True, tlp_marking="red", confidence=90))
    .write_to(cli)
    .deduplicate(key_fields=["name"])
    .run()
)
```

**NVD CVE feed → vulnerability tracking:**
```python
result = (
    gnat.IngestPipeline("nvd-daily")
    .read_from(gnat.JSONReader("nvdcve-1.1-recent.json", records_key="CVE_Items"))
    .map_with(gnat.NVDCVEMapper(confidence=95))
    .filter(lambda v: getattr(v, "x_cvss_score", 0) >= 7.0)   # HIGH+ only
    .run()
)
```

**Phishing email folder:**
```python
result = (
    gnat.IngestPipeline("phish-samples")
    .read_from(gnat.EmailReader("phishing_samples/", recursive=True))
    .map_with(gnat.EmailIOCMapper(ioc_types=["ips", "urls", "domains"]))
    .deduplicate(key_fields=["name"])
    .run()
)
objs = list(pipeline.iter_objects())   # collect without writing
```

**SIEM (Splunk / Elastic) → platform:**
```python
# Splunk
result = (
    gnat.IngestPipeline("splunk-hunt")
    .read_from(gnat.SplunkReader(splunk_client,
        search="search index=threat_intel type=ip | table src_ip type"))
    .map_with(gnat.SplunkResultMapper(value_field="src_ip"))
    .write_to(cli)
    .run()
)

# Elasticsearch
result = (
    gnat.IngestPipeline("elastic-iocs")
    .read_from(gnat.ElasticReader(elastic_client,
        index="threat-intel-*",
        query={"term": {"active": True}},
        source_fields=["value", "type", "confidence"]))
    .map_with(gnat.FlatIOCMapper())
    .run()
)
```

### Supported Source Readers

| Reader | Source | Requires |
|---|---|---|
| `PlainTextReader` | One IOC per line, auto-classified | — |
| `CSVReader` | Delimited files with column mapping | — |
| `JSONReader` | JSON array or object-wrapped array | — |
| `JSONLReader` | Newline-delimited JSON (NDJSON) | — |
| `STIXBundleReader` | STIX 2.x bundle JSON files | — |
| `TAXIICollectionReader` | TAXII 2.x collection | `taxii2-client` |
| `SQLReader` | Any DB-API 2.0 database | your DB driver |
| `MISPReader` | MISP event export JSON | — |
| `SyslogReader` | Syslog / CEF / LEEF log files | — |
| `RSSReader` | RSS 2.0 / Atom 1.0 feeds | `feedparser` |
| `EmailReader` | RFC 2822 .eml files | — |
| `OpenIOCReader` | OpenIOC 1.1 XML files | — |
| `SplunkReader` | Splunk REST Search API | — |
| `ElasticReader` | Elasticsearch scroll API | — |

### Supported Mappers

| Mapper | Produces | Notes |
|---|---|---|
| `FlatIOCMapper` | `Indicator` | Generic `{value, type}` dicts |
| `STIXPassthroughMapper` | Any STIX type | Already-STIX dicts from TAXII/bundles |
| `MISPAttributeMapper` | `Indicator`, `Vulnerability`, `Malware` | MISP attribute records |
| `CEFMapper` | `Indicator` | Standard CEF field names |
| `SQLRowMapper` | Any STIX type | Configurable column bindings |
| `CSVIndicatorMapper` | `Indicator` | CSV alias of `FlatIOCMapper` |
| `RSSEntryMapper` | `Indicator`, `Vulnerability` | Extracts IOCs from feed text |
| `EmailIOCMapper` | `Indicator` | IPs, domains, URLs, hashes from email |
| `OpenIOCMapper` | `Indicator` | OpenIOC `IndicatorItem` records |
| `SplunkResultMapper` | `Indicator` | Splunk/Elastic result rows |
| `ElasticResultMapper` | `Indicator` | Elasticsearch alias |
| `NVDCVEMapper` | `Vulnerability` | NVD 1.x and 2.x formats |

### Pipeline Features

```python
pipeline = (
    IngestPipeline("name")
    .read_from(reader)            # set source
    .map_with(mapper)             # set mapper
    .write_to(cli)                # optional: write to platform
    .deduplicate(                 # optional: skip seen objects
        key_fields=["name"]       #   default: ["id"]
    )
    .filter(predicate_fn)         # optional: drop objects
    .transform(transform_fn)      # optional: mutate objects
)

result = pipeline.run()           # execute + write
objs = list(pipeline.iter_objects())  # execute, no write
```
